"""Proofs for kanban factory crash effects: duplicate external effects (D1) and acceptance atomicity under crash (D2)."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_dispatch as kbd
from hermes_cli.kanban_db_connect import connect
from tests.waiting import wait_until


def record_receipt(name: str, data: dict, tmp_path: Path) -> Path:
    target = tmp_path
    cur = Path.cwd().resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / "sandbox-mount-manifest.json").exists():
            target = candidate
            break
    receipt_file = target / name
    if receipt_file.exists() or receipt_file.is_symlink():
        raise FileExistsError(f"receipt already exists: {receipt_file}")
    receipt_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return receipt_file


def test_d1_worker_crash_reproduces_duplicate_effect(tmp_path, monkeypatch):
    """D1: Crash during non-idempotent external effect retries and duplicates effect."""
    home = tmp_path / "home_d1"
    (home / "profiles" / "default").mkdir(parents=True)
    (home / "profiles" / "default" / "config.yaml").write_text("{}\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    # The dispatcher keeps a launch-window grace (default 30s) so a freshly spawned
    # worker is not reclaimed before its pid is visible; this test needs the crash
    # booked on the first sweep, so it opts into the documented immediate mode.
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    kb.init_db()

    effect_file = tmp_path / "durable_effect.log"
    procs: list[subprocess.Popen] = []

    def spawn_worker(task, workspace, board=None):
        worker_code = (
            f"import os, sys\n"
            f"with open({str(effect_file)!r}, 'a') as f:\n"
            f"    f.write('effect-line' + chr(10))\n"
            f"    f.flush()\n"
            f"    os.fsync(f.fileno())\n"
            f"os._exit(7)\n"
        )
        p = subprocess.Popen([sys.executable, "-c", worker_code], start_new_session=True)
        procs.append(p)
        return p.pid

    try:
        with connect() as conn:
            kb.create_board(slug="default", name="Test")
            tid = kb.create_task(conn, title="d1-crash-effect", assignee="default")

            res1 = kbd.dispatch_once(conn, spawn_fn=spawn_worker, dry_run=False)
            assert len(res1.spawned) == 1
            p1 = procs[0]

            wait_until(lambda: effect_file.exists() and len(effect_file.read_text().splitlines()) >= 1, timeout=10)
            wait_until(lambda: p1.poll() is not None, timeout=10)
            assert p1.returncode == 7

            crashed = kbd.detect_crashed_workers(conn)
            assert tid in crashed
            assert kb.get_task(conn, tid).status == "ready"

            res2 = kbd.dispatch_once(conn, spawn_fn=spawn_worker, dry_run=False)
            assert len(res2.spawned) == 1
            p2 = procs[1]

            wait_until(lambda: len(effect_file.read_text().splitlines()) >= 2, timeout=10)
            wait_until(lambda: p2.poll() is not None, timeout=10)
            assert p2.returncode == 7

            lines = effect_file.read_text().splitlines()
            assert len(lines) == 2, f"Expected 2 duplicate effect lines, got {len(lines)}"
            assert lines == ["effect-line", "effect-line"]

            runs = conn.execute("SELECT id, status, outcome FROM task_runs WHERE task_id = ?", (tid,)).fetchall()
            assert len(runs) >= 2
            events = [r[0] for r in conn.execute("SELECT kind FROM task_events WHERE task_id = ?", (tid,)).fetchall()]
            assert "claimed" in events and "crashed" in events

            record_receipt(
                "receipt_d1_crash_duplicate_effect.json",
                {"defect": "D1", "reproduced": True, "effect_lines": len(lines), "task_id": tid, "pids": [p.pid for p in procs]},
                tmp_path,
            )
    finally:
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
                p.wait(timeout=5)


def test_d2_sigkill_process_group_preserves_atomic_acceptance(tmp_path, monkeypatch):
    """D2: Process group SIGKILL during blocked gh acceptance leaves no partial receipt."""
    home = tmp_path / "home_d2"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    kb.init_db()

    board_db = kb.kanban_db_path()
    db_path = Path(board_db)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_shim = bin_dir / "gh"
    block_flag = tmp_path / "block.flag"
    block_flag.write_text("block\n", encoding="utf-8")
    ready_file = tmp_path / "ready.state"
    fifo_path = tmp_path / "gh.fifo"
    os.mkfifo(fifo_path)
    log_file = tmp_path / "gh_argv.log"

    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    gh_code = f"""#!{sys.executable}
import json, os, sys
with open({str(log_file)!r}, "a") as f:
    f.write(json.dumps(sys.argv) + chr(10))
    f.flush()
    os.fsync(f.fileno())

if os.path.exists({str(block_flag)!r}):
    with open({str(ready_file)!r}, "w") as f:
        f.write("ready" + chr(10))
        f.flush()
        os.fsync(f.fileno())
    with open({str(fifo_path)!r}, "r") as fifo:
        fifo.read()

cmd = " ".join(sys.argv)
sha = "a" * 40
if "graphql" in cmd:
    out = {{"data": {{"repository": {{"pullRequest": {{
        "headRefOid": sha, "baseRefName": "main", "state": "OPEN",
        "baseRef": {{"branchProtectionRule": {{"requiredStatusChecks": [
            {{"context": "required", "app": {{"databaseId": 1}}}}
        ]}}}}
    }}}}}}}}
elif "check-runs" in cmd:
    out = [{{"total_count": 1, "check_runs": [{{
        "id": 42, "name": "required", "head_sha": sha,
        "app": {{"id": 1}}, "status": "completed", "conclusion": "success",
        "html_url": "https://github.com/acme/repo/actions/runs/42"
    }}]}}]
elif "rules" in cmd or "statuses" in cmd:
    out = [[]]
elif "pulls" in cmd:
    out = {{"head": {{"sha": sha}}, "base": {{"ref": "main"}}, "state": "open"}}
else:
    out = {{}}
print(json.dumps(out))
"""
    gh_shim.write_text(gh_code, encoding="utf-8")
    gh_shim.chmod(0o755)
    assert Path(shutil.which("gh")).resolve() == gh_shim.resolve()

    with connect(db_path) as conn:
        kb.create_board(slug="default", name="Test")
        tid = kb.create_task(conn, title="Publish PR", completion_contract="acme/repo", assignee=None)

    child_code = (
        f"import sys\n"
        f"from pathlib import Path\n"
        f"import hermes_cli.kanban_db as kb\n"
        f"from hermes_cli.kanban_db_connect import connect\n"
        f"db_p = Path({str(db_path)!r})\n"
        f"with connect(db_p) as conn:\n"
        f"    kb.complete_task(conn, {tid!r}, result='substantive task completion', "
        f"metadata={{'published_pr': 'https://github.com/acme/repo/pull/7'}})\n"
    )
    child_proc = subprocess.Popen([sys.executable, "-c", child_code], start_new_session=True)

    try:
        wait_until(lambda: ready_file.exists() and ready_file.read_text().strip() == "ready", timeout=10)
        os.killpg(child_proc.pid, signal.SIGKILL)
        child_proc.wait(timeout=10)
        assert child_proc.returncode == -signal.SIGKILL

        with connect(db_path) as conn:
            task = kb.get_task(conn, tid)
            assert task.status != "done"
            row = conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()
            assert row[0] == 0

        block_flag.unlink(missing_ok=True)

        with connect(db_path) as conn:
            ok = kb.complete_task(
                conn, tid, result="substantive task completion",
                metadata={"published_pr": "https://github.com/acme/repo/pull/7"},
            )
            assert ok is True
            task_final = kb.get_task(conn, tid)
            assert task_final.status == "done"

            events = [r[0] for r in conn.execute("SELECT kind FROM task_events WHERE task_id=? ORDER BY id", (tid,)).fetchall()]
            assert events.count("pr_acceptance") == 1
            assert events.count("completed") == 1

        record_receipt(
            "receipt_d2_sigkill_pr_acceptance.json",
            {
                "defect": "D2", "verified": True, "task_id": tid,
                "killed_returncode": child_proc.returncode, "status_after_death": task.status,
                "final_status": task_final.status, "pr_acceptance_count": events.count("pr_acceptance"),
                "completed_count": events.count("completed"),
            },
            tmp_path,
        )
    finally:
        if child_proc.poll() is None:
            try:
                os.killpg(child_proc.pid, signal.SIGKILL)
            except OSError:
                pass
            child_proc.wait(timeout=5)
        fifo_path.unlink(missing_ok=True)
