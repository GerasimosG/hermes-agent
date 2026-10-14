from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

def get_receipt_dir(tmp_path: Path) -> Path:
    cur = Path.cwd().resolve()
    for p in (cur, *cur.parents):
        if (p / "sandbox-mount-manifest.json").is_file():
            return p
    return tmp_path


def write_receipt(tmp_path: Path, name: str, data: dict) -> str:
    path = get_receipt_dir(tmp_path) / f"receipt_{name}.json"
    if path.exists():
        raise FileExistsError(f"Receipt already exists: {path}")
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)


def count_running_by_assignee(conn) -> dict[str, int]:
    return {
        row["assignee"]: int(row["c"])
        for row in conn.execute(
            "SELECT assignee, COUNT(*) AS c FROM tasks "
            "WHERE status = 'running' AND assignee IS NOT NULL "
            "GROUP BY assignee"
        )
    }


def spawn_worker(ready_path: Path, procs: list[subprocess.Popen]) -> subprocess.Popen:
    cmd = [
        sys.executable,
        "-c",
        "import os, signal, sys\n"
        "with open(sys.argv[1], 'w') as f:\n"
        "    f.write('ready')\n"
        "    f.flush()\n"
        "    os.fsync(f.fileno())\n"
        "signal.pause()\n",
        str(ready_path),
    ]
    proc = subprocess.Popen(cmd, start_new_session=True)
    procs.append(proc)
    try:
        from tests.waiting import wait_until
        wait_until(
            lambda: ready_path.exists() and ready_path.stat().st_size > 0,
            timeout=10.0,
            what="worker ready receipt",
        )
    except Exception:
        cleanup_procs([proc])
        raise
    return proc


def cleanup_procs(procs: list[subprocess.Popen]) -> None:
    for proc in procs:
        if proc.poll() is not None:
            continue
        try:
            proc.send_signal(signal.SIGCONT)
            proc.terminate()
            proc.wait(timeout=5.0)
        except ProcessLookupError:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            proc.wait(timeout=5.0)


@pytest.fixture
def kanban_env(tmp_path, monkeypatch):
    from hermes_cli import kanban_db_connect as kbc
    from hermes_cli import kanban_db_dispatch as kbd

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")
    (tmp_path / "config.yaml").write_text("kanban:\n  review_dispatch: true\n", encoding="utf-8")
    for prof in ("alpha", "beta", "default", "builder", "reviewer"):
        pdir = tmp_path / "profiles" / prof
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "config.yaml").write_text("{}\n", encoding="utf-8")
    assert kbd.review_dispatch_enabled() is True
    conn = kbc.connect(tmp_path / "kanban.db")
    procs: list[subprocess.Popen] = []
    try:
        yield conn, tmp_path, procs
    finally:
        cleanup_procs(procs)
        conn.close()


def test_recovery_budget_proof_e1_ttl_sigstop_crash_retry(kanban_env):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_dispatch as kbd
    from tests.waiting import wait_until

    conn, tmp_path, procs = kanban_env
    t1 = kb.create_task(conn, title="job-e1", assignee="builder", max_runtime_seconds=60)
    ready_1 = tmp_path / "ready_e1_1.txt"
    ready_2 = tmp_path / "ready_e1_2.txt"

    def spawn_fn(task, workspace, board=None):
        rpath = ready_2 if ready_1.exists() else ready_1
        proc = spawn_worker(rpath, procs)
        return proc.pid

    res1 = kbd.dispatch_once(conn, spawn_fn=spawn_fn)
    assert len(res1.spawned) == 1 and res1.spawned[0][0] == t1
    proc1 = procs[0]
    assert kb.get_task(conn, t1).worker_pid == proc1.pid

    past = int(time.time()) - 3600
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET claim_expires = ? WHERE id = ?", (past, t1))

    os.kill(proc1.pid, signal.SIGSTOP)
    reclaimed = kb.release_stale_claims(conn)
    assert reclaimed == 0
    events = [e.kind for e in kb.list_events(conn, t1)]
    assert "claim_extended" in events
    res_dup = kbd.dispatch_once(conn, spawn_fn=spawn_fn)
    assert len(res_dup.spawned) == 0

    os.kill(proc1.pid, signal.SIGCONT)
    proc1.terminate()
    wait_until(lambda: proc1.poll() is not None, timeout=5.0, what="proc1 exit")

    crashed = kbd.detect_crashed_workers(conn)
    assert t1 in crashed
    assert kb.get_task(conn, t1).status == "ready"

    res2 = kbd.dispatch_once(conn, spawn_fn=spawn_fn)
    assert len(res2.spawned) == 1 and res2.spawned[0][0] == t1
    proc2 = procs[1]
    assert proc2.pid != proc1.pid
    assert kb.get_task(conn, t1).worker_pid == proc2.pid

    runs = conn.execute(
        "SELECT id, status, worker_pid FROM task_runs WHERE task_id = ? ORDER BY id ASC",
        (t1,),
    ).fetchall()
    assert len(runs) == 2
    write_receipt(tmp_path, "E1", {
        "case": "E1",
        "task_id": t1,
        "spawn_pids": [proc1.pid, proc2.pid],
        "counts": {"spawned": 2, "crashed": len(crashed)},
        "caps": {"max_runtime": 60},
        "run_statuses": [r["status"] for r in runs],
    })


def test_recovery_budget_proof_e2_simulated_pid_reuse(kanban_env):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_dispatch as kbd

    conn, tmp_path, procs = kanban_env
    t2 = kb.create_task(conn, title="reuse-e2", assignee="builder")
    kb.claim_task(conn, t2)
    stranger = spawn_worker(tmp_path / "ready_stranger.txt", procs)

    simulated_fingerprint = "SIMULATED:OLD_FINGERPRINT_REUSED"
    past = int(time.time()) - 3600
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET worker_pid = ?, worker_started_at = ?, started_at = ?, claim_expires = ? WHERE id = ?",
            (stranger.pid, simulated_fingerprint, past, past, t2),
        )
        conn.execute(
            "UPDATE task_runs SET worker_pid = ?, worker_started_at = ?, started_at = ? WHERE id = (SELECT current_run_id FROM tasks WHERE id = ?)",
            (stranger.pid, simulated_fingerprint, past, t2),
        )

    assert kbd._worker_alive(stranger.pid, simulated_fingerprint) is False
    assert kb._pid_alive(stranger.pid) is True

    signaled = []
    spy = lambda pid, sig: signaled.append((pid, sig))
    reclaimed = kb.release_stale_claims(conn, signal_fn=spy)
    assert reclaimed == 1
    assert signaled == []
    assert stranger.poll() is None

    task = kb.get_task(conn, t2)
    assert task.status == "ready"
    assert task.worker_pid is None and task.claim_lock is None

    runs = conn.execute(
        "SELECT id, status, worker_pid FROM task_runs WHERE task_id = ? ORDER BY id ASC",
        (t2,),
    ).fetchall()
    write_receipt(tmp_path, "E2", {
        "case": "E2",
        "task_id": t2,
        "stranger_pid": stranger.pid,
        "simulated_fingerprint": simulated_fingerprint,
        "signaled": signaled,
        "reclaimed": reclaimed,
        "run_statuses": [r["status"] for r in runs],
    })


def test_recovery_budget_proof_f1_shared_cap_and_review_cap(kanban_env):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_dispatch as kbd

    conn, tmp_path, procs = kanban_env
    t_ready = kb.create_task(conn, title="ready-f1", assignee="builder")
    t_rev1 = kb.create_task(conn, title="rev-f1-1", assignee="reviewer")
    c1 = kb.claim_task(conn, t_rev1)
    kb.request_review(conn, t_rev1, summary="review1", expected_run_id=c1.current_run_id)
    t_rev2 = kb.create_task(conn, title="rev-f1-2", assignee="reviewer")
    c2 = kb.claim_task(conn, t_rev2)
    kb.request_review(conn, t_rev2, summary="review2", expected_run_id=c2.current_run_id)

    count = 0
    def spawn_fn(task, workspace, board=None):
        nonlocal count
        count += 1
        proc = spawn_worker(tmp_path / f"ready_f1_{count}.txt", procs)
        return proc.pid

    res = kbd.dispatch_once(
        conn,
        spawn_fn=spawn_fn,
        max_in_progress=2,
        max_in_progress_per_profile=1,
    )
    assert len(res.spawned) == 2
    assert len(procs) == 2
    assert all(p.poll() is None for p in procs)
    assert kbd.count_running_tasks(conn) == 2
    assert count_running_by_assignee(conn).get('builder',0) == 1
    assert count_running_by_assignee(conn).get('reviewer',0) == 1

    spawned_ids = [s[0] for s in res.spawned]
    assert t_ready in spawned_ids
    assert (t_rev1 in spawned_ids) ^ (t_rev2 in spawned_ids)
    unspawned_rev = t_rev2 if t_rev1 in spawned_ids else t_rev1
    assert kb.get_task(conn, unspawned_rev).status == "review"

    res_blocked = kbd.dispatch_once(
        conn,
        spawn_fn=spawn_fn,
        max_in_progress=2,
        max_in_progress_per_profile=1,
    )
    assert len(res_blocked.spawned) == 0
    assert kbd.count_running_tasks(conn) == 2
    assert count_running_by_assignee(conn).get('builder',0) == 1
    assert count_running_by_assignee(conn).get('reviewer',0) == 1

    runs = conn.execute(
        f"SELECT id, status FROM task_runs WHERE task_id IN ({','.join('?' * len(spawned_ids))}) ORDER BY id ASC",
        tuple(spawned_ids),
    ).fetchall()
    write_receipt(tmp_path, "F1", {
        "case": "F1",
        "spawned": spawned_ids,
        "spawn_pids": [p.pid for p in procs],
        "counts": {
            "spawned": len(res.spawned),
            "running": kbd.count_running_tasks(conn),
            "builder_running": count_running_by_assignee(conn).get('builder',0),
            "reviewer_running": count_running_by_assignee(conn).get('reviewer',0),
        },
        "caps": {
            "max_in_progress": 2,
            "max_in_progress_per_profile": 1,
        },
        "run_statuses": [r["status"] for r in runs],
    })


def test_recovery_budget_proof_f2_unspawnable_review_releases_ready_slot(kanban_env):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_dispatch as kbd

    conn, tmp_path, procs = kanban_env
    r1 = kb.create_task(conn, title="r1", assignee="builder")
    r2 = kb.create_task(conn, title="r2", assignee="builder")
    rev = kb.create_task(conn, title="rev-unspawnable", assignee="nonexistent_lane")
    c = kb.claim_task(conn, rev)
    kb.request_review(conn, rev, summary="rev-unspawnable", expected_run_id=c.current_run_id)

    assert kbd.has_spawnable_review(conn) is False
    rev_rows = conn.execute(
        "SELECT id, assignee FROM tasks WHERE status = 'review'"
    ).fetchall()
    assert kbd._any_spawnable_review(conn, rev_rows) is False

    count = 0
    def spawn_fn(task, workspace, board=None):
        nonlocal count
        count += 1
        proc = spawn_worker(tmp_path / f"ready_f2_{count}.txt", procs)
        return proc.pid

    res = kbd.dispatch_once(conn, spawn_fn=spawn_fn, max_spawn=2)
    assert len(res.spawned) == 2
    spawned_ids = [s[0] for s in res.spawned]
    assert set(spawned_ids) == {r1, r2}
    assert kb.get_task(conn, rev).status == "review"
    assert len(procs) == 2
    assert all(p.poll() is None for p in procs)
    assert kbd.count_running_tasks(conn) == 2

    runs = conn.execute(
        f"SELECT id, status FROM task_runs WHERE task_id IN ({','.join('?' * len(spawned_ids))}) ORDER BY id ASC",
        tuple(spawned_ids),
    ).fetchall()
    write_receipt(tmp_path, "F2", {
        "case": "F2",
        "spawned": spawned_ids,
        "spawn_pids": [p.pid for p in procs],
        "counts": {
            "spawned": len(res.spawned),
            "skipped_nonspawnable": len(res.skipped_nonspawnable),
            "running": kbd.count_running_tasks(conn),
        },
        "caps": {"max_spawn": 2},
        "run_statuses": [r["status"] for r in runs],
    })
