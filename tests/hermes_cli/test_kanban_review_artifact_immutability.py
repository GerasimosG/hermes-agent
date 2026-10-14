from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import profiles


@pytest.fixture
def kanban_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def persist_receipt(tmp_path: Path, name: str, payload: dict) -> Path:
    out_dir = tmp_path
    for cand in [Path.cwd(), *Path.cwd().parents]:
        manifest = cand / "sandbox-mount-manifest.json"
        if manifest.exists():
            out_dir = cand
            break
    target = out_dir / name
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


@pytest.mark.parametrize("variant,payload_before,payload_after", [
    ("same_size", b"SAME_SIZE_12345", b"SAME_SIZE_MUTAT"),
    ("diff_size", b"DIFF_SIZE_12345", b"DIFF_MUTATED_LONGER_PAYLOAD"),
])
def test_review_artifact_mutation_detected_or_reproduced(
    kanban_home: Path, tmp_path: Path, variant: str, payload_before: bytes, payload_after: bytes,
) -> None:
    # Staging only runs for a managed scratch workspace
    # (_persist_scratch_completion_artifacts returns early otherwise), so the
    # declared artifact must live inside the task's scratch dir under
    # kanban/workspaces and the task must name that dir.
    workspace_dir = kanban_home / "kanban" / "workspaces" / f"stage_{variant}"
    workspace_dir.mkdir(parents=True)
    src_file = workspace_dir / f"src_{variant}.bin"
    src_file.write_bytes(payload_before)

    with kbc.connect() as conn:
        tid = kb.create_task(
            conn, title=f"stage mutation {variant}", assignee="worker",
            workspace_kind="scratch", workspace_path=str(workspace_dir),
        )
        kb.claim_task(conn, tid)
        impl_run = kb.get_task(conn, tid).current_run_id
        assert impl_run is not None

        req_ok = kb.request_review(
            conn, tid, summary="ready for review", reviewer="reviewer",
            expected_run_id=impl_run, metadata={"artifacts": [str(src_file)]},
        )
        assert req_ok is True and kb.get_task(conn, tid).status == "review"

        rows = conn.execute(
            "SELECT filename, stored_path, size FROM task_attachments WHERE task_id = ?", (tid,),
        ).fetchall()
        assert len(rows) == 1
        staged_path = Path(rows[0]["stored_path"])
        assert rows[0]["filename"] == src_file.name and rows[0]["size"] == len(payload_before)
        assert staged_path != src_file and staged_path.read_bytes() == payload_before

        staged_path.write_bytes(payload_after)
        assert staged_path.read_bytes() == payload_after
        if variant == "same_size":
            assert len(staged_path.read_bytes()) == len(payload_before)
        else:
            assert len(staged_path.read_bytes()) != len(payload_before)

        hash_before = hashlib.sha256(payload_before).hexdigest()
        hash_after = hashlib.sha256(payload_after).hexdigest()
        count_before, count_after = len(payload_before), len(payload_after)

        claimed = kb.claim_review_task(conn, tid)
        assert claimed is not None and claimed.current_run_id is not None
        rev_run = claimed.current_run_id

        completed = kb.complete_task(conn, tid, expected_run_id=rev_run, result="approved")
        t_now = kb.get_task(conn, tid)
        events = conn.execute("SELECT kind, payload FROM task_events WHERE task_id = ?", (tid,)).fetchall()

        mismatch_payloads = [json.loads(e["payload"]) for e in events if e["kind"] == "review_artifact_mismatch"]
        verdict = "ENFORCED" if (completed is False and mismatch_payloads) else "REPRODUCED"
        detail = ("refused completion with durable mismatch event" if verdict == "ENFORCED"
                  else "bad done without digest gate")
        persist_receipt(tmp_path, f"receipt_t_a_a1_{variant}.json", {
            "proof": "T-A", "case": f"A1_{variant}", "variant": variant, "verdict": verdict,
            "task_id": tid, "status": t_now.status, "completed": completed, "detail": detail,
            "hash_before": hash_before, "hash_after": hash_after,
            "count_before": count_before, "count_after": count_after,
            "mismatch_reasons": [payload.get("reason") for payload in mismatch_payloads],
        })

        assert verdict == "ENFORCED", f"staged artifact mutation was not refused: {detail}"
        assert t_now.status != "done"
        assert len(mismatch_payloads) == 1
        assert mismatch_payloads[0].get("reason") == "digest_mismatch"


def test_review_caller_identity_enforced_or_reproduced(kanban_home: Path, tmp_path: Path) -> None:
    (kanban_home / "profiles" / "designated_rev").mkdir(parents=True, exist_ok=True)
    ((kanban_home / "profiles" / "designated_rev") / "config.yaml").write_text("name: designated_rev\n", encoding="utf-8")
    intruder_home = tmp_path / "intruder_home"
    (intruder_home / "profiles" / "intruder").mkdir(parents=True, exist_ok=True)
    ((intruder_home / "profiles" / "intruder") / "config.yaml").write_text("name: intruder\n", encoding="utf-8")

    with kbc.connect() as conn:
        tid = kb.create_task(conn, title="reviewer identity test", assignee="worker")
        kb.claim_task(conn, tid)
        impl_run = kb.get_task(conn, tid).current_run_id
        assert impl_run is not None

        req_ok = kb.request_review(
            conn, tid, summary="handoff", reviewer="designated_rev", expected_run_id=impl_run,
        )
        assert req_ok is True and kb.get_task(conn, tid).status == "review"

        claimed = kb.claim_review_task(conn, tid)
        assert claimed is not None and claimed.current_run_id is not None
        rev_run = claimed.current_run_id

        run_row = conn.execute("SELECT profile FROM task_runs WHERE id = ?", (rev_run,)).fetchone()
        assert run_row["profile"] == "designated_rev"
        board_file = str(conn.execute("PRAGMA database_list").fetchone()[2])

        env = os.environ.copy()
        env["HERMES_HOME"] = str(intruder_home)
        env["HERMES_PROFILE_NAME"] = "intruder"
        env["HERMES_PROFILE"] = "intruder"

        child_code = (
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "from hermes_cli import profiles, kanban_db as kb, kanban_db_connect as kbc\n"
            "assert profiles.current_profile_name() == 'intruder'\n"
            f"os.environ['HERMES_KANBAN_TASK'] = {tid!r}\n"
            "os.environ.pop('HERMES_KANBAN_RUN_ID', None)\n"
            "from tools import kanban_tools as kt\n"
            "try:\n"
            f"    kt._worker_guard('kanban_complete', {{'task_id': {tid!r}}})\n"
            "    guard = 'ALLOWED'\n"
            "except Exception as exc:\n"
            "    guard = 'REFUSED:' + type(exc).__name__\n"
            f"with kbc.connect(db_path=Path({board_file!r})) as conn:\n"
            f"    completed = kb.complete_task(conn, {tid!r}, expected_run_id={rev_run}, result='approved', fire_lifecycle_hook=False)\n"
            f"    task_now = kb.get_task(conn, {tid!r})\n"
            "    print(json.dumps({'caller_profile': profiles.current_profile_name(), 'status': task_now.status,"
            " 'completed': completed, 'worker_guard': guard}))\n"
        )

        proc = subprocess.run(
            [sys.executable, "-c", child_code], env=env, capture_output=True, text=True, timeout=30,
            check=False,
        )
        assert proc.returncode == 0
        child_out = json.loads(proc.stdout)
        assert child_out["caller_profile"] == "intruder"

        t_now = kb.get_task(conn, tid)
        assert t_now.status == child_out["status"]

        events = conn.execute("SELECT kind, payload FROM task_events WHERE task_id = ?", (tid,)).fetchall()
        kinds = [e["kind"] for e in events]
        completed = child_out["completed"]
        verdict = "REPRODUCED" if (completed and t_now.status == "done") else "ENFORCED"
        detail = "done with no reviewer-identity check" if verdict == "REPRODUCED" else "refusal on profile mismatch"

        persist_receipt(tmp_path, "receipt_t_a_a2.json", {
            "proof": "T-A", "case": "A2", "verdict": verdict, "task_id": tid,
            "status": t_now.status, "completed": completed, "reviewer": "designated_rev",
            "caller_profile": "intruder", "detail": detail,
            "worker_guard": child_out.get("worker_guard"),
            "enforcement_scope": "manual/operator path (no HERMES_KANBAN_TASK): run ownership is the gate, profile identity is not",
        })

        if verdict == "REPRODUCED":
            assert completed is True and t_now.status == "done" and "completed" in kinds
            last_run = conn.execute("SELECT status, outcome FROM task_runs WHERE id = ?", (rev_run,)).fetchone()
            assert last_run["status"] == "done" and last_run["outcome"] == "completed"
        else:
            assert not completed or t_now.status != "done"

        # A2b: the intended worker path. A review card under a LIVE dispatched
        # worker must refuse foreign completions (no run id -> LiveClaimError;
        # wrong run id -> run CAS miss) and accept only the owner's run id.
        (kanban_home / "config.yaml").write_text("kanban:\n  review_dispatch: true\n", encoding="utf-8")
        worker_profile = kanban_home / "profiles" / "worker"
        worker_profile.mkdir(parents=True, exist_ok=True)
        (worker_profile / "config.yaml").write_text("{}\n", encoding="utf-8")
        from hermes_cli import kanban_db_dispatch as kbd

        live_task = kb.create_task(conn, title="live reviewer ownership", assignee="worker")
        live_claim = kb.claim_task(conn, live_task)
        kb.request_review(conn, live_task, summary="live review", reviewer="designated_rev",
                          expected_run_id=live_claim.current_run_id)
        spawned: list[subprocess.Popen] = []

        def spawn_fn(task, workspace, board=None):
            proc = subprocess.Popen(
                [sys.executable, "-c", "import signal\nsignal.pause()\n"],
                start_new_session=True,
            )
            spawned.append(proc)
            return proc.pid

        ownership: dict = {}
        try:
            dispatch_result = kbd.dispatch_once(conn, spawn_fn=spawn_fn)
            assert len(dispatch_result.spawned) == 1
            live_run = kb.get_task(conn, live_task).current_run_id
            try:
                kb.complete_task(conn, live_task, result="approved")
                ownership["foreign_without_run"] = "ALLOWED"
            except kb.LiveClaimError:
                ownership["foreign_without_run"] = "REFUSED_LIVE_CLAIM"
            ownership["foreign_wrong_run_completed"] = bool(
                kb.complete_task(conn, live_task, expected_run_id=999999, result="approved"))
            ownership["owner_run_completed"] = bool(
                kb.complete_task(conn, live_task, expected_run_id=live_run, result="approved"))
        finally:
            for proc in spawned:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)

        assert ownership["foreign_without_run"] == "REFUSED_LIVE_CLAIM"
        assert ownership["foreign_wrong_run_completed"] is False
        assert ownership["owner_run_completed"] is True
        assert child_out.get("worker_guard", "").startswith("REFUSED"), child_out.get("worker_guard")
        persist_receipt(tmp_path, "receipt_t_a_a2b_ownership.json", {
            "proof": "T-A", "case": "A2b", "ownership": ownership,
            "worker_guard": child_out.get("worker_guard"),
            "scope": "intended worker path: dispatcher-spawned reviewer with a live pid",
        })
