"""Targeted regressions for staged-artifact integrity on review completion.

The native contract: a review handoff that staged durable copies binds their
SHA-256 digests in the newest ``review_requested`` payload together with an
explicit integrity-version marker. Completion out of ``review`` verifies those
copies and refuses with a durable ``review_artifact_mismatch`` event when they
were changed, removed, made unreadable, replaced by a symlink or a non-regular
file, or when a marked event's digest map is missing or corrupt. Unmarked
(legacy) in-flight reviews stay completable even when they name artifacts, and
no force path bypasses verification.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc


@pytest.fixture
def review_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def stage_artifact(home: Path, name: str, payload: bytes = b"ORIGINAL_12345") -> Path:
    workspace = home / "kanban" / "workspaces" / name
    workspace.mkdir(parents=True)
    source = workspace / "deliverable.bin"
    source.write_bytes(payload)
    return source


def make_review_card(home: Path, conn, name: str, payload: bytes = b"ORIGINAL_12345",
                     metadata: dict | None = None):
    source = stage_artifact(home, name, payload)
    tid = kb.create_task(conn, title=f"integrity {name}", assignee="worker",
                         workspace_kind="scratch", workspace_path=str(source.parent))
    impl_run = kb.claim_task(conn, tid).current_run_id
    declared = metadata if metadata is not None else {"artifacts": [str(source)]}
    if "artifacts" not in declared:
        declared = {**declared, "artifacts": [str(source)]}
    assert kb.request_review(conn, tid, summary="ready for review",
                             expected_run_id=impl_run, metadata=declared) is True
    row = conn.execute("SELECT stored_path FROM task_attachments WHERE task_id = ?", (tid,)).fetchone()
    staged = Path(row["stored_path"])
    claimed = kb.claim_review_task(conn, tid)
    assert claimed is not None and claimed.current_run_id is not None
    return tid, staged, claimed.current_run_id


def event_payloads(conn, tid: str, kind: str) -> list[dict]:
    rows = conn.execute(
        "SELECT payload FROM task_events WHERE task_id = ? AND kind = ? ORDER BY id", (tid, kind),
    ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def latest_review_event_id(conn, tid: str) -> int:
    return conn.execute(
        "SELECT MAX(id) FROM task_events WHERE task_id = ? AND kind = 'review_requested'", (tid,),
    ).fetchone()[0]


def rewrite_latest_review_payload(conn, tid: str, mutate) -> None:
    event_id = latest_review_event_id(conn, tid)
    payload = json.loads(conn.execute(
        "SELECT payload FROM task_events WHERE id = ?", (event_id,)).fetchone()["payload"])
    mutate(payload)
    with kb.write_txn(conn):
        conn.execute("UPDATE task_events SET payload = ? WHERE id = ?",
                     (json.dumps(payload), event_id))


def assert_refused(conn, tid: str, run_id: int, reason: str, **kwargs) -> None:
    assert kb.complete_task(conn, tid, expected_run_id=run_id, result="approved", **kwargs) is False
    assert kb.get_task(conn, tid).status != "done"
    mismatches = event_payloads(conn, tid, "review_artifact_mismatch")
    assert len(mismatches) == 1, mismatches
    assert mismatches[0]["reason"] == reason, mismatches


def test_unmodified_staged_artifact_completes(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "clean")
        assert staged.read_bytes() == b"ORIGINAL_12345"
        assert kb.complete_task(conn, tid, expected_run_id=run_id, result="approved") is True
        assert kb.get_task(conn, tid).status == "done"
        assert event_payloads(conn, tid, "review_artifact_mismatch") == []


def test_restored_artifact_completes(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "restored")
        staged.write_bytes(b"TAMPERED_LONGER_PAYLOAD")
        staged.write_bytes(b"ORIGINAL_12345")
        assert kb.complete_task(conn, tid, expected_run_id=run_id, result="approved") is True
        assert kb.get_task(conn, tid).status == "done"


@pytest.mark.parametrize("mutated", [b"ORIGINAL_67890", b"DIFF_SIZE_MUTATED_PAYLOAD"])
def test_mutation_is_refused_with_durable_mismatch(review_home: Path, mutated: bytes) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "mutated")
        staged.write_bytes(mutated)
        assert_refused(conn, tid, run_id, "digest_mismatch")


def test_missing_staged_file_is_refused(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "missing")
        staged.unlink()
        assert_refused(conn, tid, run_id, "missing_file")


def test_unreadable_staged_file_is_refused(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "unreadable")
        os.chmod(staged, 0o000)
        try:
            assert_refused(conn, tid, run_id, "unreadable_file")
        finally:
            os.chmod(staged, 0o600)


def test_symlink_replacement_is_refused(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "symlink")
        target = staged.parent / "porcelain.bin"
        target.write_bytes(b"ORIGINAL_12345")
        staged.unlink()
        staged.symlink_to(target)
        assert_refused(conn, tid, run_id, "symlink_refused")


def test_fifo_replacement_is_refused_without_hanging(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "fifo")
        staged.unlink()
        os.mkfifo(staged)
        assert_refused(conn, tid, run_id, "non_regular_file")
        staged.unlink()


def test_forged_reserved_metadata_does_not_bypass(review_home: Path) -> None:
    forged = {
        "artifact_digests": {},
        "artifact_integrity_version": 1,
        "_staged_digests": {},
        "_staged_artifacts": [],
    }
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "forged", metadata=forged)
        bound = event_payloads(conn, tid, "review_requested")[-1]
        assert bound.get("artifact_digests"), bound
        assert bound["artifact_digests"].get(str(staged)) is not None
        assert bound["artifact_integrity_version"] == 1
        staged.write_bytes(b"ORIGINAL_67890")
        assert_refused(conn, tid, run_id, "digest_mismatch")


def test_marked_event_without_digest_map_is_corrupt(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, _, run_id = make_review_card(review_home, conn, "corrupt")
        rewrite_latest_review_payload(conn, tid, lambda payload: payload.pop("artifact_digests", None))
        assert_refused(conn, tid, run_id, "missing_or_corrupt_digest_map")


def test_legacy_event_with_artifacts_stays_completable(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, _, run_id = make_review_card(review_home, conn, "legacy")
        rewrite_latest_review_payload(conn, tid, lambda payload: (
            payload.pop("artifact_digests", None), payload.pop("artifact_integrity_version", None)))
        assert event_payloads(conn, tid, "review_requested")[-1]["artifacts"]
        assert kb.complete_task(conn, tid, expected_run_id=run_id, result="approved") is True
        assert kb.get_task(conn, tid).status == "done"


def test_force_does_not_bypass_integrity(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, staged, run_id = make_review_card(review_home, conn, "forced")
        staged.write_bytes(b"ORIGINAL_67890")
        assert_refused(conn, tid, run_id, "digest_mismatch", force=True)


def test_rereview_binds_latest_cycle(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, first_staged, first_run = make_review_card(review_home, conn, "cycle1")
        assert kb.request_changes(conn, tid, reason="rework", expected_run_id=first_run)[0] is True
        second_source = Path(first_staged).parent.parent.parent / "workspaces" / "cycle1" / "deliverable_v2.bin"
        second_source.parent.mkdir(parents=True, exist_ok=True)
        second_source.write_bytes(b"SECOND_CYCLE_PAYLOAD")
        impl_run = kb.claim_task(conn, tid).current_run_id
        assert kb.request_review(conn, tid, summary="second cycle",
                                 expected_run_id=impl_run,
                                 metadata={"artifacts": [str(second_source)]}) is True
        second_staged = Path(conn.execute(
            "SELECT stored_path FROM task_attachments WHERE task_id = ? ORDER BY id DESC LIMIT 1",
            (tid,)).fetchone()["stored_path"])
        assert second_staged != first_staged
        claimed = kb.claim_review_task(conn, tid)
        first_staged.write_bytes(b"STALE_CYCLE_TAMPER")
        assert kb.complete_task(conn, tid, expected_run_id=claimed.current_run_id,
                                result="approved") is True
        assert kb.get_task(conn, tid).status == "done"


def test_owner_run_id_still_gates_completion(review_home: Path) -> None:
    with kbc.connect() as conn:
        tid, _, run_id = make_review_card(review_home, conn, "owner")
        assert kb.complete_task(conn, tid, expected_run_id=run_id + 999, result="approved") is False
        assert kb.get_task(conn, tid).status != "done"
        assert event_payloads(conn, tid, "review_artifact_mismatch") == []
        assert kb.complete_task(conn, tid, expected_run_id=run_id, result="approved") is True
        assert kb.get_task(conn, tid).status == "done"
