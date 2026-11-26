"""Recovery invariants for the Linux operator snapshot helper."""

import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/ops/sqlite-state-backup.sh"
pytestmark = pytest.mark.linux_only


@pytest.fixture
def backup(tmp_path):
    # Model the SQLite CLI with the same library as the fixture and verification.
    # This keeps the regression independent of an optional CI executable.
    executable = tmp_path / "sqlite3"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sqlite3, sys\n"
        "source = pathlib.Path(sys.argv[-2])\n"
        "with sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True) as db:\n"
        "    db.execute(sys.argv[-1])\n"
    )
    executable.chmod(0o700)
    source = tmp_path / "source.db"
    target = tmp_path / "snapshot.db"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    def run(minimum=1, path=env["PATH"]):
        return subprocess.run(
            ["/bin/bash", str(SCRIPT), str(source), str(target), str(minimum)],
            env={**env, "PATH": path}, text=True, capture_output=True, timeout=15,
        )

    return source, target, run


def test_snapshot_contains_uncheckpointed_commit(backup):
    source, target, run = backup
    with sqlite3.connect(source) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY)")
        writer.execute("INSERT INTO messages VALUES (42)")
        writer.commit()
        assert Path(str(source) + "-wal").stat().st_size > 0
        result = run()
        assert result.returncode == 0, result.stderr
        with sqlite3.connect(target) as restored:
            assert restored.execute("SELECT id FROM messages").fetchall() == [(42,)]
    assert target.stat().st_mode & 0o777 == 0o600


def test_backup_failure_preserves_previous_verified_file(backup, tmp_path):
    source, target, run = backup
    with sqlite3.connect(source) as writer:
        writer.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY)")
        writer.execute("INSERT INTO messages VALUES (42)")
    result = run()
    assert result.returncode == 0, result.stderr
    previous = hashlib.sha256(target.read_bytes()).digest()
    for result in (run(minimum=2), run(path=str(tmp_path / "no-sqlite"))):
        assert result.returncode != 0
        assert hashlib.sha256(target.read_bytes()).digest() == previous


def test_insufficient_space_preserves_previous_backup(backup):
    source, target, run = backup
    with sqlite3.connect(source) as writer:
        writer.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY)")
        writer.execute("INSERT INTO messages VALUES (42)")
    assert run().returncode == 0
    previous = target.read_bytes()
    # A sparse file exercises the real size check without consuming the test volume.
    with source.open("r+b") as stream:
        stream.truncate(shutil.disk_usage(source.parent).free + 1)
    result = run()
    assert result.returncode != 0
    assert "Insufficient destination space" in result.stderr
    assert target.read_bytes() == previous
