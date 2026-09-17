from __future__ import annotations

import json
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hermes_cli.backup import (
    BackupCommittedWithDurabilityWarning,
    BackupInProgressError,
    QuickSnapshotCommittedWithDurabilityWarning,
    _atomic_output_path,
    _backup_operation_lock,
    _resolve_backup_output_path,
    _write_full_zip_backup,
    create_quick_snapshot,
    list_quick_snapshots,
)


def test_backup_lock_rejects_a_second_operation(tmp_path) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()

    with _backup_operation_lock(home):
        with pytest.raises(BackupInProgressError):
            with _backup_operation_lock(home, timeout_seconds=0):
                raise AssertionError("second backup unexpectedly acquired the lock")


def test_atomic_output_publishes_only_after_clean_close(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    with _atomic_output_path(final) as partial:
        partial.write(b"complete")
        partial.flush()
        assert final.read_bytes() == b"previous"

    assert final.read_bytes() == b"complete"
    assert not list(tmp_path.glob(".backup.zip.*.partial"))


def test_atomic_output_keeps_staging_fd_until_after_rename(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    events = []
    staging_fd = None

    from hermes_cli import backup

    real_open = backup.os.open
    real_close = backup.os.close
    real_fsync = backup.os.fsync
    real_replace = backup.os.replace

    def trace_open(path, flags, mode=0o777, **kwargs):
        nonlocal staging_fd
        fd = real_open(path, flags, mode, **kwargs)
        if isinstance(path, str) and path.endswith(".partial"):
            staging_fd = fd
        return fd

    def trace_fsync(fd):
        if fd == staging_fd:
            events.append("fsync")
        return real_fsync(fd)

    def trace_replace(source, destination, **kwargs):
        assert staging_fd is not None
        backup.os.fstat(staging_fd)
        events.append("rename")
        return real_replace(source, destination, **kwargs)

    def trace_close(fd):
        if fd == staging_fd:
            events.append("close")
        return real_close(fd)

    monkeypatch.setattr(backup.os, "open", trace_open)
    monkeypatch.setattr(backup.os, "fsync", trace_fsync)
    monkeypatch.setattr(backup.os, "replace", trace_replace)
    monkeypatch.setattr(backup.os, "close", trace_close)

    with _atomic_output_path(final) as staged:
        staged.write(b"complete")

    assert events == ["fsync", "rename", "close"]


def test_atomic_output_keeps_previous_file_after_failure(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    with pytest.raises(RuntimeError):
        with _atomic_output_path(final) as partial:
            partial.write(b"incomplete")
            raise RuntimeError("compression failed")

    assert final.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".backup.zip.*.partial"))


def test_atomic_output_cleans_partial_when_promotion_fails(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    from hermes_cli import backup

    def fail_replace(source, destination, **kwargs):
        del source, destination, kwargs
        raise OSError("promotion failed")

    monkeypatch.setattr(backup.os, "replace", fail_replace)
    with pytest.raises(OSError, match="promotion failed"):
        with _atomic_output_path(final) as partial:
            partial.write(b"complete")

    assert final.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".*.partial"))
    assert not list(tmp_path.glob(".backup.zip.*"))


def test_atomic_output_surfaces_cleanup_failure_with_primary_error(
    tmp_path, monkeypatch, caplog
) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    from hermes_cli import backup

    def fail_replace(source, destination, **kwargs):
        del source, destination, kwargs
        raise OSError("promotion failed")

    real_unlink = backup.os.unlink

    def fail_stage_cleanup(path, *args, **kwargs):
        if str(path).endswith(".partial"):
            raise OSError("cleanup denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(backup.os, "replace", fail_replace)
    monkeypatch.setattr(backup.os, "unlink", fail_stage_cleanup)
    with caplog.at_level("ERROR", logger="hermes_cli.backup"):
        with pytest.raises(OSError, match="promotion failed") as raised:
            with _atomic_output_path(final) as staged:
                staged.write(b"complete")

    assert final.read_bytes() == b"previous"
    assert "cleanup failed" in caplog.text
    assert any("cleanup denied" in note for note in getattr(raised.value, "__notes__", []))


def test_atomic_output_stages_owner_only_file_in_trusted_parent(tmp_path) -> None:
    final = tmp_path / "backup.zip"

    with _atomic_output_path(final) as staged:
        staged.write(b"complete")
        staged.flush()
        staged_path = next(tmp_path.glob(".backup.zip.*.partial"))
        assert staged_path.parent == tmp_path
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(staged_path.stat().st_mode) == 0o600

    assert final.read_bytes() == b"complete"
    assert not list(tmp_path.glob(".backup.zip.*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_atomic_output_rejects_insecure_parent(tmp_path, mode) -> None:
    parent = tmp_path / "output"
    parent.mkdir(mode=mode)
    parent.chmod(mode)
    final = parent / "backup.zip"

    with pytest.raises(OSError, match="owner-only 0700"):
        with _atomic_output_path(final) as staged:
            staged.write(b"must not publish")

    assert not list(parent.glob(".*.partial"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode semantics")
def test_atomic_output_rejects_unowned_parent(tmp_path, monkeypatch) -> None:
    parent = tmp_path / "output"
    parent.mkdir(mode=0o700)
    current_uid = parent.stat().st_uid

    from hermes_cli import backup

    monkeypatch.setattr(backup.os, "geteuid", lambda: current_uid + 1)
    with pytest.raises(OSError, match="owner-only 0700"):
        with _atomic_output_path(parent / "backup.zip") as staged:
            staged.write(b"must not publish")

    assert not list(parent.glob(".*.partial"))


def test_atomic_output_retries_exclusive_stage_name(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    names = iter(("same", "same", "next"))

    from hermes_cli import backup

    monkeypatch.setattr(backup.secrets, "token_hex", lambda _size: next(names))
    with _atomic_output_path(final) as first:
        first.write(b"first")
        with pytest.raises(RuntimeError):
            with _atomic_output_path(final) as second:
                second.write(b"second")
                raise RuntimeError("interrupt")

    assert final.read_bytes() == b"first"
    assert not list(tmp_path.glob(".*.partial"))


def test_atomic_output_preserves_destination_on_stage_sync_failure(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    from hermes_cli import backup

    real_fsync = backup.os.fsync
    calls = 0

    def fail_stage_sync(fd):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("ENOSPC while syncing archive")
        return real_fsync(fd)

    monkeypatch.setattr(backup.os, "fsync", fail_stage_sync)
    with pytest.raises(OSError, match="ENOSPC"):
        with _atomic_output_path(final) as staged:
            staged.write(b"incomplete")

    assert final.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".*.partial"))


def test_atomic_output_cleans_stage_after_write_failure(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    with pytest.raises(ValueError):
        with _atomic_output_path(final) as staged:
            staged.close()
            staged.write(b"must not publish")

    assert final.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".*.partial"))


def test_atomic_output_disarm_race_does_not_delete_published_file(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    from hermes_cli import backup

    real_replace = backup.os.replace

    def replace_then_interrupt(source, destination, **kwargs):
        real_replace(source, destination, **kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(backup.os, "replace", replace_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        with _atomic_output_path(final) as staged:
            staged.write(b"complete")

    assert final.read_bytes() == b"complete"
    assert not list(tmp_path.glob(".*.partial"))


@pytest.mark.skipif(os.name == "nt", reason="hard-link semantics vary on Windows")
def test_atomic_output_does_not_use_link_count_as_security_gate(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    hard_link = tmp_path / "staging-copy"

    with _atomic_output_path(final) as partial:
        partial.write(b"complete")
        partial.flush()
        hard_link.hardlink_to(next(tmp_path.glob(".backup.zip.*.partial")))

    assert final.read_bytes() == b"complete"
    assert hard_link.read_bytes() == b"complete"


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow directory opens")
def test_atomic_output_rejects_symlinked_parent(tmp_path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(OSError):
        with _atomic_output_path(linked_parent / "backup.zip") as partial:
            partial.write_bytes(b"must not publish")

    assert not (real_parent / "backup.zip").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow directory opens")
def test_backup_output_rejects_intermediate_symlink_without_creating_through_it(tmp_path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    requested = linked_parent / "created" / "backup.zip"

    with pytest.raises(SystemExit):
        _resolve_backup_output_path(str(requested))

    assert not (real_parent / "created").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_backup_output_rejects_writable_ancestor_before_recursive_creation(tmp_path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    requested = unsafe / "created" / "backup.zip"

    with pytest.raises(SystemExit):
        _resolve_backup_output_path(str(requested))

    assert not (unsafe / "created").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX same-parent rename semantics")
def test_atomic_output_surfaces_cross_device_promotion_failure(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    final.write_bytes(b"previous")

    from hermes_cli import backup

    def fail_cross_device(source, destination, **kwargs):
        del source, destination, kwargs
        raise OSError(18, "cross-device link")

    monkeypatch.setattr(backup.os, "replace", fail_cross_device)
    with pytest.raises(OSError, match="cross-device"):
        with _atomic_output_path(final) as partial:
            partial.write(b"complete")

    assert final.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".*.partial"))


@pytest.mark.skipif(os.name == "nt", reason="symlink permissions vary on Windows")
def test_atomic_output_rejects_preexisting_symlink(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    symlink_target = tmp_path / "existing.zip"
    symlink_target.write_bytes(b"previous")
    final.symlink_to(symlink_target.name)

    with pytest.raises(OSError, match="non-regular"):
        with _atomic_output_path(final) as partial:
            partial.write_bytes(b"must not publish")

    assert final.is_symlink()
    assert symlink_target.read_bytes() == b"previous"


@pytest.mark.skipif(os.name == "nt", reason="POSIX special-file semantics")
def test_atomic_output_rejects_non_regular_destination(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    os.mkfifo(final)

    with pytest.raises(OSError, match="non-regular"):
        with _atomic_output_path(final) as staged:
            staged.write(b"must not publish")

    assert stat.S_ISFIFO(os.lstat(final).st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX special-file semantics")
def test_atomic_output_rejects_destination_directory(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    final.mkdir()

    with pytest.raises(OSError, match="non-regular"):
        with _atomic_output_path(final) as staged:
            staged.write(b"must not publish")

    assert final.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX device semantics")
def test_atomic_output_rejects_destination_device(tmp_path) -> None:
    final = tmp_path / "backup.zip"
    if not hasattr(os, "mknod"):
        pytest.skip("device nodes unavailable")
    try:
        os.mknod(final, stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except OSError as exc:
        pytest.skip(f"device nodes unavailable: {exc}")

    with pytest.raises(OSError, match="non-regular"):
        with _atomic_output_path(final) as staged:
            staged.write(b"must not publish")

    assert stat.S_ISCHR(os.lstat(final).st_mode)


@pytest.mark.skipif(os.name == "nt", reason="hard-link semantics vary on Windows")
def test_atomic_output_replaces_only_the_named_hardlink(tmp_path, monkeypatch) -> None:
    final = tmp_path / "backup.zip"
    peer = tmp_path / "backup-peer.zip"
    final.write_bytes(b"previous")
    peer.hardlink_to(final)

    from hermes_cli import backup

    real_replace = backup.os.replace

    def same_parent_replace(source, destination, **kwargs):
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        assert str(source).endswith(".partial")
        return real_replace(source, destination, **kwargs)

    monkeypatch.setattr(backup.os, "replace", same_parent_replace)
    with _atomic_output_path(final) as staged:
        staged.write(b"complete")

    assert final.read_bytes() == b"complete"
    assert peer.read_bytes() == b"previous"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("umask", [0, 0o022, 0o077])
def test_full_zip_backup_archive_is_owner_only_under_permissive_umask(tmp_path, umask) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    archive = tmp_path / "backup.zip"

    old_umask = os.umask(umask)
    try:
        assert _write_full_zip_backup(archive, home) == archive
    finally:
        os.umask(old_umask)

    assert stat.S_IMODE(archive.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_default_backup_uses_private_managed_dir_without_tightening_home(tmp_path, monkeypatch) -> None:
    """The default full archive must not require a 0700 real home directory."""
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    tmp_path.chmod(0o755)
    hermes_home.chmod(0o755)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    archive = _resolve_backup_output_path(None)

    assert archive.parent == hermes_home / "backups"
    assert stat.S_IMODE(hermes_home.stat().st_mode) == 0o755
    assert stat.S_IMODE(archive.parent.stat().st_mode) == 0o700


def test_quick_snapshot_is_published_with_manifest(tmp_path, monkeypatch) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    published: list[tuple[Path, Path]] = []

    from hermes_cli import backup

    real_replace = backup.os.replace

    def replace(source, destination, **kwargs) -> None:
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        source_path = home / "state-snapshots" / source
        destination_path = home / "state-snapshots" / destination
        if destination_path.parent == home / "state-snapshots":
            assert source_path.name.endswith(".partial")
            assert (source_path / "manifest.json").is_file()
            assert not destination_path.exists()
            published.append((source_path, destination_path))
        real_replace(source, destination, **kwargs)

    monkeypatch.setattr(backup.os, "replace", replace)
    snapshot_id = create_quick_snapshot(hermes_home=home)

    assert snapshot_id is not None
    assert len(published) == 1
    manifest = json.loads(
        (home / "state-snapshots" / snapshot_id / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["id"] == snapshot_id
    assert manifest["files"] == {"config.yaml": 10}


def test_quick_snapshot_syncs_root_after_publication(tmp_path, monkeypatch) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    events: list[str] = []

    from hermes_cli import backup

    root_fd = None
    real_open_trusted_directory = backup.open_trusted_directory
    real_replace = backup.os.replace
    real_fsync = backup.os.fsync

    def trace_open_trusted_directory(path, **kwargs):
        nonlocal root_fd
        fd = real_open_trusted_directory(path, **kwargs)
        if Path(path) == home / "state-snapshots":
            root_fd = fd
        return fd

    def trace_replace(source, destination, **kwargs):
        events.append("publish")
        return real_replace(source, destination, **kwargs)

    def trace_fsync(fd):
        if fd == root_fd:
            events.append("root-fsync")
        return real_fsync(fd)

    monkeypatch.setattr(backup, "open_trusted_directory", trace_open_trusted_directory)
    monkeypatch.setattr(backup.os, "replace", trace_replace)
    monkeypatch.setattr(backup.os, "fsync", trace_fsync)

    snapshot_id = create_quick_snapshot(hermes_home=home)

    assert snapshot_id is not None
    assert events[-2:] == ["publish", "root-fsync"]


def test_quick_snapshot_surfaces_root_durability_warning(tmp_path, monkeypatch) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")

    from hermes_cli import backup

    root_fd = None
    real_open_trusted_directory = backup.open_trusted_directory
    real_fsync = backup.os.fsync

    def trace_open_trusted_directory(path, **kwargs):
        nonlocal root_fd
        fd = real_open_trusted_directory(path, **kwargs)
        if Path(path) == home / "state-snapshots":
            root_fd = fd
        return fd

    def fail_root_fsync(fd):
        if fd == root_fd:
            raise OSError("snapshot root fsync failed")
        return real_fsync(fd)

    monkeypatch.setattr(backup, "open_trusted_directory", trace_open_trusted_directory)
    monkeypatch.setattr(backup.os, "fsync", fail_root_fsync)

    with pytest.raises(QuickSnapshotCommittedWithDurabilityWarning) as raised:
        create_quick_snapshot(hermes_home=home)

    snapshot_id = raised.value.snapshot_id
    assert raised.value.path == home / "state-snapshots" / snapshot_id
    assert (raised.value.path / "manifest.json").is_file()
    assert "snapshot-root directory durability" in str(raised.value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow directory opens")
def test_quick_snapshot_does_not_touch_partial_under_untrusted_root(tmp_path, monkeypatch) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    real_root = tmp_path / "real-snapshots"
    real_root.mkdir()
    marker = real_root / f".20260917-123456.{os.getpid()}.partial" / "sentinel"
    marker.parent.mkdir()
    marker.write_text("must survive", encoding="utf-8")
    (home / "state-snapshots").symlink_to(real_root, target_is_directory=True)

    from hermes_cli import backup

    class FixedDateTime:
        @staticmethod
        def now(tz=None):
            del tz
            return datetime(2026, 9, 17, 12, 34, 56, tzinfo=timezone.utc)

    monkeypatch.setattr(backup, "datetime", FixedDateTime)
    with pytest.raises(OSError):
        create_quick_snapshot(hermes_home=home)

    assert marker.read_text(encoding="utf-8") == "must survive"


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow directory opens")
def test_quick_snapshot_collision_preserves_old_partial_and_cleans_own_stage(
    tmp_path, monkeypatch
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    root = home / "state-snapshots"
    root.mkdir(mode=0o777)
    root.chmod(0o777)
    stale = root / f".20260917-123456.{os.getpid()}.partial"
    stale.mkdir()
    marker = stale / "sentinel"
    marker.write_text("must survive", encoding="utf-8")

    from hermes_cli import backup

    class FixedDateTime:
        @staticmethod
        def now(tz=None):
            del tz
            return datetime(2026, 9, 17, 12, 34, 56, tzinfo=timezone.utc)

    monkeypatch.setattr(backup, "datetime", FixedDateTime)
    assert create_quick_snapshot(hermes_home=home) is None

    assert marker.read_text(encoding="utf-8") == "must survive"
    assert sorted(path.name for path in root.iterdir()) == [stale.name]
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_quick_snapshot_tree_is_owner_only_under_permissive_umask(tmp_path) -> None:
    """Recovery snapshots must never inherit world-readable default modes.

    A normal 0022 umask creates SQLite databases and JSON files as 0644 and
    directories as 0755.  Quick snapshots contain session state, credentials,
    pairing records, and cron data, so every published file must be 0600 and
    every directory 0700 regardless of the caller's umask or source modes.
    """
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    with sqlite3.connect(home / "state.db") as conn:
        conn.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY)")

    old_umask = os.umask(0o022)
    try:
        snapshot_id = create_quick_snapshot(hermes_home=home)
    finally:
        os.umask(old_umask)

    assert snapshot_id is not None
    root = home / "state-snapshots"
    snapshot = root / snapshot_id
    directories = [root, snapshot, *(p for p in snapshot.rglob("*") if p.is_dir())]
    files = [p for p in snapshot.rglob("*") if p.is_file()]

    assert directories
    assert files
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in directories)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files)


def test_quick_snapshot_listing_ignores_partial_directories(tmp_path) -> None:
    home = tmp_path / ".hermes"
    partial = home / "state-snapshots" / ".unfinished.1.partial"
    partial.mkdir(parents=True)
    (partial / "manifest.json").write_text('{"id":"unfinished"}', encoding="utf-8")

    assert list_quick_snapshots(hermes_home=home) == []


def test_failed_automatic_backup_preserves_previous_archive(tmp_path, monkeypatch) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "state.db").write_bytes(b"not-a-database")
    archive = tmp_path / "automatic.zip"
    archive.write_bytes(b"previous-valid-backup")

    monkeypatch.setattr("hermes_cli.backup._safe_copy_db", lambda _src, _dst: False)

    assert _write_full_zip_backup(archive, home) is None
    assert archive.read_bytes() == b"previous-valid-backup"
    assert list(tmp_path.glob(".*.partial")) == []


def test_automatic_backup_surfaces_durability_uncertainty_when_directory_fsync_fails(
    tmp_path, monkeypatch, caplog
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    archive = tmp_path / "automatic.zip"
    archive.write_bytes(b"previous-valid-backup")

    from hermes_cli import backup

    real_fsync = backup.os.fsync
    calls = 0

    def fail_directory_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync failed")
        return real_fsync(fd)

    monkeypatch.setattr(backup.os, "fsync", fail_directory_fsync)
    with caplog.at_level("WARNING", logger="hermes_cli.backup"):
        with pytest.raises(BackupCommittedWithDurabilityWarning) as raised:
            _write_full_zip_backup(archive, home)

    assert raised.value.path == archive
    assert raised.value.error.args == ("directory fsync failed",)
    assert archive.read_bytes() != b"previous-valid-backup"
    assert "directory durability could not be confirmed" in str(raised.value)
    assert "committed with durability warning" in caplog.text


def test_automatic_backup_reports_post_commit_cleanup_failure(
    tmp_path, monkeypatch, caplog
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    archive = tmp_path / "automatic.zip"
    parent_fd = None

    from hermes_cli import backup

    real_close = backup.os.close

    real_open_trusted_directory = backup.open_trusted_directory

    def trace_open_trusted_directory(path, **kwargs):
        nonlocal parent_fd
        fd = real_open_trusted_directory(path, **kwargs)
        if Path(path) == tmp_path:
            parent_fd = fd
        return fd

    def fail_parent_cleanup(fd):
        if fd == parent_fd:
            raise OSError("directory close failed")
        return real_close(fd)

    monkeypatch.setattr(backup, "open_trusted_directory", trace_open_trusted_directory)
    monkeypatch.setattr(backup.os, "close", fail_parent_cleanup)
    with caplog.at_level("ERROR", logger="hermes_cli.backup"):
        result = _write_full_zip_backup(archive, home)

    assert result == archive
    assert archive.is_file()
    assert "backup cleanup failed while closing the backup directory" in caplog.text
