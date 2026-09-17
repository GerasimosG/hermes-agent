"""Tirith pre-exec security scanning wrapper: runs the tirith binary as a subprocess to scan
commands for content-level threats (homograph URLs, pipe-to-interpreter, terminal injection).
The exit code is the verdict source of truth (0 allow, 1 block, 2 warn); JSON stdout only
enriches findings. Operational failures (spawn error, timeout, unknown exit) respect
``fail_open``; positive scanner verdicts never do, and programming errors propagate. Auto-install: a missing tirith is downloaded from
GitHub releases to $HERMES_HOME/bin/tirith in a background thread -- SHA-256 always verified,
cosign provenance when cosign is on PATH. Scans use Hermes's deadlock-safe bounded probe runner."""

import hashlib
import json
import logging
import math
import ntpath
import os
import platform
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from contextlib import suppress
from pathlib import Path

from hermes_constants import get_hermes_home, get_hermes_home_override, hermes_home_key
from hermes_cli._subprocess_compat import bounded_probe_run
from tools.approval_context import parse_tirith_env_bool, parse_tirith_env_timeout

logger = logging.getLogger(__name__)
_REPO = "sheeki03/tirith"
# Cosign provenance pinned to the release workflow, not the whole repo.
_COSIGN_IDENTITY_REGEXP = f"^https://github.com/{_REPO}/\\.github/workflows/release\\.yml@refs/tags/v"
_COSIGN_ISSUER = "https://token.actions.githubusercontent.com"

# --- Config helpers ---
def _env_bool(key: str, default: bool) -> bool:
    value, valid = parse_tirith_env_bool(key)
    return default if value is None or not valid else value


def _env_int(key: str, default: int) -> int:
    value, valid = parse_tirith_env_timeout(key)
    return default if value is None or not valid else value


def _validate_tirith_path(path: object, *, is_windows: bool | None = None) -> bool:
    """Validate the configured executable spelling without resolving or spawning it.

    The documented ``tirith`` PATH lookup and ``~`` expansion remain valid.  This
    check only rejects spellings that cannot be a safe executable name: non-strings,
    surrounding/only whitespace, control characters, traversal components, relative
    paths other than the documented bare ``tirith`` PATH lookup, and platform-specific
    path syntax that would address a different object than the operator intended.
    Existence and ownership checks stay in resolution/execution so a missing default
    binary can still be installed and handled by the configured fallback.
    """
    if not isinstance(path, str) or not path or path != path.strip():
        return False
    if (any(not char.isprintable() for char in path)
            or any(char in path for char in ";|&$`<>*?[](){}!")):
        return False
    if path == "tirith":
        return True
    expanded = os.path.expanduser(path)
    windows = os.name == "nt" if is_windows is None else is_windows
    if windows:
        # The resolver uses the native Windows path rules when this branch runs.
        # Reject UNC shares and alternate data streams rather than allowing a
        # config value to select a remote or secondary stream executable.
        if path.startswith(("\\\\", "//")) or path.endswith((".", " ")):
            return False
        drive, tail = ntpath.splitdrive(expanded)
        if (drive and not ntpath.isabs(expanded)) or (not drive and expanded.startswith(("\\", "/"))):
            return False
        if ":" in tail or tail.endswith(("\\", "/")):
            return False
        parts = [part for part in tail.replace("/", "\\").split("\\") if part not in {"", "."}]
        if any(part == ".." for part in parts):
            return False
        if not drive and ("/" in path or "\\" in path):
            return False
        reserved_check = getattr(ntpath, "isreserved", None)
        reserved_names = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                          *(f"LPT{i}" for i in range(1, 10))}
        for part in parts:
            if reserved_check is not None and reserved_check(part):
                return False
            stem = part.rstrip(" .").split(".", 1)[0].upper()
            if stem in reserved_names:
                return False
        return bool(drive or ntpath.basename(expanded))
    # Keep the supported bare ``tirith`` PATH lookup, but do not accept a path
    # which is only a directory marker or traverses above the configured root.
    if not os.path.isabs(expanded) or expanded in {".", "..", os.sep} or expanded.endswith(os.sep):
        return False
    return ".." not in expanded.split(os.sep)


def _load_security_config() -> dict:
    """Security settings from config.yaml, with env var overrides."""
    config_valid = True
    try:
        from hermes_cli.config import get_active_config_parse_failure, load_config_readonly
        loaded = load_config_readonly()
        config_valid = get_active_config_parse_failure() is None
        cfg = loaded.get("security", {}) if isinstance(loaded, dict) else None
        if not isinstance(loaded, dict) or ("security" in loaded and not isinstance(cfg, dict)):
            config_valid = False
            cfg = {}
    except Exception:
        cfg = {}
        config_valid = False
    enabled = cfg.get("tirith_enabled", True)
    if not isinstance(enabled, bool):
        config_valid = False
        enabled = True
    path = cfg.get("tirith_path", "tirith")
    if not _validate_tirith_path(path):
        return {
            "tirith_enabled": True,
            "tirith_path": path if isinstance(path, str) else "",
            "tirith_timeout": 5,
            "tirith_fail_open": False,
            "tirith_config_error": "malformed security.tirith_path",
        }
    timeout = cfg.get("tirith_timeout", 5)
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or timeout <= 0 or (isinstance(timeout, float) and not math.isfinite(timeout))):
        config_valid = False
        timeout = 5
    fail_open = cfg.get("tirith_fail_open", False)
    if not isinstance(fail_open, bool):
        config_valid = False
        fail_open = False
    if config_valid:
        path = os.getenv("TIRITH_BIN", path)
        if not _validate_tirith_path(path):
            return {
                "tirith_enabled": True,
                "tirith_path": path if isinstance(path, str) else "",
                "tirith_timeout": 5,
                "tirith_fail_open": False,
                "tirith_config_error": "malformed TIRITH_BIN executable path",
            }
    env_enabled, env_enabled_valid = parse_tirith_env_bool("TIRITH_ENABLED")
    env_timeout, env_timeout_valid = parse_tirith_env_timeout("TIRITH_TIMEOUT")
    env_fail_open, env_fail_open_valid = parse_tirith_env_bool("TIRITH_FAIL_OPEN")
    config_valid &= env_enabled_valid and env_timeout_valid and env_fail_open_valid
    if not config_valid:
        enabled, path, timeout, fail_open = True, "tirith", 5, False
    else:
        if env_enabled is not None:
            enabled = env_enabled
        if env_timeout is not None:
            timeout = env_timeout
        if env_fail_open is not None:
            fail_open = env_fail_open
    return {
        "tirith_enabled": enabled,
        "tirith_path": path,
        "tirith_timeout": timeout,
        "tirith_fail_open": fail_open}


# --- Module state ---
# Cached path after first resolution. _INSTALL_FAILED means "tried and failed" (distinct
# from None = "not yet tried") so a failed install is not retried per command.
_resolved_path: str | None | bool = None
_INSTALL_FAILED = False
_install_failure_reason: str = ""  # reason tag when _resolved_path is _INSTALL_FAILED
# Routed profiles (multiplexed gateway) resolve their own binary: ``security.tirith_path`` and
# ``<home>/bin/tirith`` are per profile, so the launch profile's slot above must not answer for them.
_resolved_path_by_home: dict[str, str] = {}

# Circuit breaker: after _CRASH_LIMIT consecutive spawn/execution failures tirith is disabled
# until a cooldown expires, then one scan probes for recovery. The state is guarded by a lock
# because gateway scans can run concurrently; a failed half-open probe reopens the breaker.
_CRASH_LIMIT = 3
_CIRCUIT_COOLDOWN_SECONDS = 60.0
_CIRCUIT_PROBE_LEASE_SECONDS = 30.0
# Reset on a recognized scan result (see _record_tirith_crash / check_command_security). The
# breaker state is locked because gateway scans can run concurrently; the counter is capped at
# _CRASH_LIMIT so repeated failed half-open probes cannot overflow it. See #41400.
_crash_count: int = 0
_circuit_open: bool = False
_circuit_opened_at: float | None = None
_circuit_probe_in_flight: bool = False
_circuit_probe_claimed_at: float | None = None
# One admission generation is shared by concurrent normal scans.  A generation advances only
# when the breaker changes state, so an older normal failure is still counted while a stale
# completion from before a half-open transition cannot alter the newer state.
_circuit_probe_generation: int = 0
# Highest generation fenced by a state transition.  Kept separately so a late half-open
# completion cannot be accepted after its success already moved the breaker forward.
_circuit_last_released_generation: int = 0
_circuit_lock = threading.Lock()
_probe_claim = threading.local()

_install_lock = threading.Lock()
_install_thread: threading.Thread | None = None

# Warn-once: spawn/path warnings sit in the hot path and would otherwise repeat once per
# terminal command while tirith is unavailable (e.g. install thread still running).
_warned_messages: set[str] = set()
_warned_lock = threading.Lock()

_MARKER_TTL = 86400  # disk failure marker validity (24h) -- avoids retry across restarts


def _record_tirith_crash(probe_generation: int | None = None) -> None:
    global _crash_count, _circuit_open, _circuit_opened_at
    global _circuit_probe_in_flight, _circuit_probe_claimed_at
    global _circuit_probe_generation, _circuit_last_released_generation
    with _circuit_lock:
        if _circuit_probe_generation == 0:
            _circuit_probe_generation = 1
        if probe_generation is not None and probe_generation != _circuit_probe_generation:
            # A newer state transition owns the breaker now. Do not let a stale
            # worker alter that newer admission's state.
            return
        was_open = _circuit_open
        _circuit_probe_in_flight = False
        _circuit_probe_claimed_at = None
        _crash_count = min(_crash_count + 1, _CRASH_LIMIT)
        opened = was_open or _crash_count >= _CRASH_LIMIT
        if opened:
            _crash_count = _CRASH_LIMIT
            _circuit_open = True
            _circuit_opened_at = time.monotonic()
            # Fence all scans from the closed epoch, including a failed half-open
            # probe, before another completion can observe the open state.
            _circuit_last_released_generation = _circuit_probe_generation
            _circuit_probe_generation += 1
        count = _crash_count
    if opened:
        logger.warning("event=tirith_circuit_open failures=%d retry_after=%.0fs",
                       count, _CIRCUIT_COOLDOWN_SECONDS)


def circuit_is_open() -> bool:
    """Observe whether the breaker is open without claiming its recovery probe."""
    with _circuit_lock:
        return _circuit_open


def circuit_allows_probe() -> bool:
    """Claim the single recovery probe, or allow a normal scan through."""
    global _circuit_probe_in_flight, _circuit_probe_claimed_at, _circuit_opened_at
    global _circuit_probe_generation, _circuit_last_released_generation
    with _circuit_lock:
        if not _circuit_open:
            # Normal scans share the current epoch.  Advancing per scan would
            # discard a legitimate failure when a newer normal scan finishes first.
            if _circuit_probe_generation == 0:
                _circuit_probe_generation = 1
            _probe_claim.generation = _circuit_probe_generation
            _probe_claim.is_half_open_probe = False
            return True
        now = time.monotonic()
        if _circuit_probe_in_flight:
            if (_circuit_probe_claimed_at is not None
                    and now - _circuit_probe_claimed_at >= _CIRCUIT_PROBE_LEASE_SECONDS):
                # A stuck resolver or subprocess must not hold the half-open slot forever. Keep
                # the breaker open and start a fresh cooldown. The stale worker's completion is
                # fenced from this point onward.
                _circuit_probe_in_flight = False
                _circuit_probe_claimed_at = None
                _circuit_opened_at = now
                _circuit_last_released_generation = _circuit_probe_generation
                _circuit_probe_generation += 1
                logger.warning("event=tirith_probe_lease_expired retry_after=%.0fs",
                               _CIRCUIT_COOLDOWN_SECONDS)
            else:
                return False
        if (_circuit_opened_at is not None
                and now - _circuit_opened_at >= _CIRCUIT_COOLDOWN_SECONDS):
            _circuit_probe_in_flight = True
            _circuit_probe_claimed_at = now
            _circuit_last_released_generation = _circuit_probe_generation
            _circuit_probe_generation += 1
            _probe_claim.generation = _circuit_probe_generation
            _probe_claim.is_half_open_probe = True
            return True
        _probe_claim.generation = None
        _probe_claim.is_half_open_probe = False
        return False


def reset_circuit_breaker(probe_generation: int | None = None) -> None:
    global _crash_count, _circuit_open, _circuit_opened_at
    global _circuit_probe_in_flight, _circuit_probe_claimed_at
    global _circuit_probe_generation, _circuit_last_released_generation
    with _circuit_lock:
        if _circuit_probe_generation == 0:
            _circuit_probe_generation = 1
        if probe_generation is not None and probe_generation != _circuit_probe_generation:
            return
        half_open_success = _circuit_probe_in_flight
        _crash_count = 0
        _circuit_open = False
        _circuit_opened_at = None
        _circuit_probe_in_flight = False
        _circuit_probe_claimed_at = None
        if half_open_success:
            # A normal scan admitted after this success gets a new epoch.  This
            # prevents a late completion from the half-open worker from touching
            # the state of that normal scan.
            _circuit_last_released_generation = _circuit_probe_generation
            _circuit_probe_generation += 1


def _warn_once(key: str, message: str, *args) -> None:
    """``logger.warning`` at most once per ``key`` for the process lifetime."""
    with _warned_lock:
        if key in _warned_messages:
            return
        _warned_messages.add(key)
    logger.warning(message, *args)


def _cached_path() -> str | None:
    """The path resolved on a previous call, or None if unresolved (None) / failed (_INSTALL_FAILED)."""
    if get_hermes_home_override() is not None:
        return _resolved_path_by_home.get(hermes_home_key())
    return _resolved_path or None


def _store_resolved(path: str) -> None:
    global _resolved_path
    if get_hermes_home_override() is not None:
        _resolved_path_by_home[hermes_home_key()] = path
    else:
        _resolved_path = path


def _set_resolved(path: str) -> None:
    global _install_failure_reason
    _store_resolved(path)
    _install_failure_reason = ""


def _set_failed(reason: str) -> None:
    global _resolved_path, _install_failure_reason
    _resolved_path, _install_failure_reason = _INSTALL_FAILED, reason


# --- Disk failure marker ---
def _failure_marker_path() -> str:
    return os.path.join(str(get_hermes_home()), ".tirith-install-failed")


def _read_failure_reason() -> str | None:
    """The marker's reason, or None if absent or older than _MARKER_TTL."""
    try:
        p = _failure_marker_path()
        if (time.time() - os.path.getmtime(p)) >= _MARKER_TTL:
            return None
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def _is_install_failed_on_disk() -> bool:
    """True if a recent install failure was persisted and is still non-retryable.
    A 'cosign_missing' marker is auto-cleared once cosign appears on PATH."""
    reason = _read_failure_reason()
    if reason == "cosign_missing" and shutil.which("cosign"):
        _clear_install_failed()
        return False
    return reason is not None


def _mark_install_failed(reason: str = ""):
    """Persist install failure to disk; ``reason`` is a short retryability tag."""
    with suppress(OSError):
        p = _failure_marker_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(reason)


def _clear_install_failed():
    """Remove the failure marker and reset warn-once state (so a failure after a reinstall surfaces again)."""
    with _warned_lock:
        _warned_messages.clear()
    with suppress(OSError):
        os.unlink(_failure_marker_path())


def _disk_marker_blocks_install() -> bool:
    """Apply a still-valid disk marker to module state; True if install must be skipped.
    Keeps the marker's real reason so in-process retry can detect cosign_missing."""
    if (disk_reason := _read_failure_reason()) is None or not _is_install_failed_on_disk():
        return False
    _set_failed(disk_reason)
    return True


# --- Auto-install ---
def _hermes_bin_dir() -> str:
    """Return ``$HERMES_HOME/bin`` after a best-effort trusted lookup.

    The installer uses the returned path only for diagnostics and local lookup.  Actual
    publication stays descriptor-relative through :func:`open_tirith_bin_dir`; an unsafe
    directory is therefore returned for the caller's normal validation path, never created or
    written through this compatibility helper.
    """
    d = Path(get_hermes_home()) / "bin"
    try:
        directory_fd, _ = open_tirith_bin_dir()
    except OSError:
        return str(d)
    os.close(directory_fd)
    return str(d)


def open_tirith_bin_dir() -> tuple[int, Path]:
    """Open the managed Tirith directory through a trusted, no-follow descriptor.

    ``open_trusted_directory`` walks every component with ``O_NOFOLLOW`` and rejects untrusted
    owners or group/other-writable components.  The final ``bin`` directory must be an existing
    or newly-created owner-only ``0700`` directory.  Callers must close the returned descriptor.
    """
    from hermes_cli.backup import open_trusted_directory

    bin_dir = Path(get_hermes_home()) / "bin"
    directory_fd = open_trusted_directory(bin_dir, create=True, owner_only=True)
    return directory_fd, bin_dir


def _trusted_install_directory(fd: int) -> bool:
    """Return whether a pinned installer directory still has its trusted metadata."""
    uid_getter = getattr(os, "geteuid", None)
    if uid_getter is None:
        return False
    try:
        directory_stat = os.fstat(fd)
        return (stat.S_ISDIR(directory_stat.st_mode)
                and directory_stat.st_uid == uid_getter()
                and stat.S_IMODE(directory_stat.st_mode) == 0o700)
    except OSError:
        return False


def _open_install_stage(directory_fd: int, name: str) -> tuple[int, str]:
    """Create a unique owner-only staging file below the pinned install directory."""
    if not (hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd):
        raise OSError("Tirith installer requires descriptor-relative file creation")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    for _ in range(128):
        stage_name = f".{name}.{secrets.token_hex(8)}.partial"
        try:
            return os.open(stage_name, flags, 0o700, dir_fd=directory_fd), stage_name
        except FileExistsError:
            continue
    raise OSError("could not allocate a unique Tirith staging name")


def publish_tirith_binary(source: str, directory_fd: int, directory: Path) -> Path:
    """Copy *source* into a descriptor-pinned staging file and atomically publish it.

    The source is never moved into the managed tree.  The destination directory is held open
    from its no-follow trust check through staging, validation, and the same-directory rename,
    so a symlink or path swap cannot redirect the downloaded bytes elsewhere.
    """
    if os.name == "nt" or not (hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd
                               and os.rename in os.supports_dir_fd):
        raise OSError("Tirith installer requires POSIX descriptor-relative publication")
    if not _trusted_install_directory(directory_fd):
        raise OSError(f"Tirith install directory is not owner-only 0700: {directory}")

    source_fd = -1
    stage_fd = -1
    stage_name: str | None = None
    stage_identity: tuple[int, int] | None = None
    committed = False
    try:
        source_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        source_fd = os.open(source, source_flags)
        source_stat = os.fstat(source_fd)
        uid_getter = getattr(os, "geteuid", None)
        if (uid_getter is None or not stat.S_ISREG(source_stat.st_mode)
                or source_stat.st_uid != uid_getter()):
            raise OSError("Tirith archive member is not an owner-safe regular file")

        stage_fd, stage_name = _open_install_stage(directory_fd, "tirith")
        stage_stat = os.fstat(stage_fd)
        stage_identity = (stage_stat.st_dev, stage_stat.st_ino)
        if (not stat.S_ISREG(stage_stat.st_mode) or stage_stat.st_uid != uid_getter()
                or stat.S_IMODE(stage_stat.st_mode) != 0o700):
            raise OSError("Tirith staging file is not owner-only 0700")

        with os.fdopen(source_fd, "rb", closefd=False) as source_file, \
                os.fdopen(stage_fd, "wb", closefd=False) as stage_file:
            shutil.copyfileobj(source_file, stage_file)
            stage_file.flush()
        os.fsync(stage_fd)
        if hasattr(os, "fchmod"):
            os.fchmod(stage_fd, 0o700)
        final_stage_stat = os.fstat(stage_fd)
        if (not stat.S_ISREG(final_stage_stat.st_mode)
                or final_stage_stat.st_uid != uid_getter()
                or final_stage_stat.st_dev != os.fstat(directory_fd).st_dev
                or stat.S_IMODE(final_stage_stat.st_mode) != 0o700
                or (final_stage_stat.st_dev, final_stage_stat.st_ino) != stage_identity):
            raise OSError("Tirith staging file changed before publication")
        if not _trusted_install_directory(directory_fd):
            raise OSError(f"Tirith install directory changed before publication: {directory}")

        # Refuse to replace an existing symlink, directory, or untrusted file.  A regular trusted
        # destination may be replaced, but its identity is rechecked immediately before rename.
        destination_identity: tuple[int, int] | None = None
        destination_flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW
        destination_flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            destination_fd = os.open("tirith", destination_flags, dir_fd=directory_fd)
        except FileNotFoundError:
            destination_fd = -1
        else:
            try:
                destination_stat = os.fstat(destination_fd)
                if (not stat.S_ISREG(destination_stat.st_mode)
                        or destination_stat.st_uid != uid_getter()
                        or destination_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                    raise OSError("existing Tirith destination is not owner-safe")
                destination_identity = (destination_stat.st_dev, destination_stat.st_ino)
            finally:
                os.close(destination_fd)

        latest_destination_fd = -1
        try:
            try:
                latest_destination_fd = os.open("tirith", destination_flags, dir_fd=directory_fd)
            except FileNotFoundError:
                latest_destination_identity = None
            else:
                latest_destination_stat = os.fstat(latest_destination_fd)
                latest_destination_identity = (
                    latest_destination_stat.st_dev, latest_destination_stat.st_ino
                )
                if (not stat.S_ISREG(latest_destination_stat.st_mode)
                        or latest_destination_stat.st_uid != uid_getter()
                        or latest_destination_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                    raise OSError("Tirith destination changed to an unsafe file")
            if latest_destination_identity != destination_identity:
                raise OSError("Tirith destination changed before publication")
        finally:
            if latest_destination_fd >= 0:
                os.close(latest_destination_fd)

        os.replace(stage_name, "tirith", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        committed = True
        published_fd = os.open("tirith", destination_flags, dir_fd=directory_fd)
        try:
            published_stat = os.fstat(published_fd)
            if ((published_stat.st_dev, published_stat.st_ino) != stage_identity
                    or not stat.S_ISREG(published_stat.st_mode)
                    or published_stat.st_uid != uid_getter()
                    or stat.S_IMODE(published_stat.st_mode) != 0o700):
                raise OSError("published Tirith executable failed descriptor validation")
        finally:
            os.close(published_fd)
        os.fsync(directory_fd)
        return directory / "tirith"
    finally:
        if source_fd >= 0:
            with suppress(OSError):
                os.close(source_fd)
        if stage_fd >= 0:
            with suppress(OSError):
                os.close(stage_fd)
        if not committed and stage_name is not None:
            with suppress(OSError):
                os.unlink(stage_name, dir_fd=directory_fd)


# Rust target triple components. Android (Termux) is ABI-compatible with Linux. Windows is
# absent on purpose (no tirith build): None = "never available here", pattern guards still run.
_TARGET_PLATFORMS = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu", "Android": "unknown-linux-gnu"}
_TARGET_ARCHES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def _detect_target() -> str | None:
    """Rust target triple for this platform, or None if tirith has no build for it."""
    plat = _TARGET_PLATFORMS.get(platform.system())
    arch = _TARGET_ARCHES.get(platform.machine().lower())
    return f"{arch}-{plat}" if plat and arch else None


def is_platform_supported() -> bool:
    """True when tirith ships a prebuilt binary for this OS+arch (CLI banner uses this)."""
    return _detect_target() is not None


def _remaining_resolver_timeout(deadline: float | None, default: float) -> float:
    """Return the remaining resolver lease, or the ordinary operation timeout."""
    if deadline is None:
        return default
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("tirith resolver lease expired")
    return min(default, remaining)


def _download_file(url: str, dest: str, timeout: int = 10):
    from agent.secret_scope import get_secret
    req = urllib.request.Request(url)
    if token := get_secret("GITHUB_TOKEN"):
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def _verify_cosign(checksums_path: str, sig_path: str, cert_path: str,
                   *, deadline: float | None = None) -> bool | None:
    """Cosign provenance of checksums.txt: True verified, False rejected, None if cosign absent/failed."""
    if not (cosign := shutil.which("cosign")):
        logger.info("cosign not found on PATH")
        return None
    try:
        result = subprocess.run(
            [cosign, "verify-blob", "--certificate", cert_path, "--signature", sig_path,
             "--certificate-identity-regexp", _COSIGN_IDENTITY_REGEXP,
             "--certificate-oidc-issuer", _COSIGN_ISSUER, checksums_path],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=_remaining_resolver_timeout(deadline, 15), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("cosign execution failed: %s", exc)
        return None
    if result.returncode:
        logger.warning("cosign verification failed (exit %d): %s", result.returncode, result.stderr.strip())
        return False
    logger.info("cosign provenance verification passed")
    return True


def _verify_release_provenance(base_url: str, tmpdir: str, checksums_path: str, log,
                               *, deadline: float | None = None) -> tuple[bool, str]:
    """Cosign step of the install -> ``(cosign_verified, failure_reason)``. Only an explicit
    cosign rejection aborts; missing/broken cosign or artifacts fall back to SHA-256 only."""
    if not shutil.which("cosign"):
        logger.info("cosign not on PATH — installing tirith with SHA-256 verification only "
                    "(install cosign for full supply chain verification)")
        return False, ""
    sig_path, cert_path = os.path.join(tmpdir, "checksums.txt.sig"), os.path.join(tmpdir, "checksums.txt.pem")
    try:
        _download_file(f"{base_url}/checksums.txt.sig", sig_path,
                       timeout=_remaining_resolver_timeout(deadline, 10))
        _download_file(f"{base_url}/checksums.txt.pem", cert_path,
                       timeout=_remaining_resolver_timeout(deadline, 10))
    except TimeoutError:
        raise
    except Exception as exc:
        logger.info("cosign artifacts unavailable (%s), proceeding with SHA-256 only", exc)
        return False, ""
    verified = _verify_cosign(checksums_path, sig_path, cert_path, deadline=deadline)
    if verified is False:
        log("tirith install aborted: cosign provenance verification failed")
        return False, "cosign_verification_failed"
    if verified is None:
        logger.info("cosign execution failed, proceeding with SHA-256 only")
    return verified is True, ""


def _verify_checksum(archive_path: str, checksums_path: str, archive_name: str) -> bool:
    """Verify SHA-256 of the archive against checksums.txt ("<hash>  <filename>" lines)."""
    with open(checksums_path, encoding="utf-8") as f:
        parsed = (line.strip().split("  ", 1) for line in f)
        expected = next((h for h, *n in parsed if n == [archive_name]), None)
    if not expected:
        logger.warning("No checksum entry for %s", archive_name)
        return False
    sha = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    actual = sha.hexdigest()
    if actual != expected:
        logger.warning("Checksum mismatch: expected %s, got %s", expected, actual)
    return actual == expected


def _extract_tirith_binary(tar: tarfile.TarFile, dest_dir: str, log) -> tuple[str | None, str]:
    """Extract the tirith binary from a release archive into dest_dir -> ``(path, reason)``."""
    for member in tar.getmembers():
        if member.name.rsplit("/", 1)[-1] != "tirith" or ".." in member.name:
            continue
        if not member.isfile():
            log("tirith archive member is not a regular file: %s", member.name)
            return None, "binary_not_regular_file"
        if (src_file := tar.extractfile(member)) is None:
            log("tirith binary could not be read from archive")
            return None, "binary_extract_failed"
        dest_path = os.path.join(dest_dir, "tirith")
        with src_file, open(dest_path, "wb") as out:
            shutil.copyfileobj(src_file, out)
        return dest_path, ""
    log("tirith binary not found in archive")
    return None, "binary_not_in_archive"


def _install_tirith(*, log_failures: bool = True,
                    deadline: float | None = None) -> tuple[str | None, str]:
    """Download and install tirith to $HERMES_HOME/bin/tirith -> ``(installed_path,
    failure_reason)``; the reason ("" on success) is the disk marker's retryability tag."""
    log = logger.warning if log_failures else logger.debug
    if not (target := _detect_target()):
        logger.info("tirith auto-install: unsupported platform %s/%s", platform.system(), platform.machine())
        return None, "unsupported_platform"
    archive_name = f"tirith-{target}.tar.gz"
    base_url = f"https://github.com/{_REPO}/releases/latest/download"
    try:
        tmpdir = tempfile.mkdtemp(prefix="tirith-install-")
    except OSError as exc:
        log("tirith install failed: cannot create temp dir: %s", exc)
        return None, "no_space"
    try:
        archive_path, checksums_path = os.path.join(tmpdir, archive_name), os.path.join(tmpdir, "checksums.txt")
        logger.info("tirith not found — downloading latest release for %s...", target)
        try:
            _download_file(f"{base_url}/{archive_name}", archive_path,
                           timeout=_remaining_resolver_timeout(deadline, 10))
            _download_file(f"{base_url}/checksums.txt", checksums_path,
                           timeout=_remaining_resolver_timeout(deadline, 10))
        except TimeoutError:
            raise
        except Exception as exc:
            log("tirith download failed: %s", exc)
            return None, "download_failed"
        cosign_verified, reason = _verify_release_provenance(
            base_url, tmpdir, checksums_path, log, deadline=deadline)
        if reason:
            return None, reason
        _remaining_resolver_timeout(deadline, 10)
        if not _verify_checksum(archive_path, checksums_path, archive_name):
            return None, "checksum_failed"
        with tarfile.open(archive_path, "r:gz") as tar:
            src, reason = _extract_tirith_binary(tar, tmpdir, log)
        if src is None:
            return None, reason
        _remaining_resolver_timeout(deadline, 10)
        try:
            directory_fd, directory = open_tirith_bin_dir()
        except OSError as exc:
            log("tirith install refused unsafe destination directory: %s", exc)
            return None, "destination_unsafe"
        try:
            dest = publish_tirith_binary(src, directory_fd, directory)
        except OSError as exc:
            log("tirith install failed before safe publication: %s", exc)
            return None, "destination_unsafe"
        finally:
            with suppress(OSError):
                os.close(directory_fd)
        logger.info("tirith installed to %s (%s)", dest, "cosign + SHA-256" if cosign_verified else "SHA-256 only")
        return str(dest), ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --- Path resolution ---
def _is_executable(path: str, *, secure: bool = False) -> bool:
    """True for an executable path; ``secure`` also enforces owner-safe filesystem metadata."""
    if not secure:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    uid_getter = getattr(os, "geteuid", None)
    if os.name == "nt":
        if not _validate_tirith_path(path, is_windows=True) or not ntpath.isabs(path):
            return False
        if uid_getter is None:
            try:
                file_stat = os.lstat(path)
                current_stat = os.lstat(path)
                return (stat.S_ISREG(file_stat.st_mode) and file_stat == current_stat
                        and os.access(path, os.X_OK)
                        and not any(os.path.islink(parent) for parent in Path(path).parents))
            except OSError:
                return False
        # Windows has no portable effective-uid/mode equivalent.  Keep the native path and
        # regular-file checks rather than rejecting every explicitly configured binary.
        try:
            file_stat = os.lstat(path)
            current_stat = os.lstat(path)
            return (stat.S_ISREG(file_stat.st_mode) and file_stat == current_stat
                    and os.access(path, os.X_OK)
                    and not any(os.path.islink(parent) for parent in Path(path).parents))
        except OSError:
            return False
    if uid_getter is None or not os.path.isabs(path) or ".." in Path(path).parts:
        return False
    candidate = Path(path)
    try:
        trusted_uids = {uid_getter(), 0, os.lstat(os.sep).st_uid}
        file_stat = os.lstat(candidate)
        if (not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid not in trusted_uids
                or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not file_stat.st_mode & stat.S_IXUSR
                or not os.access(candidate, os.X_OK)):
            return False
        current_stat = os.lstat(candidate)
        if (current_stat.st_dev, current_stat.st_ino, current_stat.st_mode, current_stat.st_uid) != (
                file_stat.st_dev, file_stat.st_ino, file_stat.st_mode, file_stat.st_uid):
            return False
        for parent in candidate.parents:
            parent_stat = os.lstat(parent)
            parent_writable = bool(parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
            sticky_shared = bool(parent_stat.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(parent_stat.st_mode)
                    or parent_stat.st_uid not in trusted_uids
                    or (parent_writable and not sticky_shared)):
                return False
    except OSError:
        return False
    return True


def _validated_executable_path(path: str) -> str | None:
    """Return an absolute owner-safe executable path, or ``None``."""
    if not _validate_tirith_path(path):
        return None
    absolute = os.path.abspath(os.path.expanduser(path))
    if not os.path.isabs(absolute):
        return None
    return absolute if _is_executable(absolute, secure=True) else None


def _find_local_tirith() -> str | None:
    """Cheap local lookup for the default "tirith": PATH, then $HERMES_HOME/bin."""
    if path_from_path := shutil.which("tirith"):
        # A PATH hit that races or fails the trust checks is not silently replaced
        # by another candidate; the caller applies the configured absence fallback.
        return _validated_executable_path(path_from_path)
    return _validated_executable_path(os.path.join(_hermes_bin_dir(), "tirith"))


def _resolve_locally(configured_path: str, *, warn_missing: bool) -> tuple[str | None, bool]:
    """Network-free resolution -> ``(path, may_install)``: ``path`` set = resolved (module state
    updated); else ``may_install`` False = terminal miss (explicit path missing, cached non-retryable
    failure), True = the disk marker / install step may proceed."""
    global _resolved_path, _install_failure_reason
    expanded = os.path.expanduser(configured_path)
    # An explicit (non-"tirith") path is authoritative: never auto-download a replacement.
    if configured_path != "tirith":
        if is_platform_supported():
            found = _validated_executable_path(expanded)
        else:
            found = expanded if _is_executable(expanded) else shutil.which(expanded)
        if found:
            found = os.path.abspath(found)
            _store_resolved(found)
            return found, False
        if warn_missing:
            logger.warning("Configured tirith path %r not found; scanning disabled", configured_path)
        _set_failed("explicit_path_missing")
        return None, False
    # Always re-run the cheap local checks so a manual install is picked up even after a
    # previous network failure (a long-lived gateway recovers without restart).
    if found := _find_local_tirith():
        _set_resolved(found)
        _clear_install_failed()
        return found, False
    # Previous install failed: skip the network retry unless the retryable cosign_missing
    # cause has been resolved in-process.
    if _resolved_path is _INSTALL_FAILED:
        if _install_failure_reason != "cosign_missing" or not shutil.which("cosign"):
            return None, False
        _resolved_path, _install_failure_reason = None, ""
        _clear_install_failed()
    return None, True


def _record_install_result(installed: str | None, reason: str) -> str | None:
    """Cache an install outcome in module state + disk marker; returns *installed*."""
    if installed and (validated := _validated_executable_path(installed)):
        _set_resolved(validated)
        _clear_install_failed()
        return validated
    _set_failed(reason or "installed_path_unsafe")
    _mark_install_failed(reason or "installed_path_unsafe")
    return None


def _clear_cached_path() -> None:
    global _resolved_path
    if get_hermes_home_override() is not None:
        _resolved_path_by_home.pop(hermes_home_key(), None)
    else:
        _resolved_path = None


def _resolve_tirith_path(configured_path: str, *, deadline: float | None = None) -> str | None:
    """Resolve the tirith path, auto-installing synchronously if needed (default "tirith": PATH →
    $HERMES_HOME/bin/tirith → install; failures cached in-process and on disk for 24h). On a miss
    an explicit path is returned expanded so the caller applies its configured fallback policy;
    a missing bare ``tirith`` returns ``None`` for that operational fallback."""
    expanded = os.path.expanduser(configured_path)
    if cached := _cached_path():
        if validated := _validated_executable_path(cached):
            return validated
        _clear_cached_path()
    if deadline is not None and time.monotonic() >= deadline:
        return None if configured_path == "tirith" else expanded
    # No tirith build for this platform: cache the miss so the caller applies its fallback policy.
    if configured_path == "tirith" and not is_platform_supported():
        _set_failed("unsupported_platform")
        return expanded
    found, may_install = _resolve_locally(configured_path, warn_missing=True)
    if found or not may_install:
        return found or (None if configured_path == "tirith" else expanded)
    # A background install is running: don't start a parallel one; the caller applies its fallback policy.
    if _install_running() or _disk_marker_blocks_install():
        return None if configured_path == "tirith" else expanded
    installed = _install_tirith(deadline=deadline)
    return _record_install_result(*installed)


def _install_running() -> bool:
    return _install_thread is not None and _install_thread.is_alive()


def _background_install(*, log_failures: bool = True):
    """Background thread target: download and install tirith."""
    with _install_lock:
        if _resolved_path is not None:  # another thread resolved meanwhile
            return
        if found := _find_local_tirith():  # may have been installed by another process
            _set_resolved(found)
            return
        _record_install_result(*_install_tirith(log_failures=log_failures))


def ensure_installed(*, log_failures: bool = True):
    """Resolved path if available now, else None after kicking off a daemon-thread download (local
    checks are synchronous; the download never blocks startup). Safe to call repeatedly."""
    global _install_thread
    cfg = _load_security_config()
    if not cfg["tirith_enabled"]:
        return None
    if cached := _cached_path():
        if validated := _validated_executable_path(cached):
            return validated
        _clear_cached_path()
    # No tirith build here (e.g. Windows): stay silent -- no PATH probe, no download thread,
    # no disk marker. Pattern-matching guards still run.
    if not is_platform_supported():
        _set_failed("unsupported_platform")
        return None
    found, may_install = _resolve_locally(cfg["tirith_path"], warn_missing=False)
    if found or not may_install or _disk_marker_blocks_install():
        return found
    if not _install_running():
        _install_thread = threading.Thread(target=_background_install, daemon=True,
                                           kwargs={"log_failures": log_failures})
        _install_thread.start()
    return None  # not available yet; callers apply their configured fallback policy.


# --- Main API ---
_MAX_FINDINGS = 50
_MAX_SUMMARY_LEN = 500
_EXIT_ACTIONS = {0: "allow", 1: "block", 2: "warn"}
# Summary when tirith's JSON is unparseable and only the exit code is known.
_NO_DETAILS_SUMMARY = {
    "block": "security issue detected (details unavailable)",
    "warn": "security warning detected (details unavailable)"}


def _verdict(action: str, summary: str = "", findings: list | None = None) -> dict:
    return {"action": action, "findings": [] if findings is None else findings, "summary": summary}


def _fail(fail_open: bool, open_summary: str, closed_summary: str, *, reason: str) -> dict:
    if fail_open:
        logger.warning("event=tirith_fail_open_bypass reason=%s", reason)
        return _verdict("allow", open_summary)
    return _verdict("block", closed_summary)


def _crash(fail_open: bool, open_summary: str, closed_summary: str, *, reason: str,
           probe_generation: int | None = None) -> dict:
    """An operational failure: count it toward the circuit breaker, then apply the fallback policy."""
    _record_tirith_crash(probe_generation)
    return _fail(fail_open, open_summary, closed_summary, reason=reason)


def check_command_security(command: str) -> dict:
    """Run the tirith scan on a command -> ``{"action": allow|warn|block, "findings", "summary"}``.
    Exit code determines the action; JSON enriches. Spawn failures/timeouts respect fail_open."""
    cfg = _load_security_config()
    tirith_path = cfg.get("tirith_path")
    # Validate before consulting enabled/fail_open.  A malformed executable path
    # must never be converted into an allow by an opt-in operational fallback.
    if not _validate_tirith_path(tirith_path):
        return _verdict("block", "malformed security.tirith_path: expected a valid executable path")
    enabled = cfg.get("tirith_enabled", True)
    fail_open = cfg.get("tirith_fail_open", False)
    timeout = cfg.get("tirith_timeout", 5)
    if not enabled:
        return _verdict("allow")
    # No binary for this platform, ever: skip the resolver so we never spawn.
    if tirith_path == "tirith" and not is_platform_supported():
        return _fail(fail_open, "", "tirith unavailable on this platform (fail-closed)",
                     reason="unsupported_platform")
    # Circuit breaker: after _CRASH_LIMIT runtime failures, stop spawning until the cooldown
    # allows one recovery probe. Without this, a corrupted or missing binary causes every tool
    # call to hit the same spawn failure → fail-open → agent retry loop (issue #41400).
    if not circuit_allows_probe():
        return _fail(fail_open, "tirith disabled (circuit breaker)",
                     "tirith disabled (circuit breaker, fail-closed)", reason="circuit_breaker")
    probe_generation = getattr(_probe_claim, "generation", None)
    is_half_open_probe = bool(getattr(_probe_claim, "is_half_open_probe", False))
    scan_completed = False
    failure_recorded = False
    try:
        resolver_deadline = (
            time.monotonic() + _CIRCUIT_PROBE_LEASE_SECONDS
            if is_half_open_probe else None)
        if is_half_open_probe:
            # A half-open claim is leased.  Bound the child process to that lease so
            # a configured multi-minute timeout cannot hold recovery indefinitely.
            timeout = min(timeout, _CIRCUIT_PROBE_LEASE_SECONDS)
        try:
            tirith_path = _resolve_tirith_path(tirith_path, deadline=resolver_deadline)
        except TimeoutError:
            failure_recorded = True
            return _crash(fail_open, "tirith resolver timed out",
                          "tirith resolver timed out (fail-closed)", reason="resolver_timeout",
                          probe_generation=probe_generation)
        if tirith_path is None:
            _warn_once("tirith_path_none", "tirith path resolved to None; scanning disabled")
            failure_recorded = True
            return _crash(
                fail_open, "tirith executable unavailable",
                "tirith executable unavailable (fail-closed)",
                reason="executable_unavailable", probe_generation=probe_generation,
            )
        if tirith_path == "tirith" or not os.path.isabs(tirith_path):
            failure_recorded = True
            _record_tirith_crash(probe_generation)
            return _verdict("block", "tirith executable path is not absolute (fail-closed)")
        if not _is_executable(tirith_path, secure=True):
            try:
                os.lstat(tirith_path)
            except FileNotFoundError:
                failure_recorded = True
                return _crash(
                    fail_open, "tirith executable disappeared",
                    "tirith executable disappeared (fail-closed)",
                    reason="executable_missing", probe_generation=probe_generation,
                )
            else:
                failure_recorded = True
                _record_tirith_crash(probe_generation)
                return _verdict("block", "tirith executable path is unsafe (must be an owner-safe regular file)")
        if resolver_deadline is not None:
            try:
                timeout = min(timeout, _remaining_resolver_timeout(resolver_deadline, timeout))
            except TimeoutError:
                failure_recorded = True
                return _crash(fail_open, "tirith resolver timed out",
                              "tirith resolver timed out (fail-closed)", reason="resolver_timeout",
                              probe_generation=probe_generation)
        # The resolver's path checks happen before this point.  Recheck immediately before the
        # spawn so a replacement observed after resolution is never executed.  A tiny scheduling
        # window remains between this final check and Popen; trusted parent ownership/no-write
        # checks mean only the configured owner can win that race, and a future fexecve/execveat
        # path can remove it without breaking script-based PATH installations.
        if not _is_executable(tirith_path, secure=True):
            try:
                os.lstat(tirith_path)
            except FileNotFoundError:
                failure_recorded = True
                return _crash(
                    fail_open, "tirith executable disappeared before spawn",
                    "tirith executable disappeared before spawn (fail-closed)",
                    reason="executable_missing", probe_generation=probe_generation,
                )
            failure_recorded = True
            _record_tirith_crash(probe_generation)
            return _verdict(
                "block", "tirith executable path changed before spawn (unsafe; fail-closed)"
            )
        try:
            result = bounded_probe_run(
                [tirith_path, "check", "--json", "--non-interactive", "--shell", "posix", "--", command],
                timeout=timeout, raise_on_spawn_failure=True)
            if result is None:
                raise subprocess.TimeoutExpired(tirith_path, timeout)
        except OSError as exc:
            # FileNotFoundError / PermissionError / exec format error: dedupe by (class, errno)
            # so each failure mode surfaces once, not per command.
            _warn_once(f"tirith_spawn_failed:{type(exc).__name__}:{getattr(exc, 'errno', '')}",
                       "tirith spawn failed: %s", exc)
            failure_recorded = True
            return _crash(fail_open, f"tirith unavailable: {exc}",
                          f"tirith spawn failed (fail-closed): {exc}", reason="spawn_failure",
                          probe_generation=probe_generation)
        except subprocess.TimeoutExpired:
            _warn_once(f"tirith_timeout:{timeout}", "tirith timed out after %ds", timeout)
            failure_recorded = True
            return _crash(fail_open, f"tirith timed out ({timeout}s)",
                          "tirith timed out (fail-closed)", reason="timeout",
                          probe_generation=probe_generation)
        exit_code = result.returncode
        if (action := _EXIT_ACTIONS.get(exit_code)) is None:
            # Unknown exit code (includes signal-killed, e.g. -11): respect fail_open.
            logger.warning("tirith returned unexpected exit code %d", exit_code)
            failure_recorded = True
            return _crash(fail_open, f"tirith exit code {exit_code} (fail-open)",
                          f"tirith exit code {exit_code} (fail-closed)", reason="unknown_exit",
                          probe_generation=probe_generation)
        # A recognized scanner exit owns the probe outcome even if enriching its
        # result below raises.  The breaker is reset exactly once here.
        scan_completed = True
        reset_circuit_breaker(probe_generation)
        # JSON enriches findings/summary; a parse failure never changes the verdict.
        findings, summary = [], ""
        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
            findings = data.get("findings", [])[:_MAX_FINDINGS]
            summary = (data.get("summary", "") or "")[:_MAX_SUMMARY_LEN]
        except (json.JSONDecodeError, AttributeError):
            logger.debug("tirith JSON parse failed, using exit code only")
            summary = _NO_DETAILS_SUMMARY.get(action, "")
        return _verdict(action, summary, findings)
    finally:
        # A claimed probe that escapes through an unexpected resolver, subprocess,
        # or result-processing exception is still a failed probe.  This releases
        # the slot and restarts the open-state cooldown without swallowing the
        # original exception.  Normal operational failures set failure_recorded
        # before _crash(), and recognized exits set scan_completed before parsing.
        if not scan_completed and not failure_recorded:
            _record_tirith_crash(probe_generation)
