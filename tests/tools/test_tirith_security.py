"""Tests for the tirith security scanning subprocess wrapper."""

import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import tools.tirith_security as _tirith_mod
from tools.approval_context import _tirith_fail_open
from tools.tirith_security import check_command_security, ensure_installed


@pytest.fixture(autouse=True)
def _reset_resolved_path(tmp_path):
    """Pre-set cached path to skip auto-install in scan tests.
    Tests that specifically test ensure_installed / resolve behavior
    reset this to None themselves.
    """
    cache_dir = tmp_path / "cached"
    cache_dir.mkdir(mode=0o700)
    binary = cache_dir / "tirith"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    _tirith_mod._resolved_path = str(binary)
    _tirith_mod._install_thread = None
    _tirith_mod._install_failure_reason = ""
    _tirith_mod._crash_count = 0
    _tirith_mod._circuit_open = False
    _tirith_mod._circuit_opened_at = None
    _tirith_mod._circuit_probe_in_flight = False
    _tirith_mod._circuit_probe_claimed_at = None
    _tirith_mod._circuit_probe_generation = 0
    _tirith_mod._circuit_last_released_generation = 0
    _tirith_mod._probe_claim.generation = None
    _tirith_mod._probe_claim.is_half_open_probe = False
    yield
    _tirith_mod._resolved_path = None
    _tirith_mod._install_thread = None
    _tirith_mod._install_failure_reason = ""
    _tirith_mod._crash_count = 0
    _tirith_mod._circuit_open = False
    _tirith_mod._circuit_opened_at = None
    _tirith_mod._circuit_probe_in_flight = False
    _tirith_mod._circuit_probe_claimed_at = None
    _tirith_mod._circuit_probe_generation = 0
    _tirith_mod._circuit_last_released_generation = 0
    _tirith_mod._probe_claim.generation = None
    _tirith_mod._probe_claim.is_half_open_probe = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_run(returncode=0, stdout="", stderr=""):
    """Build a mock subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


def _json_stdout(findings=None, summary=""):
    return json.dumps({"findings": findings or [], "summary": summary})


# ---------------------------------------------------------------------------
# Exit code → action mapping
# ---------------------------------------------------------------------------

class TestExitCodeMapping:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_0_allow(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(0, _json_stdout())
        result = check_command_security("echo hello")
        assert result["action"] == "allow"
        assert result["findings"] == []

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_1_block_with_findings(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        findings = [{"rule_id": "homograph_url", "severity": "high"}]
        mock_run.return_value = _mock_run(1, _json_stdout(findings, "homograph detected"))
        result = check_command_security("curl http://gооgle.com")
        assert result["action"] == "block"
        assert len(result["findings"]) == 1
        assert result["summary"] == "homograph detected"

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_2_warn_with_findings(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        findings = [{"rule_id": "shortened_url", "severity": "medium"}]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "shortened URL"))
        result = check_command_security("curl https://bit.ly/abc")
        assert result["action"] == "warn"
        assert len(result["findings"]) == 1
        assert result["summary"] == "shortened URL"


class TestSecurityConfigFallback:
    def test_missing_config_uses_fail_closed_default(self, monkeypatch):
        monkeypatch.delenv("TIRITH_ENABLED", raising=False)
        monkeypatch.delenv("TIRITH_BIN", raising=False)
        monkeypatch.delenv("TIRITH_TIMEOUT", raising=False)
        monkeypatch.delenv("TIRITH_FAIL_OPEN", raising=False)
        with patch("hermes_cli.config.load_config_readonly", return_value={}):
            config = _tirith_mod._load_security_config()
        assert config["tirith_enabled"] is True
        assert config["tirith_fail_open"] is False

    def test_missing_or_malformed_config_fails_closed(self, monkeypatch):
        monkeypatch.delenv("TIRITH_ENABLED", raising=False)
        monkeypatch.delenv("TIRITH_BIN", raising=False)
        monkeypatch.delenv("TIRITH_TIMEOUT", raising=False)
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "true")
        with patch("hermes_cli.config.load_config_readonly", side_effect=ValueError("bad config")):
            config = _tirith_mod._load_security_config()
        assert config["tirith_fail_open"] is False

    def test_malformed_security_section_fails_closed(self, monkeypatch):
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "true")
        with patch("hermes_cli.config.load_config_readonly", return_value={"security": []}):
            config = _tirith_mod._load_security_config()
        assert config["tirith_fail_open"] is False

    def test_parse_failure_ignores_fail_open_opt_in(self, monkeypatch):
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "true")
        with patch("hermes_cli.config.load_config_readonly", return_value={"security": {}}), \
             patch("hermes_cli.config.get_active_config_parse_failure", return_value="invalid yaml"):
            config = _tirith_mod._load_security_config()
        assert config["tirith_enabled"] is True
        assert config["tirith_fail_open"] is False

    @pytest.mark.parametrize("config", [
        None,
        {},
        {"security": []},
        {"security": {"tirith_enabled": "false"}},
        {"security": {"tirith_fail_open": "true"}},
    ])
    def test_import_fallback_does_not_opt_into_fail_open(self, config, monkeypatch):
        monkeypatch.delenv("TIRITH_ENABLED", raising=False)
        with patch("hermes_cli.config.load_config_readonly", return_value=config):
            assert _tirith_fail_open() is False

    def test_fail_closed_config_survives_enabled_env_cleanup(self, monkeypatch):
        """A valid enabled scanner config remains fail-closed during import fallback."""
        monkeypatch.delenv("TIRITH_ENABLED", raising=False)
        config = {"security": {"tirith_enabled": True, "tirith_fail_open": False}}
        with patch("hermes_cli.config.load_config_readonly", return_value=config):
            assert _tirith_fail_open() is False

    @pytest.mark.parametrize("security", [
        {"tirith_enabled": False, "tirith_path": 123},
        {"tirith_enabled": False, "tirith_timeout": 0},
        {"tirith_enabled": False, "tirith_fail_open": "true"},
    ])
    def test_disabled_scanner_does_not_hide_malformed_config(self, security):
        with patch("hermes_cli.config.load_config_readonly", return_value={"security": security}):
            assert _tirith_fail_open() is False

    def test_explicit_env_opt_in_is_preserved(self, monkeypatch):
        monkeypatch.delenv("TIRITH_ENABLED", raising=False)
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "true")
        with patch("hermes_cli.config.load_config_readonly", return_value={"security": {}}):
            assert _tirith_fail_open() is True

    @pytest.mark.parametrize("name, value", [
        ("TIRITH_ENABLED", "maybe"),
        ("TIRITH_TIMEOUT", "not-a-number"),
        ("TIRITH_TIMEOUT", "0"),
        ("TIRITH_FAIL_OPEN", "maybe"),
    ])
    def test_ambiguous_env_config_cannot_opt_into_fail_open(self, monkeypatch, name, value):
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "true")
        monkeypatch.setenv(name, value)
        config = {"security": {"tirith_fail_open": True}}
        with patch("hermes_cli.config.load_config_readonly", return_value=config):
            assert _tirith_mod._load_security_config()["tirith_fail_open"] is False
            assert _tirith_fail_open() is False

    def test_import_fallback_rejects_missing_configured_binary(self, tmp_path):
        missing = tmp_path / "missing-tirith"
        config = {"security": {"tirith_path": str(missing), "tirith_fail_open": True}}
        with patch("hermes_cli.config.load_config_readonly", return_value=config):
            assert _tirith_fail_open() is False

    def test_disabled_scanner_allows_import_fallback(self, monkeypatch):
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "false")
        with patch("hermes_cli.config.load_config_readonly",
                   return_value={"security": {"tirith_enabled": False, "tirith_fail_open": False}}):
            assert _tirith_fail_open() is True

    def test_disabled_scanner_env_override_allows_import_fallback(self, monkeypatch):
        monkeypatch.setenv("TIRITH_ENABLED", "false")
        with patch("hermes_cli.config.load_config_readonly",
                   return_value={"security": {"tirith_enabled": True, "tirith_fail_open": False}}):
            assert _tirith_fail_open() is True

    @pytest.mark.parametrize("path", ["", " \t", "\u00a0", "\x00", "tirith\n", ".", "../tirith",
                                       "./tirith", "bin/tirith", "tirith;evil"])
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_malformed_executable_path_blocks_before_fail_open(self, mock_cfg, mock_resolve,
                                                               mock_run, path):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": path,
                                 "tirith_timeout": 5, "tirith_fail_open": True}

        result = check_command_security("echo should-not-run")

        assert result["action"] == "block"
        assert "malformed" in result["summary"]
        mock_resolve.assert_not_called()
        mock_run.assert_not_called()


class TestExecutableValidation:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_owner_safe_regular_binary_runs(self, mock_cfg, mock_resolve, mock_run):
        with tempfile.TemporaryDirectory(prefix="tirith-safe-") as safe_root:
            binary = Path(safe_root) / "tirith"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(binary),
                                     "tirith_timeout": 5, "tirith_fail_open": True}
            mock_resolve.return_value = str(binary)
            mock_run.return_value = _mock_run(0, _json_stdout())

            result = check_command_security("echo safe")

        assert result["action"] == "allow"
        mock_run.assert_called_once()

    @pytest.mark.parametrize("mode", [0o775, 0o757])
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_group_or_world_writable_binary_is_blocked(self, mock_cfg, mock_resolve, mock_run,
                                                       tmp_path, mode):
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(mode)
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(binary),
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_resolve.return_value = str(binary)

        result = check_command_security("echo unsafe")

        assert result["action"] == "block"
        mock_run.assert_not_called()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and symlink semantics")
    @pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_non_regular_or_symlink_binary_is_blocked(self, mock_cfg, mock_resolve, mock_run,
                                                      tmp_path, kind):
        target = tmp_path / "target"
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        target.chmod(0o755)
        binary = tmp_path / "tirith"
        if kind == "symlink":
            binary.symlink_to(target)
        elif kind == "directory":
            binary.mkdir()
        else:
            os.mkfifo(binary)
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(binary),
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_resolve.return_value = str(binary)

        result = check_command_security("echo unsafe")

        assert result["action"] == "block"
        mock_run.assert_not_called()

    @pytest.mark.skipif(not hasattr(os, "geteuid"), reason="effective uid unavailable")
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_unowned_binary_is_blocked(self, mock_cfg, mock_resolve, mock_run, tmp_path, monkeypatch):
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(binary),
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_resolve.return_value = str(binary)
        monkeypatch.setattr(os, "geteuid", lambda: binary.stat().st_uid + 1)

        result = check_command_security("echo unsafe")

        assert result["action"] == "block"
        mock_run.assert_not_called()

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    @pytest.mark.parametrize("fail_open, action", [(True, "allow"), (False, "block")])
    def test_missing_configured_binary_uses_absence_fallback(self, mock_cfg, mock_resolve,
                                                             mock_run, tmp_path, fail_open, action):
        missing = tmp_path / "missing-tirith"
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(missing),
                                 "tirith_timeout": 5, "tirith_fail_open": fail_open}
        mock_resolve.return_value = str(missing)

        result = check_command_security("echo missing")

        assert result["action"] == action
        assert "disappeared" in result["summary"]
        mock_run.assert_not_called()

    def test_writable_parent_is_blocked(self, tmp_path):
        from tools.tirith_security import _is_executable

        parent = tmp_path / "writable-parent"
        parent.mkdir()
        parent.chmod(0o777)
        binary = parent / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)

        assert not _is_executable(str(binary), secure=True)


class TestBareExecutableResolution:
    def test_bare_path_uses_absolute_owner_safe_path(self, tmp_path):
        from tools.tirith_security import _resolve_tirith_path

        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        _tirith_mod._resolved_path = None

        with patch("tools.tirith_security.shutil.which", return_value=str(binary)):
            assert _resolve_tirith_path("tirith") == str(binary)

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._install_tirith", return_value=(None, "download_failed"))
    @patch("tools.tirith_security._disk_marker_blocks_install", return_value=False)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._load_security_config")
    @pytest.mark.parametrize("fail_open, action", [(True, "allow"), (False, "block")])
    def test_bare_missing_uses_absence_fallback(self, mock_cfg, mock_which,
                                                mock_marker, mock_install, mock_run,
                                                tmp_path, fail_open, action):
        del mock_which, mock_marker, mock_install
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": fail_open}
        _tirith_mod._resolved_path = None
        with patch("tools.tirith_security._hermes_bin_dir",
                   return_value=str(tmp_path / "missing-bin")):
            result = check_command_security("echo missing")

        assert result["action"] == action
        assert "unavailable" in result["summary"]
        mock_run.assert_not_called()

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    @pytest.mark.parametrize("fail_open, action", [(True, "allow"), (False, "block")])
    def test_bare_path_race_uses_absence_fallback(self, mock_cfg, mock_resolve, mock_run,
                                                  tmp_path, fail_open, action):
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": fail_open}

        def remove_after_resolution(path, **kwargs):
            del kwargs
            binary.unlink()
            return str(binary)

        mock_resolve.side_effect = remove_after_resolution
        result = check_command_security("echo raced")

        assert result["action"] == action
        assert "disappeared" in result["summary"]
        mock_run.assert_not_called()

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_replacement_after_validation_fails_closed_before_spawn(
        self, mock_cfg, mock_resolve, mock_run, tmp_path
    ):
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(binary),
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_resolve.return_value = str(binary)

        with patch.object(_tirith_mod, "_is_executable", side_effect=(True, False)):
            result = check_command_security("echo replaced")

        assert result["action"] == "block"
        assert "unsafe" in result["summary"]
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# JSON parse failure (exit code still wins)
# ---------------------------------------------------------------------------

class TestJsonParseFailure:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_1_invalid_json_still_blocks(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(1, "NOT JSON")
        result = check_command_security("bad command")
        assert result["action"] == "block"
        assert "details unavailable" in result["summary"]

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_0_invalid_json_allows(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(0, "NOT JSON")
        result = check_command_security("safe command")
        assert result["action"] == "allow"


# ---------------------------------------------------------------------------
# Operational failures + fail_open
# ---------------------------------------------------------------------------

class TestOSErrorFailOpen:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_file_not_found_fail_open_is_audited(self, mock_cfg, mock_run, caplog):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.side_effect = FileNotFoundError("No such file: tirith")
        with caplog.at_level("WARNING", logger="tools.tirith_security"):
            result = check_command_security("echo hi")
        assert result["action"] == "allow"
        assert "unavailable" in result["summary"]
        assert any("event=tirith_fail_open_bypass" in record.message for record in caplog.records)

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_os_error_fail_closed(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.side_effect = FileNotFoundError("No such file: tirith")
        result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert "fail-closed" in result["summary"]


class TestTimeoutFailOpen:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_timeout_fail_closed(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="tirith", timeout=5)
        result = check_command_security("slow command")
        assert result["action"] == "block"
        assert "fail-closed" in result["summary"]

    @pytest.mark.parametrize("fail_open, action", [(True, "allow"), (False, "block")])
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_resolver_timeout_uses_failure_verdict(self, mock_cfg, mock_resolve,
                                                    fail_open, action):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": fail_open}
        mock_resolve.side_effect = TimeoutError("resolver lease expired")

        result = check_command_security("slow install")

        assert result["action"] == action
        assert "resolver timed out" in result["summary"]


class TestNormalScanTimeout:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._resolve_tirith_path")
    @patch("tools.tirith_security._load_security_config")
    def test_normal_scan_is_not_capped_by_half_open_lease(self, mock_cfg, mock_resolve,
                                                           mock_run, tmp_path):
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        timeout = _tirith_mod._CIRCUIT_PROBE_LEASE_SECONDS + 5
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": str(binary),
                                 "tirith_timeout": timeout, "tirith_fail_open": False}
        mock_resolve.return_value = str(binary)
        mock_run.return_value = _mock_run(0, _json_stdout())

        result = check_command_security("normal scan")

        assert result["action"] == "allow"
        assert mock_resolve.call_args.kwargs["deadline"] is None
        assert mock_run.call_args.kwargs["timeout"] == timeout


class TestUnknownExitCode:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_unknown_exit_code_fail_closed(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.return_value = _mock_run(99, "")
        result = check_command_security("cmd")
        assert result["action"] == "block"
        assert "exit code 99" in result["summary"]

    @pytest.mark.parametrize("exit_code", [99, -9])
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_unknown_exit_code_fail_open_is_audited(self, mock_cfg, mock_run, caplog, exit_code):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(exit_code, "")
        with caplog.at_level("WARNING", logger="tools.tirith_security"):
            result = check_command_security("cmd")
        assert result["action"] == "allow"
        assert any("event=tirith_fail_open_bypass reason=unknown_exit" in record.message
                   for record in caplog.records)


class TestCircuitBreaker:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_fail_closed_circuit_breaker_blocks(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        _tirith_mod._circuit_open = True
        with patch("tools.tirith_security.is_platform_supported", return_value=True):
            result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert "fail-closed" in result["summary"]
        mock_run.assert_not_called()

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_circuit_breaker_half_open_probe_resets_on_recovery(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.return_value = _mock_run(0, _json_stdout())
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1

        with patch("tools.tirith_security.is_platform_supported", return_value=True):
            result = check_command_security("echo recovered")

        assert result["action"] == "allow"
        assert _tirith_mod._circuit_open is False
        assert _tirith_mod._crash_count == 0
        mock_run.assert_called_once()

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_threat_detection_resets_runtime_failure_count(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.return_value = _mock_run(1, _json_stdout([{"rule_id": "danger"}], "blocked"))
        _tirith_mod._crash_count = _tirith_mod._CRASH_LIMIT - 1

        with patch("tools.tirith_security.is_platform_supported", return_value=True):
            result = check_command_security("dangerous command")

        assert result["action"] == "block"
        assert _tirith_mod._crash_count == 0
        assert _tirith_mod._circuit_open is False

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_circuit_breaker_half_open_failure_remains_open(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.side_effect = FileNotFoundError("tirith missing")
        _tirith_mod._crash_count = _tirith_mod._CRASH_LIMIT
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1

        with patch("tools.tirith_security.is_platform_supported", return_value=True):
            result = check_command_security("echo retry")

        assert result["action"] == "block"
        assert _tirith_mod._circuit_open is True
        assert _tirith_mod._crash_count == _tirith_mod._CRASH_LIMIT

    def test_circuit_breaker_allows_one_half_open_probe(self):
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1

        assert _tirith_mod.circuit_is_open() is True
        assert _tirith_mod.circuit_allows_probe() is True
        assert _tirith_mod.circuit_is_open() is True
        assert _tirith_mod.circuit_allows_probe() is False

    def test_expired_probe_lease_restarts_cooldown_without_claiming_again(self):
        _tirith_mod._circuit_open = True
        opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1
        _tirith_mod._circuit_opened_at = opened_at
        _tirith_mod._circuit_probe_in_flight = True
        _tirith_mod._circuit_probe_claimed_at = (
            time.monotonic() - _tirith_mod._CIRCUIT_PROBE_LEASE_SECONDS - 1)

        assert _tirith_mod.circuit_allows_probe() is False
        assert _tirith_mod._circuit_open is True
        assert _tirith_mod._circuit_probe_in_flight is False
        assert _tirith_mod._circuit_probe_claimed_at is None
        assert _tirith_mod._circuit_opened_at > opened_at

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_status_observation_does_not_consume_half_open_probe(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.return_value = _mock_run(0, _json_stdout())
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1

        assert _tirith_mod.circuit_is_open() is True
        with patch("tools.tirith_security.is_platform_supported", return_value=True):
            result = check_command_security("echo status")

        assert result["action"] == "allow"
        assert _tirith_mod._circuit_open is False
        mock_run.assert_called_once()

    @patch("tools.tirith_security._resolve_tirith_path", return_value=None)
    @patch("tools.tirith_security._load_security_config")
    def test_half_open_path_none_releases_probe_and_restarts_cooldown(self, mock_cfg, mock_resolve):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "/custom/tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = opened_at

        result = check_command_security("echo retry")

        assert result["action"] == "block"
        assert _tirith_mod._circuit_open is True
        assert _tirith_mod._circuit_probe_in_flight is False
        assert _tirith_mod._circuit_opened_at > opened_at
        mock_resolve.assert_called_once()
        assert mock_resolve.call_args.kwargs["deadline"] is not None

        assert _tirith_mod.circuit_allows_probe() is False

    @patch("tools.tirith_security._resolve_tirith_path", side_effect=RuntimeError("resolver exploded"))
    @patch("tools.tirith_security._load_security_config")
    def test_half_open_unexpected_exception_releases_probe(self, mock_cfg, mock_resolve):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "/custom/tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = opened_at

        with pytest.raises(RuntimeError, match="resolver exploded"):
            check_command_security("echo retry")

        assert _tirith_mod._circuit_open is True
        assert _tirith_mod._circuit_probe_in_flight is False
        assert _tirith_mod._circuit_probe_claimed_at is None
        assert _tirith_mod._circuit_opened_at > opened_at
        assert _tirith_mod.circuit_allows_probe() is False
        mock_resolve.assert_called_once()
        assert mock_resolve.call_args.kwargs["deadline"] is not None

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_half_open_timeout_releases_probe(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.return_value = None
        opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = opened_at

        result = check_command_security("echo timeout")

        assert result["action"] == "block"
        assert _tirith_mod._circuit_open is True
        assert _tirith_mod._circuit_probe_in_flight is False
        assert _tirith_mod._circuit_probe_claimed_at is None
        assert _tirith_mod._circuit_opened_at > opened_at
        mock_run.assert_called_once()

    def test_stale_normal_completion_cannot_reset_newer_half_open_probe(self):
        _tirith_mod._circuit_open = False
        assert _tirith_mod.circuit_allows_probe() is True
        normal_generation = _tirith_mod._probe_claim.generation

        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = (
            time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1)
        assert _tirith_mod.circuit_allows_probe() is True
        probe_generation = _tirith_mod._probe_claim.generation
        assert probe_generation > normal_generation

        _tirith_mod.reset_circuit_breaker(normal_generation)
        _tirith_mod._record_tirith_crash(normal_generation)

        assert _tirith_mod._circuit_open is True
        assert _tirith_mod._circuit_probe_in_flight is True
        assert _tirith_mod._crash_count == 0

        _tirith_mod.reset_circuit_breaker(probe_generation)
        _tirith_mod.reset_circuit_breaker(probe_generation)
        assert _tirith_mod._circuit_open is False
        assert _tirith_mod._circuit_probe_in_flight is False

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_concurrent_normal_failure_is_recorded_after_newer_clean_scan(
            self, mock_cfg, mock_run):
        """A newer normal completion must not discard an older real failure."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        old_started = threading.Event()
        release_old = threading.Event()

        def scan(args, **kwargs):
            del kwargs
            if args[-1] == "old scan":
                old_started.set()
                assert release_old.wait(timeout=5)
                raise FileNotFoundError("tirith disappeared")
            return _mock_run(0, _json_stdout())

        mock_run.side_effect = scan
        old_result = []
        old_thread = threading.Thread(
            target=lambda: old_result.append(check_command_security("old scan")))
        old_thread.start()
        assert old_started.wait(timeout=5)

        assert check_command_security("new scan")["action"] == "allow"
        release_old.set()
        old_thread.join(timeout=5)

        assert not old_thread.is_alive()
        assert old_result[0]["action"] == "allow"
        assert _tirith_mod._crash_count == 1

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_stale_positive_detection_still_blocks_after_half_open_recovery(
            self, mock_cfg, mock_run):
        """A stale positive verdict remains a terminal block for its command."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        old_started = threading.Event()
        release_old = threading.Event()

        def scan(args, **kwargs):
            del kwargs
            if args[-1] == "old threat":
                old_started.set()
                assert release_old.wait(timeout=5)
                return _mock_run(1, _json_stdout([{"rule_id": "homograph_url"}], "blocked"))
            return _mock_run(0, _json_stdout())

        mock_run.side_effect = scan
        old_result = []
        old_thread = threading.Thread(
            target=lambda: old_result.append(check_command_security("old threat")))
        old_thread.start()
        assert old_started.wait(timeout=5)

        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = time.monotonic() - _tirith_mod._CIRCUIT_COOLDOWN_SECONDS - 1
        assert check_command_security("recovery")["action"] == "allow"
        release_old.set()
        old_thread.join(timeout=5)

        assert not old_thread.is_alive()
        assert old_result[0]["action"] == "block"
        assert _tirith_mod._circuit_open is False

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._install_tirith")
    @patch("tools.tirith_security._disk_marker_blocks_install", return_value=False)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._load_security_config")
    def test_half_open_resolver_deadline_fences_delayed_completion(self, mock_cfg, mock_which,
                                                                    mock_marker, mock_install,
                                                                    mock_run, tmp_path,
                                                                    monkeypatch):
        del mock_which, mock_marker
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        _tirith_mod._resolved_path = None
        clock = [100.0]
        monkeypatch.setattr(_tirith_mod.time, "monotonic", lambda: clock[0])
        _tirith_mod._circuit_open = True
        _tirith_mod._circuit_opened_at = 0.0

        def delayed_install(*, deadline):
            assert deadline == 100.0 + _tirith_mod._CIRCUIT_PROBE_LEASE_SECONDS
            clock[0] = deadline + 1
            return str(binary), ""

        mock_install.side_effect = delayed_install
        with patch("tools.tirith_security._hermes_bin_dir",
                   return_value=str(tmp_path / "missing-bin")):
            result = check_command_security("echo delayed")

        assert result["action"] == "block"
        assert _tirith_mod._circuit_probe_in_flight is False
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Disabled
# ---------------------------------------------------------------------------

class TestDisabled:
    @patch("tools.tirith_security._load_security_config")
    def test_disabled_returns_allow(self, mock_cfg):
        mock_cfg.return_value = {"tirith_enabled": False, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        result = check_command_security("rm -rf /")
        assert result["action"] == "allow"


# ---------------------------------------------------------------------------
# Findings cap + summary cap
# ---------------------------------------------------------------------------

class TestCaps:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_findings_and_summary_capped(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        findings = [{"rule_id": f"rule_{i}"} for i in range(100)]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "x" * 1000))
        result = check_command_security("cmd")
        assert len(result["findings"]) == 50
        assert len(result["summary"]) == 500


# ---------------------------------------------------------------------------
# Programming errors propagate
# ---------------------------------------------------------------------------

class TestProgrammingErrors:
    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_attribute_error_propagates(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.side_effect = AttributeError("unexpected bug")
        with pytest.raises(AttributeError):
            check_command_security("cmd")


# ---------------------------------------------------------------------------
# ensure_installed
# ---------------------------------------------------------------------------

class TestEnsureInstalled:
    @patch("tools.tirith_security._load_security_config")
    def test_disabled_returns_none(self, mock_cfg):
        mock_cfg.return_value = {"tirith_enabled": False, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        _tirith_mod._resolved_path = None
        assert ensure_installed() is None

    @patch("tools.tirith_security.shutil.which", return_value="/usr/local/bin/tirith")
    @patch("tools.tirith_security._load_security_config")
    def test_found_on_path_returns_immediately(self, mock_cfg, mock_which, tmp_path):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        binary = tmp_path / "tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        mock_which.return_value = str(binary)
        _tirith_mod._resolved_path = None
        result = ensure_installed()
        assert result == str(binary)
        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Unsupported platform (Windows etc.) — silent fast-path everywhere
# ---------------------------------------------------------------------------

class TestUnsupportedPlatform:
    """When _detect_target() returns None (no tirith binary for this OS+arch),
    the resolver stays silent: no PATH probes, no download thread, no disk
    failure marker, no spawn attempts, no CLI banner. Pattern-matching guards
    still cover the gap; an explicit fail-open bypass is auditable."""

    @pytest.mark.parametrize("system, machine, expected", [
        ("Linux", "x86_64", True),
        ("Windows", "AMD64", False),
        ("Linux", "riscv64", False),
    ])
    def test_is_platform_supported(self, system, machine, expected):
        # The patched (system, machine) pairs are table inputs, not a host
        # fake: is_platform_supported() is a pure string mapping that touches
        # no OS facility beneath the check, so there is nothing for a real
        # host to falsify. Two of the rows (Windows/AMD64, Linux/riscv64)
        # could never execute honestly anyway — the second has no CI runner
        # on any lane.
        with patch("tools.tirith_security.platform.system", return_value=system), \
             patch("tools.tirith_security.platform.machine", return_value=machine):
            assert _tirith_mod.is_platform_supported() is expected


    @patch("tools.tirith_security._load_security_config")
    def test_check_command_security_unsupported_allows_with_audit(self, mock_cfg, caplog):
        """Windows: skip the resolver and spawn entirely — return allow with
        an empty summary so callers can't accidentally surface 'tirith
        unavailable' messaging to the user."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        with caplog.at_level("WARNING", logger="tools.tirith_security"), \
             patch("tools.tirith_security.is_platform_supported", return_value=False), \
             patch("tools.tirith_security.subprocess.run") as mock_run, \
             patch("tools.tirith_security._resolve_tirith_path") as mock_resolve:
            result = check_command_security("rm -rf /")
        assert result == {"action": "allow", "findings": [], "summary": ""}
        assert any("event=tirith_fail_open_bypass reason=unsupported_platform" in record.message
                   for record in caplog.records)
        mock_run.assert_not_called()
        mock_resolve.assert_not_called()

    @patch("tools.tirith_security._load_security_config")
    def test_check_command_security_unsupported_fails_closed_by_default(self, mock_cfg):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        with patch("tools.tirith_security.is_platform_supported", return_value=False), \
             patch("tools.tirith_security.subprocess.run") as mock_run, \
             patch("tools.tirith_security._resolve_tirith_path") as mock_resolve:
            result = check_command_security("rm -rf /")
            assert result["action"] == "block"
            assert "fail-closed" in result["summary"]
            mock_run.assert_not_called()
            mock_resolve.assert_not_called()

    @patch("tools.tirith_security._load_security_config")
    def test_explicit_path_still_honored_on_unsupported_platform(self, mock_cfg):
        """If a user explicitly configured a tirith_path (e.g. they built it
        themselves under WSL), the unsupported-platform short-circuit must
        NOT override that — explicit config wins."""
        mock_cfg.return_value = {"tirith_enabled": True,
                                 "tirith_path": "/opt/custom/tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        _tirith_mod._resolved_path = None
        with patch("tools.tirith_security.is_platform_supported", return_value=False), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True):
            result = _tirith_mod._resolve_tirith_path("/opt/custom/tirith")
            assert result == "/opt/custom/tirith"
            assert _tirith_mod._resolved_path == "/opt/custom/tirith"

    @pytest.mark.parametrize("path, expected", [
        ("tirith.exe", True),
        (r"C:\\Program Files\\Tirith\\tirith.exe", True),
        ("NUL", False),
        ("C:relative.exe", False),
        (r"C:\\Tirith\\..\\other.exe", False),
        (r"relative\\tirith.exe", False),
    ])
    def test_windows_path_validation_is_absolute_or_bare(self, path, expected):
        from tools.tirith_security import _validate_tirith_path
        from tools.approval_context import _valid_tirith_path

        assert _validate_tirith_path(path, is_windows=True) is expected
        assert _valid_tirith_path(path, is_windows=True) is expected


# ---------------------------------------------------------------------------
# Failed download caches the miss (Finding #1)
# ---------------------------------------------------------------------------

class TestFailedDownloadCaching:
    @patch("tools.tirith_security._mark_install_failed")
    @patch("tools.tirith_security._is_install_failed_on_disk", return_value=False)
    @patch("tools.tirith_security._install_tirith", return_value=(None, "download_failed"))
    @patch("tools.tirith_security.shutil.which", return_value=None)
    def test_failed_install_cached_no_retry(self, mock_which, mock_install,
                                             mock_disk_check, mock_mark):
        """After a failed download, subsequent resolves must not retry."""
        from tools.tirith_security import _resolve_tirith_path, _INSTALL_FAILED
        _tirith_mod._resolved_path = None

        # First call: tries install, fails
        _resolve_tirith_path("tirith")
        assert mock_install.call_count == 1
        assert _tirith_mod._resolved_path is _INSTALL_FAILED
        mock_mark.assert_called_once_with("download_failed")  # reason persisted

        # Second call: hits the cache, does NOT call _install_tirith again
        _resolve_tirith_path("tirith")
        assert mock_install.call_count == 1  # still 1, not 2

        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Explicit path must not auto-download (Finding #2)
# ---------------------------------------------------------------------------

class TestExplicitPathNoAutoDownload:
    @patch("tools.tirith_security._install_tirith")
    @patch("tools.tirith_security.shutil.which", return_value=None)
    def test_tilde_explicit_path_missing_no_download(self, mock_which, mock_install):
        """An explicit ~/path that doesn't exist must NOT trigger download."""
        from tools.tirith_security import _resolve_tirith_path, _INSTALL_FAILED
        _tirith_mod._resolved_path = None

        result = _resolve_tirith_path("~/bin/tirith")
        mock_install.assert_not_called()
        assert _tirith_mod._resolved_path is _INSTALL_FAILED
        assert "~" not in result  # tilde still expanded

        _tirith_mod._resolved_path = None

    @patch("tools.tirith_security._mark_install_failed")
    @patch("tools.tirith_security._is_install_failed_on_disk", return_value=False)
    @patch("tools.tirith_security._install_tirith", return_value=("/auto/tirith", ""))
    @patch("tools.tirith_security.shutil.which", return_value=None)
    def test_default_path_does_auto_download(self, mock_which, mock_install,
                                              mock_disk_check, mock_mark, tmp_path):
        """The default bare 'tirith' SHOULD trigger auto-download."""
        from tools.tirith_security import _resolve_tirith_path
        _tirith_mod._resolved_path = None
        binary = tmp_path / "installed-tirith"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        mock_install.return_value = (str(binary), "")

        result = _resolve_tirith_path("tirith")
        mock_install.assert_called_once()
        assert result == str(binary)

        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Cosign provenance verification (P1)
# ---------------------------------------------------------------------------

class TestCosignVerification:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security.shutil.which", return_value="/usr/bin/cosign")
    def test_cosign_identity_pinned_to_release_workflow(self, mock_which, mock_run):
        """Identity regexp must pin to the release workflow, not the whole repo."""
        from tools.tirith_security import _verify_cosign
        mock_run.return_value = _mock_run(0, "Verified OK")
        _verify_cosign("/tmp/checksums.txt", "/tmp/sig", "/tmp/cert")
        args = mock_run.call_args[0][0]
        # Find the value after --certificate-identity-regexp
        idx = args.index("--certificate-identity-regexp")
        identity = args[idx + 1]
        # The identity contains regex-escaped dots
        assert "workflows/release" in identity
        assert "refs/tags/v" in identity


    @patch("tools.tirith_security.tarfile.open")
    @patch("tools.tirith_security._verify_checksum", return_value=True)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._download_file")
    @patch("tools.tirith_security._detect_target", return_value="aarch64-apple-darwin")
    def test_install_proceeds_without_cosign(self, mock_target, mock_dl,
                                              mock_which, mock_checksum,
                                              mock_tarfile):
        """_install_tirith proceeds with SHA-256 only when cosign is not on PATH."""
        from tools.tirith_security import _install_tirith
        mock_tar = MagicMock()
        mock_tar.__enter__ = MagicMock(return_value=mock_tar)
        mock_tar.__exit__ = MagicMock(return_value=False)
        mock_tar.getmembers.return_value = []
        mock_tarfile.return_value = mock_tar

        path, reason = _install_tirith()
        # Reaches extraction (no binary in mock archive), but got past cosign
        assert path is None
        assert reason == "binary_not_in_archive"
        assert mock_checksum.called  # SHA-256 verification ran


class TestInstallArchiveMemberValidation:
    def _write_archive(self, tmp_path, member: tarfile.TarInfo, data: bytes | None = None):
        archive = tmp_path / "tirith-aarch64-apple-darwin.tar.gz"
        checksums = tmp_path / "checksums.txt"
        with tarfile.open(archive, "w:gz") as tar:
            if data is None:
                tar.addfile(member)
            else:
                tar.addfile(member, io.BytesIO(data))
        checksums.write_text(
            "ignored  tirith-aarch64-apple-darwin.tar.gz\n",
            encoding="utf-8",
        )
        return archive, checksums

    def _download_side_effect(self, archive, checksums):
        def _download(url, dest, timeout=10):
            del timeout
            if url.endswith(".tar.gz"):
                with open(archive, "rb") as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                return
            if url.endswith("checksums.txt"):
                with open(checksums, "rb") as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                return
            raise AssertionError(f"unexpected download URL: {url}")

        return _download

    @patch("tools.tirith_security._verify_checksum", return_value=True)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._detect_target", return_value="aarch64-apple-darwin")
    def test_install_extracts_regular_tirith_member(self, mock_target, mock_which,
                                                    mock_checksum, tmp_path, monkeypatch):
        """A valid regular-file tirith member is installed as a plain file."""
        del mock_target, mock_which, mock_checksum
        from tools.tirith_security import _install_tirith

        payload = b"#!/bin/sh\nexit 0\n"
        member = tarfile.TarInfo("bin/tirith")
        member.mode = 0o755
        member.size = len(payload)
        archive, checksums = self._write_archive(tmp_path, member, payload)

        hermes_home = tmp_path / "hermes-home"
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        with patch("tools.tirith_security._verify_checksum", return_value=True), \
                patch("tools.tirith_security._download_file",
                      side_effect=self._download_side_effect(archive, checksums)):
            path, reason = _install_tirith(log_failures=False)

        assert reason == ""
        assert path == str(hermes_home / "bin" / "tirith")
        assert os.path.isfile(path)
        assert not os.path.islink(path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
        with open(path, "rb") as f:
            assert f.read() == payload

    @pytest.mark.parametrize("unsafe_bin", ["symlink", "writable"])
    def test_install_refuses_untrusted_bin_without_external_write(
            self, tmp_path, monkeypatch, unsafe_bin):
        """An unsafe managed bin path fails before publication or redirection."""
        from tools.tirith_security import _install_tirith

        payload = b"#!/bin/sh\nexit 0\n"
        member = tarfile.TarInfo("bin/tirith")
        member.mode = 0o755
        member.size = len(payload)
        archive, checksums = self._write_archive(tmp_path, member, payload)
        hermes_home = tmp_path / "hermes-home"
        hermes_home.mkdir(mode=0o700)
        unsafe_bin_path = hermes_home / "bin"
        external_dir = tmp_path / "external"
        external_dir.mkdir(mode=0o700)
        if unsafe_bin == "symlink":
            unsafe_bin_path.symlink_to(external_dir, target_is_directory=True)
        else:
            unsafe_bin_path.mkdir(mode=0o770)
            unsafe_bin_path.chmod(0o770)
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        with patch("tools.tirith_security._verify_checksum", return_value=True), \
                patch("tools.tirith_security._download_file",
                      side_effect=self._download_side_effect(archive, checksums)):
            path, reason = _install_tirith(log_failures=False)

        assert path is None
        assert reason == "destination_unsafe"
        assert not (external_dir / "tirith").exists()
        if unsafe_bin == "symlink":
            assert unsafe_bin_path.is_symlink()
        else:
            assert not list(unsafe_bin_path.glob(".tirith.*.partial"))

    @patch("tools.tirith_security._verify_checksum", return_value=True)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._detect_target", return_value="aarch64-apple-darwin")
    def test_install_rejects_non_regular_tirith_member(self, mock_target, mock_which,
                                                       mock_checksum, tmp_path, monkeypatch):
        """Symlink or hardlink tar members must not be installed as tirith."""
        del mock_target, mock_which, mock_checksum
        from tools.tirith_security import _install_tirith

        member = tarfile.TarInfo("bin/tirith")
        member.type = tarfile.SYMTYPE
        member.linkname = "/bin/sh"
        archive, checksums = self._write_archive(tmp_path, member)

        hermes_home = tmp_path / "hermes-home"
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        with patch("tools.tirith_security._download_file",
                   side_effect=self._download_side_effect(archive, checksums)):
            path, reason = _install_tirith(log_failures=False)

        assert path is None
        assert reason == "binary_not_regular_file"
        assert not os.path.lexists(hermes_home / "bin" / "tirith")


# ---------------------------------------------------------------------------
# Background install / non-blocking startup (P2)
# ---------------------------------------------------------------------------

class TestBackgroundInstall:
    def test_ensure_installed_non_blocking(self):
        """ensure_installed must return immediately when download needed."""
        _tirith_mod._resolved_path = None

        with patch("tools.tirith_security._load_security_config",
                   return_value={"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}), \
             patch("tools.tirith_security.shutil.which", return_value=None), \
             patch("tools.tirith_security._hermes_bin_dir", return_value="/nonexistent"), \
             patch("tools.tirith_security._is_install_failed_on_disk", return_value=False), \
             patch("tools.tirith_security.threading.Thread") as MockThread:
            mock_thread = MagicMock()
            mock_thread.is_alive.return_value = False
            MockThread.return_value = mock_thread

            result = ensure_installed()
            assert result is None  # not available yet
            MockThread.assert_called_once()
            mock_thread.start.assert_called_once()

        _tirith_mod._resolved_path = None

    def test_resolve_returns_default_when_thread_alive(self):
        """_resolve_tirith_path returns default while background thread runs."""
        from tools.tirith_security import _resolve_tirith_path
        _tirith_mod._resolved_path = None
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        _tirith_mod._install_thread = mock_thread

        with patch("tools.tirith_security.shutil.which", return_value=None), \
             patch("tools.tirith_security._hermes_bin_dir", return_value="/nonexistent"):
            result = _resolve_tirith_path("tirith")
            assert result is None  # bare paths never fall back to a non-absolute spawn

        _tirith_mod._install_thread = None
        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Disk failure marker persistence (P2)
# ---------------------------------------------------------------------------

class TestDiskFailureMarker:
    def test_expired_marker_ignored(self):
        """Marker older than TTL should be ignored."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        marker = os.path.join(tmpdir, ".tirith-install-failed")
        with patch("tools.tirith_security._failure_marker_path", return_value=marker):
            from tools.tirith_security import _mark_install_failed, _is_install_failed_on_disk
            assert not _is_install_failed_on_disk()
            _mark_install_failed("download_failed")
            assert _is_install_failed_on_disk()
            # Backdate the file past 24h TTL
            old_time = time.time() - 90000  # 25 hours ago
            os.utime(marker, (old_time, old_time))
            assert not _is_install_failed_on_disk()


    def test_in_memory_cosign_exec_failed_not_retried(self):
        """In-memory _INSTALL_FAILED with cosign_exec_failed is NOT retried."""
        from tools.tirith_security import _resolve_tirith_path, _INSTALL_FAILED
        _tirith_mod._resolved_path = _INSTALL_FAILED
        _tirith_mod._install_failure_reason = "cosign_exec_failed"

        with patch("tools.tirith_security.shutil.which", return_value=None), \
             patch("tools.tirith_security._hermes_bin_dir", return_value="/nonexistent"), \
             patch("tools.tirith_security._install_tirith") as mock_install:
            result = _resolve_tirith_path("tirith")
            assert result is None  # bare paths never fall back to a non-absolute spawn
            mock_install.assert_not_called()

        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# HERMES_HOME isolation
# ---------------------------------------------------------------------------

class TestHermesHomeIsolation:
    def test_hermes_bin_dir_respects_hermes_home(self):
        """_hermes_bin_dir must use HERMES_HOME, not hardcoded ~/.hermes."""
        from tools.tirith_security import _hermes_bin_dir
        import tempfile
        tmpdir = tempfile.mkdtemp()
        with patch.dict(os.environ, {"HERMES_HOME": tmpdir}):
            result = _hermes_bin_dir()
        assert result == os.path.join(tmpdir, "bin")
        assert os.path.isdir(result)


# ---------------------------------------------------------------------------
# Warn-once dedupe (issue: tirith spawn failed spamming on Windows)
# ---------------------------------------------------------------------------

class TestSpawnWarningDedup:
    """When tirith isn't installed yet (background install in flight, or
    install marked failed), every terminal command spammed an identical
    ``tirith spawn failed: [WinError 2]`` warning to ``errors.log``. The
    dedupe set in ``_warn_once`` collapses repeats by ``(exc class, errno)``
    while still surfacing the first occurrence so users see the failure.
    """

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_repeated_spawn_failure_logs_once(self, mock_cfg, mock_run, caplog):
        mock_cfg.return_value = {
            "tirith_enabled": True, "tirith_path": "tirith",
            "tirith_timeout": 5, "tirith_fail_open": True,
        }
        mock_run.side_effect = FileNotFoundError("[WinError 2]")
        # Fresh dedupe state — clear any keys left by other tests.
        _tirith_mod._warned_messages.clear()

        with caplog.at_level("WARNING", logger="tools.tirith_security"):
            for i in range(15):
                result = check_command_security("echo hi")
                # Behavior must remain the same on every call —
                # fail-open allow, with the exception captured in summary.
                assert result["action"] == "allow"
                if i < _tirith_mod._CRASH_LIMIT:
                    # Before circuit breaker opens, summary has the exception
                    assert "unavailable" in result["summary"]
                else:
                    # After circuit breaker opens, summary is generic
                    assert "circuit breaker" in result["summary"]

        spawn_warnings = [
            rec for rec in caplog.records
            if "tirith spawn failed" in rec.message
        ]
        assert len(spawn_warnings) == 1, (
            f"expected exactly 1 spawn-failed warning across 15 commands, "
            f"got {len(spawn_warnings)}: {[r.message for r in spawn_warnings]}"
        )


# ---------------------------------------------------------------------------
# Recognized scanner verdicts
# ---------------------------------------------------------------------------

_CFG = {"tirith_enabled": True, "tirith_path": "tirith",
        "tirith_timeout": 5, "tirith_fail_open": True}


class TestAppTldSuppression:
    """Positive scanner warnings remain warnings even when fail-open is enabled."""

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_app_only_warn_preserved(self, mock_cfg, mock_run):
        mock_cfg.return_value = _CFG
        findings = [{"rule_id": "lookalike_tld", "value": ".app",
                     "message": "Domain uses '.app' TLD which can be confused with file extensions"}]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, ".app TLD warning"))
        result = check_command_security("curl https://example.app")
        assert result["action"] == "warn"
        assert result["findings"] == findings
        assert result["summary"] == ".app TLD warning"

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_mixed_findings_preserve_warn(self, mock_cfg, mock_run):
        """Warnings with multiple findings remain warnings."""
        mock_cfg.return_value = _CFG
        findings = [
            {"rule_id": "lookalike_tld", "value": ".app"},
            {"rule_id": "shortened_url", "severity": "medium"},
        ]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "mixed"))
        result = check_command_security("curl https://bit.ly/test.app")
        assert result["action"] == "warn"
        assert len(result["findings"]) == 2

    @patch("tools.tirith_security.bounded_probe_run")
    @patch("tools.tirith_security._load_security_config")
    def test_block_verdict_never_suppressed(self, mock_cfg, mock_run):
        """block exit code is never downgraded, even if finding looks like .app."""
        mock_cfg.return_value = _CFG
        findings = [{"rule_id": "lookalike_tld", "value": ".app"}]
        mock_run.return_value = _mock_run(1, _json_stdout(findings, "block"))
        result = check_command_security("curl https://example.app")
        assert result["action"] == "block"
# ---------------------------------------------------------------------------
# mkdtemp OSError → no_space (disk-full leak prevention)
# ---------------------------------------------------------------------------

class TestMkdtempOSErrorNoSpace:
    """When tempfile.mkdtemp raises OSError (e.g. disk full), _install_tirith
    must return (None, "no_space") instead of propagating the exception.
    This prevents the unbounded retry + temp-dir leak described in #51826.
    """

    def test_mkdtemp_oserror_returns_no_space(self):
        from tools.tirith_security import _install_tirith

        with patch("tools.tirith_security.tempfile.mkdtemp",
                   side_effect=OSError(28, "No space left on device")):
            result, reason = _install_tirith(log_failures=False)
            assert result is None
            assert reason == "no_space"

    def test_mkdtemp_oserror_does_not_leak_tempdir(self):
        """No temp directory should remain after a mkdtemp failure."""
        import glob
        from tools.tirith_security import _install_tirith

        before = set(glob.glob("/tmp/tirith-install-*"))
        with patch("tools.tirith_security.tempfile.mkdtemp",
                   side_effect=OSError(28, "No space left on device")):
            _install_tirith(log_failures=False)
        after = set(glob.glob("/tmp/tirith-install-*"))
        assert after - before == set()
