"""Tests for ``agent.skill_catalog_detail``: runtime binding and write-time validation."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
import hermes_yaml as yaml

from agent.agent_init import _apply_agent_section
from hermes_cli.config import DEFAULT_CONFIG, load_config, set_config_value


def bind_agent(section=None):
    agent = SimpleNamespace(run_budget_seconds=None, valid_tool_names=set())
    agent_cfg = {"environment_probe": False}  # keep the env-probe warm-up thread out of tests
    agent_cfg.update(section or {})
    _apply_agent_section(agent, {"agent": agent_cfg})
    return agent


def detail_warnings(caplog):
    return [r for r in caplog.records if "skill_catalog_detail" in r.getMessage()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".env").touch()
    (home / "config.yaml").write_text("agent: {}\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path / "os-home"))
    monkeypatch.setenv("HERMES_HOME", str(home))
    yield home


def saved_detail(home):
    raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    return raw["agent"]["skill_catalog_detail"]


@pytest.mark.parametrize("section", [None, {}, {"skill_catalog_detail": None},
                                     {"skill_catalog_detail": ""}, {"skill_catalog_detail": "   "}])
def test_missing_none_empty_whitespace_bind_native_silently(caplog, section):
    with caplog.at_level(logging.WARNING):
        agent = bind_agent(section)
    assert agent.skill_catalog_detail == "native"
    assert detail_warnings(caplog) == []


@pytest.mark.parametrize("bad", ["full", "names", "names-only", " Native!! ", "NATIVE_"])
def test_invalid_strings_warn_once_and_bind_native(caplog, bad):
    with caplog.at_level(logging.WARNING):
        agent = bind_agent({"skill_catalog_detail": bad})
    assert agent.skill_catalog_detail == "native"
    assert len(detail_warnings(caplog)) == 1


@pytest.mark.parametrize("bad", [True, False, 0, 1, 1.5, ["names_all"], {"mode": "names_all"}])
def test_non_string_values_warn_once_and_bind_native(caplog, bad):
    with caplog.at_level(logging.WARNING):
        agent = bind_agent({"skill_catalog_detail": bad})
    assert agent.skill_catalog_detail == "native"
    assert len(detail_warnings(caplog)) == 1


@pytest.mark.parametrize("raw,expected", [("names_all", "names_all"), ("  NAMES_ALL ", "names_all"),
                                          ("native", "native"), (" NATIVE\t", "native")])
def test_valid_values_normalize_case_and_whitespace(caplog, raw, expected):
    with caplog.at_level(logging.WARNING):
        agent = bind_agent({"skill_catalog_detail": raw})
    assert agent.skill_catalog_detail == expected
    assert detail_warnings(caplog) == []


def test_binding_is_per_agent_instance():
    opted_in = bind_agent({"skill_catalog_detail": "names_all"})
    defaulted = bind_agent({})
    assert opted_in.skill_catalog_detail == "names_all"
    assert defaulted.skill_catalog_detail == "native"


def test_set_config_value_persists_both_modes(home):
    set_config_value("agent.skill_catalog_detail", "names_all")
    assert saved_detail(home) == "names_all"
    set_config_value("agent.skill_catalog_detail", "native")
    assert saved_detail(home) == "native"


@pytest.mark.parametrize("force", [False, True])
def test_invalid_value_is_refused_and_preserves_config(home, capsys, force):
    before = (home / "config.yaml").read_bytes()
    with pytest.raises(SystemExit):
        set_config_value("agent.skill_catalog_detail", "names", force=force)
    assert "Invalid agent.skill_catalog_detail" in capsys.readouterr().err
    assert (home / "config.yaml").read_bytes() == before


def test_default_loader_yields_native(home):
    assert DEFAULT_CONFIG["agent"]["skill_catalog_detail"] == "native"
    assert load_config()["agent"]["skill_catalog_detail"] == "native"