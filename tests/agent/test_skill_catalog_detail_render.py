"""Rendering tests for agent.skill_catalog_detail=names_all in build_skills_system_prompt.

Fixtures are real SKILL.md frontmatter under a tmp HERMES_HOME; the native cache is
cleared per test, so every build is a fresh render and assertions exercise real output.
"""

import logging
from pathlib import Path

import pytest

from agent import prompt_builder
from agent.prompt_builder import build_skills_system_prompt, clear_skills_system_prompt_cache


def write_skill(home: Path, category: str, slug: str, description: str) -> None:
    skill_dir = home / "skills" / category / slug
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {slug}\ndescription: {description}\n---\n# {slug}\n", encoding="utf-8"
    )


@pytest.fixture(autouse=True)
def fresh_skills_cache():
    clear_skills_system_prompt_cache(clear_snapshot=True)
    yield
    clear_skills_system_prompt_cache(clear_snapshot=True)


@pytest.fixture
def skills_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    write_skill(tmp_path, "tools", "web-search", "Search the web")
    write_skill(tmp_path, "social-media/twitter", "thread-writer", "Write threads")
    write_skill(tmp_path, ".", "standalone", "Standalone helper")
    return tmp_path


def test_native_default_is_byte_identical_to_explicit_native(skills_home):
    default = build_skills_system_prompt()
    clear_skills_system_prompt_cache(clear_snapshot=True)
    explicit = build_skills_system_prompt(skill_catalog_detail="native")
    assert default == explicit
    assert "- web-search: Search the web" in default
    assert "[names only]" not in default
    assert "agent.skill_catalog_detail=names_all" not in default


def test_names_all_covers_categories_nested_identities_and_omits_descriptions(skills_home):
    result = build_skills_system_prompt(skill_catalog_detail="names_all")
    assert "  tools [names only]: web-search" in result
    assert "  social-media/twitter [names only]: thread-writer" in result
    assert "standalone" in result
    assert "Search the web" not in result
    assert "Write threads" not in result
    assert "Standalone helper" not in result
    assert "agent.skill_catalog_detail=names_all" in result
    assert "outside the current coding" not in result


def test_mode_switch_keeps_cache_entries_separate_and_rebuild_is_byte_stable(skills_home):
    native_first = build_skills_system_prompt()
    names_all_first = build_skills_system_prompt(skill_catalog_detail="names_all")
    native_again = build_skills_system_prompt()
    names_all_again = build_skills_system_prompt(skill_catalog_detail="names_all")
    assert native_again == native_first
    assert names_all_again == names_all_first
    assert native_first != names_all_first
    assert "Search the web" in native_again and "Write threads" not in names_all_again
    clear_skills_system_prompt_cache(clear_snapshot=True)
    assert build_skills_system_prompt() == native_first
    assert build_skills_system_prompt(skill_catalog_detail="names_all") == names_all_first


def test_disabled_skills_stay_absent_under_names_all(skills_home, monkeypatch):
    monkeypatch.setattr(prompt_builder, "get_disabled_skill_names", lambda *args, **kwargs: {"thread-writer"})
    result = build_skills_system_prompt(skill_catalog_detail="names_all")
    assert "web-search" in result
    assert "thread-writer" not in result


def test_plugin_rows_render_names_only_under_names_all(skills_home, monkeypatch):
    plugin_rows = [("plugin:demo", "Plugin demo description")]
    monkeypatch.setattr(prompt_builder, "_plugin_skill_prompt_rows", lambda *args, **kwargs: plugin_rows)
    native = build_skills_system_prompt()
    names_all = build_skills_system_prompt(skill_catalog_detail="names_all")
    assert "plugin:demo: Plugin demo description" in native
    assert "  plugin [names only]: plugin:demo" in names_all
    assert "Plugin demo description" not in names_all


def test_oneshot_names_all_keeps_names_only_lines(skills_home, monkeypatch):
    monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
    result = build_skills_system_prompt(skill_catalog_detail="names_all")
    assert "web-search" in result and "thread-writer" in result
    assert "Search the web" not in result and "Write threads" not in result
    assert "[names only]" in result


@pytest.mark.parametrize("bad", ["full", "names", 0, False, [], {}])
def test_invalid_detail_warns_once_and_falls_back_to_native(skills_home, caplog, bad):
    native = build_skills_system_prompt()
    with caplog.at_level(logging.WARNING, logger="agent.prompt_builder"):
        result = build_skills_system_prompt(skill_catalog_detail=bad)
    warnings = [record for record in caplog.records if "skill_catalog_detail" in record.getMessage()]
    assert len(warnings) == 1
    assert result == native


@pytest.mark.parametrize("quiet", [None, "", "   "])
def test_none_empty_and_whitespace_detail_are_silent_native(skills_home, caplog, quiet):
    native = build_skills_system_prompt()
    with caplog.at_level(logging.WARNING, logger="agent.prompt_builder"):
        result = build_skills_system_prompt(skill_catalog_detail=quiet)
    assert result == native
    assert [record for record in caplog.records if "skill_catalog_detail" in record.getMessage()] == []
