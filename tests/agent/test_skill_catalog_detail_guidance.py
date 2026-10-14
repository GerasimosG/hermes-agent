"""Skill-catalog detail wiring: the names_all guidance check must reuse the
native render.

build_system_prompt_parts and _skills_prompt stay real; the renderer they
call (agent.prompt_builder.build_skills_system_prompt) is a controlled fake
at that executable interface, returning the bytes the real renderer would
emit per mode. The extra native render must be requested exactly once (only
with skill_view), with unchanged tools/toolsets/skills-dir/compact inputs,
and the stable/context tiers must match a native-bound agent's. The last
test pins the None-specific mode selection used by the follow-up fix.
"""

from types import SimpleNamespace
from unittest.mock import patch

from agent.prompt_builder import (
    HERMES_AGENT_HELP_GUIDANCE,
    HERMES_AGENT_HELP_GUIDANCE_NO_SKILLS,
)
from agent.system_prompt import _skills_prompt, build_system_prompt_parts

NATIVE_ROW = "- hermes-agent: autonomous agent runtime\n"
NATIVE_DEMOTED = "  autonomous-ai-agents [names only]: hermes-agent\n"
NAMES_ALL_BYTES = (
    "  autonomous-ai-agents [names only]: hermes-agent\n"
    "  general [names only]: unslop\n"
    "(Categories marked [names only] are compacted by "
    "agent.skill_catalog_detail=names_all.)"
)


def make_agent(**overrides):
    base = dict(
        load_soul_identity=False, skip_context_files=False,
        valid_tool_names=["skills_list", "skill_view"],
        _task_completion_guidance=False, _tool_use_enforcement=False,
        _environment_probe=False, _kanban_worker_guidance="",
        _memory_store=None, _memory_manager=None,
        model="", provider="", platform="", pass_session_id=False,
        session_id="", _emit_status=lambda *args, **kwargs: None,
        skill_catalog_detail="native",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def make_render(native_bytes, names_all_bytes):
    def render(**kwargs):
        render.calls.append(kwargs)
        if kwargs.get("skill_catalog_detail") == "names_all":
            return names_all_bytes
        return native_bytes

    render.calls = []
    return render


def build_parts(agent, render):
    with (
        patch("agent.prompt_builder.load_soul_md", return_value=""),
        patch("agent.prompt_builder.build_environment_hints", return_value=""),
        patch("agent.prompt_builder.build_context_files_prompt", return_value=""),
        patch("model_tools.get_toolset_for_tool", return_value="tooling"),
        patch("agent.coding_context.coding_compact_skill_categories",
              return_value=frozenset({"tooling"})),
        patch("agent.prompt_builder.build_skills_system_prompt", new=render),
    ):
        return build_system_prompt_parts(agent)


def ensure_guidance(stable, skills_variant):
    assert (HERMES_AGENT_HELP_GUIDANCE in stable) is skills_variant
    assert (HERMES_AGENT_HELP_GUIDANCE_NO_SKILLS in stable) is not skills_variant


def test_names_all_guidance_uses_the_native_row_with_identical_render_inputs():
    log = make_render(NATIVE_ROW, NAMES_ALL_BYTES)
    parts = build_parts(make_agent(skill_catalog_detail="names_all"), log)
    assert [call["skill_catalog_detail"] for call in log.calls] == ["names_all", "native"]
    names_all_call, native_call = log.calls
    assert set(native_call) == set(names_all_call)
    for key in ("available_tools", "available_toolsets", "compact_categories",
                "skills_dir_override"):
        assert native_call[key] == names_all_call[key]
    assert names_all_call["available_tools"] == ["skills_list", "skill_view"]
    assert names_all_call["available_toolsets"] == {"tooling"}
    assert names_all_call["compact_categories"] == frozenset({"tooling"})
    ensure_guidance(parts["stable"], True)
    assert parts["volatile"].startswith(NAMES_ALL_BYTES.strip())

    native_log = make_render(NATIVE_ROW, NAMES_ALL_BYTES)
    native_parts = build_parts(make_agent(skill_catalog_detail="native"), native_log)
    assert [call["skill_catalog_detail"] for call in native_log.calls] == ["native"]
    assert native_log.calls[0] == native_call
    ensure_guidance(native_parts["stable"], True)
    assert native_parts["stable"] == parts["stable"]
    assert native_parts["context"] == parts["context"]


def test_demoted_native_index_keeps_original_no_skills_choice_in_both_modes():
    names_all_log = make_render(NATIVE_DEMOTED, NAMES_ALL_BYTES)
    names_parts = build_parts(make_agent(skill_catalog_detail="names_all"), names_all_log)
    assert [call["skill_catalog_detail"] for call in names_all_log.calls] == ["names_all", "native"]
    ensure_guidance(names_parts["stable"], False)

    native_log = make_render(NATIVE_DEMOTED, NAMES_ALL_BYTES)
    native_parts = build_parts(make_agent(skill_catalog_detail="native"), native_log)
    assert [call["skill_catalog_detail"] for call in native_log.calls] == ["native"]
    ensure_guidance(native_parts["stable"], False)
    assert native_parts["stable"] == names_parts["stable"]
    assert native_parts["context"] == names_parts["context"]


def test_without_skill_view_names_all_makes_no_native_guidance_render():
    log = make_render(NATIVE_ROW, NAMES_ALL_BYTES)
    agent = make_agent(skill_catalog_detail="names_all", valid_tool_names=["skills_list"])
    parts = build_parts(agent, log)
    assert [call["skill_catalog_detail"] for call in log.calls] == ["names_all"]
    assert parts["volatile"].startswith(NAMES_ALL_BYTES.strip())
    ensure_guidance(parts["stable"], False)


def test_skills_prompt_only_none_falls_back_to_the_bound_agent_attribute():
    log = make_render(NATIVE_ROW, NAMES_ALL_BYTES)
    agent = make_agent(skill_catalog_detail="names_all")
    with (
        patch("agent.prompt_builder.build_skills_system_prompt", new=log),
        patch("model_tools.get_toolset_for_tool", return_value="tooling"),
    ):
        assert _skills_prompt(agent) == NAMES_ALL_BYTES
        assert _skills_prompt(agent, skill_catalog_detail="native") == NATIVE_ROW
        assert _skills_prompt(agent, skill_catalog_detail="") == NATIVE_ROW
    assert [call["skill_catalog_detail"] for call in log.calls] == ["names_all", "native", ""]
