"""Skills attribution follows current volatile and legacy stable layouts.

Each category uses the existing rough estimator separately. Splitting and
joining category boundaries can change rounding; totals are not provider usage.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.context_breakdown import compute_context_details, compute_session_context_breakdown
from agent.model_metadata import estimate_tokens_rough
from agent.usage_anchor import capture_usage_anchor


VOLATILE_CATALOG = "<available_skills>\n  demo:\n    - current: current skill\n</available_skills>"
STABLE_CATALOG = "<available_skills>\n  demo:\n    - legacy: older skill\n</available_skills>"
UNICODE_CATALOG = "<available_skills>\n  demo:\n    - français: révision\n</available_skills>"


@pytest.mark.parametrize(
    "stable,volatile,chosen,remaining,names",
    [
        ("identity", "clock\n\n" + VOLATILE_CATALOG, VOLATILE_CATALOG, "identity\n\nclock", ["current"]),
        ("identity\n\n" + STABLE_CATALOG, "clock", STABLE_CATALOG, "identity\n\nclock", ["legacy"]),
        ("identity", "clock", "", "identity\n\nclock", []),
        ("identity\n\n" + STABLE_CATALOG, "clock\n\n" + VOLATILE_CATALOG,
         VOLATILE_CATALOG, "identity\n\n" + STABLE_CATALOG + "\n\nclock", ["current"]),
        (VOLATILE_CATALOG, VOLATILE_CATALOG, VOLATILE_CATALOG, VOLATILE_CATALOG, ["current"]),
        ("", VOLATILE_CATALOG + "\n\n" + VOLATILE_CATALOG,
         VOLATILE_CATALOG, VOLATILE_CATALOG, ["current"]),
        (STABLE_CATALOG + "\n\n" + STABLE_CATALOG, "",
         STABLE_CATALOG, STABLE_CATALOG, ["legacy"]),
        ("identity", UNICODE_CATALOG, UNICODE_CATALOG, "identity", ["français"]),
        (STABLE_CATALOG, "<available_skills>unfinished", STABLE_CATALOG,
         "<available_skills>unfinished", ["legacy"]),
    ],
    ids=["volatile", "legacy", "absent", "volatile-precedence", "identical-tiers",
         "duplicate-volatile", "duplicate-stable", "unicode", "incomplete-volatile"],
)
def test_skills_choose_one_catalog_and_keep_other_content(stable, volatile, chosen, remaining, names):
    agent = SimpleNamespace(model="test", tools=[], context_compressor=None, _memory_store=None,
                            _usage_anchor=None, _turn_base_usage_anchor=None)
    parts = {"stable": stable, "volatile": volatile, "context": "rules"}
    original_parts = dict(parts)
    with patch("agent.system_prompt.build_system_prompt_parts", return_value=parts):
        result = compute_session_context_breakdown(agent, [])
        with patch("hermes_cli.prompt_size._skill_md_paths_by_name", return_value={}):
            details = compute_context_details(agent)

    categories = {item["id"]: item["tokens"] for item in result["categories"]}
    assert categories.get("skills", 0) == estimate_tokens_rough(chosen)
    assert ("skills" in categories) == bool(chosen)
    assert categories.get("system_prompt", 0) == estimate_tokens_rough(remaining)
    assert [item["name"] for item in details["skills"]] == names
    assert result["estimated_total"] == sum(categories.values())
    assert result["estimated_total"] == sum(estimate_tokens_rough(text) for text in (chosen, remaining, "rules"))
    assert parts == original_parts


@pytest.mark.parametrize("occupancy", ["provider", "provider-delta", "display-seed"])
def test_catalog_layout_does_not_change_occupancy_or_other_categories(occupancy):
    messages = [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "reply"}]
    anchor = capture_usage_anchor(1200, 0, messages) if occupancy != "display-seed" else None
    if occupancy == "provider-delta":
        messages = [*messages, {"role": "user", "content": "next question"}]
    compressor = SimpleNamespace(context_length=8000, last_prompt_tokens=1300, last_real_prompt_tokens=1200)
    agent = SimpleNamespace(model="test", tools=[], context_compressor=compressor, _memory_store=None,
                            _turn_base_usage_anchor=anchor, _usage_anchor=None)
    parts = {"stable": "identity", "volatile": "clock", "context": "rules"}
    with patch("agent.system_prompt.build_system_prompt_parts", return_value=parts):
        before = compute_session_context_breakdown(agent, messages)
        parts["volatile"] += "\n\n" + VOLATILE_CATALOG
        after = compute_session_context_breakdown(agent, messages)

    for field in ("context_used", "context_max", "context_percent", "context_source", "context_estimated", "model"):
        assert after[field] == before[field]
    expected_source = {"provider": "provider_usage", "provider-delta": "provider_usage_plus_estimate",
                       "display-seed": "local_estimate"}[occupancy]
    assert after["context_source"] == expected_source
    before_categories = {item["id"]: item["tokens"] for item in before["categories"]}
    after_categories = {item["id"]: item["tokens"] for item in after["categories"]}
    assert after_categories.pop("skills") > 0
    assert after_categories == before_categories
    assert compressor.last_prompt_tokens == 1300
    assert compressor.last_real_prompt_tokens == 1200
