"""skill_view must serialize frontmatter metadata that YAML parses into dates.

Regression: an unquoted date in frontmatter metadata (`imported: 2026-09-25`)
parses to ``datetime.date``; the skill JSON helpers had no serializer fallback,
so skill_view failed for the whole skill instead of serving it.
"""

import json
from unittest.mock import patch

import pytest

from tools.skills_tool import skill_view


@pytest.fixture()
def skills_root(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    return root


def write_skill(skills_root, name, metadata_block):
    skill_dir = skills_root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        "description: Date metadata skill\n"
        f"{metadata_block}"
        "---\n\n"
        f"# {name}\n",
        encoding="utf-8",
    )
    return skill_dir


def test_unquoted_date_metadata_still_serves_the_skill(skills_root):
    write_skill(
        skills_root,
        "dated-skill",
        "metadata:\n  hermes:\n    imported: 2026-09-25\n    tags: [ecc, imported]\n",
    )
    with patch("tools.skills_tool.SKILLS_DIR", skills_root):
        result = json.loads(skill_view("dated-skill"))

    assert result["success"] is True
    assert result["metadata"]["hermes"]["imported"] == "2026-09-25"
    assert result["content"]


def test_datetime_metadata_still_serves_the_skill(skills_root):
    write_skill(
        skills_root,
        "timestamped-skill",
        "metadata:\n  updated: 2025-10-20 08:30:00\n",
    )
    with patch("tools.skills_tool.SKILLS_DIR", skills_root):
        result = json.loads(skill_view("timestamped-skill"))

    assert result["success"] is True
    assert result["metadata"]["updated"].startswith("2025-10-20")
