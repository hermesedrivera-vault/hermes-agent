"""Tests for the curator protected-content gate (tools/curator_protection.py)
and its wiring into tools/skill_manager_tool.py::_apply_skill_write_gate.

Added 2026-11-17/18 after a curator over-generalization incident (see vault
postmortem 05-Postmortems/2026-11-17-curator-ci-authorization-overgeneralization.md).
Covers: a protected-skill write by the curator -> proposal; a protected-
keyword hit -> proposal; a weaken-pattern removal on an unlisted skill ->
proposal; a foreground (non-curator) write -> unaffected (writes normally).
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from tools.skill_manager_tool import skill_manage
from tools.skill_provenance import (
    BACKGROUND_REVIEW,
    reset_current_write_origin,
    set_current_write_origin,
)


@contextmanager
def _skill_dir(tmp_path):
    """Patch both SKILLS_DIR and get_all_skills_dirs so _find_skill searches
    only the temp directory — not the real ~/.hermes/skills/."""
    with patch("tools.skill_manager_tool.SKILLS_DIR", tmp_path), \
         patch("agent.skill_utils.get_all_skills_dirs", return_value=[tmp_path]):
        yield


@contextmanager
def _as_background_review():
    token = set_current_write_origin(BACKGROUND_REVIEW)
    try:
        yield
    finally:
        reset_current_write_origin(token)


PROTECTED_SKILL_CONTENT = """\
---
name: jnc-tax-engine-ops
description: jnc-tax-ai-agent PRs, IRS PDFs, deploys.
---

# JNC Tax Engine Operations

Do not deviate from the sequence below without explicit re-authorization.
"""

UNLISTED_SKILL_CONTENT = """\
---
name: some-ops-skill
description: An unlisted ops skill.
---

# Some Ops Skill

Only when Ed explicitly says go should you proceed.
"""


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    """Isolated HERMES_HOME so proposal files land under a temp dir, never
    the real ~/.hermes/skills/.curator_proposals/."""
    home = tmp_path / ".hermes"
    (home / "skills").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _proposals_dir(home: Path) -> Path:
    return home / "skills" / ".curator_proposals"


def test_protected_skill_write_routes_to_proposal(tmp_path, hermes_home):
    """A curator (background_review) write targeting jnc-tax-engine-ops never
    lands live — it's filed as a proposal, and the live SKILL.md is untouched."""
    skill_dir = tmp_path / "jnc-tax-engine-ops"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(PROTECTED_SKILL_CONTENT, encoding="utf-8")

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="jnc-tax-engine-ops",
            old_string="Do not deviate from the sequence below without explicit re-authorization.",
            new_string="Once authorized the exception stands for future reruns without asking again.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("proposed") is True
    assert result.get("live_write") is False

    proposals = list(_proposals_dir(hermes_home).glob("*.md"))
    assert len(proposals) == 1
    assert "jnc-tax-engine-ops" in proposals[0].name

    # Live file must be byte-for-byte unchanged.
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == PROTECTED_SKILL_CONTENT


def test_protected_keyword_hit_routes_to_proposal(tmp_path, hermes_home):
    """An unlisted skill isn't itself protected, but introducing a protected
    keyword ('deploy' near 'production database') still routes to a proposal."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Then deploy the new build to the production database.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert "deploy" in result["message"].lower()
    assert len(list(_proposals_dir(hermes_home).glob("*.md"))) == 1
    # Live file unchanged.
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_weaken_pattern_removal_routes_to_proposal(tmp_path, hermes_home):
    """An unlisted skill with no protected keyword at all, but whose patch
    REMOVES a guardrail phrase ('only when'), still routes to a proposal."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Proceed once the task looks ready.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert "weaken" in result["message"].lower() or "remove" in result["message"].lower()
    assert len(list(_proposals_dir(hermes_home).glob("*.md"))) == 1
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_foreground_write_is_unaffected(tmp_path, hermes_home):
    """The SAME content that would be proposed under background_review origin
    applies normally — live write, no proposal — for a foreground write
    (default origin; no set_current_write_origin call)."""
    skill_dir = tmp_path / "jnc-tax-engine-ops"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(PROTECTED_SKILL_CONTENT, encoding="utf-8")

    with _skill_dir(tmp_path):
        raw = skill_manage(
            action="patch", name="jnc-tax-engine-ops",
            old_string="Do not deviate from the sequence below without explicit re-authorization.",
            new_string="Once authorized the exception stands for future reruns without asking again.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert "proposed" not in result  # normal write-result shape, not the gate's shape
    assert not _proposals_dir(hermes_home).exists() or \
        not list(_proposals_dir(hermes_home).glob("*.md"))
    # Live file WAS updated (foreground writes are not gated by this check).
    content = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    assert "Once authorized the exception stands" in content
