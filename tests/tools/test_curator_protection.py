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


# ---------------------------------------------------------------------------
# Pause-aware gating — Ed/Claude, 2026-11-18, after a write landed on
# jnc-tax-engine-ops while `hermes curator pause` was in effect. Traced to
# agent/background_review.py's per-turn nudge, a SEPARATE subsystem from
# agent/curator.py's scheduled pass, with zero reference to curator.pause.
# The fix: curator_protection.classify_write() checks pause itself, so it
# blocks every automated actor routing through this one gate (scheduled
# curator, per-turn nudge, any future session-end review) — not just the
# literal ledger actor string "curator".
# ---------------------------------------------------------------------------

def test_session_end_review_write_refused_while_paused(tmp_path, hermes_home, monkeypatch):
    """(a) A background-review-origin write — standing in for the per-turn
    nudge / session-end review path, not just the scheduled curator pass —
    is refused while curator.pause is in effect, even for UNPROTECTED,
    keyword-free content that would otherwise sail through."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    monkeypatch.setattr("agent.curator.is_paused", lambda: True)

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Only when Ed explicitly says go should you proceed, plus a benign clarification.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert "paused" in result["message"].lower()
    assert len(list(_proposals_dir(hermes_home).glob("*.md"))) == 1
    # Live file untouched — pause blocks it before any content classification runs.
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_protected_content_refused_without_approval_even_when_not_paused(tmp_path, hermes_home, monkeypatch):
    """(b) A write to protected content is refused without Ed's explicit
    approval REGARDLESS of pause state — explicitly confirm the protected-
    skill gate still fires when curator.is_paused() is False, so the pause
    check isn't masking a separate, independently-required gate."""
    monkeypatch.setattr("agent.curator.is_paused", lambda: False)

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
    assert result.get("live_write") is False
    assert "paused" not in result["message"].lower()
    assert "protected list" in result["message"].lower()
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == PROTECTED_SKILL_CONTENT


def test_unreadable_pause_state_fails_closed_and_is_refused(tmp_path, hermes_home, monkeypatch):
    """(c) An unreadable/corrupt pause state (agent.curator.is_paused raising)
    must fail CLOSED — treated as paused, write refused — never as unpaused."""
    def _boom():
        raise OSError("corrupt .curator_state")
    monkeypatch.setattr("agent.curator.is_paused", _boom)

    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Only when Ed explicitly says go should you proceed, plus a benign clarification.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert len(list(_proposals_dir(hermes_home).glob("*.md"))) == 1
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_normal_unprotected_write_applies_when_not_paused(tmp_path, hermes_home, monkeypatch):
    """(d) A normal, unprotected, non-weakening background-review write goes
    through live (no proposal) when curator is confirmed NOT paused."""
    monkeypatch.setattr("agent.curator.is_paused", lambda: False)

    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    from tools.skill_manager_guards import mark_background_review_skill_read

    with _skill_dir(tmp_path), _as_background_review():
        mark_background_review_skill_read(skill_dir / "SKILL.md")
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Only when Ed explicitly says go should you proceed. Also run the lint step first.",
        )
    result = json.loads(raw)
    assert result["success"] is True, raw
    assert "proposed" not in result
    assert not list(_proposals_dir(hermes_home).glob("*.md"))
    content = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    assert "Also run the lint step first." in content
