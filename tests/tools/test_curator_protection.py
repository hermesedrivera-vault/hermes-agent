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
#
# B2 (Ed, 2026-11-21): these tests write REAL .curator_state files to disk
# rather than monkeypatching agent.curator.is_paused — that function's own
# load_state() silently maps a read/parse error to paused=False, so a
# monkeypatch of is_paused() itself could never exercise the actual bug
# (a corrupt file on disk). _curator_is_paused() now reads .curator_state
# directly via _read_pause_state_from_disk(), bypassing load_state() and its
# error-swallowing entirely.
# ---------------------------------------------------------------------------

def _state_path(home: Path) -> Path:
    return home / "skills" / ".curator_state"


def test_session_end_review_write_refused_while_paused(tmp_path, hermes_home):
    """(a) A background-review-origin write — standing in for the per-turn
    nudge / session-end review path, not just the scheduled curator pass —
    is refused while curator.pause is in effect (a real .curator_state file
    with paused: true), even for UNPROTECTED, keyword-free content that
    would otherwise sail through."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    _state_path(hermes_home).write_text(json.dumps({"paused": True}), encoding="utf-8")

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


def test_protected_content_refused_without_approval_even_when_not_paused(tmp_path, hermes_home):
    """(b) A write to protected content is refused without Ed's explicit
    approval REGARDLESS of pause state — explicitly confirm the protected-
    skill gate still fires with no .curator_state file at all (missing file
    -> not paused), so the pause check isn't masking a separate,
    independently-required gate.

    B8 moved 'jnc-tax-engine-ops' out of the code defaults into
    config.yaml's curator.protected_skills (it's deployment-specific). This
    test writes a REAL config.yaml under the isolated HERMES_HOME and loads
    it through the real config path (no mocking of
    curator_protection.protected_skills) — exercising B8's additive merge
    (config entries add to the code defaults) end to end, the way it
    actually runs in production."""
    assert not _state_path(hermes_home).exists()

    (hermes_home / "config.yaml").write_text(
        "curator:\n  protected_skills:\n    - jnc-tax-engine-ops\n", encoding="utf-8")

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


def test_unreadable_pause_state_fails_closed_and_is_refused(tmp_path, hermes_home):
    """(c) A REAL corrupt .curator_state file on disk (invalid JSON, not a
    monkeypatched function) must fail CLOSED — treated as paused, write
    refused — never as unpaused."""
    _state_path(hermes_home).write_text("{not valid json", encoding="utf-8")

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


def test_curator_state_non_dict_json_fails_closed(tmp_path, hermes_home):
    """A real .curator_state file whose top level parses as valid JSON but
    isn't a dict (e.g. a bare list) must fail closed — paused."""
    _state_path(hermes_home).write_text(json.dumps([1, 2, 3]), encoding="utf-8")

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
    assert "paused" in result["message"].lower()
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_curator_state_paused_value_not_bool_fails_closed(tmp_path, hermes_home):
    """A real .curator_state file with a 'paused' value that isn't a bool
    (e.g. the string "yes") must fail closed — paused."""
    _state_path(hermes_home).write_text(json.dumps({"paused": "yes"}), encoding="utf-8")

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
    assert "paused" in result["message"].lower()
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_curator_state_paused_false_does_not_block(tmp_path, hermes_home):
    """A real .curator_state file with an explicit {"paused": false} behaves
    identically to a missing file — not paused."""
    _state_path(hermes_home).write_text(json.dumps({"paused": False}), encoding="utf-8")

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
    content = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    assert "Also run the lint step first." in content


def test_normal_unprotected_write_applies_when_not_paused(tmp_path, hermes_home):
    """(d) A normal, unprotected, non-weakening background-review write goes
    through live (no proposal) when curator is confirmed NOT paused (no
    .curator_state file at all — the missing-file-means-not-paused case)."""
    assert not _state_path(hermes_home).exists()

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


# ---------------------------------------------------------------------------
# B1 (Ed, 2026-11-21): fail-closed gate. The old `with suppress(Exception):`
# around the whole background-review branch let ANY failure inside
# classify_write/write_proposal silently skip the gate and apply the write
# live. Now any such failure refuses the write outright.
# ---------------------------------------------------------------------------

def test_write_proposal_exception_fails_closed_refusal(tmp_path, hermes_home, monkeypatch):
    """If write_proposal() itself raises (disk full, permission error, etc.)
    the write must be REFUSED outright — never silently fall through to the
    normal live-write path."""
    skill_dir = tmp_path / "jnc-tax-engine-ops"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(PROTECTED_SKILL_CONTENT, encoding="utf-8")

    from tools import curator_protection as cp

    def _boom(**kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(cp, "write_proposal", _boom)

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="jnc-tax-engine-ops",
            old_string="Do not deviate from the sequence below without explicit re-authorization.",
            new_string="Once authorized the exception stands for future reruns without asking again.",
        )
    result = json.loads(raw)
    assert result["success"] is False, raw
    assert result.get("live_write") is False
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == PROTECTED_SKILL_CONTENT


def test_classify_write_exception_fails_closed_refusal(tmp_path, hermes_home, monkeypatch):
    """Same as above, one layer up: classify_write() itself raising must
    also refuse the write rather than silently applying it live."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    from tools import curator_protection as cp

    def _boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(cp, "classify_write", _boom)

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Only when Ed explicitly says go should you proceed, plus a benign clarification.",
        )
    result = json.loads(raw)
    assert result["success"] is False, raw
    assert result.get("live_write") is False
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_origin_lookup_failure_treated_as_background_review(tmp_path, hermes_home, monkeypatch):
    """If is_background_review() itself can't be determined (raises), the
    gate must treat the write as background-review (the unsafe default
    would be treating an unidentified write as trusted foreground)."""
    skill_dir = tmp_path / "jnc-tax-engine-ops"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(PROTECTED_SKILL_CONTENT, encoding="utf-8")

    def _boom():
        raise RuntimeError("context lookup failed")
    monkeypatch.setattr("tools.skill_provenance.is_background_review", _boom)

    # No _as_background_review() context here — origin lookup itself fails,
    # and the gate must still treat this as background-review.
    with _skill_dir(tmp_path):
        raw = skill_manage(
            action="patch", name="jnc-tax-engine-ops",
            old_string="Do not deviate from the sequence below without explicit re-authorization.",
            new_string="Once authorized the exception stands for future reruns without asking again.",
        )
    result = json.loads(raw)
    assert result.get("live_write") is False
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == PROTECTED_SKILL_CONTENT


# ---------------------------------------------------------------------------
# B3 (Ed, 2026-11-21): full rewrites (edit/write_file) use the CURRENT
# on-disk content as old_text for the weaken-pattern check (patch already
# gets this from old_string); delete and remove_file from background review
# always go to a proposal, unconditionally.
# ---------------------------------------------------------------------------

def test_full_rewrite_edit_weaken_pattern_detected_via_current_file(tmp_path, hermes_home):
    """action='edit' (full SKILL.md rewrite) with no old_string supplied —
    the gate must read the CURRENT on-disk SKILL.md as old_text, so removing
    a guardrail phrase is still caught even though edit never gets an
    explicit old_string the way patch does."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    new_content = UNLISTED_SKILL_CONTENT.replace(
        "Only when Ed explicitly says go should you proceed.",
        "Proceed once the task looks ready.")
    assert new_content != UNLISTED_SKILL_CONTENT

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(action="edit", name="some-ops-skill", content=new_content)
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert "weaken" in result["message"].lower() or "remove" in result["message"].lower()
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_full_rewrite_write_file_weaken_pattern_detected_via_current_file(tmp_path, hermes_home):
    """action='write_file' (full supporting-file rewrite) with no
    old_string — same as above, but for a supporting file instead of
    SKILL.md."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")
    ref_dir = skill_dir / "references"
    ref_dir.mkdir()
    old_ref = "Only when Ed explicitly says go should the deploy script run."
    (ref_dir / "notes.md").write_text(old_ref, encoding="utf-8")
    new_ref = "The deploy script runs once the task looks ready."

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(action="write_file", name="some-ops-skill",
                           file_path="references/notes.md", file_content=new_ref)
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert (ref_dir / "notes.md").read_text(encoding="utf-8") == old_ref


def test_delete_from_background_review_always_proposed(tmp_path, hermes_home):
    """action='delete' from background review always routes to a proposal —
    never auto-archived/deleted — even for an unprotected skill with no
    weaken pattern or protected keyword at all.

    Must be a curator-managed skill (a usage record with created_by="agent")
    to get past an EARLIER, pre-existing, unrelated ownership guard
    (_background_review_delete_guard, checked before this gate even runs) —
    that guard refuses a non-curator-managed delete outright (correct,
    separate, pre-existing behavior); this test is about what happens to a
    delete that DOES pass ownership."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: some-ops-skill\ndescription: An unlisted ops skill.\n---\n\nBenign content.\n",
        encoding="utf-8")

    from tools import skill_usage
    data = skill_usage.load_usage()
    data["some-ops-skill"] = skill_usage._empty_record()
    data["some-ops-skill"]["created_by"] = "agent"
    skill_usage.save_usage(data)

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(action="delete", name="some-ops-skill")
    result = json.loads(raw)
    assert result["success"] is True, raw
    assert result.get("live_write") is False
    assert "proposal" in result["message"].lower()
    assert skill_dir.exists()  # never archived or removed


def test_remove_file_from_background_review_always_proposed(tmp_path, hermes_home):
    """action='remove_file' from background review always routes to a
    proposal — the supporting file is never actually removed."""
    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: some-ops-skill\ndescription: An unlisted ops skill.\n---\n\nBenign content.\n",
        encoding="utf-8")
    ref_dir = skill_dir / "references"
    ref_dir.mkdir()
    (ref_dir / "notes.md").write_text("benign notes", encoding="utf-8")

    with _skill_dir(tmp_path), _as_background_review():
        raw = skill_manage(action="remove_file", name="some-ops-skill", file_path="references/notes.md")
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert "proposal" in result["message"].lower()
    assert (ref_dir / "notes.md").exists()  # never actually removed


# ---------------------------------------------------------------------------
# B7 (Ed, 2026-11-21): the real tool-execution path for a background review
# fork runs through TWO threading layers, both of which must carry the
# BACKGROUND_REVIEW write-origin contextvar correctly:
#   (1) agent.background_review's own review thread — a plain
#       threading.Thread wrapped with tools.thread_context's
#       propagate_context_to_thread (run_agent.py::_spawn_background_review_now).
#   (2) model_tools.py::_run_async's nested ThreadPoolExecutor branch, taken
#       whenever a tool handler needs to run sync-from-async while already
#       inside a running event loop (the gateway's normal situation) — also
#       wrapped with propagate_context_to_thread.
# This test drives BOTH real layers (not a reimplementation) and asserts the
# origin seen inside an actual skill_manage call made from the innermost
# worker thread.
# ---------------------------------------------------------------------------

def test_background_review_origin_reaches_skill_manage_through_real_thread_and_executor_layers(
        tmp_path, hermes_home):
    import asyncio
    import threading

    from model_tools import _run_async
    from tools.thread_context import propagate_context_to_thread

    skill_dir = tmp_path / "jnc-tax-engine-ops"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(PROTECTED_SKILL_CONTENT, encoding="utf-8")

    results = {}

    def _bg_review_thread_target():
        # Mirrors the real bind in agent/turn_context.py:
        #   set_current_write_origin(getattr(agent, "_memory_write_origin", ...))
        # where the review fork's agent has _memory_write_origin == "background_review"
        # (agent/background_review.py: review_agent._memory_write_origin = write_origin).
        token = set_current_write_origin(BACKGROUND_REVIEW)
        try:
            async def _inner_coro():
                with _skill_dir(tmp_path):
                    return skill_manage(
                        action="patch", name="jnc-tax-engine-ops",
                        old_string="Do not deviate from the sequence below without explicit re-authorization.",
                        new_string="Once authorized the exception stands for future reruns without asking again.",
                    )

            async def _outer():
                # Calling _run_async from within a running loop (this one)
                # forces its ThreadPoolExecutor branch — the second real
                # threading layer — rather than the synchronous fallback.
                return _run_async(_inner_coro())

            loop = asyncio.new_event_loop()
            try:
                results["raw"] = loop.run_until_complete(_outer())
            finally:
                loop.close()
        finally:
            reset_current_write_origin(token)

    t = threading.Thread(target=propagate_context_to_thread(_bg_review_thread_target))
    t.start()
    t.join(timeout=15)

    assert "raw" in results, "background-review worker thread did not complete"
    result = json.loads(results["raw"])
    assert result["success"] is True
    assert result.get("live_write") is False
    assert result.get("proposed") is True
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == PROTECTED_SKILL_CONTENT


# ---------------------------------------------------------------------------
# B8 (Ed, 2026-11-21): config.yaml's curator.protected_skills/keywords ADD
# to the code defaults, never replace them — a deployment's config lists
# only its own additions; the generic defaults (hermes-agent, etc.) must
# stay protected even if config.yaml never mentions them.
# ---------------------------------------------------------------------------

def test_config_protected_skills_adds_to_defaults_not_replaces(tmp_path, hermes_home, monkeypatch):
    """config.yaml lists ONLY 'jnc-tax-engine-ops' -> BOTH jnc-tax-engine-ops
    (from config) and hermes-agent (a code default) end up protected."""
    from tools import curator_protection as cp

    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"curator": {"protected_skills": ["jnc-tax-engine-ops"]}})

    protected = cp.protected_skills()
    assert "jnc-tax-engine-ops" in protected  # from config
    assert "hermes-agent" in protected        # code default, not dropped
    assert "enforced-gmail-send" in protected  # another code default, not dropped
    assert cp.is_protected_skill("jnc-tax-engine-ops")
    assert cp.is_protected_skill("hermes-agent")


# ---------------------------------------------------------------------------
# Claude review round 1 (Ed, 2026-11-22): config fails closed. A curator.<key>
# config that can't be loaded, or is present but not a list of strings, must
# not silently fall back to the code defaults -- classify_write() must return
# a reason so EVERY background-review write is proposed until the config is
# fixed. A valid config keeps today's behavior unchanged.
# ---------------------------------------------------------------------------

def test_malformed_config_fails_closed_and_proposes_every_background_write(
        tmp_path, hermes_home, monkeypatch):
    """curator.protected_skills present but not a list of strings -> classify_write()
    returns a 'protection config unreadable' reason, even for a write that would
    otherwise be entirely unremarkable (unlisted skill, no keyword, no weaken pattern)."""
    from tools import curator_protection as cp

    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"curator": {"protected_skills": "not-a-list"}})

    with pytest.raises(cp.ProtectionConfigError):
        cp.protected_skills()

    reason = cp.classify_write(
        "some-ops-skill", "patch", old_string="anything", new_string="anything else")
    assert reason is not None
    assert "protection config unreadable" in reason


def test_config_that_cannot_be_loaded_fails_closed(tmp_path, hermes_home, monkeypatch):
    """load_config_readonly() itself raising (not just a malformed value) is the same
    fail-closed case -- the old code's bare `except Exception: pass` treated this
    identically to 'nothing configured' and silently used only the code defaults."""
    from tools import curator_protection as cp

    def _boom():
        raise OSError("config.yaml: permission denied")

    monkeypatch.setattr("hermes_cli.config.load_config_readonly", _boom)

    reason = cp.classify_write(
        "some-ops-skill", "patch", old_string="anything", new_string="anything else")
    assert reason is not None
    assert "protection config unreadable" in reason


def test_malformed_config_routes_the_real_write_through_skill_manage_to_a_proposal(
        tmp_path, hermes_home, monkeypatch):
    """End to end through skill_manage(): a malformed config must not let an otherwise
    unremarkable background-review write land live."""
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"curator": {"protected_keywords": {"not": "a-list"}}})

    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(UNLISTED_SKILL_CONTENT, encoding="utf-8")

    from tools.skill_manager_guards import mark_background_review_skill_read

    with _skill_dir(tmp_path), _as_background_review():
        mark_background_review_skill_read(skill_dir / "SKILL.md")
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Only when Ed explicitly says go should you proceed.",
            new_string="Proceed whenever it looks ready.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert result.get("live_write") is False
    assert result.get("proposed") is True
    assert "protection config unreadable" in result["message"]
    # Live file WAS NOT updated.
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == UNLISTED_SKILL_CONTENT


def test_valid_config_keeps_todays_behavior(tmp_path, hermes_home, monkeypatch):
    """A well-formed config (the normal case) is unaffected by the fail-closed change:
    an unlisted skill with no keyword/weaken hit still applies live."""
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"curator": {"protected_skills": [], "protected_keywords": []}})

    skill_dir = tmp_path / "some-ops-skill"
    skill_dir.mkdir()
    plain_content = "---\nname: some-ops-skill\ndescription: Nothing special.\n---\n\nBody.\n"
    (skill_dir / "SKILL.md").write_text(plain_content, encoding="utf-8")

    from tools.skill_manager_guards import mark_background_review_skill_read

    with _skill_dir(tmp_path), _as_background_review():
        mark_background_review_skill_read(skill_dir / "SKILL.md")
        raw = skill_manage(
            action="patch", name="some-ops-skill",
            old_string="Body.", new_string="Updated body.",
        )
    result = json.loads(raw)
    assert result["success"] is True
    assert "proposed" not in result  # normal write-result shape, not the gate's shape
    assert (skill_dir / "SKILL.md").read_text(encoding="utf-8") == plain_content.replace(
        "Body.", "Updated body.")
