"""Regression tests for the skill write-origin leak fixed in agent/turn_context.py.

``build_turn_context()`` must pair every ``set_current_write_origin()`` call with exactly one
``release_turn_write_origin()`` from the turn's owner (``agent.conversation_loop.run_conversation``),
so a nested inline turn (compression fork, background review, curator) never leaves its origin
bleeding into whatever code runs after it in the same thread -- regardless of whether that nested
turn finishes cleanly or raises.

These deliberately exercise the REAL ``tools.skill_provenance`` ContextVar (not a stub), because
the bug this guards against is exactly "a stub in the test harness hides what the real code does."
Never replace this with a test-only autouse fixture that resets the origin on every test boundary:
that would hide a future regression of this exact leak instead of catching it.
"""

from __future__ import annotations

import json
import types
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from agent.turn_context import build_turn_context, release_turn_write_origin
from tools.skill_manager_tool import skill_manage
from tools.skill_provenance import get_current_write_origin, set_current_write_origin

from tests.agent.test_turn_context import _FakeAgent

PROTECTED_SKILL_CONTENT = """\
---
name: jnc-tax-engine-ops
description: jnc-tax-ai-agent PRs, IRS PDFs, deploys.
---

Do not deviate from the sequence below without explicit re-authorization.
"""


@contextmanager
def _skill_dir(tmp_path):
    """Patch both SKILLS_DIR and get_all_skills_dirs so _find_skill searches only the temp
    directory -- not the real ~/.hermes/skills/ (mirrors tests/tools/test_curator_protection.py)."""
    with patch("tools.skill_manager_tool.SKILLS_DIR", tmp_path), \
         patch("agent.skill_utils.get_all_skills_dirs", return_value=[tmp_path]):
        yield


def _run_turn_real_origin(agent, **overrides):
    """Like tests/agent/test_turn_context.py's ``_build()``, but wires the REAL
    ``set_current_write_origin`` so ``build_turn_context()`` actually stashes a live token.
    The lightweight fixture in test_turn_context.py stubs that callback out as a no-op, which
    is correct for its own (unrelated) assertions but would hide this leak entirely."""
    kwargs = dict(
        agent=agent, user_message="hello", system_message=None, conversation_history=None,
        task_id=None, stream_callback=None, persist_user_message=None,
        restore_or_build_system_prompt=lambda *a, **k: None,
        install_safe_stdio=lambda: None, sanitize_surrogates=lambda s: s,
        summarize_user_message_for_log=lambda s: s,
        set_session_context=lambda _sid: None,
        set_current_write_origin=set_current_write_origin,
        ra=lambda: types.SimpleNamespace(_set_interrupt=lambda *a, **k: None),
    )
    kwargs.update(overrides)
    return build_turn_context(**kwargs)


def test_nested_inline_turn_restores_callers_origin_and_foreground_write_applies_live(tmp_path):
    """A foreground turn that runs a background_review turn inline (same thread) still sees its
    own origin afterward, and a foreground skill_manage write after that applies live."""
    outer = _FakeAgent()
    outer._memory_write_origin = "foreground"
    _run_turn_real_origin(outer)
    assert get_current_write_origin() == "foreground"

    inner = _FakeAgent()
    inner._memory_write_origin = "background_review"
    _run_turn_real_origin(inner)
    assert get_current_write_origin() == "background_review"
    # The nested turn ends cleanly -- its own owner releases its own origin.
    release_turn_write_origin(inner)

    # The outer turn's origin must come back exactly as it was, unchanged by the nested turn.
    assert get_current_write_origin() == "foreground"

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
    assert "proposed" not in result  # foreground write applied live, not gated as a curator write

    release_turn_write_origin(outer)
    assert get_current_write_origin() == "foreground"  # ContextVar default, nothing left dangling


def test_release_turn_write_origin_never_raises_on_a_reused_token(caplog):
    """reset_current_write_origin() can raise (token already used, or used outside the
    Context it was created in) -- release_turn_write_origin() must swallow that and log a
    warning rather than raising, so a failed reset never fails the turn or masks whatever
    real exception the turn's own try block is already propagating."""
    agent = _FakeAgent()
    agent._memory_write_origin = "foreground"
    _run_turn_real_origin(agent)
    assert get_current_write_origin() == "foreground"

    # First release is the normal, successful path.
    release_turn_write_origin(agent)
    assert get_current_write_origin() == "foreground"

    # Simulate a second, stale token still sitting on `agent` (e.g. a bug elsewhere leaves
    # the attribute set after it was already consumed) -- reset() on an already-used token
    # raises RuntimeError. This must not propagate.
    agent._memory_write_origin = "background_review"
    _run_turn_real_origin(agent)
    stale_token = agent._pending_write_origin_token
    release_turn_write_origin(agent)  # consumes it normally
    agent._pending_write_origin_token = stale_token  # put the now-used token back

    caplog.clear()
    with caplog.at_level("WARNING"):
        release_turn_write_origin(agent)  # must not raise
    assert any("reset_current_write_origin failed" in r.message for r in caplog.records)
    assert agent._pending_write_origin_token is None


def test_real_run_conversation_restores_callers_origin_when_the_turn_raises(monkeypatch):
    """Goes through the REAL agent.conversation_loop.run_conversation() (not a copy of its
    finally logic) with a turn body that raises, and asserts the caller's prior origin is
    restored. Only ``_run_conversation_turn`` (the inner turn body) is stubbed, to a function
    that reproduces the real build_turn_context()'s prologue side effect -- binding the
    origin and stashing its token on `agent` -- before raising, mirroring a turn that fails
    after build_turn_context() already ran (e.g. a PreflightCompressionTimedOut deeper in
    the turn, or any other exception mid-turn)."""
    from agent import conversation_loop as cl

    outer = _FakeAgent()
    outer._memory_write_origin = "foreground"
    _run_turn_real_origin(outer)
    assert get_current_write_origin() == "foreground"

    inner = _FakeAgent()
    inner._memory_write_origin = "background_review"

    def _boom_turn(agent, *_a, **_kw):
        agent._pending_write_origin_token = set_current_write_origin(agent._memory_write_origin)
        assert get_current_write_origin() == "background_review"
        raise RuntimeError("nested turn blew up mid-tool-call")

    monkeypatch.setattr(cl, "_run_conversation_turn", _boom_turn)

    with pytest.raises(RuntimeError, match="blew up"):
        cl.run_conversation(inner, "hello")

    # run_conversation()'s own finally released inner's origin even though the turn body
    # raised -- the outer (still mid-turn) origin comes back unchanged.
    assert get_current_write_origin() == "foreground"

    release_turn_write_origin(outer)
    assert get_current_write_origin() == "foreground"


def test_nested_inline_turn_that_raises_still_restores_callers_origin():
    """Same scenario, but the nested turn raises -- the caller's origin must still come back,
    mirroring agent.conversation_loop.run_conversation's finally (always releases, error or not)."""
    outer = _FakeAgent()
    outer._memory_write_origin = "foreground"
    _run_turn_real_origin(outer)
    assert get_current_write_origin() == "foreground"

    inner = _FakeAgent()
    inner._memory_write_origin = "background_review"
    _run_turn_real_origin(inner)
    assert get_current_write_origin() == "background_review"

    def _nested_turn_that_raises():
        try:
            raise RuntimeError("nested turn blew up mid-tool-call")
        finally:
            release_turn_write_origin(inner)

    with pytest.raises(RuntimeError, match="blew up"):
        _nested_turn_that_raises()

    assert get_current_write_origin() == "foreground"
    release_turn_write_origin(outer)
    assert get_current_write_origin() == "foreground"
