"""Tests for check_cron_deliver_change_guard (2026-09-06): authorization
gate for a cron job's delivery-target changing to a new external recipient.

Threat model: cron_mode:deny must NOT block ordinary scheduled reports to
an already-configured target (local/origin/all/bot-chat), only a job's
deliver target being redirected to a NEW explicit platform:chat_id the
model was not separately authorized to reach for that job.
"""
import pytest

import tools.approval as approval
from tools.approval import check_cron_deliver_change_guard


@pytest.fixture
def session_ctx():
    session_token = approval.set_current_session_key("test_session_cron_deliver")
    tokens = approval.set_current_authorization_scope(task_id="t1", subagent_id="")
    yield "test_session_cron_deliver"
    approval.reset_current_authorization_scope(tokens)
    approval.reset_current_session_key(session_token)


# ---------------------------------------------------------------------------
# Safe targets never gated, regardless of session/cron context
# ---------------------------------------------------------------------------

def test_local_deliver_never_gated():
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver=None, new_deliver="local", is_create=True
    )
    assert result["approved"] is True


def test_origin_deliver_never_gated():
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver=None, new_deliver="origin", is_create=True
    )
    assert result["approved"] is True


def test_all_deliver_never_gated():
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver=None, new_deliver="all", is_create=True
    )
    assert result["approved"] is True


def test_bot_chat_deliver_never_gated():
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver=None, new_deliver="bot-chat:myprofile", is_create=True
    )
    assert result["approved"] is True


def test_none_new_deliver_never_gated():
    """update() calls with deliver=None (field not being touched) must
    never gate -- None means 'no change requested', not 'clear it'."""
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver="telegram:123", new_deliver=None, is_create=False
    )
    assert result["approved"] is True


# ---------------------------------------------------------------------------
# Explicit external targets ARE gated
# ---------------------------------------------------------------------------

def test_create_with_explicit_platform_target_gated_no_session():
    """No session identity/interactive context -> fails closed."""
    result = check_cron_deliver_change_guard(
        job_id=None, old_deliver=None, new_deliver="telegram:12345", is_create=True
    )
    assert result["approved"] is False


def test_create_with_explicit_platform_target_approved_with_callback(monkeypatch, session_ctx):
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    monkeypatch.setattr(
        approval, "_resolve_cli_approval_callback",
        lambda cb=None: (lambda *a, **k: "once"),
    )
    result = check_cron_deliver_change_guard(
        job_id=None, old_deliver=None, new_deliver="telegram:12345", is_create=True
    )
    assert result["approved"] is True


# ---------------------------------------------------------------------------
# Update drift detection: only NEW targets are gated
# ---------------------------------------------------------------------------

def test_update_to_same_target_not_gated(session_ctx):
    """Re-saving the identical deliver value introduces no new recipient --
    must not require a fresh approval every time."""
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver="telegram:12345", new_deliver="telegram:12345",
        is_create=False,
    )
    assert result["approved"] is True


def test_update_adding_new_target_gated_no_session():
    """Old target unchanged, but a NEW platform:chat_id is being added --
    that new recipient must be gated even though part of the deliver
    string was already approved."""
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver="telegram:12345",
        new_deliver="telegram:12345,discord:999", is_create=False,
    )
    assert result["approved"] is False


def test_update_reordering_same_targets_not_gated(session_ctx):
    """Token-set comparison, not string comparison -- reordering 'origin,all'
    to 'all,origin' must not look like drift."""
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver="origin,all", new_deliver="all,origin",
        is_create=False,
    )
    assert result["approved"] is True


def test_update_removing_target_not_gated(session_ctx):
    """Narrowing delivery (removing a target) introduces no NEW recipient --
    must not be gated (only additions are gated)."""
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver="telegram:12345,discord:999",
        new_deliver="telegram:12345", is_create=False,
    )
    assert result["approved"] is True


def test_create_always_gates_explicit_target_even_if_job_id_none():
    """is_create=True with job_id=None (job doesn't exist yet) must still
    gate an explicit target -- there is no 'old' value to diff against."""
    result = check_cron_deliver_change_guard(
        job_id=None, old_deliver=None, new_deliver="signal:+15551234567",
        is_create=True,
    )
    assert result["approved"] is False


# ---------------------------------------------------------------------------
# cron_mode:deny must not block SAFE targets (the actual regression this
# guard exists to avoid -- gating every delivery would break cron_mode:deny
# users' existing scheduled reports)
# ---------------------------------------------------------------------------

def test_cron_context_deny_mode_does_not_block_safe_targets(monkeypatch):
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval, "_get_cron_approval_mode", lambda: "deny")
    for safe_target in ("local", "origin", "all", "bot-chat:x"):
        result = check_cron_deliver_change_guard(
            job_id="j1", old_deliver=None, new_deliver=safe_target, is_create=True
        )
        assert result["approved"] is True, f"{safe_target} should never be gated"


def test_cron_context_deny_mode_blocks_new_explicit_target(monkeypatch):
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval, "_get_cron_approval_mode", lambda: "deny")
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver=None, new_deliver="telegram:99999", is_create=True
    )
    assert result["approved"] is False
    assert "cron" in result["message"].lower()


# ---------------------------------------------------------------------------
# Fail-closed on internal error
# ---------------------------------------------------------------------------

def test_internal_exception_fails_closed(monkeypatch):
    monkeypatch.setattr(
        approval, "_cron_deliver_target_set",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = check_cron_deliver_change_guard(
        job_id="j1", old_deliver=None, new_deliver="telegram:1", is_create=True
    )
    assert result["approved"] is False
    assert "internal error" in result["message"].lower()
