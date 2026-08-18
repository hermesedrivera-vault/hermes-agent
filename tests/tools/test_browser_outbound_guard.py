"""Tests for browser_send_message() -- Step 40 structured browser outbound
authorization (delegates to check_outbound_comm_guard(), Step 30/32/34/36).

These tests exercise the NEW capability only. They do not modify or
re-implement any authorization logic -- check_outbound_comm_guard() and
_run_approval_gate() remain untouched by Step 40 and are exercised here via
their existing, unmodified contract.
"""
import json
from unittest.mock import MagicMock

import pytest

import tools.approval as approval_module
from gateway.session_context import clear_session_vars, reset_session_vars, set_session_vars
from tools.browser_tool import browser_send_message


@pytest.fixture(autouse=True)
def _mode_manual(monkeypatch):
    monkeypatch.setattr(approval_module, "_get_approval_mode", lambda: "manual")


@pytest.fixture(autouse=True)
def _clear_approval_state():
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")
    approval_module.clear_session("test-session")
    reset_session_vars()
    yield
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")
    approval_module.clear_session("test-session")
    reset_session_vars()


def _approve_gate(*args, **kwargs):
    return {"approved": True, "message": None}


def _deny_gate(*args, **kwargs):
    return {"approved": False, "message": "BLOCKED: denied for test"}


# ---------------------------------------------------------------------------
# Structured channel/recipient reaches the existing override path
# ---------------------------------------------------------------------------

def test_structured_recipient_reaches_override_path(monkeypatch):
    """browser_send_message must call check_outbound_comm_guard with
    channel_recipient_override -- never with content-based detection alone."""
    recorded = {}

    def _fake_guard(tool_name, text_for_detection, channel_recipient_override=None):
        recorded["tool_name"] = tool_name
        recorded["text_for_detection"] = text_for_detection
        recorded["channel_recipient_override"] = channel_recipient_override
        return {"approved": True, "message": None}

    monkeypatch.setattr(approval_module, "check_outbound_comm_guard", _fake_guard)
    # browser_tool imports check_outbound_comm_guard locally inside the
    # function (from tools.approval import ...), so patch the source module.
    import tools.browser_tool as browser_tool_module

    result = browser_send_message(
        channel="gmail",
        recipient="alice@example.com",
        content="hello there",
        ref_sequence=[],
    )
    parsed = json.loads(result)
    assert parsed["success"] is True
    assert recorded["tool_name"] == "browser_send"
    assert recorded["channel_recipient_override"] == ("gmail", "alice@example.com")
    assert recorded["text_for_detection"] == "hello there"


# ---------------------------------------------------------------------------
# Missing/invalid recipient fails closed
# ---------------------------------------------------------------------------

def test_missing_recipient_fails_closed():
    result = browser_send_message(channel="gmail", recipient="", content="hi")
    parsed = json.loads(result)
    assert parsed.get("error") is not None
    assert "recipient" in parsed["error"].lower()


def test_missing_channel_fails_closed():
    result = browser_send_message(channel="", recipient="alice@example.com", content="hi")
    parsed = json.loads(result)
    assert parsed.get("error") is not None
    assert "channel" in parsed["error"].lower()


# ---------------------------------------------------------------------------
# Missing session identity fails closed (real check_outbound_comm_guard,
# not mocked -- proves end-to-end fail-closed behavior)
# ---------------------------------------------------------------------------

def test_missing_session_identity_fails_closed():
    reset_session_vars()
    result = browser_send_message(
        channel="gmail", recipient="alice@example.com", content="hi", ref_sequence=[]
    )
    parsed = json.loads(result)
    assert parsed.get("error") is not None
    assert "session identity" in parsed["error"].lower() or "blocked" in parsed["error"].lower()


# ---------------------------------------------------------------------------
# cron_mode=deny blocks the browser send
# ---------------------------------------------------------------------------

def test_cron_deny_blocks_browser_send(monkeypatch):
    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval_module, "_get_cron_approval_mode", lambda: "deny")
    monkeypatch.setattr(approval_module, "_get_outbound_comm_mode", lambda: "enforce")
    tokens = set_session_vars(session_key="test-session", cron_session="1")
    try:
        result = browser_send_message(
            channel="gmail",
            recipient="alice@example.com",
            content="hi",
            ref_sequence=[{"action": "click", "ref": "@e1"}],
        )
    finally:
        clear_session_vars(tokens)
    parsed = json.loads(result)
    assert parsed.get("error") is not None


# ---------------------------------------------------------------------------
# Pre-existing permanent grant for one recipient cannot authorize another
# ---------------------------------------------------------------------------

def test_permanent_grant_for_one_recipient_does_not_authorize_another(monkeypatch):
    granted_recipient = "preexisting-grant@external.com"
    granted_pattern_key = f"outbound_external_comm::gmail::{granted_recipient}"
    approval_module.approve_permanent(granted_pattern_key)

    monkeypatch.setattr(approval_module, "_get_outbound_comm_mode", lambda: "enforce")
    # No human present and no interactive/gateway context -> the real gate's
    # fail_closed_when_no_human path will block absent a matching grant.
    tokens = set_session_vars(session_key="test-session")
    try:
        result = browser_send_message(
            channel="gmail",
            recipient="someone-else@external.com",
            content="hi",
            ref_sequence=[{"action": "click", "ref": "@e1"}],
        )
    finally:
        clear_session_vars(tokens)
        approval_module._permanent_approved.discard(granted_pattern_key)
    parsed = json.loads(result)
    # Must NOT be silently approved via the other recipient's grant.
    assert parsed.get("error") is not None or parsed.get("success") is not True


# ---------------------------------------------------------------------------
# Authorization denial causes ZERO browser mutation calls
# ---------------------------------------------------------------------------

def test_denial_causes_zero_browser_mutation_calls(monkeypatch):
    monkeypatch.setattr(approval_module, "check_outbound_comm_guard", _deny_gate)
    import tools.browser_tool as browser_tool_module

    click_mock = MagicMock(return_value=json.dumps({"success": True}))
    type_mock = MagicMock(return_value=json.dumps({"success": True}))
    press_mock = MagicMock(return_value=json.dumps({"success": True}))
    monkeypatch.setattr(browser_tool_module, "browser_click", click_mock)
    monkeypatch.setattr(browser_tool_module, "browser_type", type_mock)
    monkeypatch.setattr(browser_tool_module, "browser_press", press_mock)

    result = browser_send_message(
        channel="gmail",
        recipient="alice@example.com",
        content="hi",
        ref_sequence=[
            {"action": "type", "ref": "@e1", "text": "alice@example.com"},
            {"action": "type", "ref": "@e2", "text": "hi"},
            {"action": "click", "ref": "@e3"},
        ],
    )
    parsed = json.loads(result)
    assert parsed.get("error") is not None
    click_mock.assert_not_called()
    type_mock.assert_not_called()
    press_mock.assert_not_called()


# ---------------------------------------------------------------------------
# Approved authorization permits the underlying send sequence
# ---------------------------------------------------------------------------

def test_approval_permits_underlying_send_sequence(monkeypatch):
    monkeypatch.setattr(approval_module, "check_outbound_comm_guard", _approve_gate)
    import tools.browser_tool as browser_tool_module

    click_mock = MagicMock(return_value=json.dumps({"success": True, "clicked": "@e3"}))
    type_mock = MagicMock(return_value=json.dumps({"success": True, "ref": "@e1"}))
    monkeypatch.setattr(browser_tool_module, "browser_click", click_mock)
    monkeypatch.setattr(browser_tool_module, "browser_type", type_mock)

    result = browser_send_message(
        channel="gmail",
        recipient="alice@example.com",
        content="hi",
        ref_sequence=[
            {"action": "type", "ref": "@e1", "text": "hi"},
            {"action": "click", "ref": "@e3"},
        ],
    )
    parsed = json.loads(result)
    assert parsed.get("success") is True
    assert type_mock.call_count == 1
    assert click_mock.call_count == 1
    assert len(parsed["executed"]) == 2


# ---------------------------------------------------------------------------
# Authorization is session-scoped / cannot create a permanent approval
# ---------------------------------------------------------------------------

def test_browser_send_cannot_create_permanent_grant(monkeypatch):
    """Assert the real check_outbound_comm_guard is invoked with
    allow_permanent=False via _run_approval_gate -- mirrors the existing
    test_outbound_comm_guard.py pattern, applied to the browser call site."""
    recorded_kwargs = {}

    def _fake_gate(**kwargs):
        recorded_kwargs.update(kwargs)
        return {"approved": True, "message": None}

    monkeypatch.setattr(approval_module, "_run_approval_gate", _fake_gate)
    monkeypatch.setattr(approval_module, "_get_outbound_comm_mode", lambda: "enforce")
    tokens = set_session_vars(session_key="test-session")
    try:
        browser_send_message(
            channel="gmail",
            recipient="alice@example.com",
            content="hi",
            ref_sequence=[],
        )
    finally:
        clear_session_vars(tokens)

    assert recorded_kwargs.get("allow_permanent") is False


# ---------------------------------------------------------------------------
# Unsupported ref_sequence action fails closed (defensive)
# ---------------------------------------------------------------------------

def test_unsupported_ref_sequence_action_rejected(monkeypatch):
    monkeypatch.setattr(approval_module, "check_outbound_comm_guard", _approve_gate)
    result = browser_send_message(
        channel="gmail",
        recipient="alice@example.com",
        content="hi",
        ref_sequence=[{"action": "hover", "ref": "@e1"}],
    )
    parsed = json.loads(result)
    assert parsed.get("error") is not None
    assert "unsupported" in parsed["error"].lower()
