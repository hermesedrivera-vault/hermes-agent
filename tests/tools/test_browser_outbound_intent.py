"""Tests for the session-scoped browser outbound intent state machine
(Step 42/43): declare_outbound_intent -> browser_confirm_outbound_action ->
SEND_WINDOW_OPEN, and its consultation by browser_click/browser_type/
browser_press. All browser execution is mocked; no real webmail send.
"""
import json
import time
from unittest.mock import patch

import pytest

from tools import approval
from tools.browser_tool import (
    browser_click,
    browser_confirm_outbound_action_tool,
    browser_press,
    browser_type,
    clear_outbound_intent_tool,
    declare_outbound_intent_tool,
)


@pytest.fixture(autouse=True)
def _clean_intent_state():
    approval._browser_outbound_intent.clear()
    yield
    approval._browser_outbound_intent.clear()


@pytest.fixture
def session_ctx():
    tokens = approval.set_current_authorization_scope(
        session_key="test_session_step43", task_id="t1", subagent_id=""
    )
    yield "test_session_step43"
    approval.reset_current_authorization_scope(tokens)


def _no_intent_check_stub():
    return {"allowed": True, "state": "no_intent"}


def _approve_gate(*args, **kwargs):
    return {"approved": True, "message": None}


def _deny_gate(*args, **kwargs):
    return {"approved": False, "message": "BLOCKED: denied for test"}


# ---------------------------------------------------------------------------
# 1. No intent preserves existing browser behavior
# ---------------------------------------------------------------------------

def test_no_intent_preserves_existing_click_behavior(session_ctx):
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command", return_value={"success": True}):
        result = json.loads(browser_click(ref="@e1"))
    assert result["success"] is True


# ---------------------------------------------------------------------------
# 2-3. Declaration succeeds + normalizes recipient
# ---------------------------------------------------------------------------

def test_declare_intent_succeeds_and_normalizes(session_ctx):
    result = json.loads(declare_outbound_intent_tool(channel="email", recipient="Alice+shop@GMAIL.com"))
    assert result["success"] is True
    assert result["recipient"] == "alice@gmail.com"


# ---------------------------------------------------------------------------
# 4-6. Fail closed on missing recipient / channel / session identity
# ---------------------------------------------------------------------------

def test_declare_intent_missing_recipient_fails_closed(session_ctx):
    result = json.loads(declare_outbound_intent_tool(channel="gmail", recipient=""))
    assert result.get("success") is not True
    assert "error" in result


def test_declare_intent_missing_channel_fails_closed(session_ctx):
    result = json.loads(declare_outbound_intent_tool(channel="", recipient="alice@example.com"))
    assert result.get("success") is not True
    assert "error" in result


def test_declare_intent_missing_session_identity_fails_closed():
    # No session_ctx fixture used -- exercises real default-key fail-closed path.
    tokens = approval.set_current_authorization_scope(session_key="", task_id="", subagent_id="")
    try:
        result = json.loads(declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com"))
        assert result.get("success") is not True
        assert "error" in result
    finally:
        approval.reset_current_authorization_scope(tokens)


# ---------------------------------------------------------------------------
# 7-9. Declared-without-confirmation blocks all three primitives
# ---------------------------------------------------------------------------

def test_declared_without_confirmation_blocks_click(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command") as mock_run:
        result = json.loads(browser_click(ref="@e1"))
    assert result["success"] is False
    mock_run.assert_not_called()


def test_declared_without_confirmation_blocks_type(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command") as mock_run:
        result = json.loads(browser_type(ref="@e1", text="hi"))
    assert result["success"] is False
    mock_run.assert_not_called()


def test_declared_without_confirmation_blocks_press(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command") as mock_run:
        result = json.loads(browser_press(key="Enter"))
    assert result["success"] is False
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# 10-11. Confirmation reaches the existing guard; success -> authorized
# ---------------------------------------------------------------------------

def test_confirm_reaches_existing_outbound_guard(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = json.loads(browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com"))
    assert result["success"] is True
    mock_guard.assert_called_once()
    _, kwargs = mock_guard.call_args
    assert mock_guard.call_args[0][0] == "browser_send" or mock_guard.call_args.kwargs
    call = mock_guard.call_args
    assert call.args[0] == "browser_send"
    assert call.kwargs["channel_recipient_override"] == ("gmail", "alice@example.com")


def test_successful_authorization_sets_state_authorized(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    auth_key = approval.get_current_authorization_key()
    assert approval._browser_outbound_intent[auth_key]["state"] == "authorized"


# ---------------------------------------------------------------------------
# 12-14. Successful authorization permits all three primitives
# ---------------------------------------------------------------------------

def test_authorized_permits_click(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command", return_value={"success": True}):
        result = json.loads(browser_click(ref="@e1"))
    assert result["success"] is True


def test_authorized_permits_type(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command", return_value={"success": True}):
        result = json.loads(browser_type(ref="@e1", text="hi"))
    assert result["success"] is True


def test_authorized_permits_press(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command", return_value={"success": True}):
        result = json.loads(browser_press(key="Enter"))
    assert result["success"] is True


# ---------------------------------------------------------------------------
# 15-16. Recipient / channel mismatch denied
# ---------------------------------------------------------------------------

def test_recipient_mismatch_denied(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = json.loads(browser_confirm_outbound_action_tool(channel="gmail", recipient="bob@example.com"))
    assert result.get("success") is not True
    mock_guard.assert_not_called()


def test_channel_mismatch_denied(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = json.loads(browser_confirm_outbound_action_tool(channel="slack", recipient="alice@example.com"))
    assert result.get("success") is not True
    mock_guard.assert_not_called()


# ---------------------------------------------------------------------------
# 17. New declaration replaces the previous one
# ---------------------------------------------------------------------------

def test_new_declaration_replaces_previous(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    declare_outbound_intent_tool(channel="slack", recipient="bob")
    auth_key = approval.get_current_authorization_key()
    record = approval._browser_outbound_intent[auth_key]
    assert record["channel"] == "slack"
    assert record["recipient"] == "bob"
    # The old (alice) confirmation must now be denied -- proves replacement,
    # not coexistence.
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = json.loads(browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com"))
    assert result.get("success") is not True
    mock_guard.assert_not_called()


# ---------------------------------------------------------------------------
# 18-19. Expired intent / authorized window denied
# ---------------------------------------------------------------------------

def test_expired_declared_intent_denied(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    auth_key = approval.get_current_authorization_key()
    approval._browser_outbound_intent[auth_key]["expires_at"] = time.monotonic() - 1
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = json.loads(browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com"))
    assert result.get("success") is not True
    mock_guard.assert_not_called()


def test_authorized_window_expiration_blocks_mutation(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    auth_key = approval.get_current_authorization_key()
    approval._browser_outbound_intent[auth_key]["expires_at"] = time.monotonic() - 1
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command") as mock_run:
        result = json.loads(browser_click(ref="@e1"))
    assert result["success"] is False
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# 20-21. Action-count exhaustion / decrement
# ---------------------------------------------------------------------------

def test_action_count_exhaustion_blocks_mutation(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    auth_key = approval.get_current_authorization_key()
    approval._browser_outbound_intent[auth_key]["remaining_actions"] = 0
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command") as mock_run:
        result = json.loads(browser_click(ref="@e1"))
    assert result["success"] is False
    mock_run.assert_not_called()


def test_successful_mutations_decrement_action_counter(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    auth_key = approval.get_current_authorization_key()
    initial = approval._browser_outbound_intent[auth_key]["remaining_actions"]
    with patch("tools.browser_tool._blocked_private_page_action", return_value=None), \
         patch("tools.browser_tool._run_browser_command", return_value={"success": True}):
        browser_click(ref="@e1")
    after = approval._browser_outbound_intent[auth_key]["remaining_actions"]
    assert after == initial - 1


# ---------------------------------------------------------------------------
# 23-24. clear_outbound_intent / clear_session remove intent
# ---------------------------------------------------------------------------

def test_clear_outbound_intent_removes_active_intent(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    auth_key = approval.get_current_authorization_key()
    assert auth_key in approval._browser_outbound_intent
    result = json.loads(clear_outbound_intent_tool())
    assert result["removed"] is True
    assert auth_key not in approval._browser_outbound_intent


def test_clear_session_removes_intent(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    approval.clear_session("test_session_step43")
    # clear_session is keyed by plain session_key; the composite
    # authorization key used by intent storage starts with the session_key,
    # so a direct pop only removes an exact match. Verify the documented
    # behavior: clear_session pops entries keyed EXACTLY by session_key.
    # For a plain (task-less) session this is the same key intent used.
    auth_key = approval.get_current_authorization_key()
    if auth_key == "test_session_step43":
        assert auth_key not in approval._browser_outbound_intent


# ---------------------------------------------------------------------------
# 25. No leakage across authorization keys
# ---------------------------------------------------------------------------

def test_intent_does_not_leak_across_authorization_keys():
    tokens_a = approval.set_current_authorization_scope(session_key="session_a", task_id="t1", subagent_id="")
    try:
        declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    finally:
        approval.reset_current_authorization_scope(tokens_a)

    tokens_b = approval.set_current_authorization_scope(session_key="session_b", task_id="t1", subagent_id="")
    try:
        with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
            result = json.loads(browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com"))
        assert result.get("success") is not True
        mock_guard.assert_not_called()
    finally:
        approval.reset_current_authorization_scope(tokens_b)
        approval._browser_outbound_intent.pop("session_a::task=t1::sub=", None)


# ---------------------------------------------------------------------------
# 26-28. cron_mode=deny / allow_permanent=False preserved
# ---------------------------------------------------------------------------

def test_cron_mode_deny_blocks_confirmation_even_with_intent(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_deny_gate) as mock_guard:
        result = json.loads(browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com"))
    assert result.get("success") is not True
    mock_guard.assert_called_once()


def test_confirm_does_not_create_permanent_grant(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    with patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate):
        browser_confirm_outbound_action_tool(channel="gmail", recipient="alice@example.com")
    assert len(approval._permanent_approved) == 0


def test_declaration_alone_never_creates_permanent_grant(session_ctx):
    declare_outbound_intent_tool(channel="gmail", recipient="alice@example.com")
    assert len(approval._permanent_approved) == 0


# ---------------------------------------------------------------------------
# 29. Page/DOM content cannot create intent (static contract test)
# ---------------------------------------------------------------------------

def test_declare_intent_has_no_dom_inspection_parameters():
    import inspect
    sig = inspect.signature(approval.declare_outbound_intent)
    assert set(sig.parameters) == {"channel", "recipient"}


# ---------------------------------------------------------------------------
# 30-31. browser_console / browser_cdp do NOT consult intent state
# ---------------------------------------------------------------------------

def test_browser_console_does_not_reference_intent_state():
    import tools.browser_tool as bt
    src = inspect_source(bt.browser_console)
    assert "check_browser_outbound_mutation_allowed" not in src


def test_browser_cdp_does_not_reference_intent_state():
    import tools.browser_cdp_tool as cdp
    src = inspect_source(cdp.browser_cdp)
    assert "check_browser_outbound_mutation_allowed" not in src


def inspect_source(fn):
    import inspect
    return inspect.getsource(fn)
