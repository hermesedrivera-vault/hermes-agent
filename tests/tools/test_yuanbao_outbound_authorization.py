"""Tests for Step 48: Yuanbao outbound authorization (yb_send_dm /
yb_send_sticker wired through the canonical check_outbound_comm_guard()).
No real Yuanbao adapter is used -- adapter and guard are mocked/stubbed.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools import approval
from tools.yuanbao_tools import send_dm, send_sticker


@pytest.fixture
def session_ctx():
    session_token = approval.set_current_session_key("test_session_step48")
    tokens = approval.set_current_authorization_scope(task_id="t1", subagent_id="")
    yield "test_session_step48"
    approval.reset_current_authorization_scope(tokens)
    approval.reset_current_session_key(session_token)


def _approve_gate(*args, **kwargs):
    return {"approved": True, "message": None}


def _deny_gate(*args, **kwargs):
    return {"approved": False, "message": "BLOCKED: denied for test"}


def _make_send_result(success=True, message_id="m1", error=None):
    r = MagicMock()
    r.success = success
    r.message_id = message_id
    r.error = error
    return r


def _make_adapter():
    adapter = MagicMock()
    adapter.send_dm = AsyncMock(return_value=_make_send_result())
    adapter.send_image_file = AsyncMock(return_value=_make_send_result())
    adapter.send_document = AsyncMock(return_value=_make_send_result())
    adapter.send_sticker = AsyncMock(return_value=_make_send_result())
    adapter.get_group_member_list = AsyncMock(return_value={"members": []})
    return adapter


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# 1 & 4. First-time recipient -> blocked pending authorization
# ---------------------------------------------------------------------------

def test_send_dm_first_time_recipient_blocked(session_ctx):
    adapter = _make_adapter()
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_deny_gate) as mock_guard:
        result = run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))
    assert result["success"] is False
    assert "error" in result
    mock_guard.assert_called_once()
    adapter.send_dm.assert_not_called()


def test_send_sticker_first_time_recipient_blocked(session_ctx):
    adapter = _make_adapter()
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_deny_gate) as mock_guard:
        result = run(send_sticker(sticker="", chat_id="direct:u123"))
    assert result["success"] is False
    assert "error" in result
    mock_guard.assert_called_once()
    adapter.send_sticker.assert_not_called()


# ---------------------------------------------------------------------------
# 2 & 5. Previously-approved exact recipient -> proceeds
# ---------------------------------------------------------------------------

def test_send_dm_approved_recipient_proceeds(session_ctx):
    adapter = _make_adapter()
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))
    assert result["success"] is True
    adapter.send_dm.assert_called_once()
    # Recipient binding: resolved_user_id, not name/group_code
    _, kwargs = mock_guard.call_args
    assert kwargs["channel_recipient_override"] == ("yuanbao", "u123")


def test_send_sticker_approved_recipient_proceeds(session_ctx):
    adapter = _make_adapter()
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = run(send_sticker(sticker="", chat_id="direct:u123"))
    assert result["success"] is True
    adapter.send_sticker.assert_called_once()
    _, kwargs = mock_guard.call_args
    assert kwargs["channel_recipient_override"] == ("yuanbao", "direct:u123")


# ---------------------------------------------------------------------------
# 3. Different recipient does not inherit another recipient's approval
# ---------------------------------------------------------------------------

def test_send_dm_recipient_exact_binding_no_cross_reuse(session_ctx):
    adapter = _make_adapter()

    def _guard(tool_name, content, channel_recipient_override=None):
        channel, recipient = channel_recipient_override
        if recipient == "u123":
            return {"approved": True, "message": None}
        return {"approved": False, "message": "BLOCKED: different recipient"}

    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_guard):
        approved = run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))
        denied = run(send_dm(group_code="g1", name="", message="hi", user_id="u999"))

    assert approved["success"] is True
    assert denied["success"] is False
    assert adapter.send_dm.call_count == 1


# ---------------------------------------------------------------------------
# 6. cron_mode=deny blocks both sends
# ---------------------------------------------------------------------------

def test_cron_mode_deny_blocks_dm_and_sticker(session_ctx):
    adapter = _make_adapter()

    def _cron_deny_gate(*args, **kwargs):
        return {"approved": False, "message": "BLOCKED: cron_mode=deny"}

    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_cron_deny_gate):
        dm_result = run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))
        sticker_result = run(send_sticker(sticker="", chat_id="direct:u123"))

    assert dm_result["success"] is False
    assert sticker_result["success"] is False
    adapter.send_dm.assert_not_called()
    adapter.send_sticker.assert_not_called()


# ---------------------------------------------------------------------------
# 7. allow_permanent=False remains enforced (inherited from the canonical
#    guard -- Yuanbao introduces no override / new path to this behavior).
# ---------------------------------------------------------------------------

def test_no_permanent_approval_override_introduced(session_ctx):
    """Yuanbao call sites must not pass allow_permanent or any kwarg that
    could relax the canonical guard's hardcoded allow_permanent=False."""
    adapter = _make_adapter()
    captured = {}

    def _capture_gate(tool_name, content, channel_recipient_override=None, **kwargs):
        captured["kwargs"] = kwargs
        return {"approved": True, "message": None}

    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_capture_gate):
        run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))

    assert "allow_permanent" not in captured["kwargs"]


# ---------------------------------------------------------------------------
# 8. Missing authorization/session identity fails closed
# ---------------------------------------------------------------------------

def test_missing_session_identity_fails_closed():
    # No session_ctx fixture -- exercises the real check_outbound_comm_guard
    # default-identity fail-closed path (no mocking of the guard itself).
    tokens = approval.set_current_authorization_scope(task_id="", subagent_id="")
    adapter = _make_adapter()
    try:
        with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter):
            result = run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))
        assert result["success"] is False
        assert "error" in result
        adapter.send_dm.assert_not_called()
    finally:
        approval.reset_current_authorization_scope(tokens)


# ---------------------------------------------------------------------------
# 9. Authorization exception fails closed; adapter is NOT called
# ---------------------------------------------------------------------------

def test_send_dm_guard_exception_fails_closed(session_ctx):
    adapter = _make_adapter()
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=RuntimeError("boom")):
        result = run(send_dm(group_code="g1", name="", message="hi", user_id="u123"))
    assert result["success"] is False
    assert "error" in result
    adapter.send_dm.assert_not_called()


def test_send_sticker_guard_exception_fails_closed(session_ctx):
    adapter = _make_adapter()
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=RuntimeError("boom")):
        result = run(send_sticker(sticker="", chat_id="direct:u123"))
    assert result["success"] is False
    assert "error" in result
    adapter.send_sticker.assert_not_called()


# ---------------------------------------------------------------------------
# Recipient-binding regression: raw nickname/name/group_code must NOT be
# used as the authorization recipient once user_id is resolved.
# ---------------------------------------------------------------------------

def test_send_dm_binds_to_resolved_user_id_not_name_or_group(session_ctx):
    adapter = _make_adapter()
    adapter.get_group_member_list = AsyncMock(
        return_value={"members": [{"user_id": "resolved_456", "nickname": "Bob"}]}
    )
    with patch("tools.yuanbao_tools._get_active_adapter", return_value=adapter), \
         patch("tools.approval.check_outbound_comm_guard", side_effect=_approve_gate) as mock_guard:
        result = run(send_dm(group_code="g1", name="Bob", message="hi", user_id=""))
    assert result["success"] is True
    _, kwargs = mock_guard.call_args
    assert kwargs["channel_recipient_override"] == ("yuanbao", "resolved_456")
