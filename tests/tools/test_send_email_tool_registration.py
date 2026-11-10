"""Fix 3 (Ed's review, 11/9/26): send_email() was built but never registered
as a callable tool -- a deploy with no registration leaves no way to send.
These tests verify the registration surface itself, not send behavior
(that's test_send_email_tool.py)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root

from tools.send_email_tool import SEND_EMAIL_SCHEMA, check_send_email_requirements, send_email


def test_schema_name_and_required_fields():
    assert SEND_EMAIL_SCHEMA["name"] == "send_email"
    props = SEND_EMAIL_SCHEMA["parameters"]["properties"]
    for field in ("to", "subject", "body_path", "cc", "bcc", "attachments", "from_account"):
        assert field in props, f"schema is missing model-facing field {field!r}"
    assert set(SEND_EMAIL_SCHEMA["parameters"]["required"]) == {"to", "subject", "body_path"}


def test_schema_never_exposes_internal_test_seams():
    """approval_gate/log_path/enforced_module/attachment_text_extractor/etc.
    are production-default-only -- the model must never be able to set
    them (that would let a call route around the approval gate or the
    send log entirely)."""
    props = SEND_EMAIL_SCHEMA["parameters"]["properties"]
    for leaked in ("approval_gate", "log_path", "approved_list_path", "enforced_module",
                   "gmail_client", "attachment_text_extractor"):
        assert leaked not in props, f"{leaked!r} must never be a model-settable field"


def test_requirements_gate_is_callable_and_boolean(tmp_path, monkeypatch):
    """Exercises the gate against tmp_path stand-ins, never the real home
    (tests/home_io_guard.py forbids real-home I/O in tests)."""
    import tools.send_email_tool as se

    approved = tmp_path / "approved.json"
    approved.write_text("{}")
    script = tmp_path / "enforced_gmail_send.py"
    script.write_text("# stand-in\n")
    monkeypatch.setattr(se, "DEFAULT_APPROVED_LIST_PATH", str(approved))
    monkeypatch.setattr(se, "CANONICAL_ENFORCED_GMAIL_PATH", str(script))
    assert check_send_email_requirements() is True

    monkeypatch.setattr(se, "DEFAULT_APPROVED_LIST_PATH", str(tmp_path / "missing.json"))
    assert check_send_email_requirements() is False


def test_dispatch_table_registers_send_email():
    """The in-process gateway dispatch table (agent/inline_tool_executors.py)
    must resolve 'send_email' to tools.send_email_tool.send_email with the
    right model-facing args mapped -- this is what makes the tool actually
    callable, not just documented."""
    from agent.inline_tool_executors import _RAW_INLINE_TOOL_EXECUTORS

    assert "send_email" in _RAW_INLINE_TOOL_EXECUTORS
    executor = _RAW_INLINE_TOOL_EXECUTORS["send_email"]

    calls = []

    class _Ctx:
        tool_call_id = "t1"

    import tools.send_email_tool as se
    original = se.send_email

    def _spy(**kwargs):
        calls.append(kwargs)
        return {"outcome": "sent", "sent": True, "message_id": "<x@y>", "reasons": [], "detail": "sent"}

    se.send_email = _spy
    try:
        result = executor(None, {"to": "ken@jnccpas.com", "subject": "hi", "body_path": "/tmp/b.txt"}, _Ctx())
    finally:
        se.send_email = original

    assert result["outcome"] == "sent"
    assert len(calls) == 1
    assert calls[0]["to"] == "ken@jnccpas.com"
    assert calls[0]["from_account"] == "hermes"  # default applied


def test_email_toolset_includes_send_email():
    import toolsets

    assert "send_email" in toolsets.TOOLSETS["email"]["tools"]
    # Opt-in by design (Ed's review, 11/9/26): not silently added to every
    # session via the default core tool list.
    assert "send_email" not in toolsets._HERMES_CORE_TOOLS
