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


def test_send_email_dispatches_only_through_the_registry():
    """CORRECTED 11/10/26: the original version of this test asserted
    send_email lived in agent/inline_tool_executors.py's
    _RAW_INLINE_TOOL_EXECUTORS table -- exactly the dual-registration bug
    that caused the 11/10 incident (a raw dict from send_email()'s blocked
    path landed straight in a tool-result message's "content" field,
    because the inline table bypasses ToolRegistry._normalize_handler_result
    entirely; OpenRouter then rejected the whole turn with HTTP 400
    'messages.N.content: Invalid input'). send_email is a pure function with
    no live-AIAgent-state dependency, so it must dispatch ONLY through the
    registry (see test_send_email_result_is_string.py for the real,
    end-to-end proof that registry.dispatch('send_email', ...) always
    returns a string)."""
    from agent.inline_tool_executors import _RAW_INLINE_TOOL_EXECUTORS

    assert "send_email" not in _RAW_INLINE_TOOL_EXECUTORS, (
        "send_email is back in the inline dispatch table -- this bypasses "
        "result-string normalization and reintroduces the 11/10 "
        "OpenRouter-400 incident."
    )

    from tools.registry import registry

    calls = []

    import tools.send_email_tool as se
    original = se.send_email

    def _spy(**kwargs):
        calls.append(kwargs)
        return {"outcome": "sent", "sent": True, "message_id": "<x@y>", "reasons": [], "detail": "sent"}

    se.send_email = _spy
    try:
        result = registry.dispatch(
            "send_email", {"to": "ken@jnccpas.com", "subject": "hi", "body_path": "/tmp/b.txt"},
        )
    finally:
        se.send_email = original

    assert isinstance(result, str), "registry.dispatch('send_email', ...) must always return a string"
    import json as _json
    parsed = _json.loads(result)
    assert parsed["outcome"] == "sent"
    assert len(calls) == 1
    assert calls[0]["to"] == "ken@jnccpas.com"
    assert calls[0]["from_account"] == "hermes"  # default applied


def test_email_toolset_includes_send_email():
    import toolsets

    assert "send_email" in toolsets.TOOLSETS["email"]["tools"]
    # Opt-in by design (Ed's review, 11/9/26): not silently added to every
    # session via the default core tool list.
    assert "send_email" not in toolsets._HERMES_CORE_TOOLS
