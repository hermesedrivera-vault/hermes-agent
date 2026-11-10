"""2026-11-10 incident: send_email was dual-registered -- once correctly via
registry.register() (tools/send_email_tool.py, toolset="email"), and ALSO as
an entry in agent/inline_tool_executors.py's INLINE_TOOL_EXECUTORS table.
The inline table bypasses ToolRegistry.dispatch()'s _normalize_handler_result,
which is the ONLY thing that guarantees a tool result is a string (or the
multimodal envelope) before it is ever written into a tool-result message's
"content" field. send_email()'s handler returns a raw Python dict on every
blocked/denied path (e.g. {"error": "Body path rejected: ...", "sent": False,
"blocked": True}); routed through the inline table, that raw dict landed in
message["content"] untouched -- and OpenRouter's API rejected the entire
turn with "messages.N.content: Invalid input" (HTTP 400), which also meant
Ed's "Denied" reply was never actually processed by the model that turn.

These tests prove the fix holds: send_email is dispatched ONLY through the
registry (never the inline table), and the registry's dispatch() always
returns a string for it, even on a raw-dict-returning blocked path -- so a
rejection/denial can never again poison an API call.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root

import tools.send_email_tool  # noqa: F401,E402 -- registers "send_email" at import time
from tools.registry import registry  # noqa: E402


def test_send_email_not_in_inline_tool_executor_table():
    """send_email is a pure function (no live-AIAgent-state dependency) --
    it must dispatch through the registry, never through the inline table
    that bypasses result normalization. Regression guard for the 11/10
    dual-registration bug."""
    from agent.inline_tool_executors import INLINE_TOOL_EXECUTORS

    assert "send_email" not in INLINE_TOOL_EXECUTORS, (
        "send_email is back in INLINE_TOOL_EXECUTORS -- this bypasses "
        "ToolRegistry._normalize_handler_result and will let a raw dict "
        "result reach the model again (the exact 11/10 OpenRouter 400 "
        "incident: 'messages.N.content: Invalid input')."
    )


def test_registry_dispatch_send_email_returns_string_on_blocked_path(tmp_path, monkeypatch):
    """Drive the REAL registry.dispatch() path (what tool_executor.py actually
    calls once send_email is removed from the inline table) through the exact
    failure mode from the incident -- a body_path outside the allowed
    directories -- and assert the result is a string, not a dict."""
    import tools.send_email_tool as se

    allowed_dir = tmp_path / "allowed_drafts"
    allowed_dir.mkdir()
    allowed_dirs_file = tmp_path / "send_email_allowed_dirs.json"
    allowed_dirs_file.write_text(f'{{"allowed_dirs": ["{allowed_dir}"]}}')

    # body file lives OUTSIDE the allowed dir -- same shape as the incident's
    # ~/.hermes/cache/scratch/smoke_test_b.txt body_path.
    disallowed_dir = tmp_path / "scratch"
    disallowed_dir.mkdir()
    body_file = disallowed_dir / "smoke_test_b.txt"
    body_file.write_text("test body -- Hermes Trismegistos (Ed's AI assistant)")

    monkeypatch.setattr(se, "_load_allowed_dirs", lambda profile_path=None: [str(allowed_dir)])

    result = registry.dispatch(
        "send_email",
        {"to": "ed_ri27@hotmail.com", "subject": "test", "body_path": str(body_file)},
    )

    assert isinstance(result, str), (
        f"registry.dispatch('send_email', ...) returned {type(result).__name__}, not str, "
        "on the exact blocked-path shape from the 11/10 incident -- this would still "
        "poison the next API call with a raw dict in message content."
    )
    assert "Body path rejected" in result or "not in allowed directories" in result

def test_normalize_handler_result_rejects_raw_dict_generically():
    """Belt-and-suspenders: even if some future handler (send_email or any
    other registry tool) returns a bare dict that isn't the multimodal
    envelope, the registry's own normalizer must turn it into a string
    error, never pass the dict through."""
    out = registry._normalize_handler_result("send_email", {"error": "x", "sent": False})
    assert isinstance(out, str)
