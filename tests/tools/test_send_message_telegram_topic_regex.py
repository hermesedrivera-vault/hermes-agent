"""Invariant: ``_parse_target_ref`` must resolve a numeric Telegram target, and the
provenance gate must receive the caller's ``session_id``.

Regression for the 2026-10-03 cron delivery failure (job ca96e07b7fdc):
``NameError: name '_TELEGRAM_TOPIC_TARGET_RE' is not defined``. The Sep-2026
split of ``send_message_tool.py`` left a dead copy of ``_parse_target_ref`` in
the facade that shadowed the canonical import. A second latent bug in the same
dead region: ``_handle_send`` referenced ``session_id`` that was never in scope,
so the provenance gate for ``send_message`` could never have fired.
"""
from unittest.mock import patch

from tools.send_message_targets import _parse_target_ref
from tools import send_message_tool as smt


def test_telegram_numeric_chat_id_parses_without_nameerror():
    chat_id, thread_id, explicit = _parse_target_ref("telegram", "8472981034")
    assert chat_id == "8472981034"
    assert thread_id is None
    assert explicit is True


def test_telegram_chat_id_with_topic_parses():
    chat_id, thread_id, explicit = _parse_target_ref("telegram", "-1001234567890:42")
    assert chat_id == "-1001234567890"
    assert thread_id == "42"
    assert explicit is True


def test_provenance_gate_receives_session_id_from_tool_kwargs():
    """The dispatcher passes ``session_id`` via **kw; the gate must see that value."""
    seen = {}

    def fake_gate(function_name, function_args, session_id):
        seen["fn"] = function_name
        seen["sid"] = session_id
        return '{"error": "blocked-by-test"}'

    with patch("tools.approval.check_outbound_comm_guard", return_value={"approved": True}), \
         patch("agent.provenance.gate.apply_provenance_gate", fake_gate):
        out = smt.send_message_tool(
            {"action": "send", "target": "telegram:123", "message": "hi"},
            session_id="sess-xyz",
        )
    assert seen == {"fn": "send_message", "sid": "sess-xyz"}
    assert "blocked-by-test" in out
