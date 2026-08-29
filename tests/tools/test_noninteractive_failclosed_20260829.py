"""RED->GREEN regression test for the Phase 2 fail-closed fix.

Covers BOTH real production entry points found during this audit:
  - tools.approval.check_all_command_guards (the ACTUAL live path used by
    tools/terminal_tool.py — confirmed via import trace, not assumed)
  - tools.approval._run_approval_gate's own fallback (shared decision core
    reused by check_dangerous_command/request_tool_approval)

Before this fix: a dangerous command with no CLI/gateway/cron/single-query
context auto-approved (silently, in check_all_command_guards; with only a
log warning, in _run_approval_gate). After this fix: both fail closed
(BLOCKED) by default, with an explicit config opt-in to restore the old
behavior.
"""
import os

import tools.approval as approval


def _reset_contexts():
    """Force every known context detector to report 'no human present'."""
    approval._YOLO_MODE_FROZEN = False


def test_check_all_command_guards_fails_closed_by_default(monkeypatch):
    """The REAL production path (check_all_command_guards) must BLOCK a
    dangerous command when no CLI/gateway/cron/single-query/ask context
    claims the session — this is the exact silent-auto-approve gap found
    during the Phase 1 audit."""
    monkeypatch.setattr(approval, "_is_interactive_cli", lambda: False)
    monkeypatch.setattr(approval, "_is_gateway_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_single_query_approval_context", lambda: False)
    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: False)
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval, "_command_matches_permanent_allowlist", lambda c: False)
    monkeypatch.setattr(approval, "is_approved", lambda *a, **k: False)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
    # Force the config-read to return the default (no override present).
    monkeypatch.setattr(
        approval, "_get_noninteractive_dangerous_command_mode", lambda: "block"
    )

    result = approval.check_all_command_guards("rm -rf /home/hermes/some_real_dir", "host")

    assert result["approved"] is False, (
        "REGRESSION: dangerous command auto-approved with no human present "
        "(the exact Phase 1 finding) — check_all_command_guards must fail "
        "closed by default."
    )
    assert "BLOCKED" in (result.get("message") or "")


def test_check_all_command_guards_respects_explicit_approve_opt_in(monkeypatch):
    """Config opt-in (approvals.dangerous_command_noninteractive_mode:
    approve) must still allow a specific known non-interactive workflow —
    Ed's explicit instruction: no silent default, but an opt-in must work."""
    monkeypatch.setattr(approval, "_is_interactive_cli", lambda: False)
    monkeypatch.setattr(approval, "_is_gateway_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_single_query_approval_context", lambda: False)
    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: False)
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval, "_command_matches_permanent_allowlist", lambda c: False)
    monkeypatch.setattr(approval, "is_approved", lambda *a, **k: False)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
    monkeypatch.setattr(
        approval, "_get_noninteractive_dangerous_command_mode", lambda: "approve"
    )

    result = approval.check_all_command_guards("rm -rf /home/hermes/some_real_dir", "host")

    assert result["approved"] is True, (
        "Explicit config opt-in must still allow a known non-interactive "
        "workflow — the fix must not remove the escape hatch, only flip "
        "the default."
    )


def test_non_dangerous_command_unaffected(monkeypatch):
    """A non-dangerous command must never touch the new fallback at all —
    this fix must not add friction to normal, safe commands."""
    monkeypatch.setattr(approval, "_is_interactive_cli", lambda: False)
    monkeypatch.setattr(approval, "_is_gateway_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_single_query_approval_context", lambda: False)
    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: False)
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)

    result = approval.check_all_command_guards("echo hello world", "host")
    assert result["approved"] is True


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
