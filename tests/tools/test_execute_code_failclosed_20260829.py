"""RED->GREEN regression test for the execute_code fail-closed fix
(Phase 4 priority item, 2026-08-29 approval-fallback exposure audit).

check_execute_code_guard's non-interactive/non-gateway/non-ask/non-cli
fallback previously auto-approved silently (no logging at all, unlike the
shell-command fallback which at least logged). This closes that gap with
its OWN separate config key (approvals.execute_code_noninteractive_mode),
deliberately not shared with the shell-command opt-in
(approvals.dangerous_command_noninteractive_mode) given execute_code's
higher, uninspected risk surface (arbitrary Python, no DANGEROUS_PATTERNS
inspection at all).
"""
import tools.approval as approval


def _base_patches(monkeypatch, is_cli=False):
    monkeypatch.setattr(approval, "_should_skip_container_guards", lambda *a, **k: False)
    monkeypatch.setattr(approval, "_get_approval_mode", lambda: "manual")
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: False)
    monkeypatch.setattr(approval, "_is_gateway_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_interactive_cli", lambda: is_cli)
    monkeypatch.setattr(approval, "_is_single_query_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: False)
    monkeypatch.setattr(approval, "_resolve_cli_approval_callback", lambda: None)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)


def test_execute_code_fails_closed_by_default_headless(monkeypatch):
    """The real fail-open gap: no CLI/gateway/ask/cron/single-query context
    present at all (a bare headless script) — must now BLOCK, not silently
    auto-approve as it always had before this fix."""
    _base_patches(monkeypatch, is_cli=False)
    monkeypatch.setattr(approval, "_get_execute_code_noninteractive_mode", lambda: "block")

    result = approval.check_execute_code_guard("print('hi')", "host")

    assert result["approved"] is False, (
        "REGRESSION: execute_code auto-approved with no human present and "
        "no logging — the exact gap this fix closes."
    )
    assert "BLOCKED" in (result.get("message") or "")


def test_execute_code_respects_own_explicit_opt_in(monkeypatch):
    """Config opt-in specific to execute_code must still allow a known
    non-interactive workflow."""
    _base_patches(monkeypatch, is_cli=False)
    monkeypatch.setattr(approval, "_get_execute_code_noninteractive_mode", lambda: "approve")

    result = approval.check_execute_code_guard("print('hi')", "host")
    assert result["approved"] is True


def test_execute_code_opt_ins_are_not_shared(monkeypatch):
    """Critical isolation check: authorizing the SHELL-command fallback
    (approvals.dangerous_command_noninteractive_mode: approve) must NOT
    also silently authorize execute_code's fallback. Different risk
    profile, different config key, independently gated."""
    _base_patches(monkeypatch, is_cli=False)
    # Shell-command opt-in is "approve", but execute_code's own key still
    # defaults to "block" (not patched to approve here).
    monkeypatch.setattr(approval, "_get_noninteractive_dangerous_command_mode", lambda: "approve")
    monkeypatch.setattr(approval, "_get_execute_code_noninteractive_mode", lambda: "block")

    result = approval.check_execute_code_guard("print('hi')", "host")
    assert result["approved"] is False, (
        "REGRESSION: the shell-command opt-in silently covered execute_code "
        "too — these must be independently gated, per explicit instruction."
    )


def test_execute_code_cli_interactive_unaffected(monkeypatch):
    """CLI-interactive sessions are NOT the fail-open gap this fix targets
    (a human is present; per-call terminal() guards inside the script
    protect it). Must remain approved, unaffected by this fix."""
    _base_patches(monkeypatch, is_cli=True)
    monkeypatch.setattr(approval, "_get_execute_code_noninteractive_mode", lambda: "block")

    result = approval.check_execute_code_guard("print('hi')", "host")
    assert result["approved"] is True, (
        "REGRESSION: CLI-interactive execute_code usage must not be blocked "
        "by the non-interactive fail-closed fix — a human is present."
    )


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
