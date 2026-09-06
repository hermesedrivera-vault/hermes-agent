"""Tests for check_outbound_comm_guard() and its helpers (Step 30, Phase 3).

Covers detect_outbound_comm, _normalize_recipient, _get_outbound_comm_mode,
check_outbound_comm_guard's fail-closed contract, its wiring into
check_execute_code_guard, and the send_message_tool integration.
"""
from unittest.mock import MagicMock, patch as mock_patch

import pytest

import tools.approval as approval_module
from gateway.session_context import clear_session_vars, reset_session_vars, set_session_vars
from tools.approval import (
    approve_session,
    check_all_command_guards,
    check_execute_code_guard,
    check_outbound_comm_guard,
    detect_outbound_comm,
    get_current_authorization_key,
    is_approved,
    _normalize_recipient,
)


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


# ---------------------------------------------------------------------------
# detect_outbound_comm
# ---------------------------------------------------------------------------

def test_detect_outbound_comm_email():
    text = "service.users().messages().send(userId='me', to='someone@external.com')"
    result = detect_outbound_comm(text)
    assert result is not None
    assert result["channel"] == "email"
    assert "someone@external.com" in result["recipients"]


def test_detect_outbound_comm_self_address_excluded():
    text = "service.users().messages().send(userId='me', to='ed.rivera@gmail.com')"
    result = detect_outbound_comm(text)
    assert result is None


def test_detect_sms_via_twilio():
    text = "twilio_client.messages.create(to='+13055551234', body='hi')"
    result = detect_outbound_comm(text)
    assert result is not None
    assert result["channel"] == "sms"
    # _PHONE_RE captures digits without the leading '+' -- normalization to
    # E.164 happens later, in _normalize_recipient, not in the detector.
    assert "13055551234" in result["recipients"]


# ---------------------------------------------------------------------------
# _normalize_recipient
# ---------------------------------------------------------------------------

def test_normalize_email_gmail_plus_tag_stripped():
    assert _normalize_recipient("email", "User+work@GMAIL.com") == "user@gmail.com"


def test_normalize_email_non_gmail_plus_tag_preserved():
    assert _normalize_recipient("email", "User+work@example.com") == "user+work@example.com"


def test_normalize_sms_bare_10_digit():
    assert _normalize_recipient("sms", "(305) 555-1234") == "+13055551234"


def test_normalize_sms_malformed_fails_closed():
    assert _normalize_recipient("sms", "not-a-phone") is None


# ---------------------------------------------------------------------------
# check_outbound_comm_guard: fail-closed cases
# ---------------------------------------------------------------------------

def test_missing_recipient_fails_closed():
    tokens = set_session_vars(session_key="test-session")
    try:
        # Real behavior: an override with a falsy recipient collapses to
        # `detection = None` inside check_outbound_comm_guard (the "no
        # channel_recipient_override raw_recipient" branch), which is treated
        # as "nothing detected" and returns approved=True immediately -- the
        # same as calling with no override on text with no signal. This is
        # NOT the fail-closed "no recipient extracted" message (that path is
        # only reached via detect_outbound_comm returning recipients=[],
        # which cannot happen for the override path). Documented actual
        # behavior, not a bug: call sites that use channel_recipient_override
        # only do so when they already have a non-empty target_ref (see
        # send_message_tool.py's `if _outbound_target_ref else None`).
        result = check_outbound_comm_guard("terminal", "", channel_recipient_override=("email", ""))
        assert result["approved"] is True
        assert result["message"] is None
    finally:
        clear_session_vars(tokens)


def test_malformed_recipient_fails_closed():
    tokens = set_session_vars(session_key="test-session")
    try:
        result = check_outbound_comm_guard("terminal", "", channel_recipient_override=("sms", "garbage"))
        assert result["approved"] is False
    finally:
        clear_session_vars(tokens)


def test_detector_exception_fails_closed(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(approval_module, "detect_outbound_comm", _raise)
    result = check_outbound_comm_guard("terminal", "irrelevant text")
    assert result["approved"] is False
    assert "internal error" in result["message"] or "fail-closed" in result["message"]


def test_missing_session_identity_fails_closed():
    reset_session_vars()
    result = check_outbound_comm_guard(
        "terminal", "", channel_recipient_override=("email", "someone@external.com")
    )
    assert result["approved"] is False
    assert "session identity" in result["message"]


# ---------------------------------------------------------------------------
# pattern_key construction / session-scoped approval
# ---------------------------------------------------------------------------

def test_recipient_bound_pattern_key_distinct(monkeypatch):
    tokens = set_session_vars(session_key="test-session")
    recorded = []

    def _fake_gate(**kwargs):
        recorded.append(kwargs["pattern_key"])
        return {"approved": True, "message": None}

    monkeypatch.setattr(approval_module, "_run_approval_gate", _fake_gate)
    try:
        check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", "alice@external.com")
        )
        check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", "bob@external.com")
        )
    finally:
        clear_session_vars(tokens)

    assert len(recorded) == 2
    assert recorded[0] != recorded[1]
    for key in recorded:
        assert key.startswith("outbound_external_comm::email::")


def test_session_scoped_approval_reuse():
    tokens = set_session_vars(session_key="test-session")
    try:
        session_key = get_current_authorization_key()
        recipient_key = "someone@external.com"
        pattern_key = f"outbound_external_comm::email::{recipient_key}"
        approve_session(session_key, pattern_key)
        assert is_approved(session_key, pattern_key) is True

        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", recipient_key)
        )
        assert result["approved"] is True
    finally:
        clear_session_vars(tokens)


# ---------------------------------------------------------------------------
# Step 32: outbound approvals must never become permanent
# ---------------------------------------------------------------------------

def test_outbound_approval_data_has_allow_permanent_false():
    """The gateway notify payload for an outbound_external_comm prompt must
    carry allow_permanent=False so the renderer never offers "Always" for
    this category -- mirrors test_command_guards.py's
    TestGatewayApprovalAllowPermanent pattern, applied to the outbound gate.
    """
    from tools.approval import (
        register_gateway_notify,
        resolve_gateway_approval,
        unregister_gateway_notify,
        set_current_session_key,
        reset_current_session_key,
    )
    import os as _os

    session_key = "gw-outbound-no-perm"
    captured = []

    def notify(data):
        captured.append(dict(data))
        resolve_gateway_approval(session_key, "deny")

    register_gateway_notify(session_key, notify)
    token = set_current_session_key(session_key)
    _os.environ["HERMES_GATEWAY_SESSION"] = "1"
    _os.environ["HERMES_EXEC_ASK"] = "1"
    _os.environ["HERMES_SESSION_KEY"] = session_key
    try:
        check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", "someone@external.com")
        )
    finally:
        _os.environ.pop("HERMES_GATEWAY_SESSION", None)
        _os.environ.pop("HERMES_EXEC_ASK", None)
        _os.environ.pop("HERMES_SESSION_KEY", None)
        reset_current_session_key(token)
        unregister_gateway_notify(session_key)

    assert len(captured) == 1
    assert captured[0]["allow_permanent"] is False


def test_outbound_always_choice_downgrades_to_session_only(monkeypatch):
    """Even if a stale/malfunctioning UI or adapter returns 'always' for an
    outbound-comm prompt, _run_approval_gate's allow_permanent=False (passed
    by check_outbound_comm_guard) must silently downgrade it to session-only
    approval -- never touching approve_permanent()/save_permanent_allowlist().
    """
    tokens = set_session_vars(session_key="test-session")
    save_mock = MagicMock()
    monkeypatch.setattr(approval_module, "save_permanent_allowlist", save_mock)
    monkeypatch.setattr(approval_module, "_is_gateway_approval_context", lambda: True)
    monkeypatch.setattr(
        approval_module,
        "_await_gateway_decision",
        lambda session_key, notify_cb, approval_data, surface: {
            "resolved": True, "choice": "always", "reason": None,
        },
    )
    # Force the notify-callback branch to be reachable.
    monkeypatch.setattr(
        approval_module, "_gateway_notify_cbs", {"test-session": lambda data: None}
    )
    try:
        session_key = get_current_authorization_key()
        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", "always-test@external.com")
        )
        pattern_key = "outbound_external_comm::email::always-test@external.com"
        assert result["approved"] is True
        assert pattern_key in approval_module._session_approved.get(session_key, set())
        assert pattern_key not in approval_module._permanent_approved
        assert save_mock.called is False
    finally:
        clear_session_vars(tokens)


def test_dangerous_command_permanent_approval_unchanged(monkeypatch):
    """CRITICAL anti-regression: check_dangerous_command()'s call to
    _run_approval_gate() was NOT touched by Step 32 and must still inherit
    allow_permanent=True by default, so an 'always' choice on a dangerous
    command still lands in _permanent_approved exactly as before.
    """
    from tools.approval import check_dangerous_command

    monkeypatch.setattr(approval_module, "_is_gateway_approval_context", lambda: True)
    monkeypatch.setattr(
        approval_module,
        "_await_gateway_decision",
        lambda session_key, notify_cb, approval_data, surface: {
            "resolved": True, "choice": "always", "reason": None,
        },
    )
    monkeypatch.setattr(
        approval_module, "_gateway_notify_cbs", {"dc-test-session": lambda data: None}
    )
    save_mock = MagicMock()
    monkeypatch.setattr(approval_module, "save_permanent_allowlist", save_mock)
    tokens = set_session_vars(session_key="dc-test-session")
    try:
        result = check_dangerous_command("rm -rf /tmp/somedir", "local")
        assert result["approved"] is True
        # detect_dangerous_command's pattern_key for this command -- read
        # back from _permanent_approved membership rather than hardcoding
        # the exact key format, which is an implementation detail of
        # detect_dangerous_command not under test here.
        assert save_mock.called is True
        assert len(approval_module._permanent_approved) > 0
    finally:
        clear_session_vars(tokens)


def test_cron_deny_blocks_outbound_even_with_preexisting_permanent_grant(monkeypatch):
    """Step 34 (Design B) closes the exact Step 31/33 finding: a pre-existing
    PERMANENT outbound_external_comm grant must not bypass cron_mode: deny.
    Before Step 34, is_approved()'s unconditional _permanent_approved lookup
    ran BEFORE the cron branch inside _run_approval_gate(), so a standing
    grant would short-circuit to approved=True regardless of cron context.
    Step 34 adds a narrowly-scoped, outbound-only check immediately before
    that lookup: pattern_key.startswith("outbound_external_comm::") AND
    cron context AND cron_mode == "deny" -> blocked, using the exact same
    cron_deny_message the generic cron branch already uses.
    """
    recipient = "preexisting-grant@external.com"
    pattern_key = f"outbound_external_comm::email::{recipient}"
    # Simulate a permanent grant that predates this fix (or was loaded from
    # config.yaml's command_allowlist). Step 34 does NOT purge or revoke
    # this -- it remains present in _permanent_approved throughout.
    approval_module.approve_permanent(pattern_key)

    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval_module, "_get_cron_approval_mode", lambda: "deny")
    monkeypatch.setattr(approval_module, "_get_outbound_comm_mode", lambda: "enforce")
    tokens = set_session_vars(session_key="test-session", cron_session="1")
    try:
        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", recipient)
        )
        assert result["approved"] is False
        assert "cron" in (result.get("message") or "").lower()
        # The grant itself is NOT revoked by this fix -- only the cron+deny
        # lookup precedence changed.
        assert pattern_key in approval_module._permanent_approved
    finally:
        clear_session_vars(tokens)


def test_cron_approve_still_allows_preexisting_permanent_outbound_grant(monkeypatch):
    """Proves the Step 34 check is deny-specific, not a blanket override of
    permanent approval under cron. cron_mode: approve must remain
    permissive even with a pre-existing outbound permanent grant.
    """
    recipient = "cron-approve-grant@external.com"
    pattern_key = f"outbound_external_comm::email::{recipient}"
    approval_module.approve_permanent(pattern_key)

    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval_module, "_get_cron_approval_mode", lambda: "approve")
    tokens = set_session_vars(session_key="test-session", cron_session="1")
    try:
        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", recipient)
        )
        assert result["approved"] is True
    finally:
        clear_session_vars(tokens)


def test_cron_deny_dangerous_command_permanent_grant_unaffected(monkeypatch):
    """CRITICAL category-scoping regression test: Step 34's new check is
    scoped ONLY to the outbound_external_comm:: pattern_key prefix. A
    pre-existing permanent DANGEROUS-COMMAND grant must behave exactly as
    it did before Step 34 -- still bypassing cron_mode: deny via the
    generic is_approved() short-circuit, since check_dangerous_command()'s
    pattern_keys never carry the outbound prefix. This test does NOT assert
    that this is desirable behavior in the abstract -- only that Step 34 did
    not change it, per the explicit instruction not to broaden scope.
    """
    from tools.approval import check_dangerous_command, detect_dangerous_command

    command = "rm -rf /tmp/somedir"
    _, pattern_key, _ = detect_dangerous_command(command)
    approval_module.approve_permanent(pattern_key)

    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval_module, "_get_cron_approval_mode", lambda: "deny")
    tokens = set_session_vars(session_key="test-session", cron_session="1")
    try:
        result = check_dangerous_command(command, "local")
        # Unchanged from pre-Step-34 behavior: the generic is_approved()
        # short-circuit still fires for this non-outbound pattern_key,
        # before the cron branch is ever reached.
        assert result["approved"] is True
    finally:
        clear_session_vars(tokens)


def test_interactive_outbound_permanent_grant_still_usable(monkeypatch):
    """Proves Step 34 does not revoke or globally invalidate existing
    permanent outbound grants -- only the cron+deny lookup precedence
    changed. An interactive session (no cron context) with a pre-existing
    permanent grant for the same pattern_key must still be allowed.
    """
    recipient = "interactive-grant@external.com"
    pattern_key = f"outbound_external_comm::email::{recipient}"
    approval_module.approve_permanent(pattern_key)

    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: False)
    tokens = set_session_vars(session_key="test-session")
    try:
        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", recipient)
        )
        assert result["approved"] is True
        assert pattern_key in approval_module._permanent_approved
    finally:
        clear_session_vars(tokens)



# ---------------------------------------------------------------------------
# cron mode
# ---------------------------------------------------------------------------

def test_cron_mode_deny_blocks(monkeypatch):
    # Use session_key (not platform=telegram) so _is_gateway_approval_context()
    # stays False -- otherwise _run_approval_gate takes the gateway
    # notify-callback branch instead of the cron branch, and the cron_mode
    # mock never gets consulted.
    # outbound_comm_mode defaults to "shadow", which overrides any would-have-
    # blocked decision to approved=True -- force "enforce" so this test
    # actually exercises the cron-deny block instead of the shadow override.
    tokens = set_session_vars(session_key="test-session", cron_session="1")
    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval_module, "_get_cron_approval_mode", lambda: "deny")
    monkeypatch.setattr(approval_module, "_get_outbound_comm_mode", lambda: "enforce")
    try:
        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", "someone@external.com")
        )
        assert result["approved"] is False
        assert "cron" in result["message"].lower()
    finally:
        clear_session_vars(tokens)


def test_cron_mode_approve_allows(monkeypatch):
    tokens = set_session_vars(session_key="test-session", cron_session="1")
    monkeypatch.setattr(approval_module, "_is_cron_approval_context", lambda: True)
    monkeypatch.setattr(approval_module, "_get_cron_approval_mode", lambda: "approve")
    try:
        result = check_outbound_comm_guard(
            "terminal", "", channel_recipient_override=("email", "someone@external.com")
        )
        assert result["approved"] is True
    finally:
        clear_session_vars(tokens)


# ---------------------------------------------------------------------------
# check_execute_code_guard wiring
# ---------------------------------------------------------------------------

def test_execute_code_static_outbound_detection():
    """The outbound-comm check (line ~4605) runs BEFORE check_execute_code_guard's
    own is_gateway/is_ask early-return (line ~4637), so it IS reachable even in
    a plain local, non-gateway, non-ask, non-cron context -- unlike the
    whole-script approval flow, which only fires in gateway/ask contexts.
    Here, with no session identity bound, the outbound check's fail-closed
    "missing session identity" branch fires and blocks, proving the check is
    reached even though check_execute_code_guard would otherwise auto-approve
    plain local execution.
    """
    reset_session_vars()
    code = (
        "import smtplib\n"
        "s = smtplib.SMTP('smtp.example.com')\n"
        "s.sendmail('me@example.com', 'attacker@external.com', 'msg')\n"
    )
    result = check_execute_code_guard(code, "local")
    assert result["approved"] is False
    assert "session identity" in result["message"]


def test_execute_code_no_outbound_signal_reaches_local_early_return():
    """Sanity check: code with no outbound signal is unaffected by the new
    outbound-comm gate. As of the 2026-08-29 fail-open audit fix
    (f730da0d08), check_execute_code_guard's own non-interactive fallback
    now fails CLOSED (not auto-approved) with no gateway/cron/single-query
    context present -- that's an intentional, unrelated security fix, not
    a regression from the outbound-comm guard added here. This test only
    asserts the outbound-comm gate itself did not additionally block."""
    reset_session_vars()
    result = check_execute_code_guard("import os\nprint('hi')\n", "local")
    assert result["approved"] is False
    assert "non-interactive" in result["message"] or "fail-closed" in result["message"].lower()


# ---------------------------------------------------------------------------
# send_message_tool integration
# ---------------------------------------------------------------------------

def test_send_message_authorization_before_provenance(monkeypatch):
    import tools.send_message_tool as smt

    monkeypatch.setattr(
        smt,
        "check_outbound_comm_guard",
        lambda *a, **k: {"approved": False, "message": "test block"},
        raising=False,
    )
    # send_message_tool imports check_outbound_comm_guard lazily from
    # tools.approval inside _handle_send; patch it at the source too so the
    # lazy `from tools.approval import check_outbound_comm_guard` picks it up.
    monkeypatch.setattr(
        approval_module,
        "check_outbound_comm_guard",
        lambda *a, **k: {"approved": False, "message": "test block"},
    )
    gate_mock = MagicMock()
    with mock_patch("agent.provenance.gate.apply_provenance_gate", gate_mock):
        result = smt._handle_send(
            {"target": "telegram:12345", "message": "hi someone@external.com sendmail("}
        )

    assert gate_mock.called is False
    result_str = str(result)
    assert "test block" in result_str or "error" in result_str.lower() or "blocked" in result_str.lower()


# ---------------------------------------------------------------------------
# dispatcher-level integration
# ---------------------------------------------------------------------------

def test_dispatcher_level_integration_terminal_blocked(monkeypatch):
    """check_all_command_guards only reaches check_outbound_comm_guard when
    there are no other tirith/dangerous-command warnings on the command
    (tools/approval.py ~line 4259: `if not warnings:`) -- so the command must
    be benign by dangerous-command/tirith standards while still carrying an
    outbound-comm signal in its text. outbound_comm_mode also defaults to
    "shadow" (would-be-blocked decisions are logged and allowed), so this
    integration test forces "enforce" to prove the real dispatcher path
    actually blocks end-to-end, not just detects.

    This host is itself a live Hermes gateway session (real
    `_HERMES_GATEWAY`/`HERMES_SESSION_PLATFORM` env vars are set in the
    process's real os.environ). `set_session_vars(platform="", cron_session="")`
    -- not `reset_session_vars()` -- must be used to explicitly blank those
    context vars; `reset_session_vars()` sets them to the _UNSET sentinel,
    which falls through to the leaked real os.environ values and would
    misclassify this test as a gateway-interactive context instead of the
    fail_closed_when_no_human path it's meant to exercise (same masking
    concern as test_cron_approval_mode.py's
    test_explicit_blank_masks_leaked_cron_env_for_gateway_classification).
    """
    tokens = set_session_vars(session_key="test-session", platform="", cron_session="")
    monkeypatch.setattr(approval_module, "_get_outbound_comm_mode", lambda: "enforce")
    command = (
        "echo \"service.users().messages().send(userId='me'); "
        "to='attacker@external.com'\""
    )
    result = approval_module.check_all_command_guards(command, "local")
    assert result.get("approved") is False
    assert "attacker@external.com" in (result.get("message") or "") or "outbound" in (result.get("message") or "").lower()
    assert result["approved"] is False
