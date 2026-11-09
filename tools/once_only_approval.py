"""Shared once-only human-approval helper: gateway/CLI dual path with
allow_session=False, allow_permanent=False baked in -- the card/prompt
offers only Approve once / Deny, never a persisted scope.

Factored out of tools/file_tools_write_guards.py's
_request_protected_instruction_approval (the proven, live-verified
mechanism: a denied kenneth-rosa config.yaml write and outbound_classify.py
review cards both went through this exact code shape on Ed's Telegram,
2026-11-01/11-09). tools/send_email_tool.py is the first other caller.

Refactor status (Ed, 11/9/26): file_tools_write_guards.py does NOT call
this shared helper yet -- queued as a follow-up (see
tests/tools/test_once_only_approval_parity.py for the structural-parity
test that stands in for the refactor until it lands, and the vault
handoff note). Do not let the two implementations drift: any change here
must be mirrored there until the refactor actually happens.
"""
from __future__ import annotations

from typing import Optional


def request_once_only_approval(description: str, display: str, pattern_key: str) -> dict:
    """Ask a human for approval via whichever surface exists, once-only.

    Returns ``{"approved": bool, "outcome": ...}`` -- "outcome" is present
    ONLY for a real human decision (approved/denied/timeout); its absence
    is the gate-unreachable signal (no human/gateway channel at all).

    pattern_key MUST be unique per distinct action (e.g. include a content
    hash) -- gateway-side leader/follower coalescing matches on exact
    session_key + command text + pattern_keys equality, so two DIFFERENT
    actions sharing a pattern_key could otherwise be coalesced into one
    prompt. Two actions with the SAME pattern_key (genuinely identical
    content) coalescing into one prompt is correct and intended.
    """
    try:
        import tools.approval as _approval
        from tools.approval_context import get_current_session_key, _no_user_can_answer, _fire_approval_hook
        from tools.approval_gateway_wait import _await_gateway_decision
        from tools.approval_prompt import prompt_dangerous_approval
    except Exception:
        return {"approved": False}  # gate_unreachable: approval subsystem unavailable

    session_key = get_current_session_key()
    try:
        with _approval._lock:
            notify_cb = _approval._gateway_notify_cbs.get(session_key)
    except Exception:
        notify_cb = None

    if notify_cb is not None:
        # Gateway surface (Telegram/desktop card): block on the button
        # round-trip. One-operation only -- no scope buttons offered.
        approval_data = {
            "command": display, "pattern_key": pattern_key, "pattern_keys": [pattern_key],
            "description": description, "allow_permanent": False, "allow_session": False,
        }
        decision = _await_gateway_decision(session_key, notify_cb, approval_data, surface="gateway")
        if decision.get("notify_failed") or decision.get("cancelled"):
            return {"approved": False}  # gate_unreachable: card could not be delivered/was withdrawn
        choice, timed = decision.get("choice"), not decision.get("resolved")
    else:
        # CLI surface: per-thread approval callback (prompt_toolkit panel).
        try:
            from tools.terminal_tool import _get_approval_callback
            callback = _get_approval_callback()
        except Exception:
            callback = None
        if callback is None or _no_user_can_answer():
            return {"approved": False}  # gate_unreachable: no human channel present
        hook_kwargs = dict(command=display, description=description, pattern_key=pattern_key,
                           pattern_keys=[pattern_key], session_key=session_key, surface="cli")
        _fire_approval_hook("pre_approval_request", **hook_kwargs)
        choice = prompt_dangerous_approval(
            display, description, allow_permanent=False, allow_session=False, approval_callback=callback)
        _fire_approval_hook("post_approval_response", **hook_kwargs, choice=choice)
        if choice == "cancelled":
            return {"approved": False}  # gate_unreachable: prompt never reached a human
        timed = choice == "timeout"

    # Any tapped scope is a one-operation grant; nothing is persisted. (The
    # UI only ever offers once/deny here, but this mirrors the proven
    # protected-instruction gate's own defensive handling exactly.)
    if not timed and choice in {"once", "session", "always"}:
        return {"approved": True, "outcome": "approved"}
    return {"approved": False, "outcome": "timeout" if timed else "denied"}
