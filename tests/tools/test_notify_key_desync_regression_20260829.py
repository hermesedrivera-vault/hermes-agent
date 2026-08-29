"""Regression test for the 2026-08-24 approval-gate notify-callback key
mismatch (see Obsidian: 05-Postmortems/2026-08-24-approval-gate-notify-key-
mismatch-fix.md), run specifically against the upstream-merged branch
(reconcile/upstream-20260829) to confirm the fix survived the merge.

Bug recap: ``_request_general_file_write_approval`` in tools/file_tools.py
looked up the gateway notify callback using the COMPOSITE authorization key
(session::task=X::sub=Y) from ``get_current_authorization_key()``, but
``register_gateway_notify`` in gateway/run.py only ever registers the BARE
session key from ``get_current_session_key()``. Whenever a task/subagent
scope was bound, the lookup was a guaranteed miss even with a live,
correctly-registered callback -> fail-closed BLOCKED on every gated write.

A second bug in ``get_current_authorization_key()``: when a task_id was
bound but subagent_id was empty/falsy, it unconditionally appended
``::sub={subagent_id}``, producing a literal trailing ``::sub=``.

This test proves both symptoms are gone on the merged tree:
  1. The composite key never carries a dangling ``::sub=`` when no
     subagent is bound.
  2. The notify-callback dict is looked up under the BARE session key
     (``notify_session_key``), not the composite key, so a scoped task
     binding does not collapse a live registration into a miss.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tools.approval as _approval


def test_authorization_key_no_dangling_sub_suffix_when_subagent_unset():
    """get_current_authorization_key() must not append a bare '::sub=' when
    a task scope is bound but no subagent_id is set (the formatting half
    of the 2026-08-24 bug)."""
    token = _approval.set_current_authorization_scope(task_id="task123", subagent_id="")
    try:
        key = _approval.get_current_authorization_key(default="agent:main:telegram:dm:8472981034")
    finally:
        _approval.reset_current_authorization_scope(token)

    assert key == "agent:main:telegram:dm:8472981034::task=task123", (
        f"Expected no dangling '::sub=' suffix, got: {key!r}"
    )
    assert "::sub=" not in key


def test_notify_callback_lookup_uses_bare_session_key_not_composite():
    """The gateway notify-callback registered under the BARE session key
    must still be found when a task/subagent scope is bound and the
    approval path looks it up via notify_session_key (bare), not the
    composite authorization key. This is the core desync bug: composite
    lookup against a bare-key registration always misses."""
    bare_session_key = "agent:main:telegram:dm:8472981034"

    def _fake_notify_cb(*args, **kwargs):
        return {"approved": True}

    # Simulate gateway/run.py's register_gateway_notify: always bare key.
    _approval.register_gateway_notify(bare_session_key, _fake_notify_cb)
    try:
        token = _approval.set_current_authorization_scope(
            task_id="task123", subagent_id="sub456"
        )
        try:
            composite_key = _approval.get_current_authorization_key(
                default=bare_session_key
            )
            notify_session_key = _approval.get_current_session_key(
                default=bare_session_key
            )

            # The bug: composite key must NOT equal the bare key when a
            # scope is bound (otherwise this test can't distinguish the
            # two lookup paths).
            assert composite_key != notify_session_key, (
                "Test setup invalid: composite and bare session keys are "
                "identical, so this test cannot detect the desync."
            )

            with _approval._lock:
                # This is the fixed behavior: lookup by notify_session_key
                # (bare) succeeds.
                hit_bare = _approval._gateway_notify_cbs.get(notify_session_key)
                # This is the REGRESSED behavior the bug produced: lookup
                # by the composite key must miss, proving bare-key lookup
                # is the only correct path post-fix.
                hit_composite = _approval._gateway_notify_cbs.get(composite_key)

            assert hit_bare is not None, (
                "Notify callback lookup via bare session key (the fix) "
                "returned no callback — regression reintroduced."
            )
            assert hit_composite is None, (
                "Notify callback was found via the COMPOSITE key — this "
                "means the registration itself changed shape, which would "
                "mask the original bug rather than fix it. Investigate."
            )
        finally:
            _approval.reset_current_authorization_scope(token)
    finally:
        with _approval._lock:
            _approval._gateway_notify_cbs.pop(bare_session_key, None)
