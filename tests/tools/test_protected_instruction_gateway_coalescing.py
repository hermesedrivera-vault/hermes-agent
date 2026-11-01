"""Reproduction tests for the 2026-11-01 Fix-2 live silent-pass incident.

A write to profiles/kenneth-rosa/config.yaml landed with zero Telegram
prompt, `success: true`. Detection, stale-code, and approvals.db persistence
were all ruled out (see vault 05-Postmortems/2026-11-01-cycle3-handoff.md).
Remaining candidate: `tools.approval_gateway_wait._await_gateway_decision`'s
leader/follower coalescing, which matches purely on session_key + exact
`command` text + `pattern_keys` equality and can adopt a leftover/orphaned
leader entry's cached `session`/`always` result without ever calling
notify_cb for the follower -- even though this gate's own approval_data sets
allow_session=False / allow_permanent=False.

These tests exercise the GATEWAY surface (register_gateway_notify /
_gateway_queues), not the CLI-callback surface the existing
TestProtectedInstructionFiles class covers -- the existing suite never
reaches this code path, which is why it passed 56/10516 while the live
gateway still failed.
"""
import threading
import time

import pytest


SESSION_KEY = "test-fix2-coalescing-session"


@pytest.fixture(autouse=True)
def _gate_on(monkeypatch):
    import tools.file_tools_write_guards as ft
    monkeypatch.setattr(ft, "_protected_instruction_config", lambda: (True, []))
    yield


@pytest.fixture
def gateway_session():
    from tools.approval import register_gateway_notify, unregister_gateway_notify, _gateway_queues
    from tools.approval_context import set_current_session_key, reset_current_session_key
    token = set_current_session_key(SESSION_KEY)
    yield SESSION_KEY
    reset_current_session_key(token)
    unregister_gateway_notify(SESSION_KEY)
    _gateway_queues.pop(SESSION_KEY, None)


def _write(path, content="injected"):
    import json
    from tools.file_tools import write_file_tool
    return json.loads(write_file_tool(str(path), content))


def test_a_fresh_write_notifies_gateway(tmp_path, gateway_session):
    """(a) No prior leader: a single fresh protected-instruction write on the
    gateway surface MUST call notify_cb. Baseline -- must pass before (b)
    means anything."""
    from tools.approval import register_gateway_notify, resolve_gateway_approval

    calls = []

    def notify(data):
        calls.append(data)
        threading.Thread(
            target=lambda: (time.sleep(0.05), resolve_gateway_approval(SESSION_KEY, "once")),
            daemon=True,
        ).start()

    register_gateway_notify(SESSION_KEY, notify)
    target = tmp_path / "AGENTS.md"
    res = _write(target, "a: 1")

    assert len(calls) == 1, "fresh protected-instruction write must always notify"
    assert not res.get("error"), res
    assert calls[0]["pattern_key"] == "protected_instruction_file"
    assert calls[0]["allow_session"] is False
    assert calls[0]["allow_permanent"] is False
    # Outcome proof, not just the prompt: a 'once' approval must actually
    # commit the write (not silently no-op it).
    assert target.read_text(encoding="utf-8") == "a: 1", "approved write must land on disk"


def test_b_orphaned_leader_must_not_silently_approve_follower(tmp_path, gateway_session):
    """(b) Coalescing reproduction: an orphaned leader entry already sits in
    _gateway_queues[session_key] for the SAME command+pattern_keys, already
    resolved with 'always' (e.g. its own calling thread was abandoned/timed
    out before _drop_entry ran -- a real leak path, not a persisted grant).
    A second, unrelated write to the same protected file in the same session
    MUST still notify the user and must NOT inherit 'always'/'session' --
    this gate always sets allow_session=False/allow_permanent=False and
    nothing is meant to be persisted across calls.
    """
    from tools.approval import register_gateway_notify, _gateway_queues, _lock
    from tools.approval_gateway_wait import _ApprovalEntry
    import contextvars

    target = tmp_path / "AGENTS.md"
    target.write_text("a: 1", encoding="utf-8")

    # Build the exact command/pattern_keys text this gate will produce for
    # this file: targets is the protected BASENAME ("AGENTS.md"), not the
    # full path -- see _request_protected_instruction_approval's `display`.
    display = "<write to AGENTS.md>"
    leader_data = {
        "command": display,
        "pattern_key": "protected_instruction_file",
        "pattern_keys": ["protected_instruction_file"],
        "description": "orphaned leader from an abandoned earlier call",
        "allow_permanent": False,
        "allow_session": False,
    }
    leader = _ApprovalEntry(leader_data)
    leader.result = "always"   # simulates Ed having tapped a button for the FIRST call
    leader.event.set()         # resolved...
    with _lock:
        _gateway_queues.setdefault(SESSION_KEY, []).append(leader)  # ...but never dequeued (leak)

    calls = []

    def notify(data):
        calls.append(data)
        # No auto-resolution here on purpose: if the bug is present this
        # callback is never invoked at all, so there'd be nothing to resolve.

    register_gateway_notify(SESSION_KEY, notify)

    # Run the second write with a short overall watchdog: if the gate
    # silently approves (the bug), write_file_tool returns almost instantly
    # with success and notify is never called.
    result_box = {}

    def run():
        result_box["res"] = _write(target, "a: 2")

    # contextvars (our session key) do NOT propagate to a manually spawned
    # threading.Thread -- copy the current context explicitly, or the write
    # runs with session_key="" and silently falls to the CLI branch (fails
    # closed, notify_cb never called) regardless of any fix. This was a test
    # harness bug, not a library bug -- it produced an identical-looking
    # "0 notify calls" symptom both before and after the real fix.
    ctx = contextvars.copy_context()
    t = threading.Thread(target=lambda: ctx.run(run), daemon=True)
    t.start()
    t.join(timeout=1.0)

    assert len(calls) == 1, (
        "BUG REPRODUCED: the second write coalesced onto the orphaned leader "
        "and returned without ever calling notify_cb -- exactly the live "
        "silent-pass incident (profiles/kenneth-rosa/config.yaml, 2026-11-01)."
    )
    # Even if somehow adopted, the flags this gate declares must be enforced
    # server-side, not just rendered client-side.
    if calls:
        assert calls[0]["allow_session"] is False
        assert calls[0]["allow_permanent"] is False
    # Outcome proof, the real point of the whole incident: since nobody
    # resolved the fresh request (no auto-approver was wired up on purpose),
    # the write must NOT have landed. If the file now reads "a: 2" with no
    # notify call recorded, that IS the live silent-pass: an unreviewed
    # write committed to a protected instruction file.
    t.join(timeout=5.0)  # let the (approved-or-blocked) outcome settle, bounded
    current = target.read_text(encoding="utf-8")
    assert current == "a: 1", (
        f"SILENT PASS: file content is {current!r}; the second write committed "
        "without any approval ever being granted by this test."
    )


def test_c_stale_but_unresolved_leader_is_not_adopted_either(tmp_path, gateway_session):
    """(c) Leader liveness: an entry that is still UNRESOLVED (result is
    None, so (b)'s result-based filter wouldn't catch it) but far older than
    the approval timeout is stale -- its own caller is presumed gone -- and
    must not be adopted as a leader either. Uses a non-protected-instruction
    pattern_key so (a)'s blanket no-coalesce rule doesn't already mask this
    on its own, isolating the liveness guard specifically.
    """
    from tools.approval import register_gateway_notify, resolve_gateway_approval, _gateway_queues, _lock
    from tools.approval_gateway_wait import _ApprovalEntry, _await_gateway_decision
    import tools.approval_context as actx

    monkeypatch_timeout = 1  # seconds, small so the test runs fast
    orig_timeout = actx._get_approval_timeout
    actx._get_approval_timeout = lambda: monkeypatch_timeout
    try:
        stale_leader = _ApprovalEntry({
            "command": "<write to /tmp/some/other/path.txt>",
            "pattern_key": "some_other_gate",
            "pattern_keys": ["some_other_gate"],
            "description": "stale, never resolved, caller presumed abandoned",
            "allow_permanent": True,
            "allow_session": True,
        })
        stale_leader.created_at -= (monkeypatch_timeout + 5)  # force it well past the TTL
        with _lock:
            _gateway_queues.setdefault(SESSION_KEY, []).append(stale_leader)

        calls = []

        def notify(data):
            calls.append(data)
            # Leader-skip decision already happened before notify_cb fires;
            # drop the orphaned stale leader now so resolve_gateway_approval's
            # FIFO match (oldest-first, no request_id given) targets our
            # actual fresh entry instead of the still-queued orphan.
            with _lock:
                q = _gateway_queues.get(SESSION_KEY, [])
                if stale_leader in q:
                    q.remove(stale_leader)
            threading.Thread(
                target=lambda: (time.sleep(0.05), resolve_gateway_approval(SESSION_KEY, "once")),
                daemon=True,
            ).start()

        register_gateway_notify(SESSION_KEY, notify)

        decision = _await_gateway_decision(
            SESSION_KEY, notify,
            {"command": "<write to /tmp/some/other/path.txt>",
             "pattern_key": "some_other_gate", "pattern_keys": ["some_other_gate"],
             "description": "a fresh, unrelated request for the same text",
             "allow_permanent": True, "allow_session": True},
            surface="gateway",
        )
        assert len(calls) == 1, "a stale (TTL-expired) leader must not be adopted -- must re-prompt"
        assert decision["choice"] == "once"
        # Outcome proof: "once" from a FRESH prompt (not inherited) must be
        # the only thing driving the approval; the stale leader's own
        # unrelated command/scope must never leak into this decision.
        assert decision["resolved"] is True
    finally:
        actx._get_approval_timeout = orig_timeout
        with _lock:
            _gateway_queues.pop(SESSION_KEY, None)


def test_d_consecutive_calls_on_same_thread_do_not_leak_follower_flags():
    """Fix2 regression guard: ``follower_flags`` must be an explicit,
    keyword-only argument to ``_await_coalesced_leader``, never implicit
    thread-local/module-global state. A thread can be reused across
    sessions/callers in this codebase, so if the flag were cached per-thread,
    a permissive first call (allow_session=True/allow_permanent=True) would
    leak into a second, unrelated, restrictive call (allow_session=False/
    allow_permanent=False) on the SAME thread -- recreating the exact
    "coalescing silently adopts a scope it shouldn't" bug this file exists
    to catch, just via a different leak path.
    """
    from tools.approval_gateway_wait import _ApprovalEntry, _await_coalesced_leader

    permissive_leader = _ApprovalEntry({
        "command": "<write to /tmp/permissive.txt>",
        "pattern_key": "some_other_gate", "pattern_keys": ["some_other_gate"],
        "description": "leader #1, resolved under permissive terms",
        "allow_permanent": True, "allow_session": True,
    })
    permissive_leader.result = "always"
    permissive_leader.event.set()

    restrictive_leader = _ApprovalEntry({
        "command": "<write to AGENTS.md>",
        "pattern_key": "protected_instruction_file", "pattern_keys": ["protected_instruction_file"],
        "description": "leader #2, resolved under permissive terms but the FOLLOWER's own gate is restrictive",
        "allow_permanent": True, "allow_session": True,
    })
    restrictive_leader.result = "always"
    restrictive_leader.event.set()

    # Call 1, same thread: permissive follower_flags -- must adopt.
    first = _await_coalesced_leader(
        SESSION_KEY, permissive_leader, {"command": "<write to /tmp/permissive.txt>"},
        follower_flags={"allow_session": True, "allow_permanent": True},
    )
    assert first is not None and first["resolved"] is True and first["choice"] == "always", (
        "sanity check: a genuinely permissive follower should adopt an 'always' leader"
    )

    # Call 2, SAME thread, immediately after: restrictive follower_flags on an
    # unrelated request. If flags leaked from call 1 (e.g. via a thread-local
    # or module-global default), this would wrongly adopt too.
    second = _await_coalesced_leader(
        SESSION_KEY, restrictive_leader, {"command": "<write to AGENTS.md>"},
        follower_flags={"allow_session": False, "allow_permanent": False},
    )
    assert second is None, (
        "FLAG LEAK: the second call's restrictive allow_session=False/"
        "allow_permanent=False was not honoured -- it inherited (or defaulted "
        "to) the first call's permissive flags on the same thread."
    )
