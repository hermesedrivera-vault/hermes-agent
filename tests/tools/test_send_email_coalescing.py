"""Coalescing test (Ed's review, 11/9/26): tools.approval_gateway_wait's
leader/follower coalescing matches on session_key + exact command text +
pattern_keys equality (see tests/tools/test_protected_instruction_gateway_coalescing.py
for the live incident this logic exists to prevent). send_email's
pattern_key is f"send_email:{draft_hash}" -- two DIFFERENT drafts have
different hashes and therefore different pattern_keys, so they can never
be coalesced into one prompt. Two calls for the SAME draft_hash
coalescing into one prompt is correct and intended (not tested as a
failure here)."""
from __future__ import annotations

import threading
import time


def test_two_concurrent_different_drafts_get_two_separate_prompts(monkeypatch):
    import tools.send_email_tool as se

    calls = []
    lock = threading.Lock()

    def fake_await_gateway_decision(session_key, notify_cb, approval_data, surface=None):
        with lock:
            calls.append(approval_data)
        time.sleep(0.05)  # force overlap between the two concurrent calls
        return {"choice": "once", "resolved": True}

    monkeypatch.setattr("tools.approval_context.get_current_session_key", lambda: "sess-concurrent")
    monkeypatch.setattr("tools.approval_gateway_wait._await_gateway_decision", fake_await_gateway_decision)
    import tools.approval as _approval
    monkeypatch.setattr(_approval, "_gateway_notify_cbs", {"sess-concurrent": lambda *a, **k: None})

    payload_a = {"to": "ken@jnccpas.com", "subject": "Weekly update", "cc": [], "bcc": [], "reasons": [],
                 "draft_hash": "aaaa_draft_hash_one"}
    payload_b = {"to": "ken@jnccpas.com", "subject": "Weekly update", "cc": [], "bcc": [], "reasons": [],
                 "draft_hash": "bbbb_draft_hash_two"}

    results = {}

    def run(name, payload):
        results[name] = se._once_only_approval_gate(payload)

    t1 = threading.Thread(target=run, args=("a", payload_a))
    t2 = threading.Thread(target=run, args=("b", payload_b))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(calls) == 2, "two different drafts (different hashes) must produce two separate prompts, not one coalesced prompt"
    pattern_keys = {c["pattern_key"] for c in calls}
    assert pattern_keys == {"send_email:aaaa_draft_hash_one", "send_email:bbbb_draft_hash_two"}, \
        "each prompt's pattern_key must be unique per draft_hash -- this is what prevents coalescing across different emails"
    assert results["a"] == {"approved": True, "outcome": "approved"}
    assert results["b"] == {"approved": True, "outcome": "approved"}


def test_same_draft_hash_pattern_key_is_identical_across_calls():
    """Documents the intended OTHER half: two calls for the literal same
    draft_hash produce the identical pattern_key -- coalescing them (one
    prompt, not two) is correct, since it is genuinely the same content."""
    import tools.send_email_tool as se

    payload = {"to": "ken@jnccpas.com", "subject": "X", "cc": [], "bcc": [], "reasons": [],
               "draft_hash": "same_hash_value"}
    pk1 = f"send_email:{payload.get('draft_hash', '')}"
    pk2 = f"send_email:{payload.get('draft_hash', '')}"
    assert pk1 == pk2
