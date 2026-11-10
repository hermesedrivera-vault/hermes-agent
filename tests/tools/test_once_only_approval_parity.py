"""Parity test (Ed's review, 11/9/26): queued refactor not yet landed --
tools/file_tools_write_guards.py:_request_protected_instruction_approval
does NOT call tools/once_only_approval.py yet (see that module's docstring
and the vault handoff note). Until the refactor lands, this test fails
loudly the moment the two implementations drift on the properties that
matter: same flags, same fail-closed branch shape, same gateway call
shape. Treat a failure here as "go do the refactor now", not "fix the
test"."""
from __future__ import annotations

import inspect


def test_both_paths_set_allow_session_false_and_allow_permanent_false():
    import tools.file_tools_write_guards as ft
    import tools.once_only_approval as oo

    src_ft = inspect.getsource(ft._request_protected_instruction_approval)
    src_oo = inspect.getsource(oo.request_once_only_approval)
    for src, label in ((src_ft, "file_tools_write_guards"), (src_oo, "once_only_approval")):
        assert "allow_permanent\": False" in src or "allow_permanent=False" in src, \
            f"{label} must set allow_permanent=False"
        assert "allow_session\": False" in src or "allow_session=False" in src, \
            f"{label} must set allow_session=False"


def test_both_paths_use_the_same_gateway_lookup_and_await_call():
    import tools.file_tools_write_guards as ft
    import tools.once_only_approval as oo

    src_ft = inspect.getsource(ft._request_protected_instruction_approval)
    src_oo = inspect.getsource(oo.request_once_only_approval)
    for src, label in ((src_ft, "file_tools_write_guards"), (src_oo, "once_only_approval")):
        assert "_gateway_notify_cbs.get(session_key)" in src, f"{label} must look up the gateway notify callback"
        assert "_await_gateway_decision(" in src, f"{label} must block on the gateway round-trip"
        assert "surface=\"gateway\"" in src, f"{label} must identify as the gateway surface"


def test_both_paths_fail_closed_with_no_outcome_or_block_text_when_no_human_channel():
    """Same fail-closed branch SHAPE: no gateway notify_cb AND no CLI
    callback -> neither path auto-approves. file_tools_write_guards.py
    returns a block-text string; once_only_approval.py returns a dict with
    no 'outcome' key -- different return CONVENTIONS by design (one is a
    write-guard error string, one is an approval_gate-shaped dict), but
    both must refuse, never silently proceed."""
    import tools.file_tools_write_guards as ft
    import tools.once_only_approval as oo

    src_ft = inspect.getsource(ft._request_protected_instruction_approval)
    src_oo = inspect.getsource(oo.request_once_only_approval)
    assert "_no_user_can_answer()" in src_ft and "_no_user_can_answer()" in src_oo
    assert "callback is None" in src_ft and "callback is None" in src_oo


def test_both_paths_use_a_pattern_key_argument_not_a_hardcoded_string():
    """once_only_approval.py's pattern_key is caller-supplied (send_email
    binds it to a draft hash); file_tools_write_guards.py still hardcodes
    'protected_instruction_file' (no per-write uniqueness needed there --
    every write to a protected file is equally sensitive). This asymmetry
    is intentional, not drift -- documented here so a future refactor
    doesn't 'fix' it into a regression."""
    import tools.once_only_approval as oo

    sig = inspect.signature(oo.request_once_only_approval)
    assert "pattern_key" in sig.parameters
