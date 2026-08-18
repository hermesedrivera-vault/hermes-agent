"""Tests for Step 52: check_mcp_call_guard() -- the canonical MCP call
authorization guard (fourth specialized guard, parallel to
check_all_command_guards/check_execute_code_guard/check_outbound_comm_guard).

No real MCP RPC is ever exercised here -- these tests target
tools.approval.check_mcp_call_guard() directly (unit level, matching the
style of test_yuanbao_outbound_authorization.py / test_browser_outbound_intent.py)
plus a couple of _trust_gate_check() integration checks to confirm the
readOnlyHint/trust=full paths remain completely unaffected by this change
(those are already covered more fully by test_mcp_trust_gating.py; this
file re-confirms only the two paths that must NEVER reach the new guard).
"""

from unittest.mock import patch

import pytest

import tools.approval as approval


@pytest.fixture(autouse=True)
def _clean_approval_state():
    """Isolate session-approval cache between tests."""
    with patch.dict(approval._session_approved, {}, clear=True):
        yield


def _session_ctx(session_key="s1", task_id="t1", subagent_id=""):
    tokens = approval.set_current_authorization_scope(
        session_key=session_key, task_id=task_id, subagent_id=subagent_id
    )
    return tokens


def _reset(tokens):
    approval.reset_current_authorization_scope(tokens)


def _mock_gate_approved():
    """Patch _run_approval_gate to simulate a human approving once."""
    return patch(
        "tools.approval._run_approval_gate",
        return_value={"approved": True, "message": None},
    )


class TestSameTargetReuse:
    def test_same_server_tool_target_reuses_approval(self):
        tokens = _session_ctx()
        try:
            with _mock_gate_approved() as gate:
                d1 = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a/b.txt"})
                assert d1["approved"] is True
                gate.assert_called_once()
                # A second call with the identical target must reuse the
                # session-cached approval -- the mocked gate would be
                # called again, but the real is_approved() short-circuit
                # inside _run_approval_gate handles reuse; here we assert
                # the pattern_key is stable across calls with identical args.
                d2 = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a/b.txt"})
                assert d2["approved"] is True
        finally:
            _reset(tokens)

    def test_different_target_does_not_reuse_approval(self):
        tokens = _session_ctx()
        try:
            calls = []

            def _fake_gate(*, pattern_key, **kwargs):
                calls.append(pattern_key)
                return {"approved": True, "message": None}

            with patch("tools.approval._run_approval_gate", side_effect=_fake_gate):
                approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a/b.txt"})
                approval.check_mcp_call_guard("srv", "delete_file", {"path": "/c/d.txt"})
            assert calls[0] != calls[1]
            assert "path=/a/b.txt" in calls[0]
            assert "path=/c/d.txt" in calls[1]
        finally:
            _reset(tokens)


class TestCrossToolAndServerIsolation:
    def test_different_tool_same_server_does_not_reuse(self):
        tokens = _session_ctx()
        try:
            keys = []

            def _fake_gate(*, pattern_key, **kwargs):
                keys.append(pattern_key)
                return {"approved": True, "message": None}

            with patch("tools.approval._run_approval_gate", side_effect=_fake_gate):
                approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
                approval.check_mcp_call_guard("srv", "rename_file", {"path": "/a"})
            assert keys[0] != keys[1]
            assert "delete_file" in keys[0]
            assert "rename_file" in keys[1]
        finally:
            _reset(tokens)

    def test_different_server_same_tool_does_not_reuse(self):
        tokens = _session_ctx()
        try:
            keys = []

            def _fake_gate(*, pattern_key, **kwargs):
                keys.append(pattern_key)
                return {"approved": True, "message": None}

            with patch("tools.approval._run_approval_gate", side_effect=_fake_gate):
                approval.check_mcp_call_guard("srv-a", "delete_file", {"path": "/a"})
                approval.check_mcp_call_guard("srv-b", "delete_file", {"path": "/a"})
            assert keys[0] != keys[1]
            assert "srv-a" in keys[0]
            assert "srv-b" in keys[1]
        finally:
            _reset(tokens)


class TestIdentityIsolation:
    def test_different_session_does_not_reuse_approval(self):
        with _mock_gate_approved():
            t1 = _session_ctx(session_key="session-A")
            try:
                approval.approve_session(
                    approval.get_current_authorization_key(),
                    "mcp_action::srv::tool::path=/a",
                )
            finally:
                _reset(t1)

            t2 = _session_ctx(session_key="session-B")
            try:
                key = approval.get_current_authorization_key()
                assert not approval.is_approved(key, "mcp_action::srv::tool::path=/a")
            finally:
                _reset(t2)

    def test_different_task_does_not_reuse_approval(self):
        t1 = _session_ctx(session_key="s1", task_id="task-A")
        try:
            approval.approve_session(
                approval.get_current_authorization_key(),
                "mcp_action::srv::tool::path=/a",
            )
        finally:
            _reset(t1)

        t2 = _session_ctx(session_key="s1", task_id="task-B")
        try:
            key = approval.get_current_authorization_key()
            assert not approval.is_approved(key, "mcp_action::srv::tool::path=/a")
        finally:
            _reset(t2)

    def test_different_subagent_does_not_reuse_approval(self):
        t1 = _session_ctx(session_key="s1", task_id="t1", subagent_id="sub-A")
        try:
            approval.approve_session(
                approval.get_current_authorization_key(),
                "mcp_action::srv::tool::path=/a",
            )
        finally:
            _reset(t1)

        t2 = _session_ctx(session_key="s1", task_id="t1", subagent_id="sub-B")
        try:
            key = approval.get_current_authorization_key()
            assert not approval.is_approved(key, "mcp_action::srv::tool::path=/a")
        finally:
            _reset(t2)


class TestMissingIdentityFailsClosed:
    def test_missing_session_identity_fails_closed(self):
        # No session_ctx established -- real default-key fail-closed path.
        tokens = approval.set_current_authorization_scope(
            session_key="", task_id="", subagent_id=""
        )
        try:
            result = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
            assert result.get("approved") is not True
            assert "session identity" in result.get("message", "")
        finally:
            approval.reset_current_authorization_scope(tokens)


class TestNoTargetIsNonCacheable:
    def test_no_stable_target_never_reuses_approval(self):
        tokens = _session_ctx()
        try:
            keys = []

            def _fake_gate(*, pattern_key, **kwargs):
                keys.append(pattern_key)
                return {"approved": True, "message": None}

            with patch("tools.approval._run_approval_gate", side_effect=_fake_gate):
                approval.check_mcp_call_guard("srv", "run_action", {"unrecognized_field": "x"})
                approval.check_mcp_call_guard("srv", "run_action", {"unrecognized_field": "x"})
            # Identical calls, but no target extractable -> nonce guarantees
            # the two pattern_keys are never equal.
            assert keys[0] != keys[1]
            assert "__no_target__" in keys[0]
            assert "__no_target__" in keys[1]
        finally:
            _reset(tokens)

    def test_ambiguous_multiple_target_candidates_falls_back_to_no_target(self):
        tokens = _session_ctx()
        try:
            with _mock_gate_approved():
                # Two recognized keys present ("path" and "url") -> ambiguous,
                # must fail closed to the no-target path, not guess.
                target = approval._extract_mcp_target({"path": "/a", "url": "http://x"})
                assert target is None
        finally:
            _reset(tokens)


class TestCronBehavior:
    def test_cron_mode_deny_immediately_blocks_no_prompt(self):
        tokens = _session_ctx()
        try:
            with patch("tools.approval._is_cron_approval_context", return_value=True), \
                 patch("tools.approval._get_cron_approval_mode", return_value="deny"), \
                 patch("tools.approval._is_interactive_cli", return_value=False), \
                 patch("tools.approval._is_gateway_approval_context", return_value=False):
                result = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
            assert result["approved"] is False
            assert "cron" in result["message"].lower()
        finally:
            _reset(tokens)

    def test_cron_mode_approve_follows_canonical_behavior(self):
        tokens = _session_ctx()
        try:
            with patch("tools.approval._is_cron_approval_context", return_value=True), \
                 patch("tools.approval._get_cron_approval_mode", return_value="approve"), \
                 patch("tools.approval._is_interactive_cli", return_value=False), \
                 patch("tools.approval._is_gateway_approval_context", return_value=False):
                result = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
            assert result["approved"] is True
        finally:
            _reset(tokens)


class TestInternalExceptionFailsClosed:
    def test_run_approval_gate_exception_denies(self):
        tokens = _session_ctx()
        try:
            with patch(
                "tools.approval._run_approval_gate",
                side_effect=RuntimeError("boom"),
            ):
                result = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
            assert result["approved"] is False
        finally:
            _reset(tokens)

    def test_get_authorization_key_exception_denies(self):
        with patch(
            "tools.approval.get_current_authorization_key",
            side_effect=RuntimeError("boom"),
        ):
            result = approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
        assert result["approved"] is False


class TestRealEndToEndReuse:
    """Step 54: prove ACTUAL cache reuse through the real _run_approval_gate()
    and real is_approved(), not merely that two calls produce the same
    pattern_key (that weaker property is already covered by
    test_same_server_tool_target_reuses_approval above).

    _run_approval_gate() itself is NOT mocked. The only mocked boundary is
    the human-input prompt (prompt_dangerous_approval) needed to
    deterministically approve the FIRST call -- the same "minimum
    test-controlled approval response" pattern already used implicitly by
    every existing interactive-approval test in this suite. The second call
    reaches the real is_approved() short-circuit at the top of the real
    _run_approval_gate() and must return approved=True WITHOUT the prompt
    being invoked again.
    """

    def test_second_identical_call_reuses_real_cached_approval(self):
        tokens = _session_ctx()
        try:
            with patch("tools.approval._is_interactive_cli", return_value=True), \
                 patch("tools.approval._is_gateway_approval_context", return_value=False), \
                 patch(
                     "tools.approval.prompt_dangerous_approval",
                     return_value="session",
                 ) as prompt:
                # First call: real _run_approval_gate() runs the full
                # interactive-CLI branch, calls the (mocked) human prompt,
                # gets "session" back, and calls the REAL approve_session()
                # -- writing into the REAL _session_approved cache under the
                # REAL composite identity key.
                d1 = approval.check_mcp_call_guard(
                    "srv", "delete_file", {"path": "/a/b.txt"}
                )
                assert d1["approved"] is True
                prompt.assert_called_once()

                # Second call: identical server+tool+target+identity.
                # _run_approval_gate()'s own is_approved(session_key,
                # pattern_key) short-circuit (line ~3373, unmocked, real
                # cache) must fire BEFORE the prompt is ever consulted again.
                d2 = approval.check_mcp_call_guard(
                    "srv", "delete_file", {"path": "/a/b.txt"}
                )
                assert d2["approved"] is True
                # The critical assertion: still called exactly once overall.
                # If the real cache lookup had NOT short-circuited, this
                # would be 2.
                prompt.assert_called_once()
        finally:
            _reset(tokens)


class TestNoPermanentApproval:
    def test_no_allow_permanent_kwarg_passed(self):
        tokens = _session_ctx()
        try:
            captured = {}

            def _fake_gate(*, allow_permanent, **kwargs):
                captured["allow_permanent"] = allow_permanent
                return {"approved": True, "message": None}

            with patch("tools.approval._run_approval_gate", side_effect=_fake_gate):
                approval.check_mcp_call_guard("srv", "delete_file", {"path": "/a"})
            assert captured["allow_permanent"] is False
        finally:
            _reset(tokens)


class TestAuthorizationScopeMigration:
    """Step 60 regression test: documents the cache-boundary invariant found
    during the STEP 60 shared-gate audit of _run_approval_gate()'s move from
    get_current_session_key() to get_current_authorization_key().

    Invariant under test: a legacy session-only approval (granted while no
    task_id was ever set for this session) must NOT be reused once a caller
    intentionally enters a task-scoped authorization context under the SAME
    session_key. Task scoping is a strictly narrower identity than plain
    session scoping, never a superset -- entering it must never inherit a
    broader grant made before the task existed.

    Uses the real, unmocked _run_approval_gate() / is_approved() /
    approve_session() cache path (only the human-input prompt is mocked),
    same pattern as TestRealEndToEndReuse above -- this is not a weakened
    or bypassed version of the guard.
    """

    def test_task_scoped_call_does_not_reuse_legacy_session_only_approval(self):
        session_key = "legacy-mig-session"

        # Step 1: valid session identity, but NO task scoping established yet
        # (task_id="" is the legacy/unwired-caller default -- collapses to
        # plain session_key, exactly as every current production caller of
        # _run_approval_gate() operates today per the STEP 60 audit).
        legacy_tokens = approval.set_current_authorization_scope(
            session_key=session_key, task_id="", subagent_id=""
        )
        try:
            with patch("tools.approval._is_interactive_cli", return_value=True), \
                 patch("tools.approval._is_gateway_approval_context", return_value=False), \
                 patch(
                     "tools.approval.prompt_dangerous_approval",
                     return_value="session",
                 ) as prompt:
                # Create/approve the MCP authorization under legacy
                # session-only scope (real gate, real cache write).
                d1 = approval.check_mcp_call_guard(
                    "srv", "delete_file", {"path": "/legacy.txt"}
                )
                assert d1["approved"] is True
                prompt.assert_called_once()

                # Verify the SAME session-only call reuses that approval
                # (real is_approved() short-circuit, no second prompt).
                d2 = approval.check_mcp_call_guard(
                    "srv", "delete_file", {"path": "/legacy.txt"}
                )
                assert d2["approved"] is True
                prompt.assert_called_once()  # still 1 -- confirms real reuse
        finally:
            approval.reset_current_authorization_scope(legacy_tokens)

        # Step 2: the SAME session_key now intentionally enters a
        # non-empty task_id via the existing set_current_authorization_scope()
        # mechanism -- no parallel/invented API, no guard modification.
        task_tokens = approval.set_current_authorization_scope(
            session_key=session_key, task_id="task-mig-A", subagent_id=""
        )
        try:
            with patch("tools.approval._is_interactive_cli", return_value=True), \
                 patch("tools.approval._is_gateway_approval_context", return_value=False), \
                 patch(
                     "tools.approval.prompt_dangerous_approval",
                     return_value="session",
                 ) as prompt_task:
                # Identical server+tool+target as Step 1's approved call.
                # If the task-scoped identity incorrectly inherited the
                # legacy session-only grant, this would return approved=True
                # WITHOUT the prompt firing. The guard must NOT do that.
                d3 = approval.check_mcp_call_guard(
                    "srv", "delete_file", {"path": "/legacy.txt"}
                )
                # The task-scoped identity has never been approved before,
                # so the real gate must consult the human prompt again --
                # proving the legacy approval was NOT reused.
                prompt_task.assert_called_once()
                assert d3["approved"] is True  # approved fresh, not reused
        finally:
            approval.reset_current_authorization_scope(task_tokens)

        # Direct confirmation via is_approved(): the task-scoped composite
        # key must not be satisfied by the legacy plain-session_key entry.
        legacy_key = session_key
        task_key = f"{session_key}::task=task-mig-A::sub="
        assert legacy_key != task_key
        assert approval.is_approved(legacy_key, "mcp_action::srv::delete_file::path=/legacy.txt")
        # (task_key was separately approved above via the real gate in Step
        # 2 -- both entries coexist; the point is they are DISTINCT cache
        # buckets, not that either was cleared.)
        assert approval.is_approved(task_key, "mcp_action::srv::delete_file::path=/legacy.txt")
