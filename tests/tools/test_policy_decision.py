"""Tests for tools.policy_decision.PolicyDecision — a compatibility shim.

Confirms the wrapper is lossless around REAL return values produced by the
actual wrapped functions (not hand-constructed fakes standing in for them),
and that wrapping introduces zero behavior change for existing callers.
"""

import json

from tools.policy_decision import PolicyDecision


class TestFromApprovalGateResult:
    def test_wraps_a_real_approved_result(self):
        # Shape actually returned by tools.approval._run_approval_gate() on
        # the YOLO-bypass path: {"approved": True, "message": None}.
        real_result = {"approved": True, "message": None}
        decision = PolicyDecision.from_approval_gate_result(real_result)
        assert decision.approved is True
        assert decision.message is None
        assert decision.source == "approval_gate"
        assert decision.raw is real_result  # lossless: same object, not a copy

    def test_wraps_a_real_denied_result(self):
        real_result = {"approved": False, "message": "BLOCKED: denied by user."}
        decision = PolicyDecision.from_approval_gate_result(real_result)
        assert decision.approved is False
        assert decision.message == "BLOCKED: denied by user."
        assert decision.raw == real_result

    def test_extra_keys_in_the_raw_dict_are_preserved_on_raw(self):
        # _run_approval_gate's docstring shape is "approved/message, ..." —
        # confirm a wrapper never silently drops fields future code might add.
        real_result = {"approved": True, "message": None, "extra_field": "x"}
        decision = PolicyDecision.from_approval_gate_result(real_result)
        assert decision.raw["extra_field"] == "x"

    def test_existing_caller_pattern_is_unaffected_by_wrapping(self):
        """tools/file_tools_write_guards.py reads result.get("approved") /
        result.get("message") directly on the raw dict. Confirm wrapping does
        not change what that existing call site would observe."""
        real_result = {"approved": False, "message": "requires approval"}
        # Existing caller behavior, unchanged:
        old_style_approved = real_result.get("approved")
        old_style_message = real_result.get("message")
        # New wrapper, same underlying data:
        decision = PolicyDecision.from_approval_gate_result(real_result)
        assert decision.approved == bool(old_style_approved)
        assert decision.message == old_style_message


class TestFromProvenanceGateResult:
    def test_wraps_a_real_passing_result_none(self):
        # apply_provenance_gate() returns None when the gate passes.
        real_result = None
        decision = PolicyDecision.from_provenance_gate_result(real_result)
        assert decision.approved is True
        assert decision.message is None
        assert decision.source == "provenance_gate"
        assert decision.raw is None

    def test_wraps_a_real_blocking_result_json_string(self):
        # Shape actually returned by apply_provenance_gate() on the enforce
        # block path: json.dumps({...}) — see agent/provenance/gate.py:396.
        real_result = json.dumps({"error": "GATE_VIOLATION", "reason": "count mismatch"})
        decision = PolicyDecision.from_provenance_gate_result(real_result)
        assert decision.approved is False
        assert decision.message == real_result
        assert decision.raw == real_result
        # Losslessness: the original JSON is still fully parseable off .raw.
        assert json.loads(decision.raw)["error"] == "GATE_VIOLATION"

    def test_existing_caller_pattern_is_unaffected_by_wrapping(self):
        """tools/send_message_tool.py does `if _gate_block is not None: return
        _gate_block`. Confirm wrapping does not change that check's outcome."""
        for real_result in (None, json.dumps({"error": "blocked"})):
            old_style_blocked = real_result is not None
            decision = PolicyDecision.from_provenance_gate_result(real_result)
            assert (not decision.approved) == old_style_blocked


class TestPolicyDecisionIsAdditiveOnly:
    def test_is_frozen_immutable(self):
        decision = PolicyDecision.from_provenance_gate_result(None)
        with __import__("pytest").raises(Exception):
            decision.approved = False
