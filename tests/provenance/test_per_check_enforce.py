"""
Per-check enforcement granularity for the send_message gate.

Surgical rollout: count-mismatch enforces (blocks), false-absence stays in
shadow (logs only) until real-traffic FP rate is known. Verified by the
benchmark (count FP=0) vs the documented absence-claim residual risk.

Semantics under test:
- A count-mismatch violation, with count check in 'enforce', returns a BLOCK.
- A false-absence violation, with absence check in 'shadow', returns None
  (allowed) but is audited as a would-block.
- Clean messages never block.
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import agent.provenance.gate as gate
from agent.provenance.store import EvidenceStore


@pytest.fixture
def store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    s = EvidenceStore(db_path, os.urandom(32))
    yield s
    s.close()
    os.unlink(db_path)


@pytest.fixture
def surgical_mode(monkeypatch):
    """send_message gate ON; count enforces, absence shadow."""
    monkeypatch.setitem(gate.GATE_MODE, "send_message", "enforce")
    monkeypatch.setitem(gate.CHECK_MODE, "count", "enforce")
    monkeypatch.setitem(gate.CHECK_MODE, "absence", "shadow")
    monkeypatch.setattr(gate, "PROVENANCE_DISABLED", False)


def test_count_mismatch_blocks_in_enforce(store, surgical_mode):
    session_id = "surg1"
    store.mint(claim_id="search_files.x", source_uri="fs://s", content={},
               session_id=session_id, tool_name="search_files", result_count=3)
    args = {"message": "I found 5 files."}
    result = gate.apply_provenance_gate("send_message", args, session_id, _test_store=store)
    assert result is not None, "count mismatch must block in enforce"
    payload = json.loads(result)
    assert payload["status"] == "BLOCKED"
    assert any("count" in v.lower() or "mismatch" in v.lower() for v in payload["violations"])


def test_false_absence_logs_but_allows_in_shadow(store, surgical_mode):
    session_id = "surg2"
    store.mint(claim_id="search_files.y", source_uri="fs://s", content={},
               session_id=session_id, tool_name="search_files", result_count=2)
    args = {"message": "No results found; it does not exist."}
    result = gate.apply_provenance_gate("send_message", args, session_id, _test_store=store)
    assert result is None, "absence in shadow must ALLOW (log only)"
    # And it must have been audited as a would-block
    audit = store.get_audit_log(session_id=session_id)
    assert any(e["event"] == "GATE_VIOLATION" for e in audit)


def test_clean_message_never_blocks(store, surgical_mode):
    session_id = "surg3"
    store.mint(claim_id="search_files.z", source_uri="fs://s", content={},
               session_id=session_id, tool_name="search_files", result_count=5)
    args = {"message": "Thanks, talk soon."}
    result = gate.apply_provenance_gate("send_message", args, session_id, _test_store=store)
    assert result is None


def test_mixed_violations_block_only_enforced_class(store, surgical_mode):
    """
    Message trips BOTH a count mismatch (enforce) and an absence claim (shadow).
    Must BLOCK (because at least one enforced class fired) and the block payload
    must name the count violation.
    """
    session_id = "surg4"
    store.mint(claim_id="search_files.m", source_uri="fs://s", content={},
               session_id=session_id, tool_name="search_files", result_count=3)
    args = {"message": "I found 9 files but no results were found for the other query."}
    result = gate.apply_provenance_gate("send_message", args, session_id, _test_store=store)
    assert result is not None
    payload = json.loads(result)
    assert any("count" in v.lower() for v in payload["violations"])
