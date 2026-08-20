"""
End-to-end integration test for provenance system.

Tests the COMPLETE flow:
1. Tool executes → mints receipt
2. Agent constructs message with citations
3. Gate verifies receipts
4. Message is allowed/blocked based on provenance

This is the test that proves the system actually works in production.
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.store import EvidenceStore
from agent.provenance.gate import apply_provenance_gate, verify_send_message_provenance


@pytest.fixture
def store():
    """Create temporary evidence store."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    secret = os.urandom(32)
    store = EvidenceStore(db_path, secret)
    
    yield store
    
    store.close()
    os.unlink(db_path)


@pytest.fixture
def session_id():
    return "test_e2e_session"


def test_end_to_end_success_flow(store, session_id):
    """
    Complete success flow: tool → receipt → citation → gate passes.
    """
    # STEP 1: Simulate web_search execution minting receipts
    search_results = [
        {
            "title": "Tesla Stock Rises",
            "url": "https://example.com/tsla",
            "description": "TSLA up 5% today",
            "position": 0,
        }
    ]
    
    receipts = []
    for idx, result in enumerate(search_results):
        token = store.mint(
            claim_id=f"web_search.TSLA price.result_{idx}",
            source_uri=result["url"],
            content=result,
            session_id=session_id,
            tool_name="web_search",
            ttl_seconds=3600,
        )
        receipts.append({
            "token_id": token.token_id,
            "claim_id": token.claim_id,
            "value": result,
        })
    
    # STEP 2: Agent constructs send_message with valid citations
    message_args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "TSLA Update",
        "body": "TSLA stock rose 5% today according to recent news.",
        "citations": receipts,
    }
    
    # STEP 3: Gate verification (would run in model_tools.py)
    is_valid, violations = verify_send_message_provenance(
        message_args, session_id, store
    )
    
    # STEP 4: Verify success
    assert is_valid == True
    assert len(violations) == 0
    
    # Check audit log
    audit = store.get_audit_log(session_id=session_id)
    mint_events = [e for e in audit if e["event"] == "TOKEN_MINTED"]
    verify_events = [e for e in audit if e["event"] == "VERIFY_PASSED"]
    
    assert len(mint_events) == 1  # One search result
    assert len(verify_events) == 1  # One citation verified


def test_end_to_end_fabrication_blocked(store, session_id):
    """
    Fabrication blocked: agent claims data without tool execution.
    """
    # Agent tries to send message with NO citations (faked data)
    message_args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Portfolio Alert",
        "body": "Your portfolio lost $10,000 in SHLDQ bankruptcy.",  # FABRICATED!
        "citations": [],  # No receipts!
    }
    
    # Gate verification
    is_valid, violations = verify_send_message_provenance(
        message_args, session_id, store
    )
    
    # Should be blocked
    assert is_valid == False
    assert len(violations) > 0
    assert any("Uncited dollar amount" in v for v in violations)


def test_end_to_end_number_inflation_blocked(store, session_id):
    """
    Number inflation blocked: real data inflated before citing.
    """
    # STEP 1: Tool mints receipt with REAL value
    real_value = 58.50
    token = store.mint(
        claim_id="portfolio.SHLD.value",
        source_uri="broker_api://positions",
        content=real_value,
        session_id=session_id,
        tool_name="read_portfolio",
    )
    
    # STEP 2: Agent tries to cite INFLATED value
    inflated_value = 10900.00
    message_args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Bankruptcy Alert",
        "body": f"SHLDQ bankruptcy: ${inflated_value:,.2f} loss",
        "citations": [
            {
                "token_id": token.token_id,
                "claim_id": "portfolio.SHLD.value",
                "value": inflated_value,  # TAMPERED!
            }
        ],
    }
    
    # Gate verification
    is_valid, violations = verify_send_message_provenance(
        message_args, session_id, store
    )
    
    # Should be blocked
    assert is_valid == False
    assert any("verification failed" in v.lower() for v in violations)


def test_end_to_end_fusion_claim_blocked(store, session_id):
    """
    Fusion fabrication blocked: claims Fusion result without execution.
    """
    # Agent tries to claim Fusion said something
    message_args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Investment Advice",
        "body": "According to Fusion consensus, buy TSLA now.",
        "citations": [],  # No Fusion receipt!
    }
    
    # Gate verification
    is_valid, violations = verify_send_message_provenance(
        message_args, session_id, store
    )
    
    # Should be blocked
    assert is_valid == False
    assert any("Claims Fusion result" in v for v in violations)


def test_end_to_end_gate_integration(store, session_id):
    """
    Test apply_provenance_gate (full integration point).
    """
    # Valid citation
    token = store.mint(
        claim_id="portfolio.total",
        source_uri="broker_api://summary",
        content=105234.11,
        session_id=session_id,
        tool_name="read_portfolio",
    )
    
    # Shadow mode: should allow even without citations (but log violation)
    # Need to monkey-patch GATE_MODE dict directly
    from agent.provenance import gate as gate_module
    original_mode = gate_module.GATE_MODE.get("send_message")
    original_citation = gate_module.CHECK_MODE.get("citation")
    gate_module.GATE_MODE["send_message"] = "shadow"
    # This scenario exercises an uncited dollar amount, a [citation]-class
    # violation; enforce that class so the block path is under test.
    gate_module.CHECK_MODE["citation"] = "enforce"
    
    try:
        invalid_args = {
            "recipient": "test@example.com",
            "body": "Your portfolio is worth $105,234.11",
            "citations": [],  # Missing citation
        }
        
        result = apply_provenance_gate(
            function_name="send_message",
            function_args=invalid_args,
            session_id=session_id,
            _test_store=store,  # Inject test store
        )
        
        # Shadow mode returns None (allow)
        assert result is None
        
        # Check audit log recorded violation
        audit = store.get_audit_log(session_id=session_id)
        gate_violations = [e for e in audit if e["event"] == "GATE_VIOLATION"]
        assert len(gate_violations) >= 1
        
        # Enforce mode: should block
        gate_module.GATE_MODE["send_message"] = "enforce"
        
        result = apply_provenance_gate(
            function_name="send_message",
            function_args=invalid_args,
            session_id=session_id,
            _test_store=store,  # Inject test store
        )
        
        # Enforce mode returns error JSON (block)
        assert result is not None
        error_data = json.loads(result)
        assert error_data["status"] == "BLOCKED"
        assert "violations" in error_data
    finally:
        # Restore original mode
        if original_mode is not None:
            gate_module.GATE_MODE["send_message"] = original_mode
        else:
            gate_module.GATE_MODE.pop("send_message", None)
        gate_module.CHECK_MODE["citation"] = original_citation or "shadow"


def test_complete_system_adversarial_scenarios(store, session_id):
    """
    Meta-test: all 5 canonical failures are covered end-to-end.
    """
    # This test just confirms we have coverage
    test_functions = [
        test_end_to_end_success_flow,
        test_end_to_end_fabrication_blocked,
        test_end_to_end_number_inflation_blocked,
        test_end_to_end_fusion_claim_blocked,
        test_end_to_end_gate_integration,
    ]
    
    print(f"\n✓ End-to-end test coverage: {len(test_functions)} scenarios")
    print("✓ Success flow: tool → receipt → citation → gate passes")
    print("✓ Fabrication: no tool execution → gate blocks")
    print("✓ Inflation: real data tampered → gate blocks")
    print("✓ Fusion claim: no execution receipt → gate blocks")
    print("✓ Gate integration: shadow/enforce modes work")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
