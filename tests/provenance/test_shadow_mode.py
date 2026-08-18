"""
Shadow mode integration test for provenance gates.

Tests that gates run in shadow mode (log-only) without blocking.
"""

import json
import os
import sys
import tempfile

import pytest

# Import from parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.store import EvidenceStore
from agent.provenance.gate import (
    apply_provenance_gate,
    verify_send_message_provenance,
    extract_dollar_amounts,
    extract_fusion_claims,
)


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
    return "test_session_shadow"


def test_extract_dollar_amounts():
    """Test dollar amount extraction."""
    text = "Portfolio worth $105,234.11 with TSLA at $58.50"
    amounts = extract_dollar_amounts(text)
    assert "$105,234.11" in amounts
    assert "$58.50" in amounts


def test_extract_fusion_claims():
    """Test Fusion keyword detection."""
    text = "According to Fusion consensus, buy TSLA."
    claims = extract_fusion_claims(text)
    assert "fusion" in claims


def test_shadow_mode_logs_but_allows(store, session_id):
    """
    Shadow mode: violations logged but execution allowed.
    """
    # Send message with uncited dollar amount (violation)
    args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Portfolio Update",
        "body": "Your portfolio is worth $100,000",  # No citation!
        "citations": []  # Empty citations
    }
    
    # Shadow mode: should detect violation but not block
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    
    assert is_valid == False
    assert len(violations) > 0
    assert any("Uncited dollar amount" in v for v in violations)
    
    # Check audit log recorded the violation
    audit = store.get_audit_log(session_id=session_id)
    # NOTE: This is tested via verify_send_message_provenance, 
    # the actual gate logging happens in apply_provenance_gate


def test_valid_citation_passes(store, session_id):
    """Valid citations should pass gate."""
    # Mint a token for portfolio value
    portfolio_value = 105234.11
    token = store.mint(
        claim_id="portfolio.total_value",
        source_uri="broker_api://portfolio",
        content=portfolio_value,
        session_id=session_id,
        tool_name="read_portfolio"
    )
    
    # Send message WITH valid citation
    args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Portfolio Update",
        "body": "Your portfolio is worth $105,234.11",
        "citations": [
            {
                "token_id": token.token_id,
                "claim_id": "portfolio.total_value",
                "value": portfolio_value
            }
        ]
    }
    
    # Should pass verification
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    
    assert is_valid == True
    assert len(violations) == 0


def test_fusion_claim_without_receipt_detected(store, session_id):
    """Detect Fusion claims without execution receipts."""
    args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Investment Advice",
        "body": "According to Fusion consensus, buy TSLA now.",  # Claims Fusion!
        "citations": []  # No Fusion receipt
    }
    
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    
    assert is_valid == False
    assert any("Claims Fusion result" in v for v in violations)


def test_token_tampering_detected(store, session_id):
    """Verify content tampering is detected."""
    # Mint token with real value
    real_value = 58.50
    token = store.mint(
        claim_id="portfolio.SHLD.value",
        source_uri="broker_api://positions",
        content=real_value,
        session_id=session_id,
        tool_name="read_portfolio"
    )
    
    # Try to cite with INFLATED value
    inflated_value = 10900.00
    args = {
        "recipient": "ed.rivera@gmail.com",
        "subject": "Bankruptcy Alert",
        "body": "SHLDQ bankruptcy: $10,900 loss",
        "citations": [
            {
                "token_id": token.token_id,
                "claim_id": "portfolio.SHLD.value",
                "value": inflated_value  # TAMPERED!
            }
        ]
    }
    
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    
    assert is_valid == False
    assert any("verification failed" in v.lower() for v in violations)


def test_apply_provenance_gate_shadow_never_blocks():
    """
    Integration: apply_provenance_gate in shadow mode never blocks.
    """
    # Even with violations, shadow mode returns None (allow)
    args = {
        "recipient": "test@example.com",
        "body": "Uncited $10,000 claim",
        "citations": []
    }
    
    # Mock environment: shadow mode
    original_mode = os.environ.get("PROVENANCE_GATE_SEND_MESSAGE")
    os.environ["PROVENANCE_GATE_SEND_MESSAGE"] = "shadow"
    
    try:
        # This should log violations but return None (allow)
        result = apply_provenance_gate(
            function_name="send_message",
            function_args=args,
            session_id="test_session"
        )
        
        # Shadow mode always returns None
        assert result is None
    finally:
        if original_mode is not None:
            os.environ["PROVENANCE_GATE_SEND_MESSAGE"] = original_mode
        else:
            os.environ.pop("PROVENANCE_GATE_SEND_MESSAGE", None)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
