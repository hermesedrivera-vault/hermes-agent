"""
Adversarial test suite for provenance system.

Tests the 5 canonical failure modes that provenance MUST block:
1. Narrated tool results (fake "Fusion said X" without execution)
2. Inflated numbers ($58.50 → $10,900)
3. Token reuse (verify AAPL, write about MSFT)
4. Forged signatures (agent tries to mint own tokens)
5. Cross-session token theft

These tests run offline ($0 cost) and must pass before any gate enforcement.
"""

import hashlib
import hmac
import json
import os
import tempfile
import time

import pytest

# Import from agent.provenance
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.store import EvidenceStore, ProvenanceToken
from agent.provenance.errors import (
    ClaimMismatchError,
    ContentTamperedError,
    CrossSessionError,
    InvalidSignatureError,
    TokenNotFoundError,
)


@pytest.fixture
def store():
    """Create temporary evidence store for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    secret = os.urandom(32)
    store = EvidenceStore(db_path, secret)

    yield store

    store.close()
    os.unlink(db_path)


@pytest.fixture
def session_id():
    """Generate test session ID."""
    return f"test_session_{os.urandom(8).hex()}"


# ============================================================================
# ADVERSARIAL TEST 1: Narrated Tool Results (The Fake Fusion Bug)
# ============================================================================


def test_narrated_fusion_without_execution(store, session_id):
    """
    FAILURE MODE: Agent claims "Fusion said X" but never called run_fusion().
    
    This is the Jun 30, 2026 incident - I fabricated a Fusion consensus.
    The gate MUST block this.
    """
    # NO run_fusion() call happened - no token minted
    # Agent tries to claim Fusion result

    from agent.provenance.errors import ProvenanceError

    # Try to verify a claim without any token
    with pytest.raises(TokenNotFoundError):
        store.verify(
            token_id="tok_nonexistent",
            claim_id="fusion.recommendation",
            content="buy TSLA",
            session_id=session_id,
        )

    # Check audit log recorded the block
    audit = store.get_audit_log(session_id=session_id, limit=1)
    assert len(audit) == 1
    assert audit[0]["event"] == "VERIFY_FAILED"
    assert audit[0]["blocked"] == True
    assert "not found" in audit[0]["reason"].lower()


# ============================================================================
# ADVERSARIAL TEST 2: Inflated Numbers (The SHLDQ Bug)
# ============================================================================


def test_inflated_number_tampered_content(store, session_id):
    """
    FAILURE MODE: Agent changes $58.50 to $10,900 in a bankruptcy claim.
    
    Real value from broker: $58.50
    Agent writes: "SHLDQ bankruptcy: $10,900 loss"
    
    Content hash MUST detect tampering.
    """
    # Mint token with real value
    real_value = 58.50
    token = store.mint(
        claim_id="portfolio.SHLD.value",
        source_uri="broker_api://positions",
        content=real_value,
        session_id=session_id,
        tool_name="read_portfolio",
    )

    # Agent tries to cite with INFLATED value
    inflated_value = 10900.00

    with pytest.raises(ContentTamperedError):
        store.verify(
            token_id=token.token_id,
            claim_id="portfolio.SHLD.value",
            content=inflated_value,  # Tampered!
            session_id=session_id,
        )

    # Verify correct value works
    verified = store.verify(
        token_id=token.token_id,
        claim_id="portfolio.SHLD.value",
        content=real_value,  # Original value
        session_id=session_id,
    )
    assert verified.content_hash == hashlib.sha256(
        json.dumps(real_value, sort_keys=True).encode()
    ).hexdigest()


# ============================================================================
# ADVERSARIAL TEST 3: Token Reuse (Verify AAPL, Write About MSFT)
# ============================================================================


def test_token_reuse_claim_mismatch(store, session_id):
    """
    FAILURE MODE: Agent verifies AAPL data, then writes bankruptcy claim about MSFT.
    
    This is the "verified one thing, asserted something else" bug.
    claim_id matching MUST catch this.
    """
    # Mint token for AAPL
    aapl_price = 185.50
    token = store.mint(
        claim_id="portfolio.AAPL.price",
        source_uri="broker_api://quote/AAPL",
        content=aapl_price,
        session_id=session_id,
        tool_name="web_search",
    )

    # Agent tries to use AAPL token for MSFT claim
    msft_price = 420.00

    with pytest.raises(ClaimMismatchError):
        store.verify(
            token_id=token.token_id,
            claim_id="portfolio.MSFT.price",  # DIFFERENT claim!
            content=msft_price,
            session_id=session_id,
        )

    # Verify correct claim works
    verified = store.verify(
        token_id=token.token_id,
        claim_id="portfolio.AAPL.price",  # Correct claim
        content=aapl_price,
        session_id=session_id,
    )
    assert verified.claim_id == "portfolio.AAPL.price"


# ============================================================================
# ADVERSARIAL TEST 4: Forged Signatures (Agent Tries to Mint Own Tokens)
# ============================================================================


def test_forged_signature_detected(store, session_id):
    """
    FAILURE MODE: Agent tries to forge a token by guessing the HMAC signature.
    
    This should be cryptographically impossible.
    """
    # Agent tries to create a fake token with wrong signature
    fake_token_id = "tok_forged_by_agent"
    claim_id = "portfolio.total_value"
    content = 1000000.00  # $1M fake

    # Try to insert fake token directly (bypassing mint)
    content_hash = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    timestamp = time.time()

    # Agent tries to forge signature with wrong secret
    wrong_secret = os.urandom(32)
    fake_sig = hmac.new(
        wrong_secret, f"{claim_id}|fake_uri|{content_hash}|{timestamp}".encode(), hashlib.sha256
    ).hexdigest()

    # Manually insert fake token (simulating agent forgery attempt)
    store.db.execute(
        """
        INSERT INTO evidence
            (token_id, claim_id, source_uri, content_hash, timestamp,
             session_id, ttl_seconds, tool_name, signature, result_count, facts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            fake_token_id,
            claim_id,
            "fake_uri",
            content_hash,
            timestamp,
            session_id,
            3600,
            "forged_tool",
            fake_sig,
            0,
            "{}",
        ),
    )
    store.db.commit()

    # Try to verify - signature check MUST fail
    with pytest.raises(InvalidSignatureError):
        store.verify(
            token_id=fake_token_id,
            claim_id=claim_id,
            content=content,
            session_id=session_id,
        )


# ============================================================================
# ADVERSARIAL TEST 5: Cross-Session Token Theft
# ============================================================================


def test_cross_session_token_theft(store):
    """
    FAILURE MODE: Agent from session A tries to reuse token from session B.
    
    Prevents token theft across conversations.
    """
    session_a = "session_alice"
    session_b = "session_bob"

    # Alice's session mints a token
    alice_token = store.mint(
        claim_id="portfolio.balance",
        source_uri="broker_api://balance",
        content=50000.00,
        session_id=session_a,
        tool_name="read_portfolio",
    )

    # Bob's session tries to steal Alice's token
    with pytest.raises(CrossSessionError):
        store.verify(
            token_id=alice_token.token_id,
            claim_id="portfolio.balance",
            content=50000.00,
            session_id=session_b,  # DIFFERENT session!
        )

    # Verify it works in the correct session
    verified = store.verify(
        token_id=alice_token.token_id,
        claim_id="portfolio.balance",
        content=50000.00,
        session_id=session_a,  # Correct session
    )
    assert verified.session_id == session_a


# ============================================================================
# ADDITIONAL TESTS: TTL / Staleness
# ============================================================================


def test_stale_token_rejected(store, session_id):
    """
    FAILURE MODE: Agent uses old data for money decisions.
    
    TTL enforcement forces fresh retrieval.
    """
    # Mint token with 1-second TTL
    token = store.mint(
        claim_id="portfolio.TSLA.price",
        source_uri="broker_api://quote/TSLA",
        content=250.00,
        session_id=session_id,
        tool_name="web_search",
        ttl_seconds=1,  # Very short TTL
    )

    # Verify immediately - should work
    verified = store.verify(
        token_id=token.token_id,
        claim_id="portfolio.TSLA.price",
        content=250.00,
        session_id=session_id,
        now=token.timestamp,  # Same time
    )
    assert verified.token_id == token.token_id

    # Wait 2 seconds (simulated)
    future_time = token.timestamp + 2.0

    # Try to verify after TTL - should fail
    from agent.provenance.errors import StaleTokenError

    with pytest.raises(StaleTokenError):
        store.verify(
            token_id=token.token_id,
            claim_id="portfolio.TSLA.price",
            content=250.00,
            session_id=session_id,
            now=future_time,  # 2 seconds later
        )


# ============================================================================
# INTEGRATION TEST: Full Send Message Flow
# ============================================================================


def test_full_send_message_gate_simulation(store, session_id):
    """
    Simulate the full send_message gate flow.
    
    Agent fetches data → mints token → cites in email → gate verifies
    """
    # Step 1: Tool execution mints token
    portfolio_value = 105234.11
    token = store.mint(
        claim_id="portfolio.total_value",
        source_uri="broker_api://portfolio/summary",
        content=portfolio_value,
        session_id=session_id,
        tool_name="read_portfolio",
    )

    # Step 2: Agent constructs email with citation
    email_body = f"Your portfolio is now worth ${portfolio_value:,.2f}"
    citation = {
        "claim_id": "portfolio.total_value",
        "token_id": token.token_id,
        "value": portfolio_value,
    }

    # Step 3: send_message gate verifies citation
    verified = store.verify(
        token_id=citation["token_id"],
        claim_id=citation["claim_id"],
        content=citation["value"],
        session_id=session_id,
    )

    assert verified is not None
    assert verified.claim_id == "portfolio.total_value"

    # Audit log should show successful verification
    audit = store.get_audit_log(session_id=session_id)
    verify_events = [e for e in audit if e["event"] == "VERIFY_PASSED"]
    assert len(verify_events) >= 1


# ============================================================================
# SUMMARY FIXTURE: All Tests Must Pass Before Enforcement
# ============================================================================


def test_all_adversarial_modes_blocked():
    """
    Meta-test: confirms all 5 adversarial modes have coverage.
    
    This is the regression guard - if any test is removed, this fails.
    """
    import inspect

    current_module = sys.modules[__name__]
    test_functions = [
        name
        for name, obj in inspect.getmembers(current_module)
        if inspect.isfunction(obj) and name.startswith("test_")
    ]

    required_tests = [
        "test_narrated_fusion_without_execution",  # Fake tool results
        "test_inflated_number_tampered_content",  # Number inflation
        "test_token_reuse_claim_mismatch",  # Token reuse
        "test_forged_signature_detected",  # Signature forgery
        "test_cross_session_token_theft",  # Session theft
    ]

    for required in required_tests:
        assert required in test_functions, f"Missing required test: {required}"

    print(f"\n✓ All {len(required_tests)} adversarial tests present")
    print(f"✓ Total test coverage: {len(test_functions)} tests")
