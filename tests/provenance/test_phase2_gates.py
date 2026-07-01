"""
Phase 2 hardening tests: count-mismatch and false-absence detection.

These target the two failure classes that bit Ed's real June 2026 sessions:
1. COUNT/NUMBER MISMATCH - "you said N, the receipt says M"
   (SHLD $10.9K inflation; $7,041-vs-$3,456 refund)
2. FALSE ABSENCE - claiming "not found / no results / doesn't exist"
   when no search receipt with an empty result set backs the claim
   (the "evidence_store.py is fabricated" lie from a single wrong-name grep)

Aligned to NabaOS (arXiv:2603.10060): result_count field + facts extraction,
verified by trusted code, not the model's self-report.

Behavior-contract tests (invariants), not value snapshots, per AGENTS.md.
Offline, $0 cost.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.store import EvidenceStore, ProvenanceToken
from agent.provenance.errors import (
    CountMismatchError,
    FalseAbsenceError,
    ProvenanceError,
)
from agent.provenance.gate import (
    verify_count_claims,
    verify_absence_claims,
    verify_send_message_provenance,
    extract_count_claims,
    extract_absence_claims,
)


@pytest.fixture
def store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    secret = os.urandom(32)
    s = EvidenceStore(db_path, secret)
    yield s
    s.close()
    os.unlink(db_path)


@pytest.fixture
def session_id():
    return f"test_session_{os.urandom(8).hex()}"


# ============================================================================
# PHASE 1 PREREQUISITE: facts + result_count on receipts, tamper-proof
# ============================================================================


def test_mint_stores_facts_and_result_count(store, session_id):
    """Receipt must persist facts dict + result_count so gates have ground truth."""
    token = store.mint(
        claim_id="gmail.inbox.search",
        source_uri="gmail://search?q=kelvin",
        content=["msg1", "msg2", "msg3"],
        session_id=session_id,
        tool_name="gmail_search",
        facts={"sender": "kelvin@example.com"},
        result_count=3,
    )
    fetched = store.get(token.token_id)
    assert fetched is not None
    assert fetched.result_count == 3
    assert fetched.facts == {"sender": "kelvin@example.com"}


def test_facts_and_count_are_signed(store, session_id):
    """
    result_count/facts must be inside the HMAC-signed payload.
    Tampering with result_count after minting must fail signature verification.
    """
    token = store.mint(
        claim_id="web.search.results",
        source_uri="web://search",
        content=["a", "b"],
        session_id=session_id,
        tool_name="web_search",
        result_count=2,
    )
    # Tamper: rewrite result_count in the DB behind the store's back
    store.db.execute(
        "UPDATE evidence SET result_count = ? WHERE token_id = ?",
        (999, token.token_id),
    )
    store.db.commit()

    from agent.provenance.errors import InvalidSignatureError

    with pytest.raises(InvalidSignatureError):
        store.verify(
            token_id=token.token_id,
            claim_id="web.search.results",
            content=["a", "b"],
            session_id=session_id,
        )


def test_backward_compat_default_facts_count(store, session_id):
    """Minting without facts/result_count must still work (defaults)."""
    token = store.mint(
        claim_id="portfolio.value",
        source_uri="broker://x",
        content=100.0,
        session_id=session_id,
        tool_name="read_portfolio",
    )
    assert token.result_count == 0
    assert token.facts == {}
    # And it verifies clean
    store.verify(
        token_id=token.token_id,
        claim_id="portfolio.value",
        content=100.0,
        session_id=session_id,
    )


# ============================================================================
# COUNT-CLAIM EXTRACTION
# ============================================================================


def test_extract_count_claims_finds_numbers():
    """Extractor should find 'N emails', 'N results', 'N messages' patterns."""
    text = "I found 5 emails from Kelvin and 3 messages in the thread."
    claims = extract_count_claims(text)
    counts = {c["count"] for c in claims}
    assert 5 in counts
    assert 3 in counts


def test_extract_count_claims_ignores_prose_numbers():
    """A year or a version number should not be treated as a result count."""
    text = "In 2026 we shipped version 4 of the tool."
    claims = extract_count_claims(text)
    # No 'N <countable-noun>' pattern -> no count claims
    assert claims == [] or all(c["count"] not in (2026,) for c in claims)


# ============================================================================
# COUNT-MISMATCH GATE (NabaOS: result_count check)
# ============================================================================


def test_count_match_passes_when_equal(store, session_id):
    """Claiming 3 emails with a receipt that says result_count=3 -> valid."""
    token = store.mint(
        claim_id="gmail.search.kelvin",
        source_uri="gmail://search",
        content=["m1", "m2", "m3"],
        session_id=session_id,
        tool_name="gmail_search",
        result_count=3,
    )
    body = "I found 3 emails from Kelvin."
    citations = [{"claim_id": "gmail.search.kelvin", "token_id": token.token_id,
                  "value": ["m1", "m2", "m3"], "count": 3}]
    ok, violations = verify_count_claims(body, citations, session_id, store)
    assert ok, violations


def test_count_mismatch_blocked(store, session_id):
    """
    THE $7,041-VS-$3,456 CLASS: claim a number that contradicts the receipt.
    Receipt says 3, agent writes '5 emails' -> must flag.
    """
    token = store.mint(
        claim_id="gmail.search.kelvin",
        source_uri="gmail://search",
        content=["m1", "m2", "m3"],
        session_id=session_id,
        tool_name="gmail_search",
        result_count=3,
    )
    body = "I found 5 emails from Kelvin."
    citations = [{"claim_id": "gmail.search.kelvin", "token_id": token.token_id,
                  "value": ["m1", "m2", "m3"], "count": 5}]  # claimed 5, receipt 3
    ok, violations = verify_count_claims(body, citations, session_id, store)
    assert not ok
    assert any("count" in v.lower() or "mismatch" in v.lower() for v in violations)


# ============================================================================
# FALSE-ABSENCE EXTRACTION + GATE (NabaOS: abhāva verification)
# ============================================================================


def test_extract_absence_claims_detects_negations():
    """Extractor should flag 'no results', 'not found', 'does not exist', 'nothing'."""
    for text in [
        "No results were found for that query.",
        "The file does not exist.",
        "I couldn't find any matching records.",
        "There is nothing in the inbox from that sender.",
    ]:
        claims = extract_absence_claims(text)
        assert len(claims) >= 1, f"failed to detect absence in: {text}"


def test_false_absence_blocked_without_receipt(store, session_id):
    """
    THE 'evidence_store.py is fabricated' CLASS: claim absence with NO search
    receipt backing it -> must flag. Absence must be proven by an empty result.
    """
    body = "That file does not exist; no results found."
    citations = []  # nothing backing the absence claim
    ok, violations = verify_absence_claims(body, citations, session_id, store)
    assert not ok
    assert any("absence" in v.lower() or "no receipt" in v.lower()
               or "unproven" in v.lower() for v in violations)


def test_false_absence_blocked_when_receipt_had_results(store, session_id):
    """
    Claiming 'not found' while the cited search receipt actually returned
    results (result_count > 0) is a lie -> must flag.
    """
    token = store.mint(
        claim_id="files.search.store",
        source_uri="fs://search?name=store",
        content=["store.py"],
        session_id=session_id,
        tool_name="search_files",
        result_count=1,  # the search DID find something
    )
    body = "No results found for that file."
    citations = [{"claim_id": "files.search.store", "token_id": token.token_id,
                  "value": ["store.py"], "count": 1}]
    ok, violations = verify_absence_claims(body, citations, session_id, store)
    assert not ok
    assert violations


def test_true_absence_allowed_with_empty_receipt(store, session_id):
    """
    Legitimate absence: cited a search receipt with result_count == 0.
    This MUST pass - we don't want false positives on honest 'not found'.
    """
    token = store.mint(
        claim_id="files.search.nonexistent",
        source_uri="fs://search?name=nonexistent",
        content=[],
        session_id=session_id,
        tool_name="search_files",
        result_count=0,  # genuinely empty
    )
    body = "No results found - that file does not exist."
    citations = [{"claim_id": "files.search.nonexistent", "token_id": token.token_id,
                  "value": [], "count": 0}]
    ok, violations = verify_absence_claims(body, citations, session_id, store)
    assert ok, violations


# ============================================================================
# INTEGRATION: full send_message gate wires in the new checks
# ============================================================================


def test_send_message_gate_blocks_count_mismatch(store, session_id):
    token = store.mint(
        claim_id="gmail.search.kelvin",
        source_uri="gmail://search",
        content=["m1", "m2", "m3"],
        session_id=session_id,
        tool_name="gmail_search",
        result_count=3,
    )
    args = {
        "body": "I found 5 emails from Kelvin.",
        "citations": [{"claim_id": "gmail.search.kelvin", "token_id": token.token_id,
                       "value": ["m1", "m2", "m3"], "count": 5}],
    }
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    assert not is_valid
    assert any("count" in v.lower() or "mismatch" in v.lower() for v in violations)


def test_send_message_gate_blocks_false_absence(store, session_id):
    args = {
        "body": "That transaction does not exist; no records found.",
        "citations": [],
    }
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    assert not is_valid
    assert any("absence" in v.lower() or "unproven" in v.lower()
               or "no receipt" in v.lower() for v in violations)


def test_send_message_gate_clean_message_passes(store, session_id):
    """No counts, no absence claims, no dollar amounts -> clean pass."""
    args = {"body": "Thanks for the update, talk soon.", "citations": []}
    is_valid, violations = verify_send_message_provenance(args, session_id, store)
    assert is_valid, violations


# ============================================================================
# REGRESSION GUARD
# ============================================================================


def test_phase2_required_tests_present():
    import inspect
    mod = sys.modules[__name__]
    fns = [n for n, o in inspect.getmembers(mod)
           if inspect.isfunction(o) and n.startswith("test_")]
    required = [
        "test_facts_and_count_are_signed",
        "test_count_mismatch_blocked",
        "test_false_absence_blocked_without_receipt",
        "test_true_absence_allowed_with_empty_receipt",
    ]
    for r in required:
        assert r in fns, f"Missing required Phase 2 test: {r}"
