"""
Option B: auto-resolve count/absence claims against the SESSION'S minted
receipts, without depending on the model to cite them (defense-in-depth vs
NabaOS self-tagging weakness).

Semantics under test:
- COUNT: if a search receipt this session contradicts a claimed 'N <noun>',
  flag it. If a receipt supports it, pass.
- ABSENCE: 'not found' auto-passes ONLY if a session search receipt has
  result_count == 0. If session search receipts all returned >0, flag as
  false absence. If NO relevant receipt exists at all, flag as unproven
  (shadow-safe: this is where explicit-citation Option A closes the gap).
- Explicit citations, when supplied, take precedence over auto-resolve.

Real store, real path. $0.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.store import EvidenceStore
from agent.provenance.gate import verify_send_message_provenance


@pytest.fixture
def store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    s = EvidenceStore(db_path, os.urandom(32))
    yield s
    s.close()
    os.unlink(db_path)


@pytest.fixture
def session_id():
    return f"autoresolve_{os.urandom(6).hex()}"


def test_autoresolve_count_mismatch_from_session_receipt(store, session_id):
    """
    Model searched (receipt result_count=3) then writes 'I found 5 emails'
    with NO explicit citation. Auto-resolve must catch the contradiction.
    """
    store.mint(
        claim_id="search_files.content.kelvin",
        source_uri="fs://search",
        content={"pattern": "kelvin"},
        session_id=session_id,
        tool_name="search_files",
        result_count=3,
    )
    args = {"message": "I found 5 emails from Kelvin."}  # no citations
    ok, violations = verify_send_message_provenance(args, session_id, store)
    assert not ok
    assert any("count" in v.lower() or "mismatch" in v.lower() for v in violations)


def test_autoresolve_count_supported_passes(store, session_id):
    """A session receipt with result_count=3 supports '3 results' -> pass."""
    store.mint(
        claim_id="search_files.content.kelvin",
        source_uri="fs://search",
        content={"pattern": "kelvin"},
        session_id=session_id,
        tool_name="search_files",
        result_count=3,
    )
    args = {"message": "The search returned 3 results."}
    ok, violations = verify_send_message_provenance(args, session_id, store)
    assert ok, violations


def test_autoresolve_false_absence_from_session_receipt(store, session_id):
    """
    Model searched and FOUND something (result_count=1) then writes
    'no results found' with no citation. Auto-resolve must catch the lie.
    """
    store.mint(
        claim_id="search_files.files.store",
        source_uri="fs://search",
        content={"pattern": "store"},
        session_id=session_id,
        tool_name="search_files",
        result_count=1,
    )
    args = {"message": "No results found for that file; it does not exist."}
    ok, violations = verify_send_message_provenance(args, session_id, store)
    assert not ok
    assert any("absence" in v.lower() for v in violations)


def test_autoresolve_true_absence_passes(store, session_id):
    """
    Model searched and found nothing (result_count=0), then writes
    'no results found'. Legitimate -> must pass (no false positive).
    """
    store.mint(
        claim_id="search_files.files.nope",
        source_uri="fs://search",
        content={"pattern": "nope"},
        session_id=session_id,
        tool_name="search_files",
        result_count=0,
    )
    args = {"message": "No results found — that file does not exist."}
    ok, violations = verify_send_message_provenance(args, session_id, store)
    assert ok, violations


def test_autoresolve_scoped_to_session(store):
    """A receipt from another session must NOT satisfy this session's claim."""
    store.mint(
        claim_id="search_files.files.nope",
        source_uri="fs://search",
        content={"pattern": "nope"},
        session_id="other_session",
        tool_name="search_files",
        result_count=0,
    )
    args = {"message": "No results found — nothing exists."}
    ok, violations = verify_send_message_provenance(args, "my_session", store)
    # No receipt in MY session -> unproven absence, must flag
    assert not ok
    assert any("absence" in v.lower() or "unproven" in v.lower() for v in violations)


def test_explicit_citation_takes_precedence(store, session_id):
    """
    When the model DOES supply an explicit citation, it is used (Option A),
    even alongside auto-resolve. A correct explicit count passes.
    """
    tok = store.mint(
        claim_id="gmail.kelvin",
        source_uri="gmail://s",
        content=["a", "b", "c"],
        session_id=session_id,
        tool_name="gmail_search",
        result_count=3,
    )
    args = {
        "message": "I found 3 emails from Kelvin.",
        "citations": [{"claim_id": "gmail.kelvin", "token_id": tok.token_id,
                       "value": ["a", "b", "c"], "count": 3}],
    }
    ok, violations = verify_send_message_provenance(args, session_id, store)
    assert ok, violations
