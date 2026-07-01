"""
Provenance gates for dangerous tools.

This module implements shadow-mode and enforce-mode gates that check
provenance tokens before allowing irreversible actions.

Gates are added to handle_function_call() in model_tools.py.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .store import EvidenceStore
from .errors import ProvenanceError, CountMismatchError, FalseAbsenceError

logger = logging.getLogger(__name__)

# Gate configuration - controls shadow vs enforce mode per tool
GATE_MODE = {
    "send_message": os.environ.get("PROVENANCE_GATE_SEND_MESSAGE", "shadow"),  # shadow | enforce | off
    "write_file": os.environ.get("PROVENANCE_GATE_WRITE_FILE", "off"),
    "run_fusion": os.environ.get("PROVENANCE_GATE_RUN_FUSION", "off"),
}

# Per-CHECK enforcement granularity (surgical rollout). A violation is tagged
# with its class prefix ("[count]", "[absence]", "[citation]"); each class can
# independently enforce (block) or shadow (log-only). This lets us block the
# measured-safe count-mismatch class while keeping absence/citation in shadow
# until their real-traffic false-positive rate is known.
#   enforce = block on violation of this class
#   shadow  = log the would-block but allow
CHECK_MODE = {
    "count": os.environ.get("PROVENANCE_CHECK_COUNT", "enforce"),
    "absence": os.environ.get("PROVENANCE_CHECK_ABSENCE", "shadow"),
    "citation": os.environ.get("PROVENANCE_CHECK_CITATION", "shadow"),
}


def _classify(violation: str) -> str:
    """Extract the check-class from a violation's '[class] ...' prefix."""
    if violation.startswith("[") and "]" in violation:
        return violation[1:violation.index("]")]
    return "citation"  # untagged legacy violations default to the citation class

# Global provenance enforcement kill switch
PROVENANCE_DISABLED = os.environ.get("PROVENANCE_DISABLED", "0") == "1"

# Evidence store singleton (initialized on first use)
_EVIDENCE_STORE: Optional[EvidenceStore] = None


def get_evidence_store() -> Optional[EvidenceStore]:
    """Get or create the global evidence store."""
    global _EVIDENCE_STORE
    
    if PROVENANCE_DISABLED:
        return None
    
    if _EVIDENCE_STORE is None:
        try:
            secret_hex = os.environ.get("HERMES_PROVENANCE_SECRET")
            if not secret_hex:
                logger.warning("HERMES_PROVENANCE_SECRET not set - provenance gates disabled")
                return None
            
            secret = bytes.fromhex(secret_hex)
            db_path = os.path.expanduser("~/.hermes/provenance.db")
            
            _EVIDENCE_STORE = EvidenceStore(db_path, secret)
            logger.info(f"Provenance system initialized: {db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize provenance store: {e}")
            return None
    
    return _EVIDENCE_STORE


def extract_dollar_amounts(text: str) -> List[str]:
    """Extract dollar amounts from text for uncited claim detection."""
    # Matches: $123, $1,234, $1,234.56
    pattern = r'\$[\d,]+(?:\.\d{2})?'
    return re.findall(pattern, text)


def extract_fusion_claims(text: str) -> List[str]:
    """Detect if text contains Fusion-related claims."""
    keywords = ["fusion", "consensus", "multi-model", "openrouter fusion"]
    text_lower = text.lower()
    return [kw for kw in keywords if kw in text_lower]


# Countable nouns that indicate a claimed result count (NabaOS result_count check).
_COUNTABLE_NOUNS = (
    r"emails?|messages?|results?|records?|items?|files?|rows?|entries?|"
    r"transactions?|matches?|hits?|documents?|invoices?|orders?|posts?|"
    r"tickets?|issues?|commits?|deals?|accounts?|holdings?|positions?"
)
_COUNT_RE = re.compile(rf"\b(\d+)\s+({_COUNTABLE_NOUNS})\b", re.IGNORECASE)

# Absence phrases (abhāva) - claims that something is not there.
_ABSENCE_RE = re.compile(
    r"\b("
    r"no\s+(?:results?|records?|matches?|emails?|messages?|files?|entries?|data)|"
    r"not\s+found|"
    r"does\s+not\s+exist|doesn'?t\s+exist|"
    r"couldn'?t\s+find|could\s+not\s+find|cannot\s+find|can'?t\s+find|"
    r"nothing\s+(?:found|in|from|matching)|"
    r"no\s+such\s+(?:file|record|entry|email|message)|"
    r"there\s+(?:is|are)\s+no\b|"
    r"none\s+(?:found|exist)"
    r")",
    re.IGNORECASE,
)


def extract_count_claims(text: str) -> List[Dict[str, Any]]:
    """Extract 'N <countable-noun>' claims from text. Returns [{count, noun, phrase}]."""
    claims = []
    for m in _COUNT_RE.finditer(text):
        claims.append({
            "count": int(m.group(1)),
            "noun": m.group(2).lower(),
            "phrase": m.group(0),
        })
    return claims


def extract_absence_claims(text: str) -> List[str]:
    """Extract absence assertions ('no results', 'not found', ...) from text."""
    return [m.group(0) for m in _ABSENCE_RE.finditer(text)]


def _cited_result_counts(citations: List[Dict[str, Any]]) -> List[int]:
    """result_count values available across all citations (claim-supplied 'count' field)."""
    counts = []
    for cite in citations:
        c = cite.get("count")
        if isinstance(c, int):
            counts.append(c)
    return counts


def _available_result_counts(
    citations: List[Dict[str, Any]],
    session_id: str,
    store: EvidenceStore,
) -> List[int]:
    """
    Result counts available to check a claim against.

    Precedence: explicit citations (Option A) if present; otherwise
    auto-resolve from this session's search receipts (Option B).
    Only receipts that actually resolve in this session are counted.
    """
    counts: List[int] = []
    resolved_from_citations = False
    for cite in citations:
        tid = cite.get("token_id")
        if not tid:
            continue
        tok = store.get(tid)
        if tok is not None and tok.session_id == session_id:
            counts.append(tok.result_count)
            resolved_from_citations = True
    if resolved_from_citations:
        return counts
    # Option B fallback: session search receipts
    receipts = store.recent_search_receipts(
        session_id, tool_names=("search_files", "web_search", "gmail_search")
    )
    return [r.result_count for r in receipts]


def verify_count_claims(
    body: str,
    citations: List[Dict[str, Any]],
    session_id: str,
    store: EvidenceStore,
) -> Tuple[bool, List[str]]:
    """
    NabaOS count check: every 'N <noun>' claim in the body must be supported by
    an available receipt whose result_count equals N.

    Available receipts = explicit citations if supplied, else this session's
    search receipts (auto-resolve). If there are no count claims, passes.
    If a claim's N matches no available receipt AND at least one receipt
    contradicts it, it's a violation.
    """
    violations: List[str] = []
    count_claims = extract_count_claims(body)
    if not count_claims:
        return True, violations

    available = _available_result_counts(citations, session_id, store)
    if not available:
        # No receipts to check against -> cannot verify. Shadow-safe: do not
        # hard-block coincidental numbers with zero evidence either way.
        return True, violations

    for claim in count_claims:
        n = claim["count"]
        if n not in available:
            violations.append(
                f"[count] Count mismatch: claimed '{claim['phrase']}' but session "
                f"receipts report counts {sorted(set(available))}"
            )

    return (len(violations) == 0, violations)


def verify_absence_claims(
    body: str,
    citations: List[Dict[str, Any]],
    session_id: str,
    store: EvidenceStore,
) -> Tuple[bool, List[str]]:
    """
    NabaOS abhāva check: an absence claim ('not found', 'no results') is only
    valid if an available search receipt has result_count == 0.

    Available receipts = explicit citations if supplied, else this session's
    search receipts (auto-resolve).
    - No relevant receipt at all -> unproven absence (violation).
    - All available receipts returned > 0 -> false absence (violation).
    - At least one receipt with result_count == 0 -> legitimate (pass).
    """
    violations: List[str] = []
    absence_claims = extract_absence_claims(body)
    if not absence_claims:
        return True, violations

    available = _available_result_counts(citations, session_id, store)

    for phrase in absence_claims:
        if not available:
            violations.append(
                f"[absence] Unproven absence: '{phrase}' — no search receipt backs this claim"
            )
        elif all(c > 0 for c in available):
            violations.append(
                f"[absence] False absence: '{phrase}' — session search receipt(s) returned "
                f"{sorted(set(available))} result(s), not empty"
            )
        # else: at least one receipt has result_count == 0 -> legitimate absence

    return (len(violations) == 0, violations)


def verify_send_message_provenance(
    args: Dict[str, Any],
    session_id: str,
    store: EvidenceStore
) -> Tuple[bool, List[str]]:
    """
    Verify provenance for send_message tool.
    
    Returns:
        (is_valid, violations) tuple
        - is_valid: True if all checks pass
        - violations: List of violation descriptions
    """
    violations = []
    
    # Check citations
    citations = args.get("citations", [])
    body = args.get("body", "") or args.get("message", "") or args.get("content", "")
    
    # Verify each citation
    for cite in citations:
        token_id = cite.get("token_id")
        claim_id = cite.get("claim_id")
        value = cite.get("value")
        
        if not token_id or not claim_id:
            violations.append(f"[citation] Citation missing token_id or claim_id: {cite}")
            continue
        
        try:
            store.verify(
                token_id=token_id,
                claim_id=claim_id,
                content=value,
                session_id=session_id
            )
        except ProvenanceError as e:
            violations.append(f"[citation] Citation verification failed for {claim_id}: {str(e)}")
    
    # Defense in depth: check for uncited dollar amounts
    dollar_amounts = extract_dollar_amounts(body)
    for amount in dollar_amounts:
        # Check if this amount is cited
        # Parse the dollar amount to compare numerically
        amount_value = float(amount.replace("$", "").replace(",", ""))
        cited = any(
            abs(float(cite.get("value", 0)) - amount_value) < 0.01  # Within 1 cent
            for cite in citations
            if isinstance(cite.get("value"), (int, float))
        )
        if not cited:
            violations.append(f"[citation] Uncited dollar amount: {amount}")
    
    # Check for Fusion claims without receipts
    fusion_keywords = extract_fusion_claims(body)
    if fusion_keywords:
        # Require at least one fusion receipt
        has_fusion_receipt = any(
            cite.get("claim_id", "").startswith("fusion.")
            for cite in citations
        )
        if not has_fusion_receipt:
            violations.append(f"[citation] Claims Fusion result (keywords: {fusion_keywords}) without execution receipt")

    # NabaOS count-mismatch check (the SHLD / $7,041-refund failure class)
    count_ok, count_violations = verify_count_claims(body, citations, session_id, store)
    violations.extend(count_violations)

    # NabaOS false-absence check (the "evidence_store.py is fabricated" failure class)
    absence_ok, absence_violations = verify_absence_claims(body, citations, session_id, store)
    violations.extend(absence_violations)

    return (len(violations) == 0, violations)


def apply_provenance_gate(
    function_name: str,
    function_args: Dict[str, Any],
    session_id: Optional[str],
    _test_store: Optional[EvidenceStore] = None,  # For testing only
) -> Optional[str]:
    """
    Apply provenance gate before tool execution.
    
    Returns:
        - None if gate passes (allow execution)
        - JSON error string if gate blocks
    """
    # Global kill switch
    if PROVENANCE_DISABLED:
        return None
    
    # Check if this tool has a gate
    mode = GATE_MODE.get(function_name, "off")
    if mode == "off":
        return None
    
    # Get evidence store (use test store if provided)
    store = _test_store or get_evidence_store()
    if store is None:
        logger.warning(f"Provenance store unavailable, allowing {function_name}")
        return None
    
    # Session ID required for verification
    if not session_id:
        logger.warning(f"No session_id provided for {function_name}, skipping provenance check")
        return None
    
    # Apply tool-specific verification
    violations = []
    
    if function_name == "send_message":
        is_valid, violations = verify_send_message_provenance(
            function_args, session_id, store
        )
    else:
        # Other tools not yet implemented
        return None
    
    # Log violations, split by per-check enforcement mode
    if violations:
        blocking = [v for v in violations if CHECK_MODE.get(_classify(v), "shadow") == "enforce"]
        shadowed = [v for v in violations if v not in blocking]

        store.audit(
            event="GATE_VIOLATION",
            tool=function_name,
            reason="; ".join(violations),
            session_id=session_id,
            mode=mode,
            blocked=bool(blocking),
            details=json.dumps(
                {"args": function_args, "blocking": blocking, "shadowed": shadowed},
                default=str,
            ),
        )

        if shadowed:
            logger.info(f"SHADOW MODE: Would have blocked {function_name} due to: {shadowed}")

        # Only block if the tool gate is on AND at least one ENFORCED-class
        # violation fired. Shadow-class violations are logged but never block.
        if mode == "enforce" and blocking:
            logger.warning(f"Provenance gate BLOCKED {function_name}: {blocking}")
            return json.dumps({
                "status": "BLOCKED",
                "error_code": "PROVENANCE_FAILURE",
                "violations": blocking,
                "remediation": (
                    "Re-fetch the data with the appropriate tool to obtain valid provenance tokens. "
                    "Include citations in your message with token_id, claim_id, and value fields."
                )
            }, ensure_ascii=False)
        # Otherwise allow (shadow, or no enforced-class violation)
        return None
    
    # All checks passed
    return None
