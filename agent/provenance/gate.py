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
from .errors import ProvenanceError

logger = logging.getLogger(__name__)

# Gate configuration - controls shadow vs enforce mode per tool
GATE_MODE = {
    "send_message": os.environ.get("PROVENANCE_GATE_SEND_MESSAGE", "shadow"),  # shadow | enforce | off
    "write_file": os.environ.get("PROVENANCE_GATE_WRITE_FILE", "off"),
    "run_fusion": os.environ.get("PROVENANCE_GATE_RUN_FUSION", "off"),
}

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
            violations.append(f"Citation missing token_id or claim_id: {cite}")
            continue
        
        try:
            store.verify(
                token_id=token_id,
                claim_id=claim_id,
                content=value,
                session_id=session_id
            )
        except ProvenanceError as e:
            violations.append(f"Citation verification failed for {claim_id}: {str(e)}")
    
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
            violations.append(f"Uncited dollar amount: {amount}")
    
    # Check for Fusion claims without receipts
    fusion_keywords = extract_fusion_claims(body)
    if fusion_keywords:
        # Require at least one fusion receipt
        has_fusion_receipt = any(
            cite.get("claim_id", "").startswith("fusion.")
            for cite in citations
        )
        if not has_fusion_receipt:
            violations.append(f"Claims Fusion result (keywords: {fusion_keywords}) without execution receipt")
    
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
    
    # Log violations
    if violations:
        store.audit(
            event="GATE_VIOLATION",
            tool=function_name,
            reason="; ".join(violations),
            session_id=session_id,
            mode=mode,
            blocked=(mode == "enforce"),
            details=json.dumps(function_args, default=str)
        )
        
        if mode == "enforce":
            # BLOCKED
            logger.warning(f"Provenance gate BLOCKED {function_name}: {violations}")
            return json.dumps({
                "status": "BLOCKED",
                "error_code": "PROVENANCE_FAILURE",
                "violations": violations,
                "remediation": (
                    "Re-fetch the data with the appropriate tool to obtain valid provenance tokens. "
                    "Include citations in your message with token_id, claim_id, and value fields."
                )
            }, ensure_ascii=False)
        else:
            # SHADOW MODE: log but allow
            logger.info(f"SHADOW MODE: Would have blocked {function_name} due to: {violations}")
            return None
    
    # All checks passed
    return None
