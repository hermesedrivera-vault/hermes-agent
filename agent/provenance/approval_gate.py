"""
Approval gate for outbound external communications.

Catches the failure class observed 2026-06-30: the agent sent emails to
external contractors (via the terminal -> Gmail API path) WITHOUT the
explicit user "Approved" that the operational protocol requires.

The existing provenance gate (gate.py) keys off function_name and only
covers the `send_message` tool. External email/SMS sent by running a
Python script through the `terminal` tool slips past it entirely. This
gate closes that hole by inspecting the *content* of a tool call for
outbound-comms signals regardless of which tool carries them.

Design follows the project axiom: "Model proposes, trusted code disposes."
- Trusted code (this module) detects an outbound external comm.
- It then checks for a framework-observed approval token in the session's
  approval ledger — NOT a flag the model set on itself.
- Shadow mode logs would-be blocks; enforce mode blocks.

Wired into handle_function_call() in model_tools.py, right after the
provenance gate.
"""

import json
import logging
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Per-tool mode: off | shadow | enforce. Default shadow so we measure the
# false-positive rate on live traffic before ever blocking (same rollout
# discipline used for the send_message provenance gate).
APPROVAL_GATE_MODE = {
    "terminal": os.environ.get("APPROVAL_GATE_TERMINAL", "shadow"),
    "send_message": os.environ.get("APPROVAL_GATE_SEND_MESSAGE", "shadow"),
}

# Global kill switch (mirrors PROVENANCE_DISABLED).
APPROVAL_GATE_DISABLED = os.environ.get("APPROVAL_GATE_DISABLED", "0") == "1"

# How long an explicit approval stays valid, in seconds. After this the
# agent must obtain a fresh "Approved" — approvals are not permanent.
APPROVAL_TTL_SECONDS = int(os.environ.get("APPROVAL_TTL_SECONDS", "900"))  # 15 min

_APPROVAL_DB: Optional[str] = None


# ── Detection ────────────────────────────────────────────────────────────

# Email send signals: an actual send call, not merely touching the mail
# resource. Must match a *.send( invocation or sendmail — NOT
# messages().list()/get() reads. This precision is what keeps inbox reads
# from being flagged (regression caught by test_reading_email_is_not_a_send).
_EMAIL_SEND_VERBS = re.compile(
    r"(\.messages\(\)\.send\s*\(|"   # Gmail API: service.users().messages().send(
    r"\bsendmail\s*\(|"              # smtplib sendmail(
    r"\.send_message\s*\()",         # smtplib send_message(
    re.IGNORECASE,
)
_EMAIL_ADDR = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# SMS / phone send signals.
_SMS_SEND_VERBS = re.compile(
    r"\b(twilio|messages\.create|send_sms|sendSms)\b", re.IGNORECASE
)
_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


def _collect_text(function_args: Dict[str, Any]) -> str:
    """Flatten the tool args into one searchable string."""
    parts: List[str] = []
    for v in function_args.values():
        if isinstance(v, str):
            parts.append(v)
        else:
            try:
                parts.append(json.dumps(v, default=str))
            except Exception:
                parts.append(str(v))
    return "\n".join(parts)


def detect_outbound_comm(
    function_name: str, function_args: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Decide whether this tool call is an outbound EXTERNAL communication.

    Returns a dict describing the detection (channel + recipients) if so,
    else None. Detection is content-based so it catches email sent via the
    `terminal` tool, not just the dedicated send_message tool.
    """
    text = _collect_text(function_args)

    # Email: require BOTH a send verb and a recipient address. This avoids
    # flagging the agent merely reading or drafting.
    if _EMAIL_SEND_VERBS.search(text):
        recipients = _EMAIL_ADDR.findall(text)
        external = [r for r in recipients if _is_external(r)]
        if external:
            return {
                "channel": "email",
                "recipients": sorted(set(external)),
                "tool": function_name,
            }

    # SMS: send verb + phone number.
    if _SMS_SEND_VERBS.search(text):
        phones = _PHONE.findall(text)
        if phones:
            return {
                "channel": "sms",
                "recipients": sorted(set(phones)),
                "tool": function_name,
            }

    return None


# Recipients that are "self" — copying the user or the agent's own mailbox
# is not an external send that needs approval on its own.
_SELF_ADDRESSES = {
    "ed.rivera@gmail.com",
    "hermes.ed.rivera@gmail.com",
}


def _is_external(addr: str) -> bool:
    return addr.lower() not in _SELF_ADDRESSES


# ── Approval ledger (framework-observed, not model-attested) ─────────────


def _db_path() -> str:
    global _APPROVAL_DB
    if _APPROVAL_DB is None:
        _APPROVAL_DB = os.path.expanduser("~/.hermes/approvals.db")
    return _APPROVAL_DB


def _connect(db_path: Optional[str] = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or _db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            scope TEXT NOT NULL,
            raw_text TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id, timestamp)"
    )
    conn.commit()
    return conn


# What counts as an explicit approval from the USER. Deliberately strict:
# bare "ok" / "good" / "yes" do NOT approve an external send. The protocol
# requires an explicit approve word.
_APPROVAL_PHRASE = re.compile(
    r"\b(approved|approve|send it|go ahead and send|you'?re approved)\b",
    re.IGNORECASE,
)


def record_user_message(
    session_id: str, text: str, db_path: Optional[str] = None
) -> bool:
    """
    Inspect a USER message and, if it is an explicit approval, record it in
    the ledger. Called by trusted code on the inbound user-message path —
    the model cannot write here on its own behalf.

    Returns True if an approval was recorded.
    """
    if not text or not _APPROVAL_PHRASE.search(text):
        return False
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO approvals (session_id, timestamp, scope, raw_text) VALUES (?, ?, ?, ?)",
            (session_id, time.time(), "external_comm", text[:500]),
        )
        conn.commit()
    finally:
        conn.close()
    return True


def has_valid_approval(
    session_id: str,
    now: Optional[float] = None,
    db_path: Optional[str] = None,
) -> bool:
    """
    Is there an unexpired explicit approval for this session?

    This is the trusted-code check the gate relies on. It reads the ledger
    written from the USER message path, never a model-set flag.
    """
    if not session_id:
        return False
    conn = _connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT timestamp FROM approvals
            WHERE session_id = ? AND scope = 'external_comm'
            ORDER BY timestamp DESC LIMIT 1
            """,
            (session_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return False
    current = now if now is not None else time.time()
    return (current - row["timestamp"]) <= APPROVAL_TTL_SECONDS


# ── Gate ─────────────────────────────────────────────────────────────────


def apply_approval_gate(
    function_name: str,
    function_args: Dict[str, Any],
    session_id: Optional[str],
    now: Optional[float] = None,
    db_path: Optional[str] = None,
) -> Optional[str]:
    """
    Block an outbound external comm that lacks a fresh user approval.

    Returns:
        - None  -> allow execution (no outbound comm, or approval present,
                   or shadow mode)
        - JSON  -> block message (enforce mode only)
    """
    if APPROVAL_GATE_DISABLED:
        return None

    mode = APPROVAL_GATE_MODE.get(function_name, "off")
    if mode == "off":
        return None

    detection = detect_outbound_comm(function_name, function_args)
    if detection is None:
        return None  # not an outbound external comm

    approved = has_valid_approval(session_id or "", now=now, db_path=db_path)
    if approved:
        _audit(
            session_id,
            "APPROVAL_GATE_PASS",
            f"{detection['channel']} -> {detection['recipients']} (approved)",
            mode,
            blocked=False,
            db_path=db_path,
        )
        return None

    # No valid approval — this is the violation.
    reason = (
        f"Outbound {detection['channel']} to {detection['recipients']} "
        f"via {detection['tool']} without explicit user approval"
    )
    _audit(
        session_id,
        "APPROVAL_GATE_VIOLATION",
        reason,
        mode,
        blocked=(mode == "enforce"),
        db_path=db_path,
    )

    if mode == "enforce":
        logger.warning("Approval gate BLOCKED %s: %s", function_name, reason)
        return json.dumps(
            {
                "status": "BLOCKED",
                "error_code": "APPROVAL_REQUIRED",
                "channel": detection["channel"],
                "recipients": detection["recipients"],
                "remediation": (
                    "External communications require explicit user approval. "
                    "Show the user the drafted message and wait for them to "
                    "reply 'Approved' before sending. Do not send until then."
                ),
            },
            ensure_ascii=False,
        )

    # Shadow mode: log only.
    logger.info("SHADOW MODE: would block %s: %s", function_name, reason)
    return None


def _audit(
    session_id: Optional[str],
    event: str,
    reason: str,
    mode: str,
    blocked: bool,
    db_path: Optional[str] = None,
) -> None:
    """Append to the same approvals DB in a separate audit table."""
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                session_id TEXT,
                event TEXT NOT NULL,
                reason TEXT,
                mode TEXT,
                blocked BOOLEAN
            )
            """
        )
        conn.execute(
            "INSERT INTO approval_audit (timestamp, session_id, event, reason, mode, blocked) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), session_id, event, reason, mode, blocked),
        )
        conn.commit()
    finally:
        conn.close()
