"""send_email() -- the ONE in-process way an actual Gmail send can happen.

Implements the v3 design spec (vault 04-Projects/2026-11-03-send-email-policy-design.md):
  - every recipient field (To/Cc/Bcc) checked against the approved list independently
  - rate limit counted from the append-only send log, no separate counter file
  - subject/body/attachments scanned for tax/SSN patterns
  - from_account="ed" always requires a card
  - fail-closed: card-required sends do NOT go out if the approval gate is unreachable;
    known-recipient auto-sends are unaffected by gate reachability
  - every outcome (sent/denied/blocked_gate_unreachable) is logged, via the shared
    tools.email_send_log module (same schema the email platform adapter writes to)

Reuses enforced_gmail_send.py's build_message()/gmail_send() -- loaded from its one
canonical, protected path (mirrors outbound_classify.py's CANONICAL_ENFORCED_GMAIL_PATH;
the two constants must be kept in sync, they cannot import from each other across repos).
"""
from __future__ import annotations

import importlib.util
import os
import re
import types
from dataclasses import dataclass, field
from email.utils import getaddresses
from typing import Any, Callable, Optional, Sequence

from tools.email_send_log import append_log_entry, count_today

CANONICAL_ENFORCED_GMAIL_PATH = os.path.realpath(
    "/home/hermes/.hermes/skills/email/enforced-gmail-send/scripts/enforced_gmail_send.py"
)

DEFAULT_APPROVED_LIST_PATH = "/home/hermes/.hermes/protected/email_approved_recipients.json"
DEFAULT_FROM_ACCOUNT_ADDRESS = "hermes.ed.rivera@gmail.com"
MANDATORY_CC = "ed.rivera@gmail.com"
DAILY_AUTO_SEND_LIMIT = 20

# Change 4: tax/SSN pattern set. Applied to subject, body, AND attachment
# names/content -- not just attachments (that was the pre-v3 gap).
_SSN_HYPHENATED_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SSN_BARE_RE = re.compile(r"\b\d{9}\b")
_TAX_CONTEXT_RE = re.compile(
    r"\bSSN\b|\bITIN\b|\bEIN\b|form\s*1040|\btax\s*return\b|\bW-?2\b|\b1099\b",
    re.I,
)
# JNC client-file naming pattern, e.g. "RIVERA_ED_2025" style tokens.
_JNC_CLIENT_FILE_RE = re.compile(r"\b[A-Z]{2,}_[A-Z]{2,}_20\d{2}\b")


def _text_has_tax_ssn_pattern(text: str) -> bool:
    if not text:
        return False
    if _SSN_HYPHENATED_RE.search(text):
        return True
    if _JNC_CLIENT_FILE_RE.search(text):
        return True
    if _TAX_CONTEXT_RE.search(text):
        return True
    # A bare 9-digit run is only SSN-shaped WITH tax context nearby (a plain
    # phone/account number is not inherently sensitive on its own).
    if _SSN_BARE_RE.search(text) and _TAX_CONTEXT_RE.search(text):
        return True
    return False


class GateUnreachableError(Exception):
    """Raised by an approval_gate implementation when no human/gateway channel
    exists to deliver a card (Telegram down, no interactive session, etc.)."""


@dataclass
class SendEmailResult:
    outcome: str  # "sent" | "denied" | "blocked_gate_unreachable"
    sent: bool
    message_id: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "sent": self.sent, "message_id": self.message_id,
                "reasons": self.reasons, "detail": self.detail}


def _load_enforced_gmail_module() -> types.ModuleType:
    """Import enforced_gmail_send.py from its ONE canonical path -- the exact
    same resolution outbound_classify.py trusts, so send_email() can never be
    tricked into running a copy planted somewhere else."""
    spec = importlib.util.spec_from_file_location(
        "enforced_gmail_send_for_send_email_tool", CANONICAL_ENFORCED_GMAIL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load canonical enforced_gmail_send.py at {CANONICAL_ENFORCED_GMAIL_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_approved_list(path: str) -> dict:
    import json
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"domains": [], "addresses": []}
    return {
        "domains": [d.lower() for d in data.get("domains", [])],
        "addresses": [a.lower() for a in data.get("addresses", [])],
    }


def _is_approved_recipient(address: str, approved: dict) -> bool:
    address = (address or "").strip().lower()
    if not address:
        return False
    if address in approved["addresses"]:
        return True
    return any(address.endswith(domain) for domain in approved["domains"])


def _all_recipients(to: str, cc: Optional[Sequence[str]], bcc: Optional[Sequence[str]]) -> list[str]:
    addrs = [to] if to else []
    addrs += list(cc or [])
    addrs += list(bcc or [])
    return [a.lower() for a in addrs if a]


# Fix 1 (Ed's review, 11/9/26): "stranger@evil.com, ken@jnccpas.com" as a
# single `to` string passed the old endswith() check because the WHOLE
# comma-joined string happens to end with "@jnccpas.com" -- the unapproved
# first address never got checked on its own. Parsing must happen per
# individual address, using email.utils.getaddresses (the same RFC parser
# the stdlib email package itself uses), and MUST be run against the
# addresses as they actually ended up in the BUILT message's To/Cc/Bcc
# headers -- not the raw input strings -- so a header-smuggling trick that
# bypasses the input but not the header can't slip through either.
def _parsed_addresses(header_value: Optional[str]) -> list[str]:
    """Every individual address in a comma-joined header value, lowercased.

    Raises ValueError if any parsed entry is not a single, well-formed
    addr-spec (empty address, or a realname with no '@', etc.) -- callers
    must treat that as "cannot verify this field is safe" and card it,
    never guess which part was intended.
    """
    if not header_value:
        return []
    out = []
    for realname, addr in getaddresses([header_value]):
        addr = (addr or "").strip()
        if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"):
            raise ValueError(f"unparsable address entry in header: {realname!r} {addr!r}")
        out.append(addr.lower())
    return out


def _recipients_from_built_message(msg, bcc: Sequence[str]) -> list[str]:
    """Recipients as they exist in the BUILT message's own headers (To, Cc),
    plus Bcc (which build_message() never writes to a header deliberately --
    Bcc entries are validated from the input list itself, individually
    parsed the same way, since there is no header to re-derive them from).
    """
    recipients: list[str] = []
    try:
        recipients += _parsed_addresses(msg.get("To"))
        recipients += _parsed_addresses(msg.get("Cc"))
    except ValueError:
        raise
    for addr in bcc or []:
        recipients += _parsed_addresses(addr)
    return recipients


def _default_approval_gate(payload: dict) -> dict:
    """Production default: escalate to the real in-process human-approval gate
    (tools.approval.request_tool_approval), which already implements fail-closed-
    when-no-human semantics identically to what this spec requires.
    """
    from tools.approval import request_tool_approval

    reason = (
        f"send_email card: to={payload.get('to')} cc={payload.get('cc')} bcc={payload.get('bcc')} "
        f"subject={payload.get('subject')!r} reasons={payload.get('reasons')}"
    )
    return request_tool_approval("send_email", reason, rule_key=f"send_email:{payload.get('draft_id', '')}")


def _classify_gate_result(result: dict) -> str:
    """Map a tools.approval-shaped result to 'approved' | 'denied' | 'gate_unreachable'."""
    if result.get("approved"):
        return "approved"
    # _blocked() (no human/gateway present, fail_closed_when_no_human) carries
    # no "outcome" key -- that is exactly the gate-unreachable signal. A real
    # human decision (_denied()) always sets "outcome" (denied/timeout/cancelled/...).
    if "outcome" not in result:
        return "gate_unreachable"
    return "denied"


def send_email(
    to: str,
    subject: str,
    body_path: str,
    *,
    cc: Optional[Sequence[str]] = None,
    bcc: Optional[Sequence[str]] = None,
    attachments: Optional[Sequence[str]] = None,
    from_account: str = "hermes",
    gmail_client: Optional[Any] = None,
    approval_gate: Optional[Callable[[dict], dict]] = None,
    log_path: Optional[str] = None,
    approved_list_path: Optional[str] = None,
    enforced_module: Optional[types.ModuleType] = None,
) -> dict:
    """Send one email, enforcing every v3 policy check before any real send.

    *gmail_client* (test seam): object with ``refresh_token() -> str``,
    ``send(raw, thread_id, token) -> dict`` (Gmail messages.send shape,
    containing at least ``"id"``). Production default loads the real
    enforced_gmail_send.py module and uses its token/refresh/send functions.

    *approval_gate* (test seam): ``callable(payload: dict) -> dict`` shaped
    like ``tools.approval``'s gate results (``{"approved": bool, ...}``,
    "outcome" key present only for a real human decision). Defaults to the
    real in-process gate.
    """
    approval_gate = approval_gate or _default_approval_gate
    approved_list_path = approved_list_path or DEFAULT_APPROVED_LIST_PATH
    enforced = enforced_module or _load_enforced_gmail_module()

    cc = list(cc or [])
    bcc = list(bcc or [])

    with open(body_path, encoding="utf-8") as f:
        body_text = f.read()

    approved = _load_approved_list(approved_list_path)
    reasons: list[str] = []

    # Build the real message FIRST (never sent yet -- build_message() only
    # constructs the MIME object) so every downstream check inspects the
    # recipients as they actually ended up in the message, not the raw
    # inputs (Fix 1: a header-smuggling/comma-joined-string trick that
    # fools a check on the input string must still be caught against the
    # built headers).
    args = types.SimpleNamespace(
        to=to, subject=subject, body_file=body_path, cc=cc, bcc=bcc,
        attach=list(attachments or []), in_reply_to=None, references=None,
    )
    token = gmail_client.refresh_token() if gmail_client else enforced.refresh_token()
    msg, cc_list = enforced.build_message(args, token)
    if MANDATORY_CC not in cc_list:
        raise RuntimeError("INTERNAL ERROR: mandatory CC missing -- refusing to send.")

    # Change 1 / Fix 1: every recipient field checked independently, parsed
    # from the built message's headers (To/Cc) plus the raw Bcc list (never
    # written to a header). Any address that doesn't parse as exactly one
    # well-formed addr-spec is treated the same as "unknown" -- fail closed,
    # never guess which part of a malformed field was intended.
    try:
        recipients = _recipients_from_built_message(msg, bcc)
    except ValueError:
        recipients = []
        reasons.append("unknown_recipient")
    unknown = [addr for addr in recipients if not _is_approved_recipient(addr, approved)]
    if unknown:
        reasons.append("unknown_recipient")

    # Change 4: subject + body + attachment names scanned (not just attachment content).
    scan_text = "\n".join([subject or "", body_text] + list(attachments or []))
    if _text_has_tax_ssn_pattern(scan_text):
        reasons.append("tax_ssn_pattern")

    # Minor fix (Ed's review, 11/9/26): from_account="ed" is not a card
    # candidate -- there is no credential for ed.rivera@gmail.com on this
    # box at all, so a card that could never be approved into an actual
    # send is just noise. Reject outright, before any gate/log/send path.
    if from_account == "ed":
        raise ValueError(
            "send_email: from_account='ed' is rejected outright -- no credential exists "
            "for ed.rivera@gmail.com on this box. There is no card to show for this; it "
            "can never be approved into a real send."
        )

    # Change 2: rate limit counted live from the append-only log, no counter file.
    sent_today = count_today(path=log_path)
    if sent_today >= DAILY_AUTO_SEND_LIMIT:
        reasons.append("rate_limit_21st")

    needs_card = bool(reasons)

    def _log(outcome: str, message_id: Optional[str]) -> None:
        append_log_entry({
            "message_id": message_id, "to": (to or "").lower(), "cc": [a.lower() for a in cc],
            "bcc": [a.lower() for a in bcc], "subject": subject, "from_account": from_account,
            "source": "send_email", "outcome": outcome, "reasons": reasons,
        }, path=log_path)

    if needs_card:
        payload = {"to": to, "cc": cc, "bcc": bcc, "subject": subject, "reasons": reasons,
                   "draft_id": f"{to}:{subject}"}
        try:
            gate_result = approval_gate(payload)
        except GateUnreachableError:
            gate_result = {"approved": False}
        verdict = _classify_gate_result(gate_result)
        if verdict == "gate_unreachable":
            _log("blocked_gate_unreachable", None)
            return SendEmailResult(
                outcome="blocked_gate_unreachable", sent=False, reasons=reasons,
                detail="approval gate unreachable; card-required send was NOT sent",
            ).to_dict()
        if verdict == "denied":
            _log("denied", None)
            return SendEmailResult(
                outcome="denied", sent=False, reasons=reasons,
                detail="approval denied; not sent",
            ).to_dict()
        # approved -> fall through to the real send below.

    # The real send (auto-send path, or a card that was just approved).
    # msg/cc_list/token were already built above (Fix 1) -- re-using them
    # means what got approved is exactly what gets sent, byte for byte.
    import base64
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    if gmail_client is not None:
        result = gmail_client.send(raw, None, token)
    else:
        result = enforced.gmail_send(raw, None, token)
    message_id = result["id"]

    _log("sent", message_id)
    return SendEmailResult(outcome="sent", sent=True, message_id=message_id, reasons=reasons,
                            detail="sent").to_dict()
