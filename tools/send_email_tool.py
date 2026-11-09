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
import subprocess
import types
from dataclasses import dataclass, field
from email.utils import getaddresses, make_msgid
from typing import Any, Callable, Optional, Sequence

from tools.email_send_log import append_log_entry, count_today

CANONICAL_ENFORCED_GMAIL_PATH = os.path.realpath(
    "/home/hermes/.hermes/skills/email/enforced-gmail-send/scripts/enforced_gmail_send.py"
)

DEFAULT_APPROVED_LIST_PATH = "/home/hermes/.hermes/protected/email_approved_recipients.json"
DEFAULT_FROM_ACCOUNT_ADDRESS = "hermes.ed.rivera@gmail.com"
MANDATORY_CC = "ed.rivera@gmail.com"
DAILY_AUTO_SEND_LIMIT = 20

# Tax decision (Ed, 11/9/26): tax vocabulary ALONE -- "tax return", "1099",
# "W-2", "Form 1040" -- must NOT trigger a card; those words are too common
# in routine correspondence. Cards fire only on: an SSN-shaped number
# (dashed, spaced, or a bare 9-digit run that sits next to an SSN/ITIN/TIN
# label), or a JNC client file-name pattern, or either of those inside an
# attachment's extracted text (see Fix 5). _TAX_CONTEXT_RE is used ONLY to
# narrow the bare-9-digit case -- it is never itself a standalone trigger.
_SSN_HYPHENATED_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SSN_SPACED_RE = re.compile(r"\b\d{3}\s\d{2}\s\d{4}\b")
_SSN_BARE_RE = re.compile(r"\b\d{9}\b")
_TAX_CONTEXT_RE = re.compile(
    r"\bSSN\b|\bITIN\b|\bEIN\b|\bTIN\b",
    re.I,
)
# JNC client-file naming pattern, e.g. "RIVERA_ED_2025" style tokens.
_JNC_CLIENT_FILE_RE = re.compile(r"\b[A-Z]{2,}_[A-Z]{2,}_20\d{2}\b")


def _text_has_tax_ssn_pattern(text: str) -> bool:
    if not text:
        return False
    if _SSN_HYPHENATED_RE.search(text):
        return True
    if _SSN_SPACED_RE.search(text):
        return True
    if _JNC_CLIENT_FILE_RE.search(text):
        return True
    # A bare 9-digit run is only SSN-shaped when it sits next to an
    # SSN/ITIN/EIN/TIN label -- a plain phone/account/tracking number is
    # not inherently sensitive on its own, and tax vocabulary alone
    # ("tax return", "1099", "Form 1040", ...) is deliberately NOT part of
    # this check (Tax decision, 11/9/26).
    if _SSN_BARE_RE.search(text) and _TAX_CONTEXT_RE.search(text):
        return True
    return False


# Fix 5 (Ed's review, 11/9/26): the pre-fix scan only ever looked at
# attachment FILE NAMES, never their content -- a client's SSN sitting
# inside a PDF's text would never be caught. Extraction failure (missing
# binary, corrupt file, unsupported/unreadable type) must be treated as
# "content unknown" and force a card, never silently skipped.
_EXTRACTABLE_TEXT_SUFFIXES = (".txt", ".csv", ".md", ".html", ".htm", ".log")


def _extract_attachment_text(path: str) -> Optional[str]:
    """Best-effort text extraction for one attachment. Returns the extracted
    text, or None if extraction could not be performed/trusted. Callers MUST
    treat None as "content unknown" (force a card), never as "no content"."""
    lower = path.lower()
    try:
        if lower.endswith(_EXTRACTABLE_TEXT_SUFFIXES):
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        if lower.endswith(".pdf"):
            result = subprocess.run(
                ["pdftotext", path, "-"], capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                return None
            return result.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    # Unsupported extension (e.g. .docx, .png): content genuinely unknown,
    # not "known to be empty" -- fail closed, same as an extraction error.
    return None


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
    attachment_text_extractor: Optional[Callable[[str], Optional[str]]] = None,
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

    # Fix 6 (Ed's review, 11/9/26): set the RFC Message-Id header OURSELVES,
    # before sending, rather than relying on Gmail's internal message "id"
    # (messages.send's response "id" is NOT the RFC Message-Id header, and
    # the email platform adapter -- a second real send path into the same
    # mailbox -- has no Gmail "id" at all, only an RFC Message-Id it set
    # itself via smtplib). The send log and the digest's SENT-vs-log
    # cross-check both key on this RFC header so both paths compare
    # apples to apples; see tools/email_send_log.py and
    # scripts/send_email_digest.py.
    if not msg.get("Message-Id"):
        msg["Message-Id"] = make_msgid(domain="hermes.ed.rivera.gmail.com")
    rfc_message_id = msg["Message-Id"]

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

    # Change 4 / Fix 5: subject + body + attachment NAMES + attachment
    # CONTENT (extracted text) all scanned. Extraction failure for any
    # attachment forces a card -- "content unknown" is never treated the
    # same as "content clean".
    extract = attachment_text_extractor or _extract_attachment_text
    attachment_texts: list[str] = []
    extraction_failed: list[str] = []
    for path in (attachments or []):
        extracted = extract(path)
        if extracted is None:
            extraction_failed.append(path)
        else:
            attachment_texts.append(extracted)
    if extraction_failed:
        reasons.append("attachment_extraction_failed")
    scan_text = "\n".join([subject or "", body_text] + list(attachments or []) + attachment_texts)
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

    def _log(outcome: str, message_id: Optional[str], gmail_id: Optional[str] = None) -> None:
        append_log_entry({
            "message_id": message_id, "gmail_id": gmail_id, "to": (to or "").lower(),
            "cc": [a.lower() for a in cc], "bcc": [a.lower() for a in bcc], "subject": subject,
            "from_account": from_account, "source": "send_email", "outcome": outcome, "reasons": reasons,
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
    # msg/cc_list/token/rfc_message_id were already built above (Fix 1/6) --
    # re-using them means what got approved is exactly what gets sent, byte
    # for byte, with the Message-Id header already fixed.
    import base64
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    if gmail_client is not None:
        result = gmail_client.send(raw, None, token)
    else:
        result = enforced.gmail_send(raw, None, token)
    gmail_id = result["id"]

    _log("sent", rfc_message_id, gmail_id=gmail_id)
    return SendEmailResult(outcome="sent", sent=True, message_id=rfc_message_id, reasons=reasons,
                            detail="sent").to_dict()


def check_send_email_requirements() -> bool:
    """Gate for exposing the tool at all -- requires the approved-recipient
    list and the canonical enforced-send script to exist. No external
    network/credential check here (that happens per-send, not at startup)."""
    return os.path.exists(DEFAULT_APPROVED_LIST_PATH) and os.path.exists(CANONICAL_ENFORCED_GMAIL_PATH)


# Fix 3 (Ed's review, 11/9/26): send_email() was built but never registered
# as a callable tool -- a deploy with no registration leaves no way to
# actually send. SEND_EMAIL_SCHEMA + the agent/inline_tool_executors.py
# dispatch entry together are what make it callable; this schema only
# exposes the model-facing fields (to/subject/body_path/cc/bcc/attachments/
# from_account) -- every policy-enforcement/test seam parameter
# (approval_gate, log_path, enforced_module, attachment_text_extractor,
# ...) stays fixed at its production default and is never model-settable.
SEND_EMAIL_SCHEMA = {
    "name": "send_email",
    "description": (
        "Send ONE real email from hermes.ed.rivera@gmail.com. Every policy check "
        "(unknown-recipient card, SSN/JNC-pattern card, from_account='ed' rejected "
        "outright, 20/day rate limit, attachment content scan) runs in-process before "
        "anything is sent; a card-required send waits on Ed's approval and is logged "
        "either way. This is the ONLY way an actual Gmail send can happen -- never "
        "call enforced_gmail_send.py or google_api.py directly."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {"type": "string", "description": "Primary recipient address (or comma-joined addresses)."},
            "subject": {"type": "string"},
            "body_path": {"type": "string", "description": "Path to the HTML or plain-text body file."},
            "cc": {"type": "array", "items": {"type": "string"},
                   "description": "Additional Cc addresses. ed.rivera@gmail.com is always added automatically."},
            "bcc": {"type": "array", "items": {"type": "string"}},
            "attachments": {"type": "array", "items": {"type": "string"}, "description": "Paths to attach."},
            "from_account": {"type": "string", "enum": ["hermes"],
                              "description": "Always 'hermes' -- 'ed' has no credential and is rejected outright."},
        },
        "required": ["to", "subject", "body_path"],
    },
}
