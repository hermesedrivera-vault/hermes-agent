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
import json
import os
import re
import subprocess
import types
from dataclasses import dataclass, field
from email.utils import getaddresses, make_msgid
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from agent.redact import redact_registered_vault_values
from agent.file_safety import get_read_block_error
from tools.email_send_log import append_log_entry, count_today, read_entries

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
def _load_allowed_dirs(profile_path: Optional[str] = None) -> list[str]:
    """Load and return the list of allowed directories for body/attachment paths.
    
    Reads from the protected config file in the profile. Paths are returned as-is
    (with ~ unexpanded); callers must expand and resolve them.
    
    Raises ValueError if the config file cannot be read or parsed.
    """
    # Try profile path first (for tests), then fall back to live profile
    if profile_path is None:
        profile_path = os.path.expanduser("~/.hermes")
    
    allowed_dirs_file = os.path.join(profile_path, "protected", "send_email_allowed_dirs.json")
    
    if not os.path.exists(allowed_dirs_file):
        raise ValueError(f"Allowed dirs config not found at {allowed_dirs_file}")
    
    try:
        with open(allowed_dirs_file, 'r') as f:
            config = json.load(f)
        allowed = config.get("allowed_dirs", [])
        if not isinstance(allowed, list):
            raise ValueError("allowed_dirs must be a list in config")
        return allowed
    except (json.JSONDecodeError, IOError) as e:
        raise ValueError(f"Failed to load allowed dirs config: {e}")


def _is_path_allowed(path: str, allowed_dirs: list[str]) -> bool:
    """Check if a path is under one of the allowed directories.
    
    Paths are resolved (symlinks followed, ~/ expanded, made absolute).
    Returns True if the resolved path is inside one of the resolved allowed_dirs.
    """
    try:
        resolved = Path(path).expanduser().resolve()
        for allowed_dir in allowed_dirs:
            allowed_resolved = Path(allowed_dir).expanduser().resolve()
            # Check if resolved is under allowed_resolved (is_relative_to)
            try:
                resolved.relative_to(allowed_resolved)
                return True
            except ValueError:
                # Not under this directory, continue
                continue
        return False
    except (OSError, RuntimeError):
        return False


def _check_content_for_secrets(text: str) -> Optional[str]:
    """Scan text content against registered vault secrets.
    
    Returns an error message if secrets are detected, None if safe.
    Uses the vault redaction registry's own redaction function to detect matches.
    """
    if not text:
        return None
    
    # Apply the redaction function - if it changes the text, secrets were found
    redacted = redact_registered_vault_values(text)
    if redacted != text:
        return "Content contains registered secret values (detected during redaction scan)"
    
    return None


def _validate_path_and_content(path: str, allowed_dirs: list[str], is_attachment: bool = False) -> Optional[str]:
    """Validate a file path for send_email (body_path or attachment).
    
    Checks:
    1. Path is inside one of allowed_dirs (with ~ expansion and resolution)
    2. Path is not blocked by get_read_block_error() (Hermes credential/cache files)
    3. File content does not contain registered vault secrets
    
    Returns an error message if validation fails, None if path is safe.
    """
    # Step 1: Check path is in allowed dirs
    if not _is_path_allowed(path, allowed_dirs):
        return f"Path is not in allowed directories: {path}"
    
    # Step 2: Check file_safety blocklist (Hermes protected files)
    resolved = Path(path).expanduser().resolve()
    block_error = get_read_block_error(str(resolved))
    if block_error:
        return f"Path is blocked: {block_error}"
    
    # Step 3: Read and scan content for secrets
    try:
        with open(resolved, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except (OSError, IOError) as e:
        return f"Cannot read file: {e}"
    
    # For attachments, try to extract text if it's not plain text
    if is_attachment:
        extracted = _extract_attachment_text(str(resolved))
        if extracted is None and not str(resolved).lower().endswith(('.txt', '.csv', '.md', '.html', '.htm', '.log')):
            # Attachment type but no text extraction - check if this is expected
            pass  # Extraction failure is OK for unsupported types
        if extracted is not None:
            content = extracted
    
    # Scan content for secrets
    secret_error = _check_content_for_secrets(content)
    if secret_error:
        return secret_error
    
    return None


class GateUnreachableError(Exception):
    """Raised by an approval_gate implementation when no human/gateway channel
    exists to deliver a card (Telegram down, no interactive session, etc.)."""


# Fix 4 (Ed's review, 11/9/26): the approval card must be bound to a sha256
# of EVERY field that defines this exact draft, re-verified right before
# the real send (defense against anything changing between "approved" and
# "sent"), and single-use for a carded draft -- an "always"/"session"
# choice at the human-approval-gate UI layer still exists generically (that
# UI is shared by every tool, not send_email-specific), but even if chosen,
# a repeat call with byte-identical content is refused here at the
# application layer before any second real send (see the duplicate-hash
# check in send_email() below) -- "approve once" cannot be stretched into
# "resend forever" just because the gate remembered a decision.
import hashlib


def compute_draft_hash(from_account: str, to: str, cc: Sequence[str], bcc: Sequence[str],
                        subject: str, body_text: str, attachment_bytes: Sequence[bytes]) -> str:
    """Hash of everything that defines THIS draft. Any change invalidates it."""
    h = hashlib.sha256()
    h.update(("from:" + (from_account or "")).encode())
    h.update(("to:" + (to or "")).encode())
    h.update(("cc:" + ",".join(sorted(cc or []))).encode())
    h.update(("bcc:" + ",".join(sorted(bcc or []))).encode())
    h.update(("subject:" + (subject or "")).encode())
    h.update(("body:" + (body_text or "")).encode())
    for data in attachment_bytes:
        h.update(b"attach:" + data)
    return h.hexdigest()


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


from tools.once_only_approval import request_once_only_approval


def _once_only_approval_gate(payload: dict) -> dict:
    """Production default approval_gate for send_email() -- see
    request_once_only_approval(). Card includes a body preview and
    attachment names (Fix 4); rule_key/pattern_key is the draft's own
    sha256 hash, never a bare to+subject string (Fix 4: bound to every
    field that defines this exact draft)."""
    description = (
        f"send_email card: to={payload.get('to')} cc={payload.get('cc')} bcc={payload.get('bcc')} "
        f"subject={payload.get('subject')!r} reasons={payload.get('reasons')}\n"
        f"Body preview: {payload.get('body_preview', '')!r}\n"
        f"Attachments: {payload.get('attachment_names', [])}"
    )
    display = f"<send_email to={payload.get('to')} subject={payload.get('subject')!r}>"
    pattern_key = f"send_email:{payload.get('draft_hash', '')}"
    return request_once_only_approval(description, display, pattern_key)


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
    approval_gate = approval_gate or _once_only_approval_gate
    approved_list_path = approved_list_path or DEFAULT_APPROVED_LIST_PATH
    enforced = enforced_module or _load_enforced_gmail_module()

    cc = list(cc or [])
    bcc = list(bcc or [])

    # Fix 1 (Critical exfiltration): Validate body_path and all attachments
    # are within allowed directories and don't contain secrets before reading
    try:
        allowed_dirs = _load_allowed_dirs()
    except ValueError as e:
        return {"error": f"Path validation failed: {e}", "sent": False}
    
    # Validate body_path
    path_error = _validate_path_and_content(body_path, allowed_dirs, is_attachment=False)
    if path_error:
        return {"error": f"Body path rejected: {path_error}", "sent": False, "blocked": True}
    
    # Validate all attachments
    for attachment_path in (attachments or []):
        path_error = _validate_path_and_content(attachment_path, allowed_dirs, is_attachment=True)
        if path_error:
            return {"error": f"Attachment rejected ({attachment_path}): {path_error}", "sent": False, "blocked": True}

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

    # Fix 4: hash every field that defines this draft, including attachment
    # BYTES (not the extracted text -- the hash must change if the file
    # changes even if extraction failed or returned the same text).
    attachment_bytes: list[bytes] = []
    for path in (attachments or []):
        try:
            with open(path, "rb") as f:
                attachment_bytes.append(f.read())
        except OSError:
            attachment_bytes.append(f"__missing__:{path}".encode())
    draft_hash = compute_draft_hash(from_account, to, cc, bcc, subject, body_text, attachment_bytes)

    # Fix 4: a carded draft is single-use -- a prior SENT entry with this
    # EXACT hash means this content already went out once; refuse a
    # second send of byte-identical content even if the gate remembers an
    # "always"/"session" choice for this rule_key (2026-09-09 multi-draft
    # regression class, applied here to send_email() specifically).
    already_sent = any(
        e.get("draft_hash") == draft_hash and e.get("outcome") == "sent"
        for e in read_entries(path=log_path)
    )

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
            "draft_hash": draft_hash,
        }, path=log_path)

    # Fix 4: single-use enforcement -- refuse outright, before ever showing
    # a card, if this exact draft hash already has a "sent" entry.
    if already_sent:
        _log("denied", None)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=reasons + ["duplicate_draft_hash_already_sent"],
            detail="this exact draft (same from/to/cc/bcc/subject/body/attachments) was already "
                   "sent once; one approval = one send -- re-approve explicitly if this is "
                   "genuinely a new send (e.g. a resend after a bounce), by changing the subject "
                   "or body even slightly.",
        ).to_dict()

    if needs_card:
        # Fix 4: body preview + attachment names in the card, bound to a
        # sha256 of every field that defines this exact draft.
        payload = {
            "to": to, "cc": cc, "bcc": bcc, "subject": subject, "reasons": reasons,
            "body_preview": body_text[:500], "attachment_names": [p.split("/")[-1] for p in (attachments or [])],
            "draft_hash": draft_hash, "draft_id": draft_hash,
        }
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

    # Fix 4: re-verify the hash RIGHT BEFORE sending -- recomputed from the
    # same inputs that were approved. Nothing in this function mutates
    # to/cc/bcc/subject/body_text/attachment_bytes between the approval
    # above and here, so this is a hard equality that must never fail in
    # practice; if it ever does, something changed state in a way this
    # function doesn't control and the send must be refused, not guessed at.
    if compute_draft_hash(from_account, to, cc, bcc, subject, body_text, attachment_bytes) != draft_hash:
        _log("denied", None)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=reasons + ["hash_mismatch_at_send"],
            detail="draft hash changed between approval and send -- refusing to send what was "
                   "never actually approved.",
        ).to_dict()

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
