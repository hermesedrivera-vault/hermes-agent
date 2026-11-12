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
    # Try profile path first (for tests), then the HERMES_HOME env var (set by the
    # test harness's home_io_guard / isolated-profile fixtures), then fall back to
    # the live profile. Hardcoding ~/.hermes here previously broke every test in
    # this suite that runs under an isolated HERMES_HOME, by reaching for the real
    # home instead of the fixture's temp home.
    if profile_path is None:
        profile_path = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    
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
                        subject: str, body_text: str, attachment_bytes: Sequence[bytes],
                        plain_body_text: Optional[str] = None) -> str:
    """Hash of everything that defines THIS draft. Any change invalidates it.

    *plain_body_text* (multipart/alternative fix, 2026-11-12): included so a
    draft edited only in its plain-text alternative (HTML unchanged) still
    gets a new hash -- the approved-vs-sent binding must cover both parts.
    """
    h = hashlib.sha256()
    h.update(("from:" + (from_account or "")).encode())
    h.update(("to:" + (to or "")).encode())
    h.update(("cc:" + ",".join(sorted(cc or []))).encode())
    h.update(("bcc:" + ",".join(sorted(bcc or []))).encode())
    h.update(("subject:" + (subject or "")).encode())
    h.update(("body:" + (body_text or "")).encode())
    h.update(("plain_body:" + (plain_body_text or "")).encode())
    for data in attachment_bytes:
        h.update(b"attach:" + data)
    return h.hexdigest()


@dataclass
class SendEmailResult:
    outcome: str  # "sent" | "denied" | "blocked_gate_unreachable"
    sent: bool
    message_id: Optional[str] = None
    client_message_id: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "sent": self.sent, "message_id": self.message_id,
                "client_message_id": self.client_message_id,
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
    addr-spec (empty address, a realname with no '@', more than one '@',
    etc.) -- callers must treat that as a hard format problem, not a trust
    judgment, and deny outright rather than asking for approval of
    something that can never be a valid send target.
    """
    if not header_value:
        return []
    out = []
    for realname, addr in getaddresses([header_value]):
        addr = (addr or "").strip()
        if not addr or addr.count("@") != 1 or addr.startswith("@") or addr.endswith("@"):
            raise ValueError(f"unparsable address entry in header: {realname!r} {addr!r}")
        local_part, _, domain_part = addr.partition("@")
        if not local_part or "." not in domain_part or domain_part.startswith(".") or domain_part.endswith("."):
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
    plain_body_path: Optional[str] = None,
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
    allowed_dirs: Optional[Sequence[str]] = None,
) -> dict:
    """Send one email, enforcing every v3 policy check before any real send.

    *plain_body_path* (new 2026-11-12, multipart/alternative fix): optional
    path to a plain-text alternative body. When given, the real message
    carries a genuine multipart/alternative part (plain + HTML, the
    recipient's client picks) instead of the old single-part body -- this
    is what fixes the 2026-11-12 07:21 Kenneth-email paragraph-collapse
    bug (a lone plain-text part with single `\\n` breaks, rendered by
    Outlook with every paragraph joined into one block). Same path
    allowlist and secret scan as *body_path*. The required signature line
    and the empty-body guard apply to it too -- both parts are real mail,
    either one might be what the recipient's client actually displays.

    *gmail_client* (test seam): object with ``refresh_token() -> str``,
    ``send(raw, thread_id, token) -> dict`` (Gmail messages.send shape,
    containing at least ``"id"``). Production default loads the real
    enforced_gmail_send.py module and uses its token/refresh/send functions.

    *approval_gate* (test seam): ``callable(payload: dict) -> dict`` shaped
    like ``tools.approval``'s gate results (``{"approved": bool, ...}``,
    "outcome" key present only for a real human decision). Defaults to the
    real in-process gate.

    *allowed_dirs* (test seam, Fix 1): explicit override for the
    allowed-directories list body_path/attachments must resolve inside.
    Production default is None, which loads the protected config via
    _load_allowed_dirs() (the live, Ed-approved allow-list). Tests pass an
    explicit list (e.g. the test's own tmp_path) instead of requiring a
    real protected-config file to exist under a sandboxed HERMES_HOME.
    """
    approval_gate = approval_gate or _once_only_approval_gate
    approved_list_path = approved_list_path or DEFAULT_APPROVED_LIST_PATH
    enforced = enforced_module or _load_enforced_gmail_module()

    cc = list(cc or [])
    bcc = list(bcc or [])

    # Fix 1 (Critical exfiltration): Validate body_path and all attachments
    # are within allowed directories and don't contain secrets before reading
    if allowed_dirs is None:
        try:
            allowed_dirs = _load_allowed_dirs()
        except ValueError as e:
            return {"error": f"Path validation failed: {e}", "sent": False}
    
    # Validate body_path
    path_error = _validate_path_and_content(body_path, allowed_dirs, is_attachment=False)
    if path_error:
        return {"error": f"Body path rejected: {path_error}", "sent": False, "blocked": True}

    # Validate plain_body_path (multipart/alternative fix, 2026-11-12) --
    # same allowlist/secret-scan treatment as the primary body.
    if plain_body_path:
        path_error = _validate_path_and_content(plain_body_path, allowed_dirs, is_attachment=False)
        if path_error:
            return {"error": f"Plain body path rejected: {path_error}", "sent": False, "blocked": True}
    
    # Validate all attachments. A missing attachment is refused outright
    # (Ed's review, 11/10/26: the old code silently skipped path/secret
    # validation for a nonexistent file "because there's nothing to
    # exfiltrate" -- but that also meant a typo'd or already-deleted
    # attachment path would sail through every check and only fail later,
    # deep in the pipeline, with a confusing error. A missing attachment is
    # now a hard, early, unambiguous denial.)
    for attachment_path in (attachments or []):
        if not os.path.exists(os.path.expanduser(attachment_path)):
            return {"error": f"Attachment not found: {attachment_path}", "sent": False,
                    "blocked": True, "reasons": ["attachment_missing"]}
        path_error = _validate_path_and_content(attachment_path, allowed_dirs, is_attachment=True)
        if path_error:
            return {"error": f"Attachment rejected ({attachment_path}): {path_error}", "sent": False, "blocked": True}


    with open(body_path, encoding="utf-8") as f:
        body_text = f.read()

    plain_body_text: Optional[str] = None
    if plain_body_path:
        with open(plain_body_path, encoding="utf-8") as f:
            plain_body_text = f.read()

    approved = _load_approved_list(approved_list_path)
    reasons: list[str] = []

    # Build the real message FIRST (never sent yet -- build_message() only
    # constructs the MIME object) so every downstream check inspects the
    # recipients as they actually ended up in the message, not the raw
    # inputs (Fix 1: a header-smuggling/comma-joined-string trick that
    # fools a check on the input string must still be caught against the
    # built headers).
    # Fix 2: Verify signature/body/HTML checks BEFORE building the message.
    # These checks are called inside enforced.build_message() but test stubs may
    # skip them. We run them here explicitly to ensure they always fire.
    # Check 1: Body is not empty/whitespace-only (both parts, if present --
    # multipart/alternative fix, 2026-11-12: an empty alternative is just as
    # bad as an empty primary body, so it gets the identical hard refusal).
    if not body_text.strip() or (plain_body_text is not None and not plain_body_text.strip()):
        reasons.append("empty_body")
        append_log_entry({
            "message_id": None, "to": (to or "").lower(), "cc": [a.lower() for a in cc],
            "bcc": [a.lower() for a in bcc], "subject": subject, "from_account": from_account,
            "source": "send_email", "outcome": "denied", "reasons": reasons, "draft_hash": None,
        }, path=log_path)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=reasons,
            detail="Body is empty (or whitespace-only). This is the exact failure mode from "
                   "the 2026-08-09 empty-body incident. Refusing.",
        ).to_dict()

    # Check 2: HTML bodies must have required formatting markers (justified + 1.5 line-height)
    if body_path.lower().endswith((".html", ".htm")):
        REQUIRED_HTML_MARKERS = ["text-align: justify", "line-height: 1.5"]
        missing = [m for m in REQUIRED_HTML_MARKERS if m not in body_text]
        if missing:
            reasons.append("missing_html_formatting")
            append_log_entry({
                "message_id": None, "to": (to or "").lower(), "cc": [a.lower() for a in cc],
                "bcc": [a.lower() for a in bcc], "subject": subject, "from_account": from_account,
                "source": "send_email", "outcome": "denied", "reasons": reasons, "draft_hash": None,
            }, path=log_path)
            return SendEmailResult(
                outcome="denied", sent=False, reasons=reasons,
                detail=f"HTML body missing required formatting marker(s): {missing}. "
                       "Every external send must use justified paragraphs (text-align: justify) "
                       "with 0.5 line spacing (line-height: 1.5). Rebuild with house HTML template.",
            ).to_dict()

    # Check 3: Validate signature is present (Hermes Trismegistos (Ed's AI assistant))
    # -- in body_text, AND in plain_body_text too if a plain alternative is
    # present, since either part might be what the recipient's client renders.
    REQUIRED_SIGNATURE = "Hermes Trismegistos (Ed's AI assistant)"
    sig_missing = REQUIRED_SIGNATURE not in body_text or (
        plain_body_text is not None and REQUIRED_SIGNATURE not in plain_body_text
    )
    if sig_missing:
        reasons.append("missing_signature")
        append_log_entry({
            "message_id": None, "to": (to or "").lower(), "cc": [a.lower() for a in cc],
            "bcc": [a.lower() for a in bcc], "subject": subject, "from_account": from_account,
            "source": "send_email", "outcome": "denied", "reasons": reasons, "draft_hash": None,
        }, path=log_path)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=reasons,
            detail=f"Body must include the signature '{REQUIRED_SIGNATURE}'. "
                   "This is Ed's standing policy for every external send. When a plain-text "
                   "alternative is given, it must carry the signature too.",
        ).to_dict()

    args = types.SimpleNamespace(
        to=to, subject=subject, body_file=body_path, plain_body_file=plain_body_path,
        cc=cc, bcc=bcc, attach=list(attachments or []), in_reply_to=None, references=None,
    )
    token = gmail_client.refresh_token() if gmail_client else enforced.refresh_token()
    msg, cc_list = enforced.build_message(args, token)
    if MANDATORY_CC not in cc_list:
        raise RuntimeError("INTERNAL ERROR: mandatory CC missing -- refusing to send.")

    # Fix 3c (Ed's review, 11/9/26 -- corrected: this must ADD the header, not
    # just check for it): Gmail's messages.send API requires Bcc to be in the
    # raw MIME message itself (unlike raw SMTP, which has a separate
    # envelope-bcc parameter the API has no equivalent for).
    # enforced_gmail_send.py's build_message() deliberately never writes a
    # Bcc header (correct for a script meant to print a human-readable
    # preview to the terminal), so send_email() must add it itself -- done
    # HERE, immediately after the message is built and before anything else
    # reads from it (draft_hash, the approval card, the recipient-parsing
    # below), so what gets hashed/shown/approved is byte-for-byte identical
    # to what gets sent. Adding it any later would mean the card shows a
    # message without Bcc while the real send has it -- the exact
    # approved-vs-sent mismatch Fix 4's hash check exists to prevent.
    if bcc and not msg.get("Bcc"):
        msg["Bcc"] = ", ".join(bcc)

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
    except ValueError as e:
        # Fix 3b (corrected, 11/10/26): a malformed/unparsable address entry
        # is a format problem, not a trust judgment -- deny outright, before
        # ever showing a card, rather than asking Ed to approve something
        # that can never be a valid send target. This also fixes the actual
        # placement bug Ed found: the OLD code ran a raw-string "@" count
        # check on the whole, possibly comma-joined `to` input AFTER the
        # approval card -- so a legitimately comma-joined
        # "x@unknown.com, ken@jnccpas.com" (which the schema allows) got
        # miscounted as one malformed blob and denied AFTER Ed had already
        # approved it. The check now runs on PARSED, per-address entries
        # (via _recipients_from_built_message / getaddresses, using the
        # addresses as they actually ended up in the built message), before
        # needs_card is ever computed -- so a comma-joined field with
        # individually well-formed addresses sails through to the normal
        # unknown_recipient/approved-list logic below, while a genuinely
        # malformed entry (multiple '@', no '@', empty local/domain part)
        # is refused immediately.
        append_log_entry({
            "message_id": None, "to": (to or "").lower(), "cc": [a.lower() for a in cc],
            "bcc": [a.lower() for a in bcc], "subject": subject, "from_account": from_account,
            "source": "send_email", "outcome": "denied", "reasons": ["invalid_email_format"],
            "draft_hash": None,
        }, path=log_path)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=["invalid_email_format"],
            detail=f"Invalid/unparsable recipient address format ({e}); denying outright -- "
                   "this is a format problem, not a judgment call, so there is no card to show.",
        ).to_dict()
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
    scan_text = "\n".join([subject or "", body_text, plain_body_text or ""] + list(attachments or []) + attachment_texts)
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
    draft_hash = compute_draft_hash(from_account, to, cc, bcc, subject, body_text, attachment_bytes,
                                     plain_body_text=plain_body_text)

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

    def _log(outcome: str, message_id: Optional[str], gmail_id: Optional[str] = None,
             client_message_id: Optional[str] = None) -> None:
        append_log_entry({
            "message_id": message_id, "gmail_id": gmail_id, "client_message_id": client_message_id,
            "to": (to or "").lower(),
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
    if compute_draft_hash(from_account, to, cc, bcc, subject, body_text, attachment_bytes,
                           plain_body_text=plain_body_text) != draft_hash:
        _log("denied", None)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=reasons + ["hash_mismatch_at_send"],
            detail="draft hash changed between approval and send -- refusing to send what was "
                   "never actually approved.",
        ).to_dict()

    # Fix 3a: Second duplicate-hash check RIGHT BEFORE the real send call.
    # Between the first check (before approval card) and now, something could have
    # been logged with this same hash by another process/thread. Re-verify.
    already_sent_now = any(
        e.get("draft_hash") == draft_hash and e.get("outcome") == "sent"
        for e in read_entries(path=log_path)
    )
    if already_sent_now:
        _log("denied", None)
        return SendEmailResult(
            outcome="denied", sent=False, reasons=reasons + ["duplicate_draft_hash_already_sent_pre_send"],
            detail="this exact draft was already sent between approval check and send -- "
                   "refusing duplicate send.",
        ).to_dict()

    # Fix 3b's address-format validation now runs earlier, on parsed
    # per-address entries, before the approval card (see above). The
    # duplicate raw-string post-card check that used to live here was the
    # actual bug this session fixed -- removed.


    # Fix 3c sanity check: the header was injected right after build_message()
    # above; this just proves it before encoding, rather than denying (the
    # injection makes a missing header effectively unreachable, but fail
    # loud rather than silently dropping bcc delivery if that ever changes).
    raw_message_bytes = msg.as_bytes()
    raw_message_str = raw_message_bytes.decode('utf-8', errors='replace')
    if bcc:
        has_bcc_header = any(line.lower().startswith("bcc:") for line in raw_message_str.split('\n'))
        if not has_bcc_header:
            reasons.append("bcc_header_missing")
            _log("denied", None)
            return SendEmailResult(
                outcome="denied", sent=False, reasons=reasons,
                detail="Bcc header not found in raw MIME message despite injection. Bcc delivery would fail.",
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

    # Message-ID fix (Ed's spec, 11/11/26): Gmail's messages.send API does NOT
    # reliably preserve the Message-Id header we set ourselves before sending
    # (rfc_message_id, built above via make_msgid() -- Fix 6, 11/9/26).
    # Empirically confirmed against two real live sends on 2026-11-11: the
    # client-generated header (e.g. "<1794...@hermes.ed.rivera.gmail.com>")
    # was replaced by Gmail with its own ("<CAFc=...@mail.gmail.com>") in the
    # actual SENT copy. Logging the client-generated id as "message_id" made
    # the digest's cross-check (scripts/send_email_digest.py) compare against
    # a header Gmail never kept -- a guaranteed false bypass alert on every
    # real send. Fix: immediately fetch the real SENT message by gmail_id and
    # log its ACTUAL Message-Id header as "message_id"; the one we generated
    # is kept separately as "client_message_id" (useful for debugging/
    # threading, never used for the digest's bypass check).
    actual_message_id = rfc_message_id
    message_id_fetch_failed = False
    try:
        if gmail_client is not None and hasattr(gmail_client, "get_full"):
            full = gmail_client.get_full(gmail_id, token)
        else:
            full = enforced.gmail_get_full(gmail_id, token)
        headers = {h["name"]: h["value"] for h in full.get("payload", {}).get("headers", [])}
        fetched = headers.get("Message-Id") or headers.get("Message-ID")
        if fetched:
            actual_message_id = fetched
        else:
            message_id_fetch_failed = True
    except Exception:
        # The email already sent successfully (gmail_id exists) -- a failure
        # fetching it back must never be reported as a send failure. Fall back
        # to the client-generated id so the log always has SOME id, and flag
        # the gap so the digest/ops can see a fetch problem rather than
        # silently trusting an id Gmail may not have kept.
        message_id_fetch_failed = True

    if message_id_fetch_failed:
        reasons.append("actual_message_id_fetch_failed")

    _log("sent", actual_message_id, gmail_id=gmail_id, client_message_id=rfc_message_id)
    return SendEmailResult(outcome="sent", sent=True, message_id=actual_message_id,
                            client_message_id=rfc_message_id, reasons=reasons,
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
# Fix 3 (Ed's review, 11/9/26 -- CORRECTED 11/10/26: the schema/dispatch-table
# entry alone never made this callable. registry.register() was never called,
# so discover_builtin_tools() never found "send_email" and no model on any
# platform ever received its schema -- confirmed failing directly against
# live main before this fix (test_send_email_tool_real_registration.py).
# toolset="email" is what platform_toolsets.<platform> / agent.disabled_toolsets
# actually filter on (hermes_cli.tools_config._get_platform_tools) -- this MUST
# match the toolset name already used by toolsets.TOOLSETS["email"] and by
# kenneth-rosa's config.yaml disabled_toolsets entry, or the two go out of sync.
from tools.registry import registry

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
            "plain_body_path": {"type": "string",
                                 "description": "Optional path to a plain-text alternative body. "
                                                 "When set, sends real multipart/alternative "
                                                 "(plain + HTML, client picks)."},
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


def _handle_send_email(args: dict, **_kw) -> str:
    """Registry handler contract (ToolRegistry._normalize_handler_result,
    tools/registry.py): a result must be a string (or the multimodal
    envelope) -- anything else is replaced with a generic
    'unsupported result type' error, discarding every real detail.
    send_email() itself returns a plain dict (SendEmailResult.to_dict()),
    so this handler MUST serialize it before returning -- this is the
    other half of the 11/10 fix (removing send_email from
    INLINE_TOOL_EXECUTORS routes it through the registry, but the registry
    path still needs a real string out of the handler, or every call --
    success or failure -- collapses into the same opaque
    'tool_result_contract' error)."""
    result = send_email(
        to=args.get("to"),
        subject=args.get("subject"),
        body_path=args.get("body_path"),
        plain_body_path=args.get("plain_body_path"),
        cc=args.get("cc"),
        bcc=args.get("bcc"),
        attachments=args.get("attachments"),
        from_account=args.get("from_account", "hermes"),
    )
    return json.dumps(result, ensure_ascii=False)


registry.register(
    name="send_email",
    toolset="email",
    schema=SEND_EMAIL_SCHEMA,
    handler=_handle_send_email,
    check_fn=check_send_email_requirements,
    emoji="\U0001F4E7",
)
