"""Tests for tools/send_email_tool.py against a stubbed Gmail client and a
stubbed approval gate -- no real network, no real Telegram card, ever.
"""
from __future__ import annotations

import json
import sys
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root

from tools import send_email_tool as se
from tools.email_send_log import append_log_entry, read_entries


class StubGmailClient:
    """Records every (raw, thread_id, token) send instead of hitting the network."""

    def __init__(self):
        self.sent = []
        self._next_id = 1

    def refresh_token(self):
        return "stub-token"

    def send(self, raw, thread_id, token):
        msg_id = f"stub-msg-{self._next_id}"
        self._next_id += 1
        self.sent.append({"raw": raw, "thread_id": thread_id, "token": token, "id": msg_id})
        return {"id": msg_id}


def _approve_gate(_payload):
    return {"approved": True, "outcome": "approved"}


def _deny_gate(_payload):
    return {"approved": False, "outcome": "denied"}


def _unreachable_gate(_payload):
    # Shape returned by tools.approval's _blocked() when no human/gateway is
    # present (fail_closed_when_no_human=True): no "outcome" key at all.
    return {"approved": False, "message": "no interactive session"}


@pytest.fixture()
def tmp_env(tmp_path):
    log_path = str(tmp_path / "email_send_log.jsonl")
    approved_path = tmp_path / "email_approved_recipients.json"
    approved_path.write_text(json.dumps({
        "domains": ["@jnccpas.com"],
        "addresses": ["ed.rivera@gmail.com"],
    }))
    body_path = tmp_path / "body.txt"
    body_path.write_text("Hi Ken,\n\nSee attached.\n\nHermes")
    return SimpleNamespace(log_path=log_path, approved_path=str(approved_path), body_path=str(body_path))


class _FakeEnforcedModule:
    """Stand-in for enforced_gmail_send.py: build_message()/refresh_token()
    without loading the real, protected script (which is out of scope for a
    unit test and shouldn't need a live Gmail token to run)."""

    @staticmethod
    def refresh_token():
        return "fake-refresh-token"

    @staticmethod
    def build_message(args, token):
        msg = MIMEMultipart()
        msg["To"] = args.to
        msg["Subject"] = args.subject
        cc_list = list(args.cc or []) + [se.MANDATORY_CC]
        msg["Cc"] = ", ".join(cc_list)
        return msg, cc_list


def _send(tmp_env, approval_gate=_approve_gate, **overrides):
    kwargs = dict(
        to="ken@jnccpas.com", subject="Weekly update", body_path=tmp_env.body_path,
        gmail_client=StubGmailClient(), approval_gate=approval_gate,
        log_path=tmp_env.log_path, approved_list_path=tmp_env.approved_path,
        enforced_module=_FakeEnforcedModule,
    )
    kwargs.update(overrides)
    return se.send_email(**kwargs), kwargs["gmail_client"]


# 1 -----------------------------------------------------------------------
def test_known_recipient_auto_sends_no_card(tmp_env):
    result, client = _send(tmp_env, approval_gate=lambda p: pytest.fail("card should not be shown"))
    assert result["outcome"] == "sent"
    assert result["sent"] is True
    assert len(client.sent) == 1
    logged = list(read_entries(path=tmp_env.log_path))
    assert len(logged) == 1 and logged[0]["outcome"] == "sent"


# 2 -----------------------------------------------------------------------
def test_unknown_recipient_in_any_field_requires_card(tmp_env):
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    for field, value in (("to", "stranger@example.com"), ("cc", ["stranger@example.com"]),
                          ("bcc", ["stranger@example.com"])):
        calls.clear()
        kwargs = {"to": "ken@jnccpas.com"}
        kwargs[field] = value
        _send(tmp_env, approval_gate=gate, **kwargs)
        assert len(calls) == 1, f"field={field} did not trigger a card"
        assert "unknown_recipient" in calls[0]["reasons"]


# 3 -----------------------------------------------------------------------
def test_ssn_shaped_pattern_requires_card_in_body_and_attachment_name(tmp_env):
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    ssn_body = tmp_env.body_path.replace("body.txt", "body_ssn.txt")
    Path(ssn_body).write_text("Ken, Ed's SSN is 123-45-6789, please file his return.")
    _send(tmp_env, approval_gate=gate, body_path=ssn_body)
    assert "tax_ssn_pattern" in calls[-1]["reasons"]

    calls.clear()
    _send(tmp_env, approval_gate=gate, attachments=["RIVERA_ED_2025.pdf"])
    assert "tax_ssn_pattern" in calls[-1]["reasons"]


# Tax decision (Ed, 11/9/26) -- negative tests -----------------------------
def test_tax_words_alone_do_not_require_a_card(tmp_env):
    """'tax return', '1099', 'W-2', 'Form 1040' with no SSN-shaped number and
    no JNC file-name match must auto-send -- tax vocabulary alone is never a
    trigger (regression guard against over-triggering on routine mail)."""
    words_body = tmp_env.body_path.replace("body.txt", "body_words.txt")
    Path(words_body).write_text(
        "Ken, can you confirm the 1099 and W-2 are ready, and whether the "
        "Form 1040 tax return needs anything else from me? Thanks, Ed."
    )
    result, client = _send(
        tmp_env, approval_gate=lambda p: pytest.fail("tax vocabulary alone must not card"),
        body_path=words_body,
    )
    assert result["outcome"] == "sent"


def test_bare_nine_digits_with_no_ssn_label_do_not_require_a_card(tmp_env):
    """A bare 9-digit run with no adjacent SSN/ITIN/EIN/TIN label (e.g. a
    tracking or account number) must auto-send -- _TAX_CONTEXT_RE's
    adjacency requirement is what prevents this false positive."""
    nums_body = tmp_env.body_path.replace("body.txt", "body_nums.txt")
    Path(nums_body).write_text("Ken, the tracking number for the mailed documents is 123456789.")
    result, client = _send(
        tmp_env, approval_gate=lambda p: pytest.fail("bare 9 digits with no label must not card"),
        body_path=nums_body,
    )
    assert result["outcome"] == "sent"


# 4 -----------------------------------------------------------------------
def test_from_ed_rejected_outright_no_card_no_credential(tmp_env):
    """Minor fix (Ed's review, 11/9/26): from_account='ed' is rejected
    outright -- no credential exists for ed.rivera@gmail.com on this box,
    so a card for it is pointless (it can never be approved into a real
    send). It must raise, not show a card."""
    with pytest.raises(ValueError, match="from_account='ed'"):
        _send(tmp_env, approval_gate=lambda p: pytest.fail("no card for from_account='ed'"),
              from_account="ed")


# 5 -----------------------------------------------------------------------
def test_rate_limit_20th_send_today_still_auto_sends(tmp_env):
    for i in range(19):
        append_log_entry({"message_id": f"prior-{i}", "to": "ken@jnccpas.com", "cc": [], "bcc": [],
                           "subject": "s", "from_account": "hermes", "source": "send_email",
                           "outcome": "sent", "reasons": []}, path=tmp_env.log_path)
    result, _ = _send(tmp_env, approval_gate=lambda p: pytest.fail("card should not be shown on the 20th"))
    assert result["outcome"] == "sent"


# 6 -----------------------------------------------------------------------
def test_rate_limit_21st_send_today_requires_card(tmp_env):
    for i in range(20):
        append_log_entry({"message_id": f"prior-{i}", "to": "ken@jnccpas.com", "cc": [], "bcc": [],
                           "subject": "s", "from_account": "hermes", "source": "send_email",
                           "outcome": "sent", "reasons": []}, path=tmp_env.log_path)
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    _send(tmp_env, approval_gate=gate)
    assert "rate_limit_21st" in calls[-1]["reasons"]


# 7 -----------------------------------------------------------------------
def test_card_approved_sends_with_mandatory_cc_and_logs_sent(tmp_env):
    result, client = _send(tmp_env, approval_gate=_approve_gate, to="stranger@example.com")
    assert result["outcome"] == "sent" and result["sent"] is True
    sent_raw = client.sent[0]["raw"]
    import base64
    decoded = base64.urlsafe_b64decode(sent_raw).decode()
    assert se.MANDATORY_CC in decoded
    logged = list(read_entries(path=tmp_env.log_path))
    assert logged[-1]["outcome"] == "sent" and logged[-1]["message_id"] == result["message_id"]


# 8 -----------------------------------------------------------------------
def test_card_denied_not_sent_and_logs_denied(tmp_env):
    result, client = _send(tmp_env, approval_gate=_deny_gate, to="stranger@example.com")
    assert result == {"outcome": "denied", "sent": False, "message_id": None,
                       "reasons": ["unknown_recipient"], "detail": "approval denied; not sent"}
    assert client.sent == []
    logged = list(read_entries(path=tmp_env.log_path))
    assert logged[-1]["outcome"] == "denied"


# 9 -----------------------------------------------------------------------
def test_gate_unreachable_fails_closed_blocks_and_logs(tmp_env):
    result, client = _send(tmp_env, approval_gate=_unreachable_gate, to="stranger@example.com")
    assert result["outcome"] == "blocked_gate_unreachable"
    assert result["sent"] is False
    assert client.sent == [], "a card-required send must NEVER go out when the gate is unreachable"
    logged = list(read_entries(path=tmp_env.log_path))
    assert logged[-1]["outcome"] == "blocked_gate_unreachable"


# 10 ----------------------------------------------------------------------
def test_gate_unreachable_with_known_recipient_still_auto_sends(tmp_env):
    """A known recipient with no other card-trigger never calls the approval
    gate at all -- so an UNREACHABLE gate (Telegram down, no human channel)
    must have zero effect on it. Fail-closed only applies to sends that
    actually need a card; it must never become a blanket outage kill-switch
    for ordinary known-recipient auto-sends."""
    result, client = _send(tmp_env, approval_gate=_unreachable_gate)  # known recipient, nothing else flagged
    assert result["outcome"] == "sent"
    assert result["sent"] is True
    assert len(client.sent) == 1
    logged = list(read_entries(path=tmp_env.log_path))
    assert logged[-1]["outcome"] == "sent"


# 11 ----------------------------------------------------------------------
def test_approved_recipients_file_is_protected_from_direct_edit(tmp_path):
    """The approved-recipient list itself must be a protected-instruction
    basename (same gate class as outbound_classify.py) -- otherwise anyone
    able to call write_file/patch could silently widen who send_email() will
    auto-send to, bypassing the entire card system by editing its allowlist
    instead of beating its checks. Uses tmp_path, not the real hermes home
    (home_io_guard forbids real-home I/O in tests) -- the guard function
    matches on basename alone, so this is an equivalent check."""
    from tools.file_tools_write_guards import _protected_instruction_reason

    protected_dir = tmp_path / "protected"
    protected_dir.mkdir()
    target = protected_dir / "email_approved_recipients.json"
    target.write_text("{}")
    unrelated = protected_dir / "unrelated_data.json"
    unrelated.write_text("{}")
    extra_patterns = ["outbound_classify.py", "outbound_pre_tool.py", "signal_receipt.py",
                      "mode", "enforced_gmail_send.py", "email_approved_recipients.json"]

    reason = _protected_instruction_reason(str(target), enabled=True, extra_patterns=extra_patterns)
    assert reason is not None, "approved-recipients file must be flagged as a protected-instruction write"

    # Negative control: an UNRELATED json file in the same directory must NOT
    # be swept in by basename -- this gate is deliberately narrow.
    clean = _protected_instruction_reason(str(unrelated), enabled=True, extra_patterns=extra_patterns)
    assert clean is None


# Fix 1 (Ed's review, 11/9/26) -----------------------------------------------
# "stranger@evil.com, ken@jnccpas.com" as a single `to` string passed the old
# endswith() check because the WHOLE comma-joined string happens to end with
# "@jnccpas.com". Each individual address must now be checked.
def test_comma_joined_to_with_unapproved_first_address_requires_card(tmp_env):
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    _send(tmp_env, approval_gate=gate, to="stranger@evil.com, ken@jnccpas.com")
    assert len(calls) == 1, "comma-joined to= with an unapproved address must card, not auto-send"
    assert "unknown_recipient" in calls[-1]["reasons"]


def test_display_name_wrapped_address_is_parsed_and_checked(tmp_env):
    """'Ken Rosa <ken@jnccpas.com>' must parse to ken@jnccpas.com (approved,
    auto-sends) -- display-name wrapping must not itself trigger a card, and
    must not let a malicious realname hide a different address either."""
    result, client = _send(
        tmp_env, approval_gate=lambda p: pytest.fail("known recipient, display-name wrapped, must not card"),
        to="Ken Rosa <ken@jnccpas.com>",
    )
    assert result["outcome"] == "sent"

    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    _send(tmp_env, approval_gate=gate, to="Not Ken <stranger@evil.com>")
    assert len(calls) == 1 and "unknown_recipient" in calls[-1]["reasons"]


def test_mixed_approved_and_unapproved_cc_requires_card(tmp_env):
    """A mix of one approved + one unapproved address in Cc, comma-joined
    within a single list entry, must still card on the unapproved one."""
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    _send(tmp_env, approval_gate=gate, cc=["ken@jnccpas.com, stranger@evil.com"])
    assert len(calls) == 1 and "unknown_recipient" in calls[-1]["reasons"]
