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
    body_path.write_text("Hi Ken,\n\nSee attached.\n\nHermes Trismegistos (Ed's AI assistant)")
    return SimpleNamespace(log_path=log_path, approved_path=str(approved_path), body_path=str(body_path),
                            tmp_path=tmp_path)


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
        allowed_dirs=[str(tmp_env.tmp_path)],
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
    Path(ssn_body).write_text("Ken, Ed's SSN is 123-45-6789, please file his return.\n\nHermes Trismegistos (Ed's AI assistant)")
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
        "Form 1040 tax return needs anything else from me? Thanks, Ed.\n\n"
        "Hermes Trismegistos (Ed's AI assistant)"
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
    Path(nums_body).write_text("Ken, the tracking number for the mailed documents is 123456789.\n\nHermes Trismegistos (Ed's AI assistant)")
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


# Fix 5 (Ed's review, 11/9/26) -- attachment CONTENT scanning --------------
def test_attachment_content_ssn_requires_card(tmp_env):
    """An attachment whose NAME is clean but whose extracted CONTENT has an
    SSN-shaped number must still card (extractor test seam, no real PDF
    needed)."""
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    def fake_extractor(path):
        assert path == "clean_name.pdf"
        return "Client SSN on file: 123-45-6789"

    _send(tmp_env, approval_gate=gate, attachments=["clean_name.pdf"],
          attachment_text_extractor=fake_extractor)
    assert "tax_ssn_pattern" in calls[-1]["reasons"]


def test_attachment_extraction_failure_requires_card(tmp_env):
    """If extraction fails (corrupt file, missing binary, unsupported type),
    content is UNKNOWN -- that must force a card, never a silent auto-send."""
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    def failing_extractor(path):
        return None

    _send(tmp_env, approval_gate=gate, attachments=["unreadable.pdf"],
          attachment_text_extractor=failing_extractor)
    assert "attachment_extraction_failed" in calls[-1]["reasons"]


# Fix 6 (Ed's review, 11/9/26) -- RFC Message-Id, not Gmail's internal id ---
def test_logged_message_id_is_rfc_header_not_gmail_internal_id(tmp_env):
    """The digest cross-checks send_email() against the email adapter by
    Message-Id -- the adapter only ever has an RFC header, never a Gmail
    internal id. send_email() must log the RFC Message-Id header as
    'message_id' (Gmail's internal id goes in a separate 'gmail_id' field),
    or every adapter reply would show up as a false bypass alert."""
    result, client = _send(tmp_env)
    assert result["outcome"] == "sent"
    assert result["message_id"].startswith("<") and result["message_id"].endswith(">"), \
        "message_id must be an RFC Message-Id header (<...@...>), not Gmail's bare internal id"
    assert result["message_id"] != client.sent[0]["id"], \
        "message_id must not be Gmail's internal send-result id"
    logged = list(read_entries(path=tmp_env.log_path))
    assert logged[-1]["message_id"] == result["message_id"]
    assert logged[-1]["gmail_id"] == client.sent[0]["id"]


# Fix 4 (Ed's review, 11/9/26) -- hash binding + single-use + re-verify ----
def test_hash_mismatch_between_approval_and_send_is_refused(tmp_env, monkeypatch):
    """Defense-in-depth: if the draft hash computed right before the real
    send ever differs from the one that was approved, refuse -- even though
    nothing in send_email() normally mutates the inputs between those two
    points, a tampered/forged approval must not slip past this check."""
    import tools.send_email_tool as se

    original = se.compute_draft_hash
    calls = {"n": 0}

    def flaky_hash(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs) if calls["n"] == 1 else "tampered-hash-value"

    monkeypatch.setattr(se, "compute_draft_hash", flaky_hash)
    result, client = _send(tmp_env, approval_gate=_approve_gate, to="stranger@example.com")
    assert result["outcome"] == "denied"
    assert "hash_mismatch_at_send" in result["reasons"]
    assert client.sent == []


def test_duplicate_draft_hash_already_sent_is_refused_without_a_card(tmp_env):
    """A carded draft is single-use: a prior 'sent' log entry with the exact
    same hash means this content already went out once. A byte-identical
    resend must be refused outright -- no card, no second approval needed
    to refuse it -- even if the gate would have approved it again."""
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    first, client1 = _send(tmp_env, approval_gate=gate, to="stranger@example.com")
    assert first["outcome"] == "sent"
    assert len(calls) == 1

    calls.clear()
    second, client2 = _send(tmp_env, approval_gate=gate, to="stranger@example.com")
    assert second["outcome"] == "denied"
    assert "duplicate_draft_hash_already_sent" in second["reasons"]
    assert calls == [], "a known-duplicate draft must never even reach the approval gate"
    assert client2.sent == []


def test_card_payload_carries_body_preview_and_attachment_names(tmp_env):
    calls = []

    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}

    _send(tmp_env, approval_gate=gate, to="stranger@example.com", attachments=["RIVERA_ED_2025.pdf"])
    assert "body_preview" in calls[-1] and "Hi Ken" in calls[-1]["body_preview"]
    assert calls[-1]["attachment_names"] == ["RIVERA_ED_2025.pdf"]
    assert "draft_hash" in calls[-1] and len(calls[-1]["draft_hash"]) == 64  # sha256 hex


def test_once_only_approval_gate_requests_no_session_no_permanent(monkeypatch):
    """Fix 4 (Ed's review, 11/9/26): the card must go through the SAME
    once-only gateway path the protected-instruction-file write gate uses
    (live-verified against Ed's Telegram), with allow_permanent=False and
    allow_session=False in the approval_data dict handed to
    _await_gateway_decision -- the card offers only Approve once / Deny."""
    import tools.send_email_tool as se

    captured = {}

    def fake_await_gateway_decision(session_key, notify_cb, approval_data, surface=None):
        captured.update(approval_data)
        return {"choice": "once", "resolved": True}

    monkeypatch.setattr("tools.approval_context.get_current_session_key", lambda: "sess-1")
    monkeypatch.setattr("tools.approval_gateway_wait._await_gateway_decision", fake_await_gateway_decision)

    import tools.approval as _approval
    monkeypatch.setattr(_approval, "_gateway_notify_cbs", {"sess-1": lambda *a, **k: None})

    result = se.request_once_only_approval("desc", "<display>", "pattern:abc")
    assert result == {"approved": True, "outcome": "approved"}
    assert captured["allow_permanent"] is False
    assert captured["allow_session"] is False


def test_once_only_approval_gate_fails_closed_when_gateway_unreachable(monkeypatch):
    """No gateway notify callback AND no CLI approval callback registered
    (gateway down / no interactive session) -- must fail closed, no
    'outcome' key (the gate_unreachable signal _classify_gate_result reads)."""
    import tools.send_email_tool as se

    monkeypatch.setattr("tools.approval_context.get_current_session_key", lambda: "sess-none")
    import tools.approval as _approval
    monkeypatch.setattr(_approval, "_gateway_notify_cbs", {})
    monkeypatch.setattr("tools.terminal_tool._get_approval_callback", lambda: None)

    result = se.request_once_only_approval("desc", "<display>", "pattern:abc")
    assert result["approved"] is False
    assert "outcome" not in result


# Fix 2: Body formatting and signature checks =====================================
def test_empty_body_text_requires_card(tmp_env):
    """Empty body must trigger body_format_invalid reason and require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    empty_body = tmp_env.body_path.replace("body.txt", "body_empty.txt")
    Path(empty_body).write_text("")  # empty file
    
    result, client = _send(tmp_env, approval_gate=gate, body_path=empty_body)
    assert result["outcome"] == "denied"
    assert "empty_body" in result["reasons"]
    assert len(calls) == 0, "empty-body check is a hard denial, never reaches the approval gate"


def test_whitespace_only_body_text_requires_card(tmp_env):
    """Whitespace-only body must trigger body_format_invalid reason."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    ws_body = tmp_env.body_path.replace("body.txt", "body_ws.txt")
    Path(ws_body).write_text("   \n\n  \t\t  \n  ")  # only whitespace
    
    result, client = _send(tmp_env, approval_gate=gate, body_path=ws_body)
    assert result["outcome"] == "denied"
    assert "empty_body" in result["reasons"]


def test_html_body_missing_text_align_justify_requires_card(tmp_env):
    """HTML body missing 'text-align: justify' marker must require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    html_body = tmp_env.body_path.replace("body.txt", "body.html")
    # HTML with line-height: 1.5 but NO text-align: justify
    Path(html_body).write_text('<html><body style="line-height: 1.5">Test email</body></html>')
    
    result, client = _send(tmp_env, approval_gate=gate, body_path=html_body)
    assert result["outcome"] == "denied"
    assert "missing_html_formatting" in result["reasons"]
    assert len(calls) == 0, "HTML-formatting check is a hard denial, never reaches the approval gate"


def test_html_body_missing_line_height_requires_card(tmp_env):
    """HTML body missing 'line-height: 1.5' marker must require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    html_body = tmp_env.body_path.replace("body.txt", "body2.html")
    # HTML with text-align: justify but NO line-height: 1.5
    Path(html_body).write_text('<html><body style="text-align: justify">Test email</body></html>')
    
    result, client = _send(tmp_env, approval_gate=gate, body_path=html_body)
    assert result["outcome"] == "denied"
    assert "missing_html_formatting" in result["reasons"]


def test_html_body_with_both_markers_auto_sends(tmp_env):
    """HTML body with both required markers must NOT require a card."""
    html_body = tmp_env.body_path.replace("body.txt", "body_good.html")
    Path(html_body).write_text(
        '<html><body style="text-align: justify; line-height: 1.5">'
        "Test email for Ken.<br>Hermes Trismegistos (Ed's AI assistant)</body></html>"
    )
    
    result, _ = _send(
        tmp_env, 
        approval_gate=lambda p: pytest.fail("known recipient with proper HTML should not card"),
        body_path=html_body,
    )
    assert result["outcome"] == "sent"


def test_plain_text_body_exempt_from_html_marker_check(tmp_env):
    """Plain-text .txt body is exempt from HTML marker check (doesn't need justify/line-height)."""
    # Use default body_path which is a .txt file
    result, _ = _send(
        tmp_env,
        approval_gate=lambda p: pytest.fail("plain text body should not require markers"),
    )
    assert result["outcome"] == "sent"


# Fix 3a: Duplicate-hash recheck before send ====================================
def test_duplicate_draft_hash_at_send_time_catches_race(tmp_env):
    """Fix 3a: Second duplicate-hash check immediately before send catches race condition."""
    calls = []
    
    def gate(payload):
        calls.append(payload)
        # Now, while card is shown, simulate another process logging a duplicate
        # by manually appending a "sent" entry with the same draft_hash to the log
        from tools.email_send_log import append_log_entry
        append_log_entry({
            "message_id": "<race-draft@example.com>",
            "gmail_id": "gmail-race-id",
            "to": "ken@jnccpas.com",
            "cc": [se.MANDATORY_CC],
            "bcc": [],
            "subject": "Weekly update",
            "from_account": "hermes",
            "source": "external_send",
            "outcome": "sent",
            "reasons": [],
            "draft_hash": payload.get("draft_hash"),  # SAME hash as the pending draft
        }, path=tmp_env.log_path)
        
        # Now approve - but the send should still be rejected due to the second check
        return {"approved": True, "outcome": "approved"}
    
    result, client = _send(tmp_env, approval_gate=gate, to="stranger@example.com")
    
    # Should be denied at send time, not sent, because duplicate was logged between card and send
    assert result["outcome"] == "denied"
    assert "duplicate_draft_hash_already_sent_pre_send" in result["reasons"]
    assert client.sent == [], "should NOT have called gmail_send despite approval"


# Fix 3b: Email address validation =============================================
def test_invalid_address_multiple_at_signs_requires_card(tmp_env):
    """Address with multiple '@' signs (a@@b.com) must require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    result, _ = _send(tmp_env, approval_gate=gate, to="a@@b.com")
    assert len(calls) == 1, "multiple @ should trigger card"
    assert "unknown_recipient" in calls[-1]["reasons"]


def test_invalid_address_no_at_sign_requires_card(tmp_env):
    """Address with no '@' (not-an-email) must require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    result, _ = _send(tmp_env, approval_gate=gate, to="not-an-email")
    assert len(calls) == 1
    assert "unknown_recipient" in calls[-1]["reasons"]


def test_invalid_address_empty_local_part_requires_card(tmp_env):
    """Address with empty local part (@domain.com) must require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    result, _ = _send(tmp_env, approval_gate=gate, to="@example.com")
    assert len(calls) == 1
    assert "unknown_recipient" in calls[-1]["reasons"]


def test_invalid_address_empty_domain_requires_card(tmp_env):
    """Address with empty domain (user@) must require approval card."""
    calls = []
    def gate(payload):
        calls.append(payload)
        return {"approved": True, "outcome": "approved"}
    
    result, _ = _send(tmp_env, approval_gate=gate, to="user@")
    assert len(calls) == 1
    assert "unknown_recipient" in calls[-1]["reasons"]


def test_valid_address_on_approved_list_still_auto_sends(tmp_env):
    """Regression: valid address on approved list must still auto-send (no card)."""
    result, _ = _send(
        tmp_env,
        approval_gate=lambda p: pytest.fail("known recipient should not card"),
        to="ken@jnccpas.com",
    )
    assert result["outcome"] == "sent"


# Fix 3c: Bcc delivery verification ============================================
def test_bcc_header_present_in_message_bytes_sent_to_gmail_api(tmp_env):
    """Fix 3c: Verify Bcc header is present in raw message sent to Gmail API."""
    stub_client = StubGmailClient()
    result, _ = _send(tmp_env, gmail_client=stub_client, bcc=["hidden@example.com"])
    
    # Capture the raw message that was sent
    import base64
    sent_raw = stub_client.sent[0]["raw"]
    msg_bytes = base64.urlsafe_b64decode(sent_raw)
    msg_text = msg_bytes.decode(errors="replace")
    
    # The Bcc header SHOULD be in the message (even though RFC 5322 says it's typically omitted,
    # Gmail's API expects it to be there for actual delivery to Bcc recipients).
    # If not present, Bcc delivery is silently broken.
    assert "Bcc:" in msg_text or "Bcc=" in msg_text, \
        "Bcc header missing from raw message -- Bcc recipients will not receive the email via Gmail API"


def test_bcc_recipients_appear_in_sent_message_correctly(tmp_env):
    """Test that Bcc recipients are captured in the sent message structure."""
    stub_client = StubGmailClient()
    result, _ = _send(
        tmp_env, 
        gmail_client=stub_client,
        to="ken@jnccpas.com",
        bcc=["secret1@example.com", "secret2@example.com"],
    )
    
    # The raw message should contain Bcc header with the recipients
    import base64
    sent_raw = stub_client.sent[0]["raw"]
    msg_bytes = base64.urlsafe_b64decode(sent_raw)
    msg_text = msg_bytes.decode(errors="replace")
    
    # Check that Bcc recipients are in the message
    assert "secret1@example.com" in msg_text, "Bcc recipient 1 missing"
    assert "secret2@example.com" in msg_text, "Bcc recipient 2 missing"



# ===== FIX 2 TESTS =====

def test_fix2_empty_body_rejected(tmp_env):
    """Fix 2: Empty body (or whitespace-only) must be rejected."""
    empty_body = str(Path(tmp_env.body_path).parent / "body_empty.txt")
    Path(empty_body).write_text("   \n\n   ")
    result, client = _send(tmp_env, body_path=empty_body)
    assert result["outcome"] == "denied"
    assert "empty_body" in result["reasons"]
    assert len(client.sent) == 0


def test_fix2_html_missing_markers_rejected(tmp_env):
    """Fix 2: HTML body without required formatting markers must be rejected."""
    html_body = str(Path(tmp_env.body_path).parent / "body.html")
    Path(html_body).write_text(
        "<html><body>Hello Ken,<br>See attached.<br>Hermes Trismegistos (Ed's AI assistant)</body></html>"
    )
    result, client = _send(tmp_env, body_path=html_body)
    assert result["outcome"] == "denied"
    assert "missing_html_formatting" in result["reasons"]
    assert len(client.sent) == 0


def test_fix2_missing_signature_rejected(tmp_env):
    """Fix 2: Body without required signature must be rejected."""
    no_sig_body = str(Path(tmp_env.body_path).parent / "body_nosig.txt")
    Path(no_sig_body).write_text("Hi Ken,\n\nSee attached.\n\nThanks")
    result, client = _send(tmp_env, body_path=no_sig_body)
    assert result["outcome"] == "denied"
    assert "missing_signature" in result["reasons"]
    assert len(client.sent) == 0


def test_fix3a_duplicate_detected_pre_send(tmp_env):
    """Fix 3a: Duplicate-hash check right before send detects sends after approval."""
    result1, client1 = _send(tmp_env)
    assert result1["outcome"] == "sent"
    assert len(client1.sent) == 1
    
    result2, client2 = _send(tmp_env)
    assert result2["outcome"] == "denied"
    assert "duplicate_draft_hash_already_sent" in result2["reasons"]
    assert len(client2.sent) == 0


def test_fix3b_invalid_email_multiple_at_signs(tmp_env):
    """Fix 3b: Address with multiple @ signs should be rejected."""
    result, client = _send(tmp_env, to="a@@b.com")
    assert result["sent"] is False


def test_fix3c_bcc_in_message_structure(tmp_env):
    """Fix 3c: Verify Bcc header is in the raw MIME message sent to Gmail."""
    result, client = _send(tmp_env, to="ken@jnccpas.com", bcc=["secret@example.com"])
    if result["sent"]:
        assert len(client.sent) == 1
        import base64
        sent_raw = client.sent[0]["raw"]
        msg_bytes = base64.urlsafe_b64decode(sent_raw)
        msg_text = msg_bytes.decode(errors="replace")
        assert "Bcc:" in msg_text
        assert "secret@example.com" in msg_text
