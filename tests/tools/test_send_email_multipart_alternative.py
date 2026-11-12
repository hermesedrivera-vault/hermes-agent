"""Tests for send_email_tool.py's multipart/alternative support
(plain_body_path), added 2026-11-12 to fix the Kenneth-email
paragraph-collapse incident. Stubbed Gmail client / approval gate, no
real network, exactly like test_send_email_tool.py's conventions."""
from __future__ import annotations

import base64
import json
import sys
from email import message_from_bytes
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root

from tools import send_email_tool as se
from tools.email_send_log import append_log_entry, read_entries


class StubGmailClient:
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

    def get_full(self, msg_id, token):
        return {"payload": {"headers": [
            {"name": "Message-Id", "value": f"<gmail-rewritten-{msg_id}@mail.gmail.com>"},
        ]}}


def _approve_gate(_payload):
    return {"approved": True, "outcome": "approved"}


@pytest.fixture()
def tmp_env(tmp_path):
    log_path = str(tmp_path / "email_send_log.jsonl")
    approved_path = tmp_path / "email_approved_recipients.json"
    approved_path.write_text(json.dumps({
        "domains": ["@jnccpas.com"], "addresses": ["ed.rivera@gmail.com"],
    }))
    html_path = tmp_path / "body.html"
    html_path.write_text(
        '<div style="text-align: justify; line-height: 1.5">'
        "<p>Paragraph one.</p><p>Paragraph two.</p>"
        "<p>Hermes Trismegistos (Ed's AI assistant)</p></div>"
    )
    plain_path = tmp_path / "body.txt"
    plain_text = "Paragraph one.\n\nParagraph two.\n\nHermes Trismegistos (Ed's AI assistant)"
    plain_path.write_text(plain_text)
    return SimpleNamespace(log_path=log_path, approved_path=str(approved_path),
                            html_path=str(html_path), plain_path=str(plain_path),
                            plain_text=plain_text, tmp_path=tmp_path)


class _RealBuildEnforcedModule:
    """Exercises the REAL build_message() logic (multipart/alternative fix)
    rather than a stub that would hide a regression in the actual nesting
    logic -- loaded dynamically from the canonical profile-repo path, same
    as production, but import-only (no token/network use inside
    build_message() itself)."""

    @staticmethod
    def refresh_token():
        return "fake-refresh-token"

    @staticmethod
    def build_message(args, token):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "enforced_gmail_send_test_real",
            "/tmp/fix-multipart-profile/skills/email/enforced-gmail-send/scripts/enforced_gmail_send.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.build_message(args, token)


def _send(tmp_env, approval_gate=_approve_gate, **overrides):
    kwargs = dict(
        to="ken@jnccpas.com", subject="Weekly update", body_path=tmp_env.html_path,
        gmail_client=StubGmailClient(), approval_gate=approval_gate,
        log_path=tmp_env.log_path, approved_list_path=tmp_env.approved_path,
        enforced_module=_RealBuildEnforcedModule,
        allowed_dirs=[str(tmp_env.tmp_path)],
    )
    kwargs.update(overrides)
    return se.send_email(**kwargs), kwargs["gmail_client"]


def test_plain_body_path_produces_real_multipart_alternative_end_to_end(tmp_env):
    """The actual fix, exercised through send_email() end-to-end: the raw
    message Gmail would receive has a genuine multipart/alternative part
    with both plain and HTML, plain text preserved exactly."""
    result, client = _send(tmp_env, plain_body_path=tmp_env.plain_path)
    assert result["outcome"] == "sent"
    raw = base64.urlsafe_b64decode(client.sent[0]["raw"])
    msg = message_from_bytes(raw)
    assert msg.is_multipart()
    top_parts = msg.get_payload()
    alt = [p for p in top_parts if p.get_content_type() == "multipart/alternative"]
    assert len(alt) == 1, "expected one multipart/alternative part in the sent message"
    sub = alt[0].get_payload()
    types_found = [p.get_content_type() for p in sub]
    assert "text/plain" in types_found and "text/html" in types_found
    plain_part = next(p for p in sub if p.get_content_type() == "text/plain")
    assert plain_part.get_payload(decode=True).decode("utf-8") == tmp_env.plain_text


def test_no_plain_body_path_sends_single_part_as_before(tmp_env):
    """Backward compatibility: omitting plain_body_path must not introduce
    a multipart/alternative wrapper -- existing single-part sends unaffected."""
    result, client = _send(tmp_env)
    assert result["outcome"] == "sent"
    raw = base64.urlsafe_b64decode(client.sent[0]["raw"])
    msg = message_from_bytes(raw)
    content_types = [p.get_content_type() for p in msg.walk()]
    assert "multipart/alternative" not in content_types


def test_empty_plain_body_path_denied_before_card(tmp_env):
    empty = tmp_env.tmp_path / "empty.txt"
    empty.write_text("   \n  ")
    result, client = _send(
        tmp_env, approval_gate=lambda p: pytest.fail("empty alt body is a hard denial, never a card"),
        plain_body_path=str(empty),
    )
    assert result["outcome"] == "denied"
    assert "empty_body" in result["reasons"]
    assert client.sent == []


def test_missing_signature_in_plain_body_path_denied(tmp_env):
    """Signature must be present in the plain alternative too, not just
    the HTML part -- a client rendering plain-only must still show it."""
    no_sig = tmp_env.tmp_path / "no_sig.txt"
    no_sig.write_text("Paragraph one.\n\nParagraph two, no signature here.")
    result, client = _send(tmp_env, plain_body_path=str(no_sig))
    assert result["outcome"] == "denied"
    assert "missing_signature" in result["reasons"]
    assert client.sent == []


def test_draft_hash_changes_when_only_plain_body_differs(tmp_env):
    """Fix 4-style binding: a draft whose HTML is identical but plain
    alternative differs must hash differently -- editing only the plain
    part must not silently reuse an old approval."""
    h1 = se.compute_draft_hash("hermes", "ken@jnccpas.com", [], [], "s", "same html", [],
                                plain_body_text="plain A")
    h2 = se.compute_draft_hash("hermes", "ken@jnccpas.com", [], [], "s", "same html", [],
                                plain_body_text="plain B")
    assert h1 != h2


def test_plain_body_path_outside_allowed_dirs_rejected(tmp_env, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "plain.txt"
    outside.write_text("Paragraph one.\n\nHermes Trismegistos (Ed's AI assistant)")
    result, client = _send(
        tmp_env, approval_gate=lambda p: pytest.fail("path rejection is pre-card"),
        plain_body_path=str(outside),
    )
    assert result.get("sent") is False
    assert result.get("blocked") is True
    assert "Plain body path rejected" in result.get("error", "")
    assert client.sent == []
