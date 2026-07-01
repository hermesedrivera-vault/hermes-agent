"""
Tests for the outbound-comms approval gate.

The headline test replays the EXACT failure from 2026-06-30: the agent ran a
Python Gmail-send script through the `terminal` tool to reply to contractor
Kelvin WITHOUT an explicit user "Approved". This must be flagged.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from agent.provenance.approval_gate import (
    apply_approval_gate,
    detect_outbound_comm,
    has_valid_approval,
    record_user_message,
    APPROVAL_TTL_SECONDS,
)
import agent.provenance.approval_gate as ag


@pytest.fixture
def db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    os.unlink(path)


# The real Gmail-send command from today (trimmed but structurally identical).
KELVIN_EMAIL_CMD = '''cd ~/.hermes && python3 << 'PYTHON_EOF'
from googleapiclient.discovery import build
from email.mime.text import MIMEText
service = build('gmail', 'v1', credentials=creds)
msg = MIMEText("<p>Hi Kelvin, I'm available tomorrow...</p>", 'html')
msg['To'] = 'japaintingservicesinc@gmail.com'
msg['Cc'] = 'ed.rivera@gmail.com'
result = service.users().messages().send(userId='me', body={'raw': raw}).execute()
PYTHON_EOF'''


# ── Detection ────────────────────────────────────────────────────────────

def test_detects_todays_kelvin_email():
    det = detect_outbound_comm("terminal", {"command": KELVIN_EMAIL_CMD})
    assert det is not None
    assert det["channel"] == "email"
    assert "japaintingservicesinc@gmail.com" in det["recipients"]
    # The CC to Ed himself must NOT count as an external recipient.
    assert "ed.rivera@gmail.com" not in det["recipients"]


def test_self_only_cc_is_not_external():
    cmd = '''service.users().messages().send(userId='me', body=b)
msg['To'] = 'ed.rivera@gmail.com' '''
    assert detect_outbound_comm("terminal", {"command": cmd}) is None


def test_reading_email_is_not_a_send():
    cmd = "service.users().messages().list(userId='me', q='from:foo@bar.com').execute()"
    assert detect_outbound_comm("terminal", {"command": cmd}) is None


def test_plain_shell_command_ignored():
    assert detect_outbound_comm("terminal", {"command": "ls -la && git status"}) is None


def test_sms_detected():
    cmd = "client.messages.create(to='+17543680000', body='hi')"
    det = detect_outbound_comm("terminal", {"command": cmd})
    assert det is not None and det["channel"] == "sms"


# ── Approval ledger ──────────────────────────────────────────────────────

def test_explicit_approved_recorded(db):
    assert record_user_message("s1", "Approved", db_path=db) is True
    assert has_valid_approval("s1", db_path=db) is True


def test_bare_ok_is_not_approval(db):
    assert record_user_message("s1", "ok good", db_path=db) is False
    assert has_valid_approval("s1", db_path=db) is False


def test_approval_expires(db):
    record_user_message("s1", "Approved", db_path=db)
    future = __import__("time").time() + APPROVAL_TTL_SECONDS + 1
    assert has_valid_approval("s1", now=future, db_path=db) is False


def test_approval_is_per_session(db):
    record_user_message("s1", "Approved", db_path=db)
    assert has_valid_approval("s2", db_path=db) is False


# ── Gate behavior ────────────────────────────────────────────────────────

def test_enforce_blocks_unapproved_kelvin_email(db, monkeypatch):
    monkeypatch.setitem(ag.APPROVAL_GATE_MODE, "terminal", "enforce")
    block = apply_approval_gate("terminal", {"command": KELVIN_EMAIL_CMD}, "sess", db_path=db)
    assert block is not None
    assert '"APPROVAL_REQUIRED"' in block
    assert "japaintingservicesinc@gmail.com" in block


def test_enforce_allows_after_approval(db, monkeypatch):
    monkeypatch.setitem(ag.APPROVAL_GATE_MODE, "terminal", "enforce")
    record_user_message("sess", "Approved, send it", db_path=db)
    block = apply_approval_gate("terminal", {"command": KELVIN_EMAIL_CMD}, "sess", db_path=db)
    assert block is None


def test_shadow_never_blocks_even_unapproved(db, monkeypatch):
    monkeypatch.setitem(ag.APPROVAL_GATE_MODE, "terminal", "shadow")
    block = apply_approval_gate("terminal", {"command": KELVIN_EMAIL_CMD}, "sess", db_path=db)
    assert block is None  # shadow logs but allows


def test_off_mode_is_noop(db, monkeypatch):
    monkeypatch.setitem(ag.APPROVAL_GATE_MODE, "terminal", "off")
    assert apply_approval_gate("terminal", {"command": KELVIN_EMAIL_CMD}, "sess", db_path=db) is None


def test_non_comm_tool_call_passes(db, monkeypatch):
    monkeypatch.setitem(ag.APPROVAL_GATE_MODE, "terminal", "enforce")
    assert apply_approval_gate("terminal", {"command": "pytest -v"}, "sess", db_path=db) is None
