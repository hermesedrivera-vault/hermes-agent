"""SSN/ITIN/EIN masking at the state.db persistence layer (hermes_state_messages.py).

Every digit string in this file is a fabricated test fixture, never a real
SSN/EIN. Added 2026-11-01, Ed's SSN/backup remediation item (2b): FTS5
(`messages_fts`) indexes the `content` column, so masking must happen before
the INSERT, not just at tool-output display time -- otherwise the plaintext
lands in both `messages` and `messages_fts`.
"""
import pytest

from hermes_state import SessionDB

FAKE_SSN = "123-45-6789"
FAKE_SSN_SPACED = "987 65 4321"
FAKE_EIN = "12-3456789"


@pytest.fixture()
def db(tmp_path):
    handle = SessionDB(db_path=tmp_path / "state.db")
    try:
        yield handle
    finally:
        handle.close()


def _content(db, sid):
    row = db._conn.execute(
        "SELECT content FROM messages WHERE session_id = ? ORDER BY id DESC LIMIT 1", (sid,)
    ).fetchone()
    return row["content"]


def _fts_hits(db, query):
    rows = db._conn.execute(
        "SELECT m.content FROM messages_fts JOIN messages m ON messages_fts.rowid = m.id "
        "WHERE messages_fts MATCH ?", (query,)
    ).fetchall()
    return [r["content"] for r in rows]


# --- append_message (single) ---

def test_user_typed_ssn_masked_on_append(db):
    # The gap Ed flagged: a typed user message never passes through any tool-output
    # redaction call site, so without this fix it would land in state.db in the clear.
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    db.append_message(session_id=sid, role="user", content=f"my SSN is {FAKE_SSN}")
    stored = _content(db, sid)
    assert FAKE_SSN not in stored
    assert "[SSN-REDACTED]" in stored


def test_space_separated_ssn_masked_on_append(db):
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    db.append_message(session_id=sid, role="user", content=f"SSN {FAKE_SSN_SPACED} on file")
    stored = _content(db, sid)
    assert FAKE_SSN_SPACED not in stored
    assert "[SSN-REDACTED]" in stored


def test_tool_role_ssn_masked_on_append(db):
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    db.append_message(session_id=sid, role="tool", content=f"output contained {FAKE_SSN}",
                       tool_name="terminal", tool_call_id="tc1")
    stored = _content(db, sid)
    assert FAKE_SSN not in stored
    assert "[SSN-REDACTED]" in stored


def test_ein_with_keyword_masked_on_append(db):
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    db.append_message(session_id=sid, role="user", content=f"Company EIN {FAKE_EIN}")
    stored = _content(db, sid)
    assert FAKE_EIN not in stored
    assert "[EIN-REDACTED]" in stored


def test_ein_without_keyword_left_alone_on_append(db):
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    content = f"invoice ref {FAKE_EIN} shipped"
    db.append_message(session_id=sid, role="user", content=content)
    assert _content(db, sid) == content


# --- append_messages_batch ---

def test_batch_append_masks_ssn(db):
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    db.append_messages_batch(sid, [
        {"role": "user", "content": f"client SSN {FAKE_SSN}"},
        {"role": "assistant", "content": "noted"},
    ])
    rows = db._conn.execute(
        "SELECT content FROM messages WHERE session_id = ? ORDER BY id", (sid,)
    ).fetchall()
    contents = [r["content"] for r in rows]
    assert all(FAKE_SSN not in c for c in contents)
    assert any("[SSN-REDACTED]" in c for c in contents)


# --- FTS5 index itself must never carry the plaintext (the actual gap being closed) ---

def test_fts_index_does_not_contain_raw_ssn(db):
    sid = "s1"
    db.create_session(sid, "cli", model="m")
    db.append_message(session_id=sid, role="user", content=f"my SSN is {FAKE_SSN}")
    # A MATCH query built from the raw SSN's digits must find nothing: the plaintext
    # was never written into messages_fts's indexed content in the first place.
    hits = _fts_hits(db, "123 45 6789")  # fts5 tokenizes on non-alnum; search the raw digits
    assert hits == []
    # But the redacted row is indexable/findable by its masked marker text.
    hits = _fts_hits(db, "SSN")
    assert any("[SSN-REDACTED]" in c for c in hits)
