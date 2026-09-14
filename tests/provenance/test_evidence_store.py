"""Tests for EvidenceStore.audit_log's additive `kind` column (Control Plane
Commit 5).

Confirms: schema now includes `kind`; a pre-existing row (written before this
column existed) is still readable and returns `kind: None`; a new row can set
`kind`; every existing writer's call pattern (positional-free, `kind` omitted)
keeps working unchanged; `get_audit_log()`'s SELECT * / dict(row) reader is
unaffected by the added column.
"""

import sqlite3

import pytest

from agent.provenance.store import EvidenceStore


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_evidence.db")
    return EvidenceStore(db_path=db_path, secret=b"0" * 32)


class TestKindColumnSchema:
    def test_audit_log_table_has_kind_column(self, store):
        cols = {row[1] for row in store.db.execute("PRAGMA table_info(audit_log)").fetchall()}
        assert "kind" in cols

    def test_kind_column_is_nullable_no_default_required(self, store):
        # Insert a row the OLD way (no kind at all) via raw SQL, simulating a
        # row written by a pre-Commit-5 binary/process that never knew this
        # column existed. Must not raise (NOT NULL would break this).
        store.db.execute(
            "INSERT INTO audit_log (timestamp, event, tool, reason, mode, session_id, blocked, details) "
            "VALUES (1.0, 'OLD_EVENT', 'tool', 'reason', 'shadow', 'sess-old', 0, 'details')"
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT * FROM audit_log WHERE event = 'OLD_EVENT'"
        ).fetchone()
        assert row["kind"] is None


class TestBackwardCompatibility:
    def test_pre_existing_row_without_kind_is_still_readable(self, store):
        """Simulates a real pre-Commit-5 row (written by the OLD .audit()
        call shape, before `kind` existed as a parameter) surviving into a
        post-Commit-5 read path."""
        store.db.execute(
            "INSERT INTO audit_log (timestamp, event, tool, reason, mode, session_id, blocked, details) "
            "VALUES (2.0, 'GATE_VIOLATION', 'send_message', 'count mismatch', 'enforce', 'sess-1', 1, '{}')"
        )
        store.db.commit()
        results = store.get_audit_log(session_id="sess-1")
        assert len(results) == 1
        assert results[0]["event"] == "GATE_VIOLATION"
        assert results[0]["kind"] is None  # old row, no kind ever set

    def test_existing_writer_call_pattern_is_unaffected(self, store):
        """Every real call site today invokes audit() WITHOUT `kind` at
        all (keyword args, same as agent/provenance/gate.py:376 and every
        internal store.py call site). Confirm that still works post-change."""
        store.audit(
            event="GATE_VIOLATION",
            tool="send_message",
            reason="count mismatch",
            session_id="sess-2",
            mode="enforce",
            blocked=True,
            details="{}",
        )
        results = store.get_audit_log(session_id="sess-2")
        assert len(results) == 1
        assert results[0]["event"] == "GATE_VIOLATION"
        assert results[0]["kind"] is None  # caller never set it -- unchanged behavior

    def test_get_audit_log_select_star_is_unaffected_by_new_column(self, store):
        """SELECT * + dict(row) just gains a key; no positional/tuple access
        exists anywhere, so this is safe by construction. Directly confirm
        the dict contract every existing reader depends on still holds."""
        store.audit(event="E", tool="t", reason="r", session_id="sess-3")
        row = store.get_audit_log(session_id="sess-3")[0]
        assert isinstance(row, dict)
        for expected_key in ("id", "timestamp", "event", "tool", "reason",
                             "mode", "session_id", "blocked", "details"):
            assert expected_key in row  # every pre-existing key still present


class TestNewRowsCanSetKind:
    def test_new_row_can_set_kind(self, store):
        store.audit(
            event="approval.yolo_bypass",
            tool="_run_approval_gate",
            reason="yolo",
            session_id="sess-4",
            kind="approval_bypass",
        )
        results = store.get_audit_log(session_id="sess-4")
        assert len(results) == 1
        assert results[0]["kind"] == "approval_bypass"

    def test_kind_defaults_to_none_when_omitted(self, store):
        store.audit(event="E", tool="t", reason="r", session_id="sess-5")
        results = store.get_audit_log(session_id="sess-5")
        assert results[0]["kind"] is None


class TestMigrationIdempotency:
    def test_ensure_column_is_idempotent_on_existing_db(self, tmp_path):
        """Re-opening an EvidenceStore against a DB that already has `kind`
        (e.g. a second process start) must not error or duplicate the
        column -- exactly the guarantee _ensure_column already provides for
        evidence.result_count/facts, reused here."""
        db_path = str(tmp_path / "reopen.db")
        store1 = EvidenceStore(db_path=db_path, secret=b"1" * 32)
        store1.close()
        # Re-open the same DB file -- _init_schema/_ensure_column runs again.
        store2 = EvidenceStore(db_path=db_path, secret=b"1" * 32)
        cols = [row[1] for row in store2.db.execute("PRAGMA table_info(audit_log)").fetchall()]
        assert cols.count("kind") == 1  # exactly one column, not duplicated
        store2.close()

    def test_migrating_a_pre_commit5_db_missing_kind_column(self, tmp_path):
        """Simulates a REAL pre-Commit-5 database file: create audit_log
        WITHOUT the kind column by hand (bypassing EvidenceStore entirely),
        then open it with EvidenceStore and confirm the column gets added
        without touching any existing data."""
        db_path = str(tmp_path / "legacy.db")
        raw = sqlite3.connect(db_path)
        raw.execute("""
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event TEXT NOT NULL,
                tool TEXT,
                reason TEXT,
                mode TEXT,
                session_id TEXT,
                blocked BOOLEAN,
                details TEXT
            )
        """)
        raw.execute(
            "INSERT INTO audit_log (timestamp, event, tool, reason, mode, session_id, blocked, details) "
            "VALUES (3.0, 'LEGACY_EVENT', 'tool', 'reason', 'shadow', 'sess-legacy', 0, 'd')"
        )
        raw.commit()
        raw.close()

        # Also need the `evidence` table present, since _init_schema creates
        # both -- CREATE TABLE IF NOT EXISTS is a no-op if it already exists,
        # but audit_log here was pre-created WITHOUT `kind` to simulate drift.
        store = EvidenceStore(db_path=db_path, secret=b"2" * 32)
        cols = {row[1] for row in store.db.execute("PRAGMA table_info(audit_log)").fetchall()}
        assert "kind" in cols
        legacy_row = store.get_audit_log(session_id="sess-legacy")[0]
        assert legacy_row["event"] == "LEGACY_EVENT"
        assert legacy_row["kind"] is None  # pre-existing row, untouched
        store.close()
