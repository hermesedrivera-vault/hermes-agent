"""
Wiring regression test: the real search_files tool path must mint provenance
receipts carrying an accurate result_count, so the false-absence and
count-mismatch gates have ground truth on live traffic.

Guards three invariants:
1. A search that returns matches -> receipt.result_count == total_count (> 0)
2. A valid empty search        -> receipt.result_count == 0 (backs legit absence)
3. A search that ERRORED        -> NO receipt (a failed search must not
   masquerade as proven absence)

Real path, real imports, temp DB, temp workdir. No mocks. $0 cost.
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import agent.provenance.gate as gate


@pytest.fixture
def wired_store(monkeypatch):
    """Enable provenance against a temp DB and reset the singleton."""
    secret_hex = os.urandom(32).hex()
    monkeypatch.setenv("HERMES_PROVENANCE_SECRET", secret_hex)
    monkeypatch.setattr(gate, "PROVENANCE_DISABLED", False)

    tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
    real_store_cls = gate.EvidenceStore
    monkeypatch.setattr(
        gate, "EvidenceStore",
        lambda *a, **k: real_store_cls(tmpdb, bytes.fromhex(secret_hex)),
    )
    gate._EVIDENCE_STORE = None

    yield gate

    gate._EVIDENCE_STORE = None
    try:
        os.unlink(tmpdb)
    except OSError:
        pass


@pytest.fixture
def workdir():
    """A temp dir with a couple of files for search_files to find."""
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "alpha.py"), "w") as f:
        f.write("def alpha(): pass\n")
    with open(os.path.join(d, "beta.py"), "w") as f:
        f.write("def beta(): pass\n")
    return d


def _search_counts(store):
    rows = store.db.execute(
        "SELECT result_count FROM evidence WHERE tool_name='search_files' ORDER BY timestamp"
    ).fetchall()
    return [r["result_count"] for r in rows]


def test_search_files_mints_result_count_on_hit(wired_store, workdir):
    from tools.file_tools import search_tool
    session_id = "wiring_hit"  # picked up by the tool's inspect frame-walk
    out = search_tool(pattern="*.py", target="files", path=workdir, task_id="h")
    d = json.loads(out.split("\n\n[Hint")[0])
    assert d.get("error") is None
    store = wired_store.get_evidence_store()
    counts = _search_counts(store)
    assert counts, "a successful search must mint a receipt"
    assert max(counts) == d["total_count"] == 2


def test_search_files_mints_zero_on_valid_empty(wired_store, workdir):
    from tools.file_tools import search_tool
    session_id = "wiring_empty"
    out = search_tool(pattern="*.nonexistent_zzz", target="files", path=workdir, task_id="e")
    d = json.loads(out.split("\n\n[Hint")[0])
    assert d.get("error") is None
    store = wired_store.get_evidence_store()
    assert 0 in _search_counts(store), "valid empty search must mint result_count=0"


def test_search_files_no_receipt_on_error(wired_store):
    from tools.file_tools import search_tool
    session_id = "wiring_error"
    out = search_tool(pattern="*.py", target="files",
                      path="/no/such/path/qqq_zzz", task_id="x")
    d = json.loads(out.split("\n\n[Hint")[0])
    assert d.get("error"), "expected an error for a bad path"
    store = wired_store.get_evidence_store()
    assert _search_counts(store) == [], "errored search must NOT mint a receipt"
