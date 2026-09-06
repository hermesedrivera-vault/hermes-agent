"""Regression tests for the 2026-09-06 module-purge receipt-loss bug.

Real incident: ``hermes update``'s fleet-restart-catchup path calls
``_purge_stale_hermes_modules()`` mid-run, evicting every ``hermes_cli.*``
module from ``sys.modules`` (a legitimate, separate 2026-08-20 fix for
stale-cache import errors). That purge creates a BRAND NEW
``update_receipt`` module object with a fresh ``_current = None`` — the
in-memory receipt begun earlier in the same OS process is silently
orphaned, no exception raised anywhere. ``finalize_pending_update_receipt``
then no-ops on ``_current is None``, and the fork-safety verification line
Ed asked for (2026-09-06: "if I don't tell you to check, you don't know")
never prints, even though the run completed and had real divergence data
to report.

Fix: persist the one fact that must survive a purge (the pre-run
divergence snapshot) to a small disk sidecar the instant the receipt
begins, PID-scoped and one-shot. If ``_current`` is still ``None`` at
finalize time, reconstruct a receipt from that sidecar instead of
silently reporting nothing.
"""

import json
import os

import pytest

import hermes_cli.update_receipt as ur


@pytest.fixture()
def receipt_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setattr(
        "hermes_cli.config.get_hermes_home", lambda: home, raising=False
    )
    ur._current = None
    yield home
    ur._current = None


def _fake_divergence(local_only=0, behind=0):
    return {
        "is_fork": True,
        "branch": "main",
        "local_only_vs_origin": local_only,
        "fork_behind_upstream": behind,
        "has_upstream_remote": True,
    }


class TestInflightSnapshotSurvivesModulePurge:
    def test_begin_writes_inflight_snapshot_to_disk(self, receipt_home, monkeypatch):
        """begin_update_receipt() must persist divergence_pre to disk,
        not just to the in-memory singleton — that's the whole point."""
        monkeypatch.setattr(
            ur, "_capture_divergence_snapshot", lambda: _fake_divergence(3, 10)
        )
        ur.begin_update_receipt()

        path = ur._inflight_snapshot_path()
        assert path.is_file(), "in-flight snapshot was not written to disk"
        data = json.loads(path.read_text())
        assert data["divergence_pre"]["local_only_vs_origin"] == 3
        assert data["divergence_pre"]["fork_behind_upstream"] == 10
        assert data["pid"] == os.getpid()

    def test_finalize_pending_reconstructs_after_current_is_wiped(
        self, receipt_home, monkeypatch
    ):
        """Simulates the exact real-world failure: begin, then the module
        purge sets _current = None (as a fresh reimport would), then
        finalize_pending_update_receipt must still produce a real receipt
        with the pre-purge divergence data intact."""
        monkeypatch.setattr(
            ur, "_capture_divergence_snapshot", lambda: _fake_divergence(5, 6005)
        )
        ur.begin_update_receipt()
        assert ur._current is not None

        # Simulate _purge_stale_hermes_modules(): a fresh module reimport
        # would reset this global to None with no exception anywhere.
        ur._current = None

        path = ur.finalize_pending_update_receipt(1, "sys.exit(1)")
        assert path is not None, "finalize_pending_update_receipt returned None after purge"

        written = json.loads(path.read_text())
        assert written["reconstructed_after_module_purge"] is True
        assert written["divergence_pre"]["local_only_vs_origin"] == 5
        assert written["divergence_pre"]["fork_behind_upstream"] == 6005
        # post_update/divergence_post computed fresh at finalize time —
        # works normally because finalize() runs in the NEW (post-purge)
        # module, which is perfectly healthy on its own.
        assert "divergence_post" in written

    def test_finalize_pending_without_any_receipt_or_snapshot_is_noop(
        self, receipt_home
    ):
        """No begin() call, no leftover snapshot -> None, not a crash."""
        assert ur._current is None
        result = ur.finalize_pending_update_receipt(1, "sys.exit(1)")
        assert result is None

    def test_inflight_snapshot_is_pid_scoped(self, receipt_home, monkeypatch):
        """A stale snapshot from a DIFFERENT pid must never be mistaken
        for the current run's data — prevents a crashed prior run's
        leftover file from silently feeding wrong data into this run."""
        monkeypatch.setattr(
            ur, "_capture_divergence_snapshot", lambda: _fake_divergence(1, 1)
        )
        ur.begin_update_receipt()
        path = ur._inflight_snapshot_path()
        data = json.loads(path.read_text())
        data["pid"] = data["pid"] + 999999  # simulate a different process
        path.write_text(json.dumps(data))

        result = ur._read_and_clear_inflight_snapshot()
        assert result is None
        # Must still consume (delete) the stale file either way.
        assert not path.is_file()

    def test_normal_finalize_path_clears_inflight_snapshot(
        self, receipt_home, monkeypatch
    ):
        """When the run finalizes normally (no purge, no orphaning), the
        sidecar must not linger — it's single-use per run."""
        monkeypatch.setattr(
            ur, "_capture_divergence_snapshot", lambda: _fake_divergence(0, 0)
        )
        ur.begin_update_receipt()
        assert ur._inflight_snapshot_path().is_file()

        ur.finalize_update_receipt("success")
        assert not ur._inflight_snapshot_path().is_file()


class TestFormatUpdateIntegrityLine:
    def test_no_local_commits_lost_reports_safe(self):
        pre = _fake_divergence(5, 10)
        post = _fake_divergence(5, 10)
        line = ur.format_update_integrity_line(
            {"divergence_pre": pre, "divergence_post": post}
        )
        assert "✓ Local-commit safety" in line
        assert "5 commit(s)" in line
        assert "DISAPPEARED" not in line

    def test_local_commits_disappearing_is_flagged_red(self):
        """The exact failure class this whole feature exists to catch:
        commits present before the run, gone after."""
        pre = _fake_divergence(3, 10)
        post = _fake_divergence(0, 0)
        line = ur.format_update_integrity_line(
            {"divergence_pre": pre, "divergence_post": post}
        )
        assert "🔴" in line
        assert "DISAPPEARED" in line
        assert "3 → 0" in line

    def test_unverifiable_check_never_claims_safe(self):
        """None must never be silently treated as 0/safe — print the
        gap honestly instead of a false-positive all-clear."""
        pre = {"local_only_vs_origin": None, "fork_behind_upstream": None}
        post = {"local_only_vs_origin": None, "fork_behind_upstream": None}
        line = ur.format_update_integrity_line(
            {"divergence_pre": pre, "divergence_post": post}
        )
        assert "UNVERIFIABLE" in line
        assert "✓" not in line.split("\n")[0]

    def test_fork_behind_upstream_count_surfaces(self):
        """The second half of Ed's original complaint: hermes update's
        own output never told him how far behind upstream the fork was —
        only a CLI-startup banner he never sees in a gateway session."""
        pre = _fake_divergence(0, 5978)
        post = _fake_divergence(0, 5978)
        line = ur.format_update_integrity_line(
            {"divergence_pre": pre, "divergence_post": post}
        )
        assert "5978" in line
        assert "behind" in line
        assert "NousResearch/hermes-agent" in line

    def test_fork_at_parity_reports_clean(self):
        pre = _fake_divergence(0, 0)
        post = _fake_divergence(0, 0)
        line = ur.format_update_integrity_line(
            {"divergence_pre": pre, "divergence_post": post}
        )
        assert "at parity" in line

    def test_no_divergence_data_at_all_returns_none(self):
        """Very old receipt / non-git checkout: no line rather than a
        fabricated verdict."""
        line = ur.format_update_integrity_line({})
        assert line is None
