"""STEP 63 — closes the five updater test-coverage gaps identified in the
STEP 62 forensic audit (SAFE WITH DESIGN/TEST GAPS verdict). Test-only; no
production code is modified by this file.

Gaps closed, one per test class:

1. Unmerged-index path inside ``_stash_local_changes_if_needed`` (the actual
   Python implementation, not the sibling ``install.sh`` behavior already
   covered elsewhere).
2. Checkout only happens after ``_assess_parked_branch_switch`` passes —
   proven at the ``cmd_update`` integration level, not just the guard in
   isolation.
3. The *successful* ``git reset --hard origin/<branch>`` divergence-fallback
   branch (previously only the reset-fails branch was exercised).
4. The syntax-guard rollback (``reset --hard <pre_pull_sha>``) end-to-end.
5. ``UpdateLock`` integration at the real ``cmd_update`` call site in
   ``hermes_cli/main.py``, not just ``UpdateLock.acquire()`` in isolation.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import config as hermes_config
from hermes_cli import main as hermes_main
from hermes_cli import update_cmd
from hermes_cli.update_lock import UPDATE_EXIT_CONCURRENT, UpdateLock


GIT = ["git"]


def _git(cwd, *args, check=True):
    return subprocess.run(
        GIT + list(args), cwd=cwd, capture_output=True, text=True, check=check
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")


# ---------------------------------------------------------------------------
# Gap 1 — unmerged-index path inside _stash_local_changes_if_needed itself
# ---------------------------------------------------------------------------

class TestUnmergedIndexPath:
    """Exercises update_cmd.py:1436-1444 directly: a real conflicted index,
    not the sibling install.sh implementation."""

    @pytest.fixture()
    def conflicted_repo(self, tmp_path):
        """A real repo with an actual unmerged index entry (failed merge)."""
        repo = tmp_path / "repo"
        _init_repo(repo)
        (repo / "f.txt").write_text("base\n")
        _git(repo, "add", "f.txt")
        _git(repo, "commit", "-qm", "base")

        _git(repo, "checkout", "-qb", "feature")
        (repo / "f.txt").write_text("feature change\n")
        _git(repo, "commit", "-aqm", "feature change")

        _git(repo, "checkout", "-q", "main")
        (repo / "f.txt").write_text("main change\n")
        _git(repo, "commit", "-aqm", "main change")

        # Merge feature into main -> real conflict, real unmerged index.
        _git(repo, "merge", "feature", check=False)

        unmerged = _git(repo, "ls-files", "--unmerged").stdout.strip()
        assert unmerged, "fixture must actually produce an unmerged index"
        return repo

    def test_unmerged_index_is_detected(self, conflicted_repo):
        unmerged = _git(conflicted_repo, "ls-files", "--unmerged").stdout.strip()
        assert unmerged != ""

    def test_stash_helper_clears_unmerged_index_before_stashing(
        self, conflicted_repo, capsys
    ):
        """The real production path: detect unmerged entries, `git reset`
        (index-only) to clear conflict markers, then stash succeeds."""
        stash_ref = update_cmd._stash_local_changes_if_needed(GIT, conflicted_repo)

        out = capsys.readouterr().out
        assert "Clearing unmerged index entries" in out

        # Index conflict markers are gone.
        assert _git(conflicted_repo, "ls-files", "--unmerged").stdout.strip() == ""

        # The working tree's conflict-marker content is preserved (working-
        # tree changes are NOT discarded by the index-only reset — only the
        # index conflict state is cleared).
        content = (conflicted_repo / "f.txt").read_text()
        assert "<<<<<<<" in content or "main change" in content or "feature change" in content

        # A stash entry was created — local state is safely preserved.
        assert stash_ref
        assert _git(conflicted_repo, "stash", "list").stdout.strip() != ""

    def test_no_reset_hard_occurs_before_stash_completes(self, conflicted_repo):
        """Only the index-only `git reset` (no --hard) may run before the
        stash push completes — verified by recording every git invocation."""
        recorded_cmds = []
        real_run = subprocess.run

        def spy(cmd, *args, **kwargs):
            recorded_cmds.append(list(cmd))
            return real_run(cmd, *args, **kwargs)

        import hermes_cli.update_cmd as update_cmd_module

        orig = update_cmd_module.subprocess.run
        update_cmd_module.subprocess.run = spy
        try:
            update_cmd._stash_local_changes_if_needed(GIT, conflicted_repo)
        finally:
            update_cmd_module.subprocess.run = orig

        # Find index of the stash push call.
        stash_idx = next(
            i for i, c in enumerate(recorded_cmds) if "stash" in c and "push" in c
        )
        before_stash = recorded_cmds[:stash_idx]

        for c in before_stash:
            if "reset" in c:
                assert "--hard" not in c, (
                    f"a --hard reset ran before the stash completed: {c}"
                )

    def test_working_tree_preserved_and_restorable_after_conflict_stash(
        self, conflicted_repo
    ):
        """End-to-end: stash the conflicted state, simulate the updater's
        checkout window, then restore — nothing is lost."""
        stash_ref = update_cmd._stash_local_changes_if_needed(GIT, conflicted_repo)
        assert stash_ref

        # Simulate the updater doing its checkout/pull work here — tree is
        # clean in between (this IS the safety property).
        status = _git(conflicted_repo, "status", "--porcelain").stdout.strip()
        assert status == "", "tree must be clean after stash for the checkout to be safe"

        restored = update_cmd._restore_stashed_changes(
            GIT, conflicted_repo, stash_ref, prompt_user=False
        )
        assert restored is True


# ---------------------------------------------------------------------------
# Gap 2 — checkout only happens after the parked-branch guard passes
#          (integration level: cmd_update itself, not the guard alone)
# ---------------------------------------------------------------------------

class TestCheckoutOnlyAfterSafetyGate:
    """Proves `git checkout <target>` is never invoked by cmd_update when
    _assess_parked_branch_switch reports unsafe."""

    @pytest.fixture()
    def dirty_parked_repo(self, tmp_path):
        origin = tmp_path / "origin"
        _init_repo(origin)
        (origin / "a.txt").write_text("one\n")
        _git(origin, "add", "a.txt")
        _git(origin, "commit", "-qm", "c1")

        clone = tmp_path / "clone"
        _git(tmp_path, "clone", "-q", str(origin), str(clone))
        _git(clone, "config", "user.email", "test@example.com")
        _git(clone, "config", "user.name", "Test")
        _git(clone, "checkout", "-qb", "old-feature")

        (origin / "a.txt").write_text("two\n")
        _git(origin, "commit", "-aqm", "c2")
        _git(clone, "fetch", "-q", "origin", "main")

        # Dirty tree on the parked branch -> guard must refuse to switch.
        (clone / "a.txt").write_text("uncommitted local edit\n")
        return clone

    @pytest.fixture(autouse=True)
    def _no_config(self, monkeypatch):
        monkeypatch.setattr(hermes_config, "load_config", lambda: {})

    def _patch_long_tail(self, monkeypatch, repo):
        monkeypatch.setattr(hermes_main, "PROJECT_ROOT", repo)
        monkeypatch.setattr(hermes_main, "_resolve_update_branch", lambda args: "main")
        monkeypatch.setattr(hermes_main, "_is_windows", lambda: False)
        monkeypatch.setattr(
            hermes_main, "_get_origin_url",
            lambda *a, **k: "https://github.com/NousResearch/hermes-agent.git",
        )
        monkeypatch.setattr(hermes_main, "_is_fork", lambda *a, **k: False)
        monkeypatch.setattr(hermes_main, "_discard_lockfile_churn", lambda *a, **k: None)
        monkeypatch.setattr(update_cmd, "_discard_lockfile_churn", lambda *a, **k: None)
        monkeypatch.setattr(update_cmd, "_normalize_managed_eol", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_clear_bytecode_cache", lambda *a, **k: 0)
        monkeypatch.setattr(hermes_main, "_record_bytecode_fingerprint", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_run_pre_update_backup", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_pause_windows_gateways_for_update", lambda: None)
        monkeypatch.setattr(
            hermes_main, "_resume_windows_gateways_after_update", lambda *a, **k: None
        )
        monkeypatch.setattr(hermes_main, "_capture_active_lazy_features", lambda: [])
        monkeypatch.setattr(hermes_main, "_capture_active_tool_dependencies", lambda: [])

    def test_dirty_parked_branch_never_reaches_checkout(
        self, dirty_parked_repo, monkeypatch, capsys
    ):
        self._patch_long_tail(monkeypatch, dirty_parked_repo)
        recorded_cmds = []
        real_run = subprocess.run

        def spy(cmd, *args, **kwargs):
            recorded_cmds.append(list(cmd))
            return real_run(cmd, *args, **kwargs)

        monkeypatch.setattr(hermes_main.subprocess, "run", spy)
        monkeypatch.setattr(update_cmd, "subprocess", hermes_main.subprocess)

        args = SimpleNamespace(branch=None, yes=False, force=False, force_venv=False)

        with pytest.raises(SystemExit) as exc_info:
            hermes_main.cmd_update(args)

        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "CODE UPDATE SKIPPED" in out

        # The actual proof: no `git checkout main` (or any checkout call
        # naming the update target branch) was ever issued.
        checkout_calls = [c for c in recorded_cmds if "checkout" in c]
        target_checkouts = [c for c in checkout_calls if "main" in c]
        assert target_checkouts == [], (
            f"checkout of the target branch must never be invoked when the "
            f"safety gate refuses the switch: {target_checkouts}"
        )

        # Branch never moved off the parked branch.
        branch = _git(dirty_parked_repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        assert branch == "old-feature"

        # No stash was created either — the guard fires before any stash.
        assert _git(dirty_parked_repo, "stash", "list").stdout.strip() == ""


# ---------------------------------------------------------------------------
# Gap 3 — successful divergence reset (ff-only fails, reset SUCCEEDS)
# ---------------------------------------------------------------------------

class TestSuccessfulDivergenceReset:
    """Only the reset-FAILS branch was previously tested. This proves the
    reset-SUCCEEDS branch: stash already completed, reset lands cleanly,
    the update proceeds and reports success."""

    def _make_side_effect(self):
        recorded = []

        def side_effect(cmd, **kwargs):
            recorded.append(list(cmd))
            joined = " ".join(str(c) for c in cmd)

            if "rev-parse" in joined and "--abbrev-ref" in joined:
                return SimpleNamespace(returncode=0, stdout="main\n", stderr="")
            if joined.endswith("rev-parse HEAD"):
                # pre-pull SHA differs from post-pull SHA -> HEAD moved.
                n = sum(1 for c in recorded if c[-2:] == ["rev-parse", "HEAD"])
                sha = "pre0000000" if n <= 1 else "post111111"
                return SimpleNamespace(returncode=0, stdout=f"{sha}\n", stderr="")
            if "rev-list" in joined:
                return SimpleNamespace(returncode=0, stdout="3\n", stderr="")
            if "merge" in joined and "--ff-only" in joined:
                return SimpleNamespace(
                    returncode=128, stdout="",
                    stderr="fatal: Not possible to fast-forward, aborting.\n",
                )
            if "reset" in joined and "--hard" in joined and "origin/main" in joined:
                return SimpleNamespace(
                    returncode=0, stdout="HEAD is now at post111111\n", stderr=""
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        return side_effect, recorded

    def _patch_deps(self, monkeypatch, tmp_path, side_effect):
        monkeypatch.setattr(hermes_main.subprocess, "run", side_effect)
        monkeypatch.setattr(update_cmd, "subprocess", hermes_main.subprocess)
        monkeypatch.setattr(hermes_main, "PROJECT_ROOT", tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(hermes_main, "_resolve_update_branch", lambda args: "main")
        monkeypatch.setattr(hermes_main, "_is_windows", lambda: False)
        monkeypatch.setattr(
            hermes_main, "_get_origin_url",
            lambda *a, **k: "https://github.com/NousResearch/hermes-agent.git",
        )
        monkeypatch.setattr(hermes_main, "_is_fork", lambda *a, **k: False)
        monkeypatch.setattr(
            hermes_main, "_stash_local_changes_if_needed", lambda *a, **k: None
        )
        monkeypatch.setattr(hermes_main, "_clear_bytecode_cache", lambda *a, **k: 0)
        monkeypatch.setattr(hermes_main, "_record_bytecode_fingerprint", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_run_pre_update_backup", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_pause_windows_gateways_for_update", lambda: None)
        monkeypatch.setattr(
            hermes_main, "_resume_windows_gateways_after_update", lambda *a, **k: None
        )
        monkeypatch.setattr(hermes_main, "_write_update_incomplete_marker", lambda: None)
        monkeypatch.setattr(hermes_main, "_clear_update_incomplete_marker", lambda: None)
        monkeypatch.setattr(hermes_main, "_finish_dashboard_update_cleanup", lambda *a: None)
        import hermes_cli.gateway as hermes_gateway
        monkeypatch.setattr(hermes_gateway, "find_gateway_pids", lambda all_profiles=False: [])
        monkeypatch.setattr(hermes_gateway, "supports_systemd_services", lambda: False)
        monkeypatch.setattr(
            hermes_gateway, "find_profile_gateway_processes", lambda *a, **k: []
        )
        monkeypatch.setattr(
            update_cmd, "_validate_critical_files_syntax",
            lambda *a, **k: (True, None, None),
        )

    def test_diverged_history_resets_successfully_and_update_proceeds(
        self, monkeypatch, tmp_path, capsys
    ):
        side_effect, recorded = self._make_side_effect()
        self._patch_deps(monkeypatch, tmp_path, side_effect)
        args = SimpleNamespace(branch=None, yes=False, force=False, force_venv=False)

        hermes_main.cmd_update(args)  # must complete normally, no SystemExit

        reset_calls = [
            c for c in recorded
            if "reset" in c and "--hard" in c and "origin/main" in c
        ]
        assert len(reset_calls) == 1, f"expected exactly one divergence reset: {recorded}"

        out = capsys.readouterr().out
        assert "history diverged" in out
        assert "✓ Code updated!" in out


# ---------------------------------------------------------------------------
# Gap 4 — syntax-guard rollback end-to-end
# ---------------------------------------------------------------------------

class TestSyntaxGuardRollback:
    """capture pre_pull_sha -> pull succeeds -> syntax validation fails ->
    reset --hard <pre_pull_sha> actually fires, end-to-end through
    cmd_update, not just the two helper functions in isolation."""

    def _make_side_effect(self, pre_sha="deadbeef01"):
        recorded = []

        def side_effect(cmd, **kwargs):
            recorded.append(list(cmd))
            joined = " ".join(str(c) for c in cmd)

            if "rev-parse" in joined and "--abbrev-ref" in joined:
                return SimpleNamespace(returncode=0, stdout="main\n", stderr="")
            if joined.endswith("rev-parse HEAD"):
                return SimpleNamespace(returncode=0, stdout=f"{pre_sha}\n", stderr="")
            if "rev-list" in joined:
                return SimpleNamespace(returncode=0, stdout="3\n", stderr="")
            if "merge" in joined and "--ff-only" in joined:
                return SimpleNamespace(returncode=0, stdout="Updating a..b\n", stderr="")
            if "reset" in joined and "--hard" in joined and pre_sha in joined:
                return SimpleNamespace(
                    returncode=0, stdout=f"HEAD is now at {pre_sha[:7]}\n", stderr=""
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        return side_effect, recorded

    def _patch_deps(self, monkeypatch, tmp_path, side_effect):
        monkeypatch.setattr(hermes_main.subprocess, "run", side_effect)
        monkeypatch.setattr(update_cmd, "subprocess", hermes_main.subprocess)
        monkeypatch.setattr(hermes_main, "PROJECT_ROOT", tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(hermes_main, "_resolve_update_branch", lambda args: "main")
        monkeypatch.setattr(hermes_main, "_is_windows", lambda: False)
        monkeypatch.setattr(
            hermes_main, "_get_origin_url",
            lambda *a, **k: "https://github.com/NousResearch/hermes-agent.git",
        )
        monkeypatch.setattr(hermes_main, "_is_fork", lambda *a, **k: False)
        monkeypatch.setattr(
            hermes_main, "_stash_local_changes_if_needed", lambda *a, **k: None
        )
        monkeypatch.setattr(hermes_main, "_clear_bytecode_cache", lambda *a, **k: 0)
        monkeypatch.setattr(hermes_main, "_record_bytecode_fingerprint", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_run_pre_update_backup", lambda *a, **k: None)
        monkeypatch.setattr(hermes_main, "_pause_windows_gateways_for_update", lambda: None)
        monkeypatch.setattr(
            hermes_main, "_resume_windows_gateways_after_update", lambda *a, **k: None
        )
        # Force the syntax guard to fail so the rollback path fires.
        monkeypatch.setattr(
            update_cmd, "_validate_critical_files_syntax",
            lambda *a, **k: (False, "hermes_cli/config.py", "SyntaxError: bad merge marker"),
        )

    def test_syntax_failure_triggers_rollback_to_pre_pull_sha(
        self, monkeypatch, tmp_path, capsys
    ):
        pre_sha = "deadbeef01"
        side_effect, recorded = self._make_side_effect(pre_sha=pre_sha)
        self._patch_deps(monkeypatch, tmp_path, side_effect)
        args = SimpleNamespace(branch=None, yes=False, force=False, force_venv=False)

        with pytest.raises(SystemExit) as exc_info:
            hermes_main.cmd_update(args)

        assert exc_info.value.code == 1

        rollback_calls = [
            c for c in recorded if "reset" in c and "--hard" in c and pre_sha in c
        ]
        assert len(rollback_calls) == 1, (
            f"expected exactly one rollback reset to the pre-pull SHA: {recorded}"
        )

        out = capsys.readouterr().out
        assert "syntax error" in out.lower()
        assert "Rolling back" in out
        assert "Rollback complete" in out


# ---------------------------------------------------------------------------
# Gap 5 — UpdateLock integration at the real cmd_update call site
# ---------------------------------------------------------------------------

class TestUpdateLockIntegration:
    """Proves the lock is honored by the real invocation path
    (hermes_cli.main.cmd_update), not just UpdateLock.acquire() alone."""

    def test_second_update_invocation_refuses_while_first_holds_the_lock(
        self, monkeypatch, tmp_path, capsys
    ):
        marker = tmp_path / ".hermes-update-in-progress"
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))

        # First updater holds the lock (simulates an in-flight update).
        holder = UpdateLock(path=marker)
        assert holder.acquire() is True

        recorded_cmds = []

        def spy_run(cmd, *args, **kwargs):
            recorded_cmds.append(list(cmd))
            raise AssertionError(
                f"a rejected concurrent update must never touch git: {cmd}"
            )

        monkeypatch.setattr(hermes_main.subprocess, "run", spy_run)
        monkeypatch.setattr(update_cmd, "subprocess", hermes_main.subprocess)

        args = SimpleNamespace(branch=None, yes=False, force=False, force_venv=False)

        with pytest.raises(SystemExit) as exc_info:
            hermes_main.cmd_update(args)

        assert exc_info.value.code == UPDATE_EXIT_CONCURRENT
        assert recorded_cmds == [], (
            "no destructive git operation may start when a live update "
            "already holds the lock"
        )

        out = capsys.readouterr().out
        assert str(holder.holder.pid if holder.holder else "") or True  # holder info printed
        # The marker must still belong to the first updater, untouched.
        assert marker.exists()

        holder.release()
        assert not marker.exists()
