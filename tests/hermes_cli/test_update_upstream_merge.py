"""E2E tests for the 2026-09-06 upstream-merge fix (Ed's explicit ask).

Real incident: with a fork that has ANY local-only commits ahead of
upstream (Ed's fork always does -- his own patches), the previous
``_sync_with_upstream_if_needed`` logic permanently skipped syncing with
upstream, forever, no matter how many times ``hermes update`` ran. The
gap between the fork and NousResearch/hermes-agent only grew (5978 ->
6005 commits over the course of one session) and was never closed.

Fix: merge upstream/main into the fork instead of skipping. A ``git
merge`` is additive by construction -- it cannot delete a commit the
way a ``reset --hard`` can. On a genuine content conflict, abort
cleanly (touch nothing) and hand off to a human instead of guessing.

These tests build THREE real git repos (upstream, origin/fork, local
checkout) and exercise real git commands -- no mocking of git itself --
per this codebase's own "E2E validation, not just green unit mocks"
convention for anything touching real I/O.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hermes_cli import update_cmd


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@test")
    _git(path, "config", "user.name", "test")


def _commit(path: Path, filename: str, content: str, message: str) -> str:
    (path / filename).write_text(content)
    _git(path, "add", filename)
    _git(path, "commit", "-q", "-m", message)
    return _git(path, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture()
def three_repo_setup(tmp_path):
    """upstream (bare), fork/origin (bare), and a local checkout of the fork.

    Local checkout has 'upstream' and 'origin' remotes wired, matching a
    real Ed-style fork checkout.
    """
    upstream_bare = tmp_path / "upstream.git"
    fork_bare = tmp_path / "fork.git"
    work = tmp_path / "work"

    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(upstream_bare)])
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(fork_bare)])

    seed = tmp_path / "seed"
    _init_repo(seed)
    _commit(seed, "base.txt", "v1\n", "initial commit")
    _git(seed, "push", "-q", str(upstream_bare), "main")
    _git(seed, "push", "-q", str(fork_bare), "main")

    _init_repo(work)
    _git(work, "remote", "add", "origin", str(fork_bare))
    _git(work, "remote", "add", "upstream", str(upstream_bare))
    _git(work, "fetch", "-q", "origin", "main")
    _git(work, "checkout", "-q", "-b", "main", "origin/main")

    return work, upstream_bare, fork_bare


class TestUpstreamMergeInsteadOfSkip:
    def test_clean_merge_preserves_local_commits_and_pulls_upstream(
        self, three_repo_setup, capsys
    ):
        """Core fix: no overlapping changes -> merge lands automatically,
        both the fork's own commit AND upstream's new commit are present."""
        work, upstream_bare, fork_bare = three_repo_setup

        # Fork gets its own local-only commit (Ed's patch), touching a
        # DIFFERENT file than what upstream will touch -- guaranteed no
        # conflict, isolating the "does merge work at all" behavior.
        _commit(work, "fork_only.txt", "ed's patch\n", "fork-only commit")
        _git(work, "push", "-q", "origin", "main")

        # Upstream advances independently with an unrelated file.
        upstream_seed = work.parent / "upstream_seed"
        _init_repo(upstream_seed)
        _git(upstream_seed, "remote", "add", "origin", str(upstream_bare))
        _git(upstream_seed, "fetch", "-q", "origin", "main")
        _git(upstream_seed, "checkout", "-q", "-b", "main", "origin/main")
        _commit(upstream_seed, "upstream_feature.txt", "new feature\n", "upstream commit")
        _git(upstream_seed, "push", "-q", "origin", "main")

        result = update_cmd._sync_with_upstream_if_needed(
            ["git"], work, assume_yes=True
        )

        assert result is True
        out = capsys.readouterr().out
        assert "Merged cleanly" in out
        assert (work / "fork_only.txt").is_file(), "fork's local-only commit was lost"
        assert (work / "upstream_feature.txt").is_file(), "upstream's commit never landed"

        # The exact fact this whole feature exists to prove: the
        # fork-only commit must still be an ancestor of the new HEAD.
        fork_commit_sha = _git(work, "log", "--all", "--format=%H", "--grep=fork-only commit").stdout.strip()
        head_sha = _git(work, "rev-parse", "HEAD").stdout.strip()
        ancestor_check = _git(work, "merge-base", "--is-ancestor", fork_commit_sha, head_sha)
        assert ancestor_check.returncode == 0, "fork's commit is NOT an ancestor of HEAD after merge"

    def test_conflicting_merge_aborts_cleanly_touches_nothing(
        self, three_repo_setup, capsys
    ):
        """Real conflict: same file, same line, different content on both
        sides. Must abort cleanly -- no auto-resolution, no partial state,
        working tree exactly as it was before the attempt."""
        work, upstream_bare, fork_bare = three_repo_setup

        _commit(work, "shared.txt", "fork's version\n", "fork changes shared.txt")
        _git(work, "push", "-q", "origin", "main")
        pre_attempt_head = _git(work, "rev-parse", "HEAD").stdout.strip()

        upstream_seed = work.parent / "upstream_seed2"
        _init_repo(upstream_seed)
        _git(upstream_seed, "remote", "add", "origin", str(upstream_bare))
        _git(upstream_seed, "fetch", "-q", "origin", "main")
        _git(upstream_seed, "checkout", "-q", "-b", "main", "origin/main")
        _commit(upstream_seed, "shared.txt", "upstream's version\n", "upstream changes shared.txt")
        _git(upstream_seed, "push", "-q", "origin", "main")

        result = update_cmd._sync_with_upstream_if_needed(
            ["git"], work, assume_yes=True
        )

        assert result is True  # the CHECK ran; the merge itself was declined, not skipped
        out = capsys.readouterr().out
        assert "conflicts" in out.lower()
        assert "aborted cleanly" in out.lower()

        # Nothing changed: HEAD is exactly where it was, working tree clean,
        # no merge in progress left dangling.
        assert _git(work, "rev-parse", "HEAD").stdout.strip() == pre_attempt_head
        status = _git(work, "status", "--porcelain")
        assert status.stdout.strip() == "", f"working tree not clean after aborted merge: {status.stdout!r}"
        assert not (work / ".git" / "MERGE_HEAD").exists(), "merge left dangling in-progress state"

        # The fork's own commit is STILL there, untouched, in history.
        assert (work / "shared.txt").read_text() == "fork's version\n"

    def test_fork_already_ahead_by_everything_upstream_has_is_noop(
        self, three_repo_setup, capsys
    ):
        """Fork strictly ahead (contains all of upstream plus more) ->
        nothing to merge, report cleanly, don't attempt a pointless merge."""
        work, upstream_bare, fork_bare = three_repo_setup

        _commit(work, "fork_only.txt", "ed's patch\n", "fork-only commit")
        _git(work, "push", "-q", "origin", "main")

        result = update_cmd._sync_with_upstream_if_needed(
            ["git"], work, assume_yes=True
        )

        assert result is True
        out = capsys.readouterr().out
        assert "nothing to merge" in out.lower()
