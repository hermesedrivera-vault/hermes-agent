"""Regression test for the pre-reset safety tag.

``hermes update`` falls back to ``git reset --hard origin/{branch}`` when a
``git pull --ff-only`` fails because local and remote history diverged. That
reset is destructive to any *committed* local work that never made it to
origin — and for repos following a commit-local-never-push convention,
diverged local commits are the expected steady state, not an edge case.

This caused a real, repeated data-loss incident: ``agent/provenance/`` was
silently wiped from ``main`` four times between 2026-07-09 and 2026-07-19
because ``hermes update`` reset past locally-committed-but-unpushed work
with no trace left of what was destroyed (recovery relied entirely on
``git reflog``, which is time-limited and easy to miss for weeks).

``_tag_diverged_local_commits_before_reset`` closes that gap: before the
destructive reset, it tags the about-to-be-orphaned local tip. Tags are
refs and are never GC-eligible, so this converts "recoverable for ~2 weeks
by luck" into "recoverable indefinitely by design," and is a no-op (returns
None, creates no tag) when there is genuinely nothing local to lose.
"""

from __future__ import annotations

import subprocess

from hermes_cli.main import _tag_diverged_local_commits_before_reset


def _git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )


def _init_repo_with_remote(tmp_path):
    """Build a local repo + a bare 'origin' remote, both at the same tip."""
    origin = tmp_path / "origin.git"
    origin.mkdir()
    _git(origin, "init", "--bare", "-b", "main")

    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-b", "main")
    _git(work, "config", "user.email", "test@example.com")
    _git(work, "config", "user.name", "Test")
    (work / "a.txt").write_text("base\n")
    _git(work, "add", "a.txt")
    _git(work, "commit", "-m", "base commit")
    _git(work, "remote", "add", "origin", str(origin))
    _git(work, "push", "origin", "main")
    _git(work, "fetch", "origin")
    return work


def test_tags_orphaned_commits_when_local_has_unpushed_work(tmp_path):
    """The exact failure mode from the incident: local has committed work
    origin doesn't have. A tag must be created preserving the tip."""
    work = _init_repo_with_remote(tmp_path)

    # Simulate the incident: local gains a real commit (e.g. the provenance
    # gate) that is never pushed, while origin independently moves forward
    # (simulated here by amending on a throwaway clone and pushing that).
    (work / "provenance.txt").write_text("agent/provenance/store.py\n")
    _git(work, "add", "provenance.txt")
    _git(work, "commit", "-m", "feat: provenance gate (never pushed)")
    pre_pull_sha = _git(work, "rev-parse", "HEAD").stdout.strip()

    # Origin moves forward independently (diverges).
    other_clone = tmp_path / "other_clone"
    _git(tmp_path, "clone", str(work.parent / "origin.git"), str(other_clone))
    _git(other_clone, "config", "user.email", "test@example.com")
    _git(other_clone, "config", "user.name", "Test")
    (other_clone / "b.txt").write_text("upstream change\n")
    _git(other_clone, "add", "b.txt")
    _git(other_clone, "commit", "-m", "unrelated upstream commit")
    _git(other_clone, "push", "origin", "main")

    _git(work, "fetch", "origin")

    tag = _tag_diverged_local_commits_before_reset(
        ["git"], work, "main", pre_pull_sha
    )

    assert tag is not None
    assert tag.startswith("pre-reset-safety-")

    # The tag must actually point at the commit that's about to be
    # discarded, and that commit must contain the provenance work.
    tagged_sha = _git(work, "rev-parse", tag).stdout.strip()
    assert tagged_sha == pre_pull_sha

    show = _git(work, "show", f"{tag}:provenance.txt").stdout
    assert "agent/provenance/store.py" in show

    # Simulate the actual reset that would follow in production code, and
    # confirm the tag alone is enough to recover the "lost" commit.
    _git(work, "reset", "--hard", "origin/main")
    assert not (work / "provenance.txt").exists()  # reset did discard it...
    recovered = _git(work, "show", f"{tag}:provenance.txt").stdout
    assert "agent/provenance/store.py" in recovered  # ...but tag saved it


def test_no_tag_when_nothing_local_to_lose(tmp_path):
    """Common/harmless case: local tip has no unique commits vs origin
    (e.g. local is a strict ancestor of origin). No tag should be created."""
    work = _init_repo_with_remote(tmp_path)
    pre_pull_sha = _git(work, "rev-parse", "HEAD").stdout.strip()

    # Origin moves forward; local has NOT committed anything unique.
    other_clone = tmp_path / "other_clone2"
    _git(tmp_path, "clone", str(work.parent / "origin.git"), str(other_clone))
    _git(other_clone, "config", "user.email", "test@example.com")
    _git(other_clone, "config", "user.name", "Test")
    (other_clone / "c.txt").write_text("upstream only\n")
    _git(other_clone, "add", "c.txt")
    _git(other_clone, "commit", "-m", "upstream-only commit")
    _git(other_clone, "push", "origin", "main")
    _git(work, "fetch", "origin")

    tags_before = _git(work, "tag").stdout

    tag = _tag_diverged_local_commits_before_reset(
        ["git"], work, "main", pre_pull_sha
    )

    assert tag is None
    tags_after = _git(work, "tag").stdout
    assert tags_before == tags_after  # no new tag was created


def test_returns_none_when_pre_pull_sha_missing(tmp_path):
    """If the pre-pull SHA capture failed upstream, don't attempt anything."""
    work = _init_repo_with_remote(tmp_path)
    tag = _tag_diverged_local_commits_before_reset(["git"], work, "main", None)
    assert tag is None
