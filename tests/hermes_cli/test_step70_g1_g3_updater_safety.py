"""TDD RED tests — STEP 70 Phase 1 (G.1 durable pre-reset safety tag,
G.3 block destructive divergence reset when local-only commits exist).

These tests exercise two NOT-YET-IMPLEMENTED helpers that ``cmd_update``'s
divergence-fallback and syntax-guard-rollback ``reset --hard`` call sites
must gate on before executing:

  * ``_local_only_commits(git_cmd, cwd, branch_ref, remote_ref)`` — G.3.
    Answers "does remote_ref already contain branch_ref's tip ancestry?"
    Returns ``(commits, reason)``; ``commits is None`` means unverifiable
    and callers MUST fail closed, never treat that as "zero commits".

  * ``_create_pre_reset_safety_tag(git_cmd, cwd, sha)`` — G.1.
    Creates ``hermes-update-pre-reset-<UTC timestamp>`` pointing at ``sha``
    immediately before any permitted ``reset --hard``. Returns the tag
    name, or ``None`` on failure (caller must fail closed).

Expected result at RED time: every test in this file fails, because
neither helper exists yet on ``hermes_cli.main`` and the two reset call
sites (divergence fallback, syntax-guard rollback) do not yet call them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import main as hermes_main


def _git(cwd, *args, check=True):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=check
    )


def _init_repo(tmp_path: Path) -> Path:
    """A real git repo with one commit on 'main', used as the 'remote'."""
    remote = tmp_path / "remote.git"
    remote.mkdir()
    _git(remote, "init", "-q", "--bare")
    return remote


def _clone(remote: Path, dest: Path, branch: str = "main") -> None:
    subprocess.run(
        ["git", "clone", "-q", "-b", branch, str(remote), str(dest)],
        capture_output=True, text=True, check=False,
    )


def _make_local_clone_with_history(tmp_path: Path):
    """Build remote + local clone sharing one common commit on 'main'."""
    if shutil.which("git") is None:
        pytest.skip("git not available")

    remote = tmp_path / "remote.git"
    remote.mkdir()
    _git(remote, "init", "-q", "--bare", "-b", "main")

    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "-q", "-b", "main")
    _git(seed, "config", "user.email", "t@example.com")
    _git(seed, "config", "user.name", "t")
    (seed / "f.txt").write_text("v1\n")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-qm", "initial")
    _git(seed, "push", "-q", str(remote), "main")

    local = tmp_path / "local"
    subprocess.run(
        ["git", "clone", "-q", str(remote), str(local)],
        capture_output=True, text=True, check=True,
    )
    _git(local, "config", "user.email", "t@example.com")
    _git(local, "config", "user.name", "t")
    return remote, local


# ---------------------------------------------------------------------------
# G.3 — _local_only_commits
# ---------------------------------------------------------------------------

def test_local_only_commits_detects_commits_not_on_remote(tmp_path):
    """Local branch has a commit origin/main does not have -> reported."""
    remote, local = _make_local_clone_with_history(tmp_path)

    (local / "f.txt").write_text("v2 local-only change\n")
    _git(local, "add", "-A")
    _git(local, "commit", "-qm", "local-only work")

    commits, reason = hermes_main._local_only_commits(
        ["git"], local, "main", "origin/main"
    )

    assert reason == ""
    assert commits is not None
    assert len(commits) == 1
    assert "local-only work" in commits[0]


def test_local_only_commits_empty_when_branch_matches_remote(tmp_path):
    """No local-only commits -> empty list, not None, not an error."""
    remote, local = _make_local_clone_with_history(tmp_path)

    commits, reason = hermes_main._local_only_commits(
        ["git"], local, "main", "origin/main"
    )

    assert reason == ""
    assert commits == []


def test_local_only_commits_fails_closed_when_unverifiable(tmp_path):
    """git itself cannot answer (bad ref / not a repo) -> (None, reason),
    which callers must treat as fail-closed, never as 'zero commits'."""
    not_a_repo = tmp_path / "not_a_repo"
    not_a_repo.mkdir()

    commits, reason = hermes_main._local_only_commits(
        ["git"], not_a_repo, "main", "origin/main"
    )

    assert commits is None
    assert reason != ""


# ---------------------------------------------------------------------------
# G.1 — _create_pre_reset_safety_tag
# ---------------------------------------------------------------------------

def test_create_pre_reset_safety_tag_points_at_exact_sha(tmp_path):
    remote, local = _make_local_clone_with_history(tmp_path)
    head_sha = _git(local, "rev-parse", "HEAD").stdout.strip()

    tag_name = hermes_main._create_pre_reset_safety_tag(["git"], local, head_sha)

    assert tag_name is not None
    assert tag_name.startswith("hermes-update-pre-reset-")

    tagged_sha = _git(local, "rev-parse", tag_name).stdout.strip()
    assert tagged_sha == head_sha


def test_create_pre_reset_safety_tag_returns_none_on_failure(tmp_path):
    remote, local = _make_local_clone_with_history(tmp_path)

    # An empty/invalid sha cannot be tagged — git will refuse.
    tag_name = hermes_main._create_pre_reset_safety_tag(["git"], local, "")

    assert tag_name is None


# ---------------------------------------------------------------------------
# G.3 — the divergence-fallback reset site must refuse when local-only
# commits exist, and must never move HEAD in that case.
# ---------------------------------------------------------------------------

def _run_cmd_update_against_diverged_repo(monkeypatch, local: Path, remote: Path):
    """Drive the real ``cmd_update`` flow, with a real diverged git repo as
    PROJECT_ROOT, and enough mocking of the non-git surface area (config,
    stash, node/venv repair, etc.) that only the git plumbing is real."""
    monkeypatch.setattr(hermes_main, "PROJECT_ROOT", local)
    monkeypatch.setattr(hermes_main, "_stash_local_changes_if_needed", lambda *a, **kw: None)
    monkeypatch.setattr(hermes_main, "_restore_stashed_changes", lambda *a, **kw: True)
    monkeypatch.setattr(hermes_main, "_reload_updated_runtime_modules", lambda *a, **kw: None)
    # Unrelated fork/upstream-remote nudge: prompts interactively via
    # input() when the local clone has no 'upstream' remote configured.
    # Not part of G.1/G.3 — no-op it so it doesn't block on stdin under
    # pytest's captured-output mode (test fixture correction, STEP 70
    # Phase 5A).
    monkeypatch.setattr(
        hermes_main, "_sync_with_upstream_if_needed", lambda *a, **kw: None
    )
    # Dependency install/refresh (uv pip install -e .[all]) — unrelated to
    # G.1/G.3, and the fake test repo has no real venv for it to target.
    # Existing-suite pattern (tests/hermes_cli/test_cmd_update.py,
    # tests/hermes_cli/test_lazy_refresh_venv_repair.py): no-op it directly
    # rather than letting it run against a fake repo (test fixture
    # correction, STEP 70 Phase 5B).
    monkeypatch.setattr(
        hermes_main,
        "_install_python_dependencies_with_optional_fallback",
        lambda *a, **kw: None,
    )

    from hermes_cli import config as hermes_config
    monkeypatch.setattr(hermes_config, "get_missing_env_vars", lambda required_only=True: [])
    monkeypatch.setattr(hermes_config, "get_missing_config_fields", lambda: [])
    monkeypatch.setattr(hermes_config, "check_config_version", lambda: (5, 5))
    monkeypatch.setattr(
        hermes_config, "migrate_config",
        lambda **kw: {"env_added": [], "config_added": []},
    )
    monkeypatch.setattr(hermes_main, "_upgrade_pip_before_lazy_refresh", lambda *a, **kw: None)
    monkeypatch.setattr(hermes_main, "_refresh_active_lazy_features", lambda *a, **kw: True)


def test_divergence_reset_refused_when_local_only_commits_exist(monkeypatch, tmp_path, capsys):
    """G.3 tracer bullet: real diverged repo, local has a commit origin
    doesn't have. cmd_update must NOT reset --hard; HEAD and the local
    commit must survive untouched, and the refusal must be reported."""
    remote, local = _make_local_clone_with_history(tmp_path)

    # Diverge: origin gets a new commit from elsewhere...
    other = tmp_path / "other"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)],
                    capture_output=True, text=True, check=True)
    _git(other, "config", "user.email", "o@example.com")
    _git(other, "config", "user.name", "o")
    (other / "f.txt").write_text("upstream change\n")
    _git(other, "add", "-A")
    _git(other, "commit", "-qm", "upstream work")
    _git(other, "push", "-q", "origin", "main")

    # ...while local also has an unpushed, local-only commit.
    (local / "f.txt").write_text("local-only change\n")
    _git(local, "add", "-A")
    _git(local, "commit", "-qm", "local-only work")
    local_head_before = _git(local, "rev-parse", "HEAD").stdout.strip()

    _git(local, "fetch", "-q", "origin")

    _run_cmd_update_against_diverged_repo(monkeypatch, local, remote)

    with pytest.raises(SystemExit):
        hermes_main.cmd_update(SimpleNamespace())

    local_head_after = _git(local, "rev-parse", "HEAD").stdout.strip()
    assert local_head_after == local_head_before, (
        "HEAD moved even though local-only commits existed — the "
        "destructive reset was NOT refused (G.3 violated)"
    )

    log = _git(local, "log", "--oneline").stdout
    assert "local-only work" in log, "the local-only commit was discarded"

    out = capsys.readouterr().out
    assert "local-only work" in out or "local-only" in out.lower(), (
        "the refused/discarded commits were not clearly reported to the user"
    )


def test_divergence_reset_still_succeeds_when_no_local_only_commits(monkeypatch, tmp_path):
    """Non-divergent / no-local-commits case must NOT be falsely blocked
    by the new G.3 guard — existing successful-reset behavior preserved."""
    remote, local = _make_local_clone_with_history(tmp_path)

    other = tmp_path / "other"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)],
                    capture_output=True, text=True, check=True)
    _git(other, "config", "user.email", "o@example.com")
    _git(other, "config", "user.name", "o")
    (other / "f.txt").write_text("upstream change\n")
    _git(other, "add", "-A")
    _git(other, "commit", "-qm", "upstream work")
    _git(other, "push", "-q", "origin", "main")

    _git(local, "fetch", "-q", "origin")

    _run_cmd_update_against_diverged_repo(monkeypatch, local, remote)

    # No local-only commits exist, so this must complete without SystemExit
    # from the syntax guard (there is no syntax error), i.e. the reset
    # should be permitted and HEAD should land on the new remote tip.
    try:
        hermes_main.cmd_update(SimpleNamespace())
    except SystemExit as exc:
        pytest.fail(f"update unexpectedly aborted with SystemExit({exc.code})")

    remote_head = _git(other, "rev-parse", "origin/main", check=False)
    local_head = _git(local, "rev-parse", "HEAD").stdout.strip()
    other_main_head = _git(other, "rev-parse", "HEAD").stdout.strip()
    assert local_head == other_main_head


# ---------------------------------------------------------------------------
# G.1 — both reset sites must be preceded by a durable safety tag, and the
# reset must not occur if tag creation fails.
# ---------------------------------------------------------------------------

# NOTE (STEP 70 Phase 6D/6E/6F): two tests previously lived here —
# ``test_divergence_reset_creates_safety_tag_before_resetting`` and
# ``test_reset_does_not_occur_when_safety_tag_creation_fails`` — both
# built on the divergence-fallback reset site. Both were removed after an
# analytical + experimental reachability review (Phase 6D) proved the
# scenario they asserted is impossible under real Git semantics:
# ``git merge --ff-only`` only ever fails when ``origin/main..HEAD`` is
# non-empty, and G.3's local-only-commit check is defined as exactly that
# same non-emptiness. There is no reachable Git history where the
# divergence branch executes AND zero local-only commits exist, so a
# "G.3 passes, then G.1 tags, then reset executes" happy path at that
# specific site cannot occur in real operation — the fixtures backing
# both removed tests were, in fact, plain non-diverged upstream-advance
# scenarios (clean fast-forward, same pattern as
# ``test_divergence_reset_still_succeeds_when_no_local_only_commits``
# above) that never actually reached the divergence-fallback code at all.
# G.3's refusal behavior at that site remains fully covered by
# ``test_divergence_reset_refused_when_local_only_commits_exist`` above.
# G.1's tag-then-reset code at the divergence site remains in production
# as defense-in-depth (STEP 70 authorization requires G.1 at both existing
# reset sites regardless of reachability of the happy path) but has no
# independent, non-redundant, real-Git-reachable success/failure test of
# its own at this specific site. See Phase 6D/6E/6F session analysis for
# the full graph-reachability proof.


def test_syntax_guard_rollback_creates_safety_tag_before_rollback(monkeypatch, tmp_path):
    """G.1, rollback path: post-pull syntax guard rolls back to pre_pull_sha
    only after a durable safety tag of the pre-rollback HEAD is created."""
    remote, local = _make_local_clone_with_history(tmp_path)
    pre_pull_sha = _git(local, "rev-parse", "HEAD").stdout.strip()

    # Push a commit upstream that breaks a critical file's syntax so the
    # post-pull guard trips and the rollback path fires.
    other = tmp_path / "other"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)],
                    capture_output=True, text=True, check=True)
    _git(other, "config", "user.email", "o@example.com")
    _git(other, "config", "user.name", "o")
    critical_relpath = next(iter(hermes_main._UPDATE_CRITICAL_FILES))
    critical_path = other / critical_relpath
    critical_path.parent.mkdir(parents=True, exist_ok=True)
    critical_path.write_text("x = (\n")  # unterminated -> SyntaxError
    _git(other, "add", "-A")
    _git(other, "commit", "-qm", "breaks syntax")
    _git(other, "push", "-q", "origin", "main")

    _git(local, "fetch", "-q", "origin")
    _run_cmd_update_against_diverged_repo(monkeypatch, local, remote)

    with pytest.raises(SystemExit):
        hermes_main.cmd_update(SimpleNamespace())

    # The rollback should have moved HEAD back to pre_pull_sha...
    post_head = _git(local, "rev-parse", "HEAD").stdout.strip()
    assert post_head == pre_pull_sha

    # ...but only after tagging the pre-rollback HEAD (the bad pulled
    # commit) as a safety ref, so it isn't silently unreachable.
    tags = _git(local, "tag", "-l", "hermes-update-pre-reset-*").stdout.strip().splitlines()
    assert len(tags) == 1, f"expected exactly one pre-rollback safety tag, found: {tags}"


def test_syntax_guard_rollback_refused_when_safety_tag_creation_fails(monkeypatch, tmp_path):
    """G.1 fail-closed, rollback path: if the pre-rollback safety-tag
    helper fails, the syntax-guard rollback reset must NOT execute — HEAD
    must remain at the bad pulled commit, not at pre_pull_sha.

    Modeled directly on
    ``test_syntax_guard_rollback_creates_safety_tag_before_rollback``: a
    real syntax-breaking commit is pushed upstream, the real updater path
    pulls it and reaches the syntax-validation failure, and only the tag
    helper itself is monkeypatched to simulate a tag-creation failure —
    no merge results are faked and no Git topology is manufactured.
    """
    remote, local = _make_local_clone_with_history(tmp_path)
    pre_pull_sha = _git(local, "rev-parse", "HEAD").stdout.strip()

    # Push a commit upstream that breaks a critical file's syntax so the
    # post-pull guard trips and the rollback path fires.
    other = tmp_path / "other"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)],
                    capture_output=True, text=True, check=True)
    _git(other, "config", "user.email", "o@example.com")
    _git(other, "config", "user.name", "o")
    critical_relpath = next(iter(hermes_main._UPDATE_CRITICAL_FILES))
    critical_path = other / critical_relpath
    critical_path.parent.mkdir(parents=True, exist_ok=True)
    critical_path.write_text("x = (\n")  # unterminated -> SyntaxError
    _git(other, "add", "-A")
    _git(other, "commit", "-qm", "breaks syntax")
    _git(other, "push", "-q", "origin", "main")

    _git(local, "fetch", "-q", "origin")
    _run_cmd_update_against_diverged_repo(monkeypatch, local, remote)

    # Force the safety-tag helper to fail (simulating e.g. a git error
    # creating the ref) — the rollback reset must then be refused entirely.
    monkeypatch.setattr(
        hermes_main, "_create_pre_reset_safety_tag", lambda *a, **kw: None
    )

    with pytest.raises(SystemExit):
        hermes_main.cmd_update(SimpleNamespace())

    # The rollback must NOT have executed: HEAD stays on the bad pulled
    # commit, not back at pre_pull_sha.
    post_head = _git(local, "rev-parse", "HEAD").stdout.strip()
    assert post_head != pre_pull_sha, (
        "rollback executed even though safety-tag creation failed "
        "(G.1 violated)"
    )

    # No pre-reset safety tag should exist either, since the helper was
    # made to fail.
    tags = _git(local, "tag", "-l", "hermes-update-pre-reset-*").stdout.strip().splitlines()
    assert tags == [], f"expected no safety tag when tag creation fails, found: {tags}"
