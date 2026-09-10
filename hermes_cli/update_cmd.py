"""Hermes update pipeline: dispatchers (``_cmd_update_impl``/``_cmd_update_check``) + git plumbing.

Each concern lives in ``update_cmd_<concern>.py`` and is re-imported here so
``hermes_cli.update_cmd.<name>`` keeps resolving (and stays monkeypatchable). Imports are one-way:
main -> update_cmd -> update_cmd_*; ``_m()`` resolves ``hermes_cli.main`` at call time.
"""

import logging
from contextlib import suppress
import os
import shlex
import shutil  # noqa: F401  (tests patch update_cmd.shutil.*; split modules resolve it here)
import subprocess
import sys
import time as _time
from dataclasses import dataclass
from pathlib import Path

from hermes_cli.config import get_hermes_home  # noqa: F401  (re-exported; patched via update_cmd)
from hermes_cli.update_cmd_common import _best_effort
from hermes_constants import get_default_hermes_root, venv_python_path

# Re-exports: every split-module name stays reachable (and monkeypatchable) as update_cmd.<name>.
from hermes_cli.update_abort_recovery import (  # noqa: F401
    _abort_recovery_is_complete, _qualified_serve_skips, _recover_gateway_restart_after_abort,
    _serve_unit_recovery_available, _surviving_pre_update_serve_runtimes,
    _warn_stale_serve_runtimes)
from hermes_cli.update_cmd_windows import (  # noqa: F401
    _HOLDER_VALUE_FLAGS_FALLBACK, _clear_windows_venv_holders_or_exit,
    _cold_start_windows_gateway_after_update, _desktop_owns_gateway_lifecycle,
    _detect_venv_python_processes, _format_venv_python_holders_message,
    _handoff_reapable_backend_pids, _hermes_holder_subcommand, _holder_value_flags,
    _holder_value_flags_cache, _ledger_manual_serve_holders, _ledger_reapable_backend_pids,
    _leftover_pausable_gateway_pids, _looks_like_desktop_control_plane,
    _orphaned_desktop_backend_pids, _pause_windows_gateways_for_update,
    _refresh_bootstrap_cache_scripts, _refresh_windows_gateway_launchers,
    _refuse_gateway_ancestor_tree_kill, _relaunch_stopped_serves,
    _restore_windows_gateway_service, _resume_windows_gateways_after_update,
    _resume_windows_gateways_and_merge_outcome, _self_and_non_gateway_ancestor_pids,
    _serve_relaunch_commands, _start_windows_gateway_service, _stop_process_trees,
    _stop_windows_gateway_service, _venv_launcher_ancestors,
    _wait_for_windows_update_gateway_exit, _write_update_planned_stop_marker)
from hermes_cli.update_cmd_fleet import (  # noqa: F401
    _FLEET_RESTART_PENDING_NAME, _FRESH_RESTART_SUPERVISORS, _GatewayRestartOutcome,
    _apply_pending_fleet_restart_catchup, _clear_fleet_restart_pending_marker,
    _current_checkout_sha, _drain_or_signal_gateway_for_update, _fleet_probe_expected_runtimes,
    _fleet_restart_pending_marker_path, _for_each_systemd_gateway_unit,
    _gateway_recovery_partition, _gateway_service_matches_profile, _pending_fleet_restart_needed,
    _receipt_looks_unfinished, _receipt_reports_stale_runtime, _resolve_manage_cmd,
    _restart_gateway_fleet_after_update, _restart_launchd_gateway_after_update,
    _restart_macos_launchd_gateways, _restart_phase_failure_is_incomplete,
    _restart_systemd_gateway_units, _restart_systemd_gateway_units_best_effort,
    _run_pending_fleet_restart, _service_restart_sec,
    _service_unit_supports_graceful_sigusr1_restart, _surviving_gateway_pids_after_failed_restart,
    _systemctl, _systemctl_reset_and_restart, _verify_fleet_after_update,
    _wait_for_service_active, _warn_gateway_restart_phase_aborted,
    _warn_incomplete_gateway_fleet_restart, _warn_pending_fleet_restart,
    _warn_pending_fleet_restart_on_startup, _write_fleet_restart_pending_marker,
    _write_gateway_update_exit_code)
from hermes_cli.update_cmd_zip import (  # noqa: F401
    _ZIP_PRESERVED_TOP_LEVEL, _ZIP_STAGING_ARTIFACT_SUFFIXES, _abort_zip_update_if_dirty_tree,
    _atomic_replace_dir, _commit_staged_replacements, _discard_staged,
    _is_zip_preserved_entry_status_line, _is_zip_staging_artifact_status_line, _stage_replacement,
    _update_via_zip, _zip_overlay_block_reason)
from hermes_cli.update_cmd_stash import (  # noqa: F401
    _AUTOSTASH_NAME_PREFIX, _AUTOSTASH_WARN_AGE_DAYS, _discard_stashed_changes,
    _git_untracked_paths, _park_stashed_changes, _print_stash_cleanup_guidance,
    _reject_unsafe_stash_restore, _resolve_stash_selector, _restore_stashed_changes,
    _restored_python_paths, _stash_apply_failed_only_on_existing_untracked,
    _stash_local_changes_if_needed, _warn_orphaned_update_autostashes)
from hermes_cli.update_cmd_config import (  # noqa: F401
    _LAST_SIBLING_SNAPSHOTS, _check_and_apply_config_migration, _migrate_sibling_profile_configs,
    _print_items, _reload_config_modules, _run_config_check_fresh, _run_migrate_config_fresh)
from hermes_cli.update_cmd_deps import (  # noqa: F401
    _INSTALL_DEFINING_FILES, _SELF_LOCKING_NATIVE_MODULES, _UPDATE_CRITICAL_MODULES,
    _abort_dependency_sync_if_self_locked, _capture_active_lazy_features,
    _capture_active_tool_dependencies, _critical_module_import_failures,
    _defer_update_for_self_lock, _dependency_sync_would_rewrite, _desktop_app_present,
    _detect_self_loaded_native_modules, _editable_install_is_current, _ensure_uv_for_termux,
    _ensure_venv_pip, _install_psutil_android_compat, _is_android_python, _npm_bin_exists,
    _npm_lockfile_changed, _npm_manifest_paths, _npm_manifests_digest, _path_uid,
    _rebuild_desktop_after_update, _record_npm_lockfile_hash, _refresh_active_lazy_features,
    _refresh_active_memory_provider_dependencies, _refuse_update_if_venv_foreign_owned,
    _repair_node_deps_on_current_checkout, _restore_active_tool_dependencies,
    _sync_python_dependencies_after_pull, _update_node_dependencies,
    _upgrade_pip_before_lazy_refresh, _validate_critical_modules_import,
    _venv_core_imports_healthy, _venv_foreign_owned_paths, _web_build_toolchain_ready,
    _web_toolchain_roots)
from hermes_cli.update_cmd_git import (  # noqa: F401
    OFFICIAL_REPO_URL, OFFICIAL_REPO_URLS, SKIP_UPSTREAM_PROMPT_FILE, _ORPHAN_RESCUE_REFS_TO_KEEP,
    _ORPHAN_RESCUE_REF_MAX_AGE_DAYS, _add_upstream_remote, _assess_parked_branch_switch,
    _branch_head_label, _branch_head_suffix, _classify_fetch_failure, _count_commits_between,
    _discard_lockfile_churn, _ensure_non_trampoline_git, _get_origin_url, _git_is_trampoline,
    _has_upstream_remote, _is_fork, _locate_real_git, _mark_skip_upstream_prompt,
    _normalize_managed_eol, _portable_git_candidates, _print_fetch_failure,
    _print_parked_branch_kept_notice, _print_parked_branch_skip_warning,
    _prune_orphan_rescue_refs, _should_skip_upstream_prompt, _sync_fork_with_upstream)
from hermes_cli.update_cmd_maint import (  # noqa: F401
    _PRE_UPDATE_SNAPSHOT_KEEP, _PRE_UPDATE_SNAPSHOT_MAX_FILE_SIZE, _STALE_PURGE_PREFIXES,
    _STALE_PURGE_PROTECTED, _UPDATE_RUNTIME_RELOAD_MODULES, _clear_stale_sqlite_sidecars,
    _ensure_acp_launcher, _ensure_fhs_path_guard, _finish_dashboard_update_cleanup,
    _format_time_ago, _post_update_sqlite_runtime_status, _print_bundled_skills_sync_report,
    _print_curator_first_run_notice, _print_curator_recent_run_notice,
    _print_fts_optimize_available_notice, _print_update_completion, _print_update_summary,
    _print_verified_update_completion, _purge_stale_hermes_modules, _read_project_version,
    _reload_process_scan_modules, _reload_updated_runtime_modules,
    _resolve_pre_update_backup_mode, _restore_state_db_from_snapshot,
    _run_post_update_maintenance, _run_pre_update_backup, _sweep_bytecode_after_update,
    _update_complete_message, _verify_and_restore_one_state_db,
    _verify_and_restore_state_dbs_post_update)
logger = logging.getLogger(__name__)


def _m():
    """Lazy ``hermes_cli.main`` handle: keeps main-side test patches effective, import one-way."""
    from hermes_cli import main
    return main


def _updates_config() -> dict:
    """The ``updates:`` config section (``{}`` when absent/malformed); may raise on config errors."""
    from hermes_cli.config import load_config
    section = (load_config() or {}).get("updates", {})
    return section if isinstance(section, dict) else {}


def _no_prompt_git_kwargs() -> dict:
    """``subprocess.run`` kwargs for network git: a 401 (GitHub outage) would block forever on
    ``Username for ...``; disable only the *prompt* (credential helpers still run) so it fails fast."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"}
    return {"stdin": subprocess.DEVNULL, "env": env}


# CLI-startup files (+ web_server.py, launched by a fresh Windows Desktop install) that must
# parse post-update; the syntax guard rolls back when one doesn't.
_UPDATE_CRITICAL_FILES = (
    "hermes_cli/main.py", "hermes_cli/config.py", "hermes_cli/__init__.py",
    "hermes_cli/web_server.py", "cli.py", "run_agent.py", "model_tools.py", "toolsets.py",
    "hermes_constants.py")


def _record_update_step(step: str, ok: bool, detail: str = "") -> None:
    """Best-effort ``update_receipt.record_step``; the receipt must never break an update."""
    with suppress(Exception):
        from hermes_cli.update_receipt import record_step
        record_step(step, ok, detail)


def _git_run(git_cmd, args, cwd=None, *, check=False, network=False):
    """Run git capturing utf-8 text (default cwd: checkout); ``network=True`` disables the
    terminal prompt so an HTTP 401 fails fast instead of hanging."""
    return subprocess.run(
        git_cmd + args, cwd=_m().PROJECT_ROOT if cwd is None else cwd, capture_output=True,
        text=True, encoding="utf-8", errors="replace", check=check,
        **(_no_prompt_git_kwargs() if network else {}))


def _capture_head_sha(git_cmd, cwd) -> str | None:
    """Return the current HEAD SHA, or None if it can't be resolved."""
    try:
        result = _git_run(git_cmd, ["rev-parse", "HEAD"], cwd, check=True)
        return result.stdout.strip() or None
    except (subprocess.CalledProcessError, OSError):
        return None


def _local_only_commits(
    git_cmd: list, cwd, branch_ref: str, remote_ref: str
) -> tuple[list[str] | None, str]:
    """List commits reachable from ``branch_ref`` but not from ``remote_ref``.

    STEP 70 G.3: answers the narrow question a destructive
    ``reset --hard <remote_ref>`` is about to act on — does ``remote_ref``
    already contain ``branch_ref``'s tip ancestry? Per the authorized
    scope, this does NOT search other branches/remotes for the same
    commits; it only protects commits on the current branch from being
    discarded by resetting it to ``remote_ref``.

    Returns ``(commits, reason)``:
      - ``commits`` is a list of one-line ``git log`` entries (oldest-safe
        ordering not guaranteed; each entry uniquely identifies a
        local-only commit for reporting purposes). An empty list means
        verified: no local-only commits exist.
      - ``commits is None`` means the check itself was unverifiable (git
        command failed). Callers MUST treat ``None`` as fail-closed —
        never as "zero commits" — and MUST NOT proceed with a destructive
        reset. ``reason`` is ``""`` on success, and a short diagnostic
        string when ``commits is None``.
    """
    try:
        result = subprocess.run(
            git_cmd + ["log", "--oneline", "--no-decorate",
                       f"{remote_ref}..{branch_ref}"],
            cwd=cwd,
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )
    except OSError as exc:
        return None, f"unverifiable: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return None, f"unverifiable: git log exited {result.returncode}" + (
            f" ({stderr})" if stderr else ""
        )

    commits = [line for line in result.stdout.splitlines() if line.strip()]
    return commits, ""


def _create_pre_reset_safety_tag(git_cmd: list, cwd, sha: str | None) -> str | None:
    """Tag ``sha`` as a durable, discoverable pre-reset safety ref.

    STEP 70 G.1: called immediately before every updater ``reset --hard``,
    with ``sha`` set to the exact HEAD that exists at that moment (before
    the reset moves it). Returns the created tag name on success, or
    ``None`` on any failure (missing ``sha``, git error, OSError). Callers
    MUST treat ``None`` as fail-closed and MUST NOT execute the reset.

    Tag name format: ``hermes-update-pre-reset-<UTC timestamp>``, with
    microsecond precision so back-to-back updater runs never collide.
    """
    if not sha:
        return None

    tag_name = "hermes-update-pre-reset-" + datetime.utcnow().strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )
    try:
        result = subprocess.run(
            git_cmd + ["tag", tag_name, sha],
            cwd=cwd,
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    # Verify the tag actually points at the exact SHA we intended — belt
    # and suspenders against a git version/quirk that reports success
    # without creating the expected ref.
    try:
        verify_result = subprocess.run(
            git_cmd + ["rev-parse", tag_name],
            cwd=cwd,
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        return None
    if verify_result.returncode != 0:
        return None
    if verify_result.stdout.strip() != sha:
        return None

    return tag_name


# Files that define the editable install. A pull that touches none of them
# cannot have invalidated it.
_INSTALL_DEFINING_FILES = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "MANIFEST.in",
    "uv.lock",
)

def _validate_python_files_syntax(root, relpaths) -> tuple[bool, str | None, str | None]:
    """Compile *relpaths* under *root*; the .pyc goes to a temp dir, not ``__pycache__/`` (no
    race with test workers, no stale pyc for another interpreter)."""
    import py_compile
    import tempfile
    root = Path(root)
    with tempfile.TemporaryDirectory(prefix="hermes-syntax-check-") as tmpdir:
        for relpath in relpaths:
            path = root / relpath
            if not path.exists():
                continue
            cfile = Path(tmpdir) / (str(relpath).replace("/", "__") + "c")
            try:
                py_compile.compile(str(path), cfile=str(cfile), doraise=True)
            except py_compile.PyCompileError as exc:
                return False, str(path), str(exc)
            except OSError as exc:
                return False, str(path), f"could not read: {exc}"
    return True, None, None


def _validate_critical_files_syntax(root) -> tuple[bool, str | None, str | None]:
    """Compile ``_UPDATE_CRITICAL_FILES`` -> ``(ok, failing_path, error_message)``."""
    return _validate_python_files_syntax(root, _UPDATE_CRITICAL_FILES)


def _gateway_prompt(prompt_text: str, default: str = "", timeout: float = 300.0) -> str:
    """File-based IPC prompt for ``--gateway``: write a marker the gateway forwards to the
    messenger, poll for a response file, fall back to *default* on timeout."""
    import json as _json
    import uuid as _uuid
    from hermes_constants import get_hermes_home  # noqa: F811  (deliberate: constants variant)
    home = get_hermes_home()
    prompt_path, response_path = home / ".update_prompt.json", home / ".update_response"
    response_path.unlink(missing_ok=True)

    payload = {"prompt": prompt_text, "default": default, "id": str(_uuid.uuid4())}
    tmp = prompt_path.with_suffix(".tmp")
    tmp.write_text(_json.dumps(payload), encoding="utf-8")
    tmp.replace(prompt_path)

    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if response_path.exists():
            with suppress(OSError, ValueError):
                answer = response_path.read_text(encoding="utf-8").strip()
                response_path.unlink(missing_ok=True)
                prompt_path.unlink(missing_ok=True)
                return answer if answer else default
        _time.sleep(0.5)

    prompt_path.unlink(missing_ok=True)
    response_path.unlink(missing_ok=True)
    print(f"  (no response after {int(timeout)}s, using default: {default!r})")
    return default


def _called_process_error_cmd_parts(exc: subprocess.CalledProcessError) -> list[str]:
    """Normalize ``CalledProcessError.cmd`` into argv-style tokens."""
    cmd = exc.cmd
    if cmd is None:
        return []
    if isinstance(cmd, (str, bytes)):
        text = cmd.decode("utf-8", "replace") if isinstance(cmd, bytes) else cmd
        try:
            return shlex.split(text, posix=os.name != "nt")
        except ValueError:
            return text.split()
    return [str(part) for part in cmd]


def _called_process_error_is_git(exc: subprocess.CalledProcessError) -> bool:
    """True when the failed subprocess was git itself."""
    parts = _called_process_error_cmd_parts(exc)
    if not parts:
        return False
    # Windows argv may use backslashes; POSIX basename() would keep the whole path.
    name = os.path.basename(parts[0].replace("\\", "/")).lower()
    return name in {"git", "git.exe"}


def _called_process_error_is_python_dep_install(exc: subprocess.CalledProcessError) -> bool:
    """True when the failed subprocess was a uv/pip (or ensurepip) install."""
    parts = [part.lower() for part in _called_process_error_cmd_parts(exc)]
    if not parts:
        return False
    exe = os.path.basename(parts[0].replace("\\", "/"))
    return "ensurepip" in parts or ("install" in parts and (
        "pip" in parts or exe in {"pip", "pip.exe", "pip3", "pip3.exe", "uv", "uv.exe"}))


def _format_update_failure_stage(exc: subprocess.CalledProcessError) -> str:
    """Name the failed stage: git pull and dep install share one ``try``, and calling every
    CalledProcessError a git failure misled users and keyed the ZIP overlay on exception
    *type* rather than on git actually failing.

    See #85840, #87304.
    """
    if _called_process_error_is_python_dep_install(exc):
        return "Python dependency install failed"
    if _called_process_error_is_git(exc):
        return "Git update failed"
    return "Update step failed"


def _shim_quarantine_error_type() -> "type[BaseException]":
    """Strict-quarantine refusal type via ``_m()``; falls back to a never-raised private
    type when main.py lacks it (torn mid-update tree) so the ``except`` stays valid."""
    cls = getattr(_m(), "ShimQuarantineError", None)
    if isinstance(cls, type) and issubclass(cls, BaseException):
        return cls

    class _Never(Exception):
        pass

    return _Never


def _refuse_update_for_contended_shims(exc: BaseException) -> None:
    """Fail closed when live shims could not be quarantined: a rename failing every retry
    proves a holder without FILE_SHARE_DELETE, and installing anyway strands the venv between
    versions. The code swap is already committed; only the dep install is deferred (via the
    update-incomplete marker). Exits 2 so the receipt records a refusal, not a failure.

    See #87331.
    """
    print("✗ Cannot continue the update: live Hermes launcher(s) could not be")
    print("  moved aside:")
    for name in getattr(exc, "failed_shims", []) or ["hermes.exe"]:
        print(f"    {name}")
    print("  Another process is holding this install's venv — typically Hermes")
    print("  Desktop, a gateway, or another hermes REPL — and mutating the venv")
    print("  now would strand it half-updated.")
    print("  The dependency install has been deferred: close the process(es)")
    print("  above, then run any `hermes` command to finish it automatically.")
    # Idempotent (git path already dropped it); covers ZIP/repair paths so the deferral is never silent.
    _write_update_incomplete_marker()
    sys.exit(2)


def _should_zip_fallback_on_update_error(exc: BaseException) -> bool:
    """ZIP fallback is only for Windows git file-I/O breakage: after a dep-install failure the
    pull already succeeded, so a ZIP overlay can't fix it and would replace every top-level
    entry except venv/node_modules/.git/.env, deleting uncommitted and untracked files."""
    return (
        isinstance(exc, subprocess.CalledProcessError)
        and _m()._is_windows()
        and _called_process_error_is_git(exc))


def _print_called_process_error_tail(exc: subprocess.CalledProcessError, *, limit: int = 12) -> None:
    """Print a captured stderr/stdout tail when the failing call recorded one."""
    blob = exc.stderr or exc.stdout or ""
    if isinstance(blob, bytes):
        blob = blob.decode("utf-8", "replace")
    lines = [line for line in str(blob).splitlines() if line.strip()]
    if not lines:
        return
    print("  Last output:")
    for line in lines[-limit:]:
        print(f"    {line}")


def _sync_with_upstream_if_needed(
    git_cmd: list[str],
    cwd: Path,
    *,
    assume_yes: bool = False,
    input_fn=None,
) -> bool:
    """Check if fork is behind upstream and sync if safe.

    This implements the fork upstream sync logic:
    - If upstream remote doesn't exist, ask user if they want to add it
    - Compare origin/main with upstream/main
    - If origin/main is strictly behind upstream/main, pull from upstream
    - Try to sync fork back to origin if possible

    Returns True when origin/main was actually verified against the official
    upstream/main, False when the check never happened (prompt skipped or
    declined, remote add failed, fetch or compare failed) so the caller can
    avoid reporting the checkout as up to date on the strength of an origin
    comparison alone (#97052 review).
    """
    has_upstream = _has_upstream_remote(git_cmd, cwd)

    if not has_upstream:
        # Check if user previously declined
        if _should_skip_upstream_prompt():
            return False

        print()
        print("ℹ Your fork is not tracking the official Hermes repository.")
        print("  This means you may miss updates from NousResearch/hermes-agent.")
        print()

        if assume_yes or (
            input_fn is None and not (sys.stdin.isatty() and sys.stdout.isatty())
        ):
            # --yes means "don't block", not "mutate my git remotes". Skip
            # without persisting the decline so interactive runs still get asked.
            print("  Skipping upstream setup (non-interactive run).")
            print(
                "  Add it later with: git remote add upstream https://github.com/NousResearch/hermes-agent.git"
            )
            return False

        # Ask user if they want to add upstream
        if input_fn is not None:
            response = (
                input_fn("Add official repo as 'upstream' remote? [y/N]", "n")
                .strip()
                .lower()
            )
        else:
            try:
                response = (
                    input("Add official repo as 'upstream' remote? [Y/n]: ")
                    .strip()
                    .lower()
                )
            except (EOFError, KeyboardInterrupt, UnicodeDecodeError):
                print()
                response = "n"

        if response in {"", "y", "yes"}:
            print("→ Adding upstream remote...")
            if _add_upstream_remote(git_cmd, cwd):
                print(
                    "  ✓ Added upstream: https://github.com/NousResearch/hermes-agent.git"
                )
                has_upstream = True
            else:
                print("  ✗ Failed to add upstream remote. Skipping upstream sync.")
                return False
        else:
            print(
                "  Skipped. Run 'git remote add upstream https://github.com/NousResearch/hermes-agent.git' to add later."
            )
            _mark_skip_upstream_prompt()
            return False

    # Fetch upstream main only. This sync compares upstream/main with
    # origin/main, so there's no reason to pull every upstream ref — and a bare
    # fetch drags in thousands of auto-generated branches.
    print()
    print("→ Fetching upstream...")
    try:
        subprocess.run(
            git_cmd + ["fetch", "upstream", "main", "--quiet"],
            cwd=cwd,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        print("  ✗ Failed to fetch upstream. Skipping upstream sync.")
        return False

    # Compare origin/main with upstream/main
    origin_ahead = _count_commits_between(git_cmd, cwd, "upstream/main", "origin/main")
    upstream_ahead = _count_commits_between(
        git_cmd, cwd, "origin/main", "upstream/main"
    )

    if origin_ahead < 0 or upstream_ahead < 0:
        print("  ✗ Could not compare branches. Skipping upstream sync.")
        return False

    # If origin/main has commits not on upstream, merge instead of
    # skipping (2026-09-06, Ed's explicit ask): a plain git merge is
    # additive by construction — it creates a new commit with BOTH
    # histories as ancestors. Nothing is ever deleted; a merge cannot
    # "lose" a commit the way a reset can. Only risk is a genuine content
    # conflict (same line changed on both sides), which git refuses to
    # guess at — abort cleanly and hand it to a human rather than picking
    # a side automatically.
    if origin_ahead > 0:
        if upstream_ahead == 0:
            print()
            print(f"ℹ Your fork has {origin_ahead} commit(s) not on upstream.")
            print("  Fork already contains everything upstream has — nothing to merge.")
            return True

        print()
        print(
            f"→ Fork has {origin_ahead} local-only commit(s) and is "
            f"{upstream_ahead} commit(s) behind upstream — attempting merge..."
        )

        pre_merge_sha = _capture_head_sha(git_cmd, cwd)
        safety_tag = _create_pre_reset_safety_tag(git_cmd, cwd, pre_merge_sha)
        if safety_tag:
            print(f"  ✓ Safety tag created: {safety_tag} (rollback: git reset --hard {safety_tag})")
        else:
            print("  ⚠ Could not create a safety tag — proceeding anyway (merge is additive; a tag is belt-and-suspenders, not required for safety).")

        merge_result = subprocess.run(
            git_cmd + ["merge", "--no-ff", "upstream/main",
                       "-m", "Merge upstream/main into fork (hermes update)"],
            cwd=cwd,
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )

        if merge_result.returncode != 0:
            # Conflict or other merge failure — abort cleanly, touch
            # nothing, hand off to a human. Never guess at a resolution.
            subprocess.run(
                git_cmd + ["merge", "--abort"],
                cwd=cwd,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace",
            )
            print("  ✗ Merge hit conflicts — aborted cleanly, nothing changed.")
            stderr_tail = (merge_result.stdout or merge_result.stderr or "").strip()
            if stderr_tail:
                print(f"    {stderr_tail.splitlines()[-1]}")
            print("  Your fork-only commits and upstream's commits are both")
            print("  still safe in git history — only the automatic merge was")
            print("  skipped. Resolve by hand:")
            print(f"    cd {cwd} && git merge upstream/main")
            print("    (fix the conflicting files, then git add + git commit)")
            return True

        # Merge landed clean. Verify our local-only commits are STILL
        # ancestors of the new HEAD — the exact fact Ed asked hermes
        # update to prove on every run, checked here immediately after
        # the operation that could theoretically have gotten it wrong.
        post_merge_sha = _capture_head_sha(git_cmd, cwd)
        ancestor_check_ok = True
        if pre_merge_sha and post_merge_sha:
            verify = subprocess.run(
                git_cmd + ["merge-base", "--is-ancestor", pre_merge_sha, post_merge_sha],
                cwd=cwd,
                capture_output=True,
            )
            ancestor_check_ok = verify.returncode == 0
        if not ancestor_check_ok:
            print("  🔴 Merge completed but pre-merge HEAD is not an ancestor of the result.")
            print(f"    This should be structurally impossible for a merge. Recover: git reset --hard {safety_tag or pre_merge_sha}")
            return True

        print(f"  ✓ Merged cleanly — {upstream_ahead} upstream commit(s) now in your fork, all {origin_ahead} of your commits intact.")

        print("→ Syncing fork...")
        if _sync_fork_with_upstream(git_cmd, cwd):
            print("  ✓ Fork synced with upstream on GitHub")
        else:
            print("  ℹ Merged locally but couldn't push to your fork (no write access?)")
            print("    Your local repo is updated, but your fork on GitHub may be behind.")
        return True

    # If upstream is not ahead, fork is up to date
    if upstream_ahead == 0:
        print("  ✓ Fork is up to date with upstream")
        return True

    # origin/main is strictly behind upstream/main (can fast-forward)
    print()
    print(f"→ Fork is {upstream_ahead} commit(s) behind upstream")
    print("→ Pulling from upstream...")

    try:
        subprocess.run(
            git_cmd + ["pull", "--ff-only", "upstream", "main"],
            cwd=cwd,
            check=True,
        )
    except subprocess.CalledProcessError:
        print(
            "  ✗ Failed to pull from upstream. You may need to resolve conflicts manually."
        )
        return False

    print("  ✓ Updated from upstream")

    # Try to sync fork back to origin
    print("→ Syncing fork...")
    if _sync_fork_with_upstream(git_cmd, cwd):
        print("  ✓ Fork synced with upstream")
    else:
        print(
            "  ℹ Got updates from upstream but couldn't push to fork (no write access?)"
        )
        print("    Your local repo is updated, but your fork on GitHub may be behind.")
    return True

def _invalidate_update_cache():
    """Delete the update-check cache for ALL profiles: the repo is shared, so one profile's
    update makes every profile current and a stale "commits behind" banner would linger."""
    default_home = get_default_hermes_root()
    profiles_root = default_home / "profiles"
    homes = [default_home]
    if profiles_root.is_dir():
        homes += [entry for entry in profiles_root.iterdir() if entry.is_dir()]
    for home in homes:
        with suppress(Exception):
            (home / ".update_check").unlink(missing_ok=True)


def _write_marker_file(path: Path, *, label: str) -> None:
    """Drop an update-recovery breadcrumb. Never raises."""
    if _m()._pytest_owns_live_checkout(path.parent):
        logger.debug("Skipping %s marker under pytest (live checkout)", label)
        return
    try:
        path.write_text(f"started={_time.time()}\npid={os.getpid()}\n", encoding="utf-8")
    except OSError as exc:
        logger.debug("Could not write %s marker: %s", label, exc)


def _write_update_incomplete_marker() -> None:
    """Drop the interrupted core-install breadcrumb. Never raises."""
    _write_marker_file(_m()._update_marker_path(), label="update-incomplete")


def _write_lazy_refresh_incomplete_marker() -> None:
    """Drop the interrupted lazy-refresh breadcrumb. Never raises."""
    _write_marker_file(_m()._lazy_refresh_marker_path(), label="lazy-refresh-incomplete")


# ``fleet_restart_pending`` lives under HERMES_HOME (not next to the venv).
# The existing ``.update-incomplete`` / ``.lazy-refresh-incomplete`` markers
# gate dependency/venv repair; this one is the fleet-restart obligation after
# a git pull that advanced HEAD (#95294). Cleared only when the restart phase
# completes or there were no running services to restart.
_FLEET_RESTART_PENDING_NAME = "fleet_restart_pending"


def _fleet_restart_pending_marker_path() -> Path:
    """HERMES_HOME breadcrumb for a pull that has not yet restarted the fleet."""
    return get_hermes_home() / _FLEET_RESTART_PENDING_NAME


def _write_fleet_restart_pending_marker(*, expected_sha: str = "") -> None:
    """Drop the pull→restart obligation breadcrumb. Never raises."""
    path = _fleet_restart_pending_marker_path()
    if _m()._pytest_owns_live_checkout(path.parent):
        logger.debug("Skipping fleet-restart-pending marker under pytest (live checkout)")
        return
    try:
        lines = [f"started={_time.time()}", f"pid={os.getpid()}"]
        if expected_sha:
            lines.append(f"expected_sha={expected_sha}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        logger.debug("Could not write fleet-restart-pending marker: %s", exc)


def _clear_fleet_restart_pending_marker() -> None:
    """Remove the pull→restart obligation breadcrumb. Never raises."""
    _m()._clear_marker_file(
        _fleet_restart_pending_marker_path(), label="fleet-restart-pending"
    )


def _current_checkout_sha() -> str | None:
    """Current on-disk checkout HEAD, or None if it cannot be resolved."""
    try:
        from hermes_cli.build_info import get_code_identity

        sha = (get_code_identity(refresh=True) or {}).get("sha")
        return str(sha) if sha else None
    except Exception:
        return _capture_head_sha(["git"], _m().PROJECT_ROOT)


def _receipt_looks_unfinished(receipt: dict) -> bool:
    """True when *receipt* is from an update that did not finish cleanly."""
    if receipt.get("stop_reason"):
        return True
    exit_code = receipt.get("exit_code")
    if exit_code not in (0, None):
        return True
    outcome = receipt.get("outcome")
    if outcome in ("failed", "partial", "running"):
        return True
    gateway_restart = receipt.get("gateway_restart")
    if isinstance(gateway_restart, dict) and gateway_restart.get("incomplete"):
        return True
    return False


def _receipt_reports_stale_runtime(expected_sha: str | None = None) -> bool:
    """True when ``update_receipts/latest.json`` records a runtime SHA skew.

    ``plan.runtimes[].code_sha`` is captured *before* the pull of that run,
    so a successful update's receipt always shows pre-update runtime SHAs.
    Those must not retrigger a restart on the next invocation. Use the
    post-restart ``fleet`` matrix when present; fall back to the plan only
    for an unfinished receipt (interrupt / failed / incomplete restart) —
    the #95294 smoking-gun shape.
    """
    try:
        from hermes_cli.update_receipt import read_latest_receipt

        receipt = read_latest_receipt()
    except Exception:
        receipt = None
    if not isinstance(receipt, dict):
        return False
    if not expected_sha:
        expected_sha = _current_checkout_sha()
    if not expected_sha:
        return False

    def _sha_mismatch(code_sha) -> bool:
        return bool(code_sha) and str(code_sha) != str(expected_sha)

    fleet = receipt.get("fleet")
    if isinstance(fleet, list) and fleet:
        for entry in fleet:
            if not isinstance(entry, dict):
                continue
            if entry.get("state") == "stale":
                return True
            if _sha_mismatch(entry.get("code_sha")):
                return True
        return False

    if not _receipt_looks_unfinished(receipt):
        return False
    plan = receipt.get("plan")
    if not isinstance(plan, dict):
        return False
    for runtime in plan.get("runtimes") or []:
        if isinstance(runtime, dict) and _sha_mismatch(runtime.get("code_sha")):
            return True
    return False


def _pending_fleet_restart_needed() -> bool:
    """True when a prior pull still owes the fleet a restart (#95294)."""
    try:
        if _fleet_restart_pending_marker_path().is_file():
            return True
    except OSError:
        pass
    return _receipt_reports_stale_runtime()


def _warn_pending_fleet_restart(*, startup: bool = False) -> None:
    """Print the specific interrupted-update fleet-restart warning."""
    stream = sys.stderr if startup else sys.stdout
    print(
        "⚠ A previous `hermes update` pulled new code but did not "
        "restart running gateways.",
        file=stream,
    )
    print(
        "  Gateways may still be serving pre-update modules (mixed sys.modules).",
        file=stream,
    )
    if startup:
        print(
            "  Run `hermes update` or `hermes gateway restart`.",
            file=stream,
        )


def _warn_pending_fleet_restart_on_startup() -> None:
    """Cheap CLI-startup hint. Never restarts; never raises."""
    try:
        if not _pending_fleet_restart_needed():
            return
        _warn_pending_fleet_restart(startup=True)
    except Exception:
        pass


def _restart_systemd_gateway_units_best_effort(failed: list) -> None:
    """Best-effort ``systemctl restart`` of every hermes-gateway/serve unit."""
    for scope, scope_cmd in (
        ("user", ["systemctl", "--user"]),
        ("system", ["systemctl"]),
    ):
        try:
            result = subprocess.run(
                scope_cmd
                + [
                    "list-units",
                    "hermes-gateway*",
                    "hermes-serve*",
                    "--plain",
                    "--no-legend",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0:
            continue

        def process_unit(svc_name: str, _scope=scope, _cmd=scope_cmd) -> None:
            restart_cmd = list(_cmd) + ["--no-ask-password", "restart", svc_name]
            if (
                _scope == "system"
                and hasattr(os, "geteuid")
                and os.geteuid() != 0  # windows-footgun: ok — systemd path, Linux-only
            ):
                restart_cmd = ["sudo", "-n"] + restart_cmd
            subprocess.run(
                restart_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )

        def on_timeout(svc_name: str, exc: subprocess.TimeoutExpired) -> None:
            failed.append(svc_name)

        _for_each_systemd_gateway_unit(
            result.stdout,
            process_unit=process_unit,
            on_unit_timeout=on_timeout,
        )


def _run_pending_fleet_restart() -> bool:
    """Catch-up restart for gateways left on pre-update code (#95294).

    Returns True when restart completed or no services were running.
    Returns False if restart was incomplete. Never raises.
    """
    print("→ Restarting gateways left on pre-update code...")
    try:
        _m()._purge_stale_hermes_modules()
    except Exception:
        pass
    try:
        from hermes_cli.gateway import (
            find_gateway_pids,
            is_macos,
            is_windows,
            kill_gateway_processes,
            supports_systemd_services,
            _wait_for_gateway_exit,
        )
    except Exception as exc:
        _warn_gateway_restart_phase_aborted(exc, None)
        return False

    try:
        pids = list(find_gateway_pids(all_profiles=True))
    except Exception as exc:
        logger.debug("Pending fleet restart: gateway probe failed: %s", exc)
        pids = None

    if pids == []:
        print("  ✓ No running gateways — nothing to restart.")
        return True

    failed: list = []
    try:
        if supports_systemd_services():
            _restart_systemd_gateway_units_best_effort(failed)
        if is_macos():
            restarted: list = []
            try:
                _restart_macos_launchd_gateways(restarted, failed, 45.0)
            except Exception as exc:
                logger.debug("Pending fleet restart: launchd failed: %s", exc)
                failed.append("launchd")
        if is_windows():
            try:
                from hermes_cli import gateway_windows

                if gateway_windows.is_installed():
                    gateway_windows.restart()
            except Exception as exc:
                logger.debug("Pending fleet restart: Windows failed: %s", exc)
                failed.append("windows-gateway")
        leftover: list = []
        try:
            leftover = list(find_gateway_pids(all_profiles=True))
        except Exception:
            leftover = list(pids or [])
        if leftover:
            try:
                kill_gateway_processes(all_profiles=True)
                # 2026-09-06 fix: this fallback previously used
                # timeout=5.0, force_after=None — the only two
                # non-intentional call sites in the codebase that never
                # escalate to SIGKILL (every other _wait_for_gateway_exit
                # call uses timeout=10.0, force_after=5.0; see that
                # function's other callers). With no force-kill, a
                # gateway that doesn't exit within the graceful window
                # just sits there — confirmed live: the gateway serving
                # this very session logged "PID still running after
                # 5.0s — restart may fail" and then stayed in systemd's
                # "deactivating" state for well over a minute afterward
                # with nothing left to push it along, until manually
                # restarted from outside the session. force_after=5.0
                # gives graceful shutdown one real window, then forces
                # the issue instead of leaving the fleet in limbo.
                _wait_for_gateway_exit(timeout=10.0, force_after=5.0)
            except Exception as exc:
                logger.debug("Pending fleet restart: PID stop failed: %s", exc)
        if failed:
            _warn_incomplete_gateway_fleet_restart(failed)
            return False
        print("  ✓ Pending fleet restart completed.")
        return True
    except Exception as exc:
        surviving = None
        try:
            surviving = list(find_gateway_pids(all_profiles=True))
        except Exception:
            surviving = pids
        _warn_gateway_restart_phase_aborted(exc, surviving)
        return False


def _apply_pending_fleet_restart_catchup() -> None:
    """On an already-up-to-date ``hermes update``, finish a skipped restart.

    No-op when nothing is pending. Exits 1 when the catch-up restart is
    incomplete so automation does not treat the fleet as healthy.
    """
    if not _pending_fleet_restart_needed():
        return
    print()
    _warn_pending_fleet_restart()
    print("→ Running the pending fleet restart...")
    if _run_pending_fleet_restart():
        _clear_fleet_restart_pending_marker()
        return
    print("  ⚠ Fleet restart incomplete. Recover with: hermes gateway restart")
    sys.exit(1)


def _format_concurrent_instances_message(matches: list[tuple[int, str]], scripts_dir: Path) -> str:
    """Explanation + remediation hint for the Windows concurrent-hermes.exe gate."""
    shim = scripts_dir / "hermes.exe"
    lines = [
        "✗ Another hermes.exe is running:",
        *(f"    PID {pid}  {name}" for pid, name in matches),
        "",
        f"  Updating now would fail to overwrite {shim} because",
        "  Windows blocks REPLACE on a running executable.",
        "",
        "  Close Hermes Desktop, exit any open `hermes` REPLs, and",
        "  stop the gateway (`hermes gateway stop`) before retrying.",
        ""]
    if matches:
        pid_args = " ".join(f"/PID {pid}" for pid, _ in matches)
        lines += [
            "  If you've already closed everything and these PIDs are",
            "  stale, terminate them directly, then retry the update:",
            f"      taskkill {pid_args} /F",
            ""]
    lines += [
        "  Override with `hermes update --force` if you've already",
        "  confirmed those processes will not write to the venv."]
    return "\n".join(lines)


def _classify_concurrent_instance(pid: int) -> str:
    """Classify ``pid`` as "gateway" / "non-gateway" / "unknown" (psutil can't read it). Uses
    ``_is_pausable_gateway`` (same matcher as the Desktop preflight and venv-holder guard) so
    "gateway" is exactly what the pause/restart machinery stops; "unknown" gates as non-gateway."""
    try:
        import psutil  # noqa: PLC0415
        cmdline_list = psutil.Process(int(pid)).cmdline()
    except Exception:
        return "unknown"

    from hermes_cli._scan_venv_blockers import _is_pausable_gateway  # noqa: PLC0415
    return "gateway" if _is_pausable_gateway(" ".join(cmdline_list or [])) else "non-gateway"


def _filter_non_gateway_concurrent_instances(matches: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Drop gateway matches (the pause + post-update restart machinery handles them); anything else
    (TUI, Desktop backend child, another REPL) has no pause path, so the gate aborts."""
    return [(pid, name) for pid, name in matches if _classify_concurrent_instance(pid) != "gateway"]


def _log_only_write(text: str) -> None:
    """Write to update.log only: reaches past the ``_UpdateOutputStream`` stdout mirror so
    loud, low-signal subprocess output stays debuggable without flooding the terminal."""
    if not text:
        return
    stream = _m().sys.stdout
    log_file = getattr(stream, "_log", None)
    with suppress(Exception):
        if log_file is None:
            log_path = get_hermes_home() / "logs" / "update.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fallback:
                fallback.write(text)
        else:
            log_file.write(text)
            log_file.flush()


def _run_logged_subprocess(cmd, *, cwd=None, env=None):
    """Stream combined build output to update.log, retaining it for failure reporting."""
    import codecs
    import io
    from hermes_cli._subprocess_compat import kill_process_tree, windows_hide_flags

    child_env = dict(os.environ if env is None else env)
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    spawn = {"creationflags": windows_hide_flags()} if os.name == "nt" else {"process_group": 0}
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=child_env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **spawn)
    # read1 delivers partial lines too; incremental decoding preserves split UTF-8
    # and the universal-newline behavior callers previously got from text=True.
    decoder = io.IncrementalNewlineDecoder(codecs.getincrementaldecoder("utf-8")("replace"), True)
    output = []
    try:
        while True:
            chunk = proc.stdout.read1(8192)
            text = decoder.decode(chunk, final=not chunk)
            output.append(text)
            _log_only_write(text)
            if not chunk:
                break
        return subprocess.CompletedProcess(cmd, proc.wait(), stdout="".join(output))
    except BaseException:
        # Unlike Popen.__exit__, do not wait for a cancelled build to finish.
        kill_process_tree(proc)
        with suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        raise
    finally:
        proc.stdout.close()


def _cmd_update_check(branch: str = "main", *, branch_explicit: bool = False):
    """``hermes update --check``: fetch and report without installing. ``branch_explicit`` is
    True iff --branch was passed (Docker installs print a notice instead of dropping the flag)."""
    # Same marker-first admission gate as the apply path, so --check never reports git
    # state for an install whose real update mechanism is an image pull.
    from hermes_cli.update_contract import evaluate_update_admission, record_refusal_receipt

    refusal = evaluate_update_admission(_m().PROJECT_ROOT)
    if refusal is not None:
        print(refusal.message)
        record_refusal_receipt(refusal)
        sys.exit(2)

    git_dir = _m().PROJECT_ROOT / ".git"
    if not git_dir.exists():
        print("✗ Not a git repository — cannot check for updates.")
        sys.exit(1)

    git_cmd = _base_git_cmd()

    # Interrupted fetches leave .git/*.lock behind ("File exists" forever); self-heal first.
    from hermes_cli.gitlock import clear_stale_git_locks, clear_stale_tmp_packs
    for lock_path in clear_stale_git_locks(_m().PROJECT_ROOT):
        print(f"  (removed stale git lock: {lock_path})")
    # Aborted fetches also strand tmp_pack_* debris (has reached 6 GB and corrupted the
    # pack dir); same age+process safety contract as the locks.
    swept = clear_stale_tmp_packs(_m().PROJECT_ROOT)
    if swept:
        print(f"  (removed {len(swept)} aborted-fetch pack temp file(s))")

    # Fetch only <branch> (a bare fetch pulls thousands of auto-generated branches). Prefer
    # upstream only for main (a fork's other branches have no upstream counterpart). Installer
    # checkouts are shallow: a plain fetch would unshallow them and rev-list would report a
    # bogus huge "behind" count, so fetch --depth 1 and report presence-only.
    is_shallow = _is_shallow_checkout(git_cmd)
    depth_args = ["--depth", "1"] if is_shallow else []

    # Probe locally for an 'upstream' remote before a network fetch non-forks always fail.
    fetch_result = None
    if branch == "main" and _git_run(git_cmd, ["remote", "get-url", "upstream"]).returncode == 0:
        print("→ Fetching from upstream...")
        fetch_result = _git_run(git_cmd, ["fetch"] + depth_args + ["upstream", branch], network=True)
    if fetch_result is not None and fetch_result.returncode == 0:
        compare_branch = f"upstream/{branch}"
    else:
        print("→ Fetching from origin...")
        fetch_result = _git_run(git_cmd, ["fetch"] + depth_args + ["origin", branch], network=True)
        compare_branch = f"origin/{branch}"

    if fetch_result.returncode != 0:
        _print_fetch_failure(fetch_result.stderr)
        sys.exit(1)

    # rev-list on a bogus ref exits 128 and (check=True) would traceback; verify first.
    verify_result = _git_run(git_cmd, ["rev-parse", "--verify", "--quiet", compare_branch])
    if verify_result.returncode != 0:
        print(f"✗ Branch '{branch}' not found on {compare_branch.split('/', 1)[0]}.")
        sys.exit(1)

    if is_shallow:
        # No history across the shallow boundary: compare tip SHAs, then recover the
        # exact count via the GitHub compare API (complete graph).
        head_sha, target_sha = _tip_shas(git_cmd, compare_branch)
        if head_sha and target_sha and head_sha == target_sha:
            print("✓ Already up to date.")
            return
        from hermes_cli.banner import _github_compare_behind
        # counted == 0 means local-ahead, not behind; None means the API could not count.
        _print_update_check_result(_github_compare_behind(head_sha, target_sha), compare_branch)
        return

    rev_result = _git_run(git_cmd, ["rev-list", f"HEAD..{compare_branch}", "--count"], check=True)
    _print_update_check_result(int(rev_result.stdout.strip()), compare_branch)


def _base_git_cmd() -> list[str]:
    """``git`` argv; Windows adds ``-c windows.appendAtomically=false`` (git can fail "unable to
    write loose object file: Invalid argument" on non-atomic appends)."""
    if sys.platform == "win32":
        return ["git", "-c", "windows.appendAtomically=false"]
    return ["git"]


def _is_shallow_checkout(git_cmd) -> bool:
    return _git_run(git_cmd, ["rev-parse", "--is-shallow-repository"]).stdout.strip() == "true"


def _tip_shas(git_cmd, target_ref: str) -> tuple[str, str]:
    """``(HEAD sha, <target_ref> sha)`` as printed by rev-parse ("" when unresolvable)."""
    return tuple(_git_run(git_cmd, ["rev-parse", ref]).stdout.strip() for ref in ("HEAD", target_ref))


def _print_update_check_result(behind: int | None, compare_branch: str) -> None:
    """Report ``--check``'s verdict: up to date, N commits behind, or behind by an unknown count."""
    if behind == 0:
        print("✓ Already up to date.")
        return
    if behind is not None:
        print(f"⚕ Update available: {behind} {'commit' if behind == 1 else 'commits'} behind {compare_branch}.")
    else:
        print(f"⚕ Update available (behind {compare_branch}).")
    from hermes_cli.config import recommended_update_command
    print(f"  Run '{recommended_update_command()}' to install.")


def _repair_venv_on_current_checkout(
    *, assume_yes, gateway_mode, pre_update_snapshot_id, desktop_dir,
    had_desktop_app_before_update, active_lazy_features, active_tool_dependencies,
    _windows_gateway_resume) -> bool:
    """Reinstall ``.[all]`` + lazy/tool deps into an unhealthy (or handed-off) venv; returns
    whether the checkout can be reported complete."""
    # Self-lock deferral: the repair rewrites the venv too (same mapped-extension hazard).
    # See #86735.
    # Self-lock deferral (relocated preflight — #86735): if THIS process holds a native extension the sync
    # must rewrite, defer NOW — after the code swap, so only the dependency install is pending and the next
    # fresh launch completes it via the marker.
    _m()._abort_dependency_sync_if_self_locked(_windows_gateway_resume)
    _write_update_incomplete_marker()
    from hermes_cli.managed_uv import ensure_uv
    repair_uv = ensure_uv()
    # Venv gone entirely (repair interrupted after the old one was moved aside): recreate.
    venv_python_missing = not (
        venv_python_path(_m().PROJECT_ROOT / "venv", windows=_m()._is_windows())).exists()
    if venv_python_missing and repair_uv:
        print("→ Recreating virtual environment...")
        subprocess.run([repair_uv, "venv", "venv"], cwd=_m().PROJECT_ROOT, check=False)
    repair_prefix, repair_env = _pip_install_prefix(repair_uv)
    _m()._install_python_dependencies_with_optional_fallback(repair_prefix, env=repair_env, group="all")
    _m()._refresh_active_lazy_features(repair_prefix, env=repair_env, features=active_lazy_features)
    _m()._restore_active_tool_dependencies(active_tool_dependencies, repair_prefix, env=repair_env)
    # Core ``.[all]`` install finished. Clear the generic core breadcrumb before the lazy-refresh phase —
    # that phase uses its own marker so a later lazy failure cannot be "healed" by clearing the core marker
    # based on a narrow 7-package import probe (#58004 review).
    _m()._clear_update_incomplete_marker()
    healthy_after, detail_after = _venv_core_imports_healthy()
    if not healthy_after:
        print(f"⚠ Venv still unhealthy after repair: {detail_after}")
        print("  Close all Hermes windows/gateways and re-run: hermes update")
        return False
    print("✓ Dependencies repaired!")
    # Check for config migrations (#91360).
    _check_and_apply_config_migration(
        assume_yes=assume_yes, gateway_mode=gateway_mode, pre_update_snapshot_id=pre_update_snapshot_id)
    # The hand-off child never reaches the commits-pulled rebuild; do it here.
    if _rebuild_desktop_after_update(desktop_dir, had_desktop_app_before_update=had_desktop_app_before_update):
        return _print_verified_update_completion("✓ Update complete!")
    _print_update_completion(
        "⚠ Update partially complete — the desktop app was not rebuilt and is still on the previous build.")
    return False


def _pip_install_prefix(uv_bin) -> tuple[list[str], dict | None]:
    """``(install prefix, env)``: ``uv pip`` isolated from third-party UV env vars (so a foreign
    UV_PYTHON_INSTALL_DIR can't hijack it), else ``sys.executable -m pip`` (avoids PEP 668 errors)."""
    if uv_bin:
        # Same third-party UV-env isolation as the main update path (#83914): a user-level
        # UV_PYTHON_INSTALL_DIR / UV_PYTHON from unrelated software must not steer which interpreter uv
        # resolves here.
        # See #83914.
        from hermes_cli.managed_uv import managed_python_env
        env = managed_python_env()
        env["VIRTUAL_ENV"] = str(_m().PROJECT_ROOT / "venv")
        return [uv_bin, "pip"], env
    return [sys.executable, "-m", "pip"], None


def _repair_current_checkout(
    *, assume_yes, gateway_mode, pre_update_snapshot_id, desktop_dir,
    had_desktop_app_before_update, active_lazy_features, active_tool_dependencies,
    upstream_checked, _windows_gateway_resume) -> bool:
    """Already-up-to-date path: keep the managed runtime current, repair a broken venv.
    Returns whether the checkout can be reported complete."""
    # "No new commits" != safe interpreter: uv can keep the same CPython patch while
    # python-build-standalone refreshes the embedded SQLite; keep the boundary hook here too.
    from hermes_cli.managed_uv import ensure_uv, update_managed_uv
    runtime_repairs = []
    update_managed_uv(repair_observer=runtime_repairs.append)
    ensure_uv(repair_observer=runtime_repairs.append)
    runtime_repaired = next((result for result in runtime_repairs if result.repaired), None)

    # A current checkout does NOT imply a healthy install (a prior sync may have died
    # partway, e.g. Windows locked .pyd); probe or "Already up to date!" hides a bricked venv.
    healthy, detail = _venv_core_imports_healthy()
    # The Windows shim hand-off child is current BY DESIGN; its one job is the pending sync,
    # not venv health — without this it would print "Already up to date!" and skip it.
    handed_off_sync = os.environ.get(_m()._UPDATE_REEXEC_ENV) == "1"
    if handed_off_sync:
        print("→ Finishing the dependency install handed off by hermes.exe...")
    elif not healthy:
        print("⚠ Checkout is current, but the venv is unhealthy:")
        print(f"  {detail}")
        print("→ Repairing Python dependencies...")
    if handed_off_sync or not healthy:
        current_checkout_complete = _repair_venv_on_current_checkout(
            assume_yes=assume_yes, gateway_mode=gateway_mode,
            pre_update_snapshot_id=pre_update_snapshot_id, desktop_dir=desktop_dir,
            had_desktop_app_before_update=had_desktop_app_before_update,
            active_lazy_features=active_lazy_features,
            active_tool_dependencies=active_tool_dependencies,
            _windows_gateway_resume=_windows_gateway_resume)
    else:
        current_checkout_complete = _repair_node_deps_on_current_checkout(
            _print_verified_update_completion, assume_yes=assume_yes, gateway_mode=gateway_mode,
            pre_update_snapshot_id=pre_update_snapshot_id,
            completion_message=(
                "✓ Already up to date!" if upstream_checked
                else "✓ Up to date with your fork (official repo not checked)."),
            had_desktop_app_before_update=had_desktop_app_before_update)
    if runtime_repaired is not None and not _m()._is_windows():
        print()
        print("⚠ Restart required to finish the managed Python runtime repair.")
        print(
            "  Any running Hermes gateways, Desktop backends, or other "
            "long-lived processes still use the previous runtime.")
        print("  Restart each of them to pick up the repaired runtime.")
    return current_checkout_complete


def _reconcile_diverged_checkout(git_cmd, branch: str, pre_pull_sha) -> None:
    """Fast-forward failed: merge on a custom branch (local commits survive) or reset --hard on the
    same branch (rescue ref first when histories share no ancestor). ``sys.exit(1)`` on failure.

    STEP 70 G.1/G.3: before ANY reset --hard on the same branch, verify origin actually contains
    this branch's tip ancestry (a local-only commit here — a manual fix, or work never pushed —
    would otherwise be silently destroyed) and create a durable pre-reset safety tag. Fail closed
    on ANY uncertainty: an unverifiable divergence check is never treated as "no divergence", and
    the reset never runs without a recoverable safety tag.
    """
    # A custom branch (local commits atop origin/<branch>) also can't ff, and reset --hard
    # would discard that work: merge instead, stop on conflict.
    _cur_branch = (_git_run(git_cmd, ["branch", "--show-current"]).stdout or "").strip()
    if _cur_branch and _cur_branch != branch:
        print(
            f"  ⚠ Checkout is on custom branch '{_cur_branch}' — "
            f"merging origin/{branch} instead of resetting so local commits survive...")
        # Best-effort safety tag as a recovery anchor.
        _git_run(git_cmd, ["tag", f"pre-update-{_time.strftime('%Y%m%d-%H%M%S')}"])
        if _git_run(git_cmd, ["merge", "--no-edit", f"origin/{branch}"]).returncode != 0:
            _git_run(git_cmd, ["merge", "--abort"])
            print("✗ Merge conflict between local commits and upstream — update stopped, nothing was changed.")
            print(f"  Resolve manually: cd {_m().PROJECT_ROOT} && git merge origin/{branch}")
            print("  Then re-run the update. Local work is untouched.")
            sys.exit(1)
        return
    # Same branch: a true upstream force-push/rebase; local changes are stashed, so reset.
    # Orphan divergence (no common ancestor: corrupted HEAD, re-init) would lose the whole
    # local graph, so park pre_pull_sha behind a rescue ref first.
    merge_base_result = _git_run(git_cmd, ["merge-base", "HEAD", f"origin/{branch}"])
    has_common_ancestor = merge_base_result.returncode == 0 and merge_base_result.stdout.strip()
    if not has_common_ancestor and pre_pull_sha:
        from datetime import datetime as _dt, timezone
        # SHA suffix so two updates in the same second get distinct refs.
        rescue_ref = (
            f"refs/hermes-update-backups/orphan-{branch}-"
            f"{_dt.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{pre_pull_sha[:12]}")
        head = f"  ⚠ Local history shares no common ancestor with origin/{branch} (orphan divergence) — "
        if _git_run(git_cmd, ["update-ref", rescue_ref, pre_pull_sha]).returncode == 0:
            print(
                f"{head}backed up current HEAD to {rescue_ref} before resetting. "
                f"This backup expires after {_ORPHAN_RESCUE_REF_MAX_AGE_DAYS} days.")
        else:
            # update-ref failure is intentionally non-fatal, but never claim a backup exists.
            print(
                f"{head}attempted to back up current HEAD to {rescue_ref} before resetting, "
                f"but the backup write failed (pre-reset SHA was {pre_pull_sha}).")
        _prune_orphan_rescue_refs(git_cmd, _m().PROJECT_ROOT, branch)

    # STEP 70 G.3: verify origin actually contains this branch's tip ancestry before ANY
    # destructive reset. Fail closed on ANY uncertainty — an unverifiable check is never
    # treated as "no divergence", and a confirmed local-only commit blocks the reset outright.
    print("  ⚠ Fast-forward not possible (history diverged), resetting to match remote...")
    local_only, local_only_reason = _m()._local_only_commits(
        git_cmd, _m().PROJECT_ROOT, branch, f"origin/{branch}")
    if local_only is None:
        print(f"✗ Could not verify whether {branch} has local-only commits ({local_only_reason}).")
        print("  Refusing to reset --hard: an unverifiable divergence check is never treated as safe.")
        print(f"  Resolve manually, then retry: cd {_m().PROJECT_ROOT} && git log origin/{branch}..{branch}")
        sys.exit(1)
    if local_only:
        print(
            f"✗ Refusing to reset --hard origin/{branch}: {branch} has "
            f"{len(local_only)} local-only commit(s) that would be discarded:")
        for entry in local_only:
            print(f"    {entry}")
        print("  Resolve manually (cherry-pick, rebase, or push these commits) before retrying ``hermes update``.")
        sys.exit(1)

    # STEP 70 G.1: create a durable safety tag of the exact pre-reset HEAD before executing
    # the destructive reset. Fail closed if the tag cannot be created or verified — the reset
    # must never run without it.
    pre_reset_sha = _capture_head_sha(git_cmd, _m().PROJECT_ROOT)
    safety_tag = _m()._create_pre_reset_safety_tag(git_cmd, _m().PROJECT_ROOT, pre_reset_sha)
    if not safety_tag:
        print(f"✗ Could not create a pre-reset safety tag (pre-reset HEAD: {pre_reset_sha or 'unresolved'}).")
        print("  Refusing to reset --hard: a destructive reset must never run without a recoverable safety tag.")
        sys.exit(1)
    print(f"  → Safety tag created: {safety_tag}")

    reset_result = _git_run(git_cmd, ["reset", "--hard", f"origin/{branch}"])
    if reset_result.returncode != 0:
        print(f"✗ Failed to reset to origin/{branch}.")
        if reset_result.stderr.strip():
            print(f"  {reset_result.stderr.strip()}")
        print(f"  Try manually: git fetch origin && git reset --hard origin/{branch}")
        sys.exit(1)


def _rollback_if_pulled_syntax_error(git_cmd, pre_pull_sha) -> None:
    """Post-pull syntax guard: roll back to *pre_pull_sha* and ``sys.exit(1)`` when a critical
    file no longer compiles (a bad admin-merge past CI must not brick the CLI).

    STEP 70 G.1: the rollback itself is destructive (moves HEAD off the pulled-but-broken
    commit), so it tags that commit as a durable safety ref BEFORE moving HEAD back — the
    broken commit stays discoverable rather than silently going unreachable. Fail closed if
    the tag cannot be created/verified: the rollback must never run without it.
    """
    syntax_ok, failing_path, syntax_error = _validate_critical_files_syntax(_m().PROJECT_ROOT)
    if syntax_ok:
        return
    print()
    print("✗ Pulled code has a syntax error in a critical file:")
    print(f"  {failing_path}")
    # py_compile errors can be multi-line; show enough for the SyntaxError text.
    for line in str(syntax_error).splitlines()[:6] if syntax_error else ():
        print(f"    {line}")
    if not pre_pull_sha:
        print()
        print("  Could not capture pre-pull SHA — recover manually with:")
        print(f"    cd {_m().PROJECT_ROOT} && git reflog && git reset --hard <prev-sha>")
        sys.exit(1)
    print()
    print(f"→ Rolling back to {pre_pull_sha[:10]}...")
    pre_rollback_sha = _capture_head_sha(git_cmd, _m().PROJECT_ROOT)
    safety_tag = _m()._create_pre_reset_safety_tag(git_cmd, _m().PROJECT_ROOT, pre_rollback_sha)
    if not safety_tag:
        print(f"  ✗ Could not create a pre-rollback safety tag (pre-rollback HEAD: {pre_rollback_sha or 'unresolved'}).")
        print("  Refusing to roll back: a destructive reset must never run without a recoverable safety tag.")
        print(f"  Recover manually with: cd {_m().PROJECT_ROOT} && git reset --hard {pre_pull_sha}")
        sys.exit(1)
    print(f"  → Safety tag created: {safety_tag}")
    rollback_result = _git_run(git_cmd, ["reset", "--hard", pre_pull_sha])
    if rollback_result.returncode == 0:
        print("  ✓ Rollback complete — your install is unchanged.")
        print("  Try ``hermes update`` again later once a fix lands.")
    else:
        print("  ✗ Rollback failed. Recover manually with:")
        print(f"    cd {_m().PROJECT_ROOT} && git reset --hard {pre_pull_sha}")
        if rollback_result.stderr.strip():
            print(f"    ({rollback_result.stderr.strip().splitlines()[0]})")
    sys.exit(1)


def _pull_updates(
    git_cmd, branch, auto_stash_ref, *, prompt_for_restore, gw_input_fn, discard_local_changes,
    keep_stash):
    """Fast-forward onto ``origin/<branch>`` and settle the autostash. Divergence by shape:
    custom branch -> merge, same branch -> reset (STEP 70 G.1/G.3 safety-tag + local-only-commit
    guards), orphan history -> rescue ref first; a post-pull syntax error in a critical file
    rolls back. Exits on failure; returns pre-pull SHA."""
    update_succeeded = False
    # Pre-pull SHA for auto-rollback (stray conflict markers once bricked every updater).
    # Capture the pre-pull SHA so we can auto-roll-back if the new code has a syntax error in a
    # critical-path file (PR #28452 incident: orphan merge-conflict markers in hermes_cli/config.py bricked
    # every user who ran ``hermes update`` for the 7 minutes between the bad commit and the fix landing).
    pre_pull_sha = _capture_head_sha(git_cmd, _m().PROJECT_ROOT)
    try:
        # merge --ff-only the already-fetched ref instead of `git pull`, which would do a
        # SECOND network fetch; identical in effect given the fresh tracking ref.
        if _git_run(git_cmd, ["merge", "--ff-only", f"origin/{branch}"]).returncode != 0:
            _reconcile_diverged_checkout(git_cmd, branch, pre_pull_sha)
        _rollback_if_pulled_syntax_error(git_cmd, pre_pull_sha)
        update_succeeded = True
    finally:
        if auto_stash_ref is not None:
            # No stash restore if the update failed — tree state is unknown.
            if not update_succeeded:
                print(f"  ℹ️  Local changes preserved in stash (ref: {auto_stash_ref})")
                print("  Restore manually with: git stash apply")
            elif discard_local_changes:
                # Non-interactive + updates.non_interactive_local_changes: discard.
                _m()._discard_stashed_changes(git_cmd, _m().PROJECT_ROOT, auto_stash_ref)
            elif keep_stash:
                # --keep-stash (desktop updater): leave edits parked rather than re-apply silently.
                _m()._park_stashed_changes(auto_stash_ref)
            else:
                _m()._restore_stashed_changes(
                    git_cmd, _m().PROJECT_ROOT, auto_stash_ref, prompt_user=prompt_for_restore,
                    input_fn=gw_input_fn)
    return pre_pull_sha


@dataclass
class _CheckoutPlan:
    """What the pre-pull checkout phase decided (see ``_prepare_checkout_for_update``)."""

    auto_stash_ref: "str | None"
    commit_count: int
    in_place_update: bool
    parked_branch_switched: bool
    prompt_for_restore: bool
    switch_block_reason: "str | None"
    upstream_checked: bool


def _apply_parked_branch_guard(
    git_cmd, branch, current_branch, *, switch_branch, _windows_gateway_resume
) -> tuple[bool, bool, "str | None"]:
    """Decide how a checkout parked on another branch is brought to *branch* (stash-switch-pull-
    switch-back used to "update" main while the running code stayed behind).

    By branch contents + updates.parked_branch_strategy: fully merged -> switch back;
    unmerged -> "switch" (default; loud "kept" notice) or "update_in_place" (merge origin/<target>
    INTO the branch, checkout never moves; --switch-branch overrides once); dirty/unverifiable ->
    touch nothing, warn, ``sys.exit(1)`` with the code update SKIPPED (also when the target is
    missing). Returns ``(parked_branch_switched, in_place_update, switch_block_reason)``.
    """
    if current_branch == branch or current_branch == "HEAD":
        return False, False, None
    switch_safe, switch_block_reason = _m()._assess_parked_branch_switch(
        git_cmd, _m().PROJECT_ROOT, current_branch, branch)
    if not switch_safe:
        _m()._print_parked_branch_skip_warning(
            git_cmd, _m().PROJECT_ROOT, current_branch, branch, switch_block_reason)
        print()
        print(f"⚠ Update finished — code update SKIPPED{_branch_head_suffix(git_cmd, _m().PROJECT_ROOT)}")
        _m()._resume_windows_gateways_after_update(_windows_gateway_resume)
        sys.exit(1)
    if not switch_block_reason.startswith("unmerged:"):
        print(f"  ⚠ Checkout was parked on '{current_branch}' (fully merged) — switching back to {branch}...")
        return True, False, switch_block_reason
    _in_place_configured = False
    with _best_effort('Could not read updates.parked_branch_strategy: %s'):
        _in_place_configured = (
            _updates_config().get("parked_branch_strategy", "switch") == "update_in_place")
    if not _in_place_configured or switch_branch:
        _m()._print_parked_branch_kept_notice(
            current_branch, branch, switch_block_reason.split(":", 1)[1])
        return True, False, switch_block_reason
    # --branch typos used to surface via the checkout failing, which this path skips.
    if _git_run(git_cmd, ["rev-parse", "--verify", "--quiet", f"origin/{branch}"]).returncode != 0:
        print(f"✗ Branch '{branch}' does not exist locally or on origin.")
        sys.exit(1)
    print(
        f"  ℹ On branch '{current_branch}' — updating it in place from "
        f"origin/{branch} (no branch switch; local commits preserved).")
    return False, True, switch_block_reason


def _prepare_checkout_for_update(
    git_cmd, branch, current_branch, *, is_fork, assume_yes, gateway_mode, gw_input_fn,
    switch_branch, _windows_gateway_resume):
    """Parked-branch guard, land on the target, stash, count new commits. Exits when the
    checkout is unsafe to move or the target is missing. ``commit_count`` is 0 when up to
    date, -1 when tips differ but the shallow count is unrecoverable."""
    parked_branch_switched, in_place_update, switch_block_reason = _apply_parked_branch_guard(
        git_cmd, branch, current_branch, switch_branch=switch_branch,
        _windows_gateway_resume=_windows_gateway_resume)

    if not in_place_update and current_branch == "HEAD" != branch:
        print(f"  ⚠ Currently on detached HEAD — switching to {branch} for update...")
    auto_stash_ref = _m()._stash_local_changes_if_needed(git_cmd, _m().PROJECT_ROOT)
    if (
        not in_place_update and current_branch != branch
        and _git_run(git_cmd, ["checkout", branch]).returncode != 0):
        track_result = _git_run(git_cmd, ["checkout", "-B", branch, f"origin/{branch}"])
        if track_result.returncode != 0:
            # Restore the stash before bailing so the user isn't stranded.
            if auto_stash_ref is not None:
                _m()._restore_stashed_changes(
                    git_cmd, _m().PROJECT_ROOT, auto_stash_ref, prompt_user=False, input_fn=gw_input_fn)
            print(f"✗ Branch '{branch}' does not exist locally or on origin.")
            if track_result.stderr.strip():
                print(f"  {track_result.stderr.strip().splitlines()[0]}")
            sys.exit(1)

    prompt_for_restore = (
        auto_stash_ref is not None
        and not assume_yes
        and (gateway_mode or (sys.stdin.isatty() and sys.stdout.isatty())))

    # On shallow checkouts `rev-list --count` can report the entire remote ancestry. The
    # zero/nonzero gate is still sound; treat the shallow NUMBER as unknown and recover it
    # via the GitHub compare API when possible.
    result = _git_run(git_cmd, ["rev-list", f"HEAD..origin/{branch}", "--count"], check=True)
    commit_count = int(result.stdout.strip())

    apply_is_shallow = _is_shallow_checkout(git_cmd)
    if commit_count > 0 and apply_is_shallow:
        from hermes_cli.banner import _github_compare_behind
        counted = _github_compare_behind(*_tip_shas(git_cmd, f"origin/{branch}"))
        # counted == 0 means local-ahead: falls through to the up-to-date path.
        commit_count = counted if counted is not None else -1

    # A fork can match origin yet trail upstream, so the sync can move HEAD with
    # commit_count == 0; detect that BEFORE the no-update return so deps, restarts AND the
    # fleet matrix still run (it used to live in the early-return branch and verified nothing).
    # The sync can therefore advance HEAD even though the origin comparison found no commits. Detect that
    # BEFORE taking the no-update return so dependency refreshes, gateway restarts, AND the fleet version
    # matrix still run for the pulled code (#73108 — previously the sync lived inside the commit_count == 0
    # branch, which returns immediately after: an update that pulled hundreds of upstream commits printed
    # "Already up to date!" and verified nothing). Non-fork checkouts have no upstream question: origin IS
    # the official repo, so "Already up to date!" is fully verified there.
    upstream_checked = True
    if commit_count == 0 and is_fork and branch == "main":
        pre_sync_sha = _capture_head_sha(git_cmd, _m().PROJECT_ROOT)
        upstream_checked = _m()._sync_with_upstream_if_needed(
            git_cmd, _m().PROJECT_ROOT, assume_yes=assume_yes, input_fn=gw_input_fn)
        post_sync_sha = _capture_head_sha(git_cmd, _m().PROJECT_ROOT)
        if pre_sync_sha and post_sync_sha and pre_sync_sha != post_sync_sha:
            synced_count = _count_commits_between(
                git_cmd, _m().PROJECT_ROOT, pre_sync_sha, post_sync_sha)
            # HEAD moving is proof of an update even if the count can't be read.
            commit_count = max(1, synced_count)

    return _CheckoutPlan(
        auto_stash_ref=auto_stash_ref, commit_count=commit_count, in_place_update=in_place_update,
        parked_branch_switched=parked_branch_switched, prompt_for_restore=prompt_for_restore,
        switch_block_reason=switch_block_reason, upstream_checked=upstream_checked)


@dataclass
class _UpdateOptions:
    """Resolved ``hermes update`` inputs (flags, config, pre-update snapshots)."""

    active_lazy_features: object
    active_tool_dependencies: object
    pre_update_version: object
    gw_input_fn: object
    assume_yes: bool
    keep_stash: bool
    switch_branch: bool
    discard_local_changes: bool


def _resolve_update_options(args, gateway_mode: bool) -> _UpdateOptions:
    """Snapshot pre-update state and resolve the flags/config ``_cmd_update_impl`` runs on."""
    # Snapshot before a managed-runtime refresh can replace site-packages, while the old
    # environment can still prove which optional backends were active.
    active_lazy_features = _m()._capture_active_lazy_features()
    active_tool_dependencies = _m()._capture_active_tool_dependencies()

    # Captured before any pull so the completion line can report the transition.
    # Snapshot the pre-update version before files are replaced so the completion line can report the
    # transition (prime-agent#630 port).
    # Snapshot the pre-update version before any code is pulled so the completion line can report the
    # transition (prime-agent#630 port).
    pre_update_version = _read_project_version()
    gw_input_fn = (
        (lambda prompt, default="": _gateway_prompt(prompt, default)) if gateway_mode else None)
    assume_yes = bool(getattr(args, "yes", False))
    # --keep-stash (desktop updater): never re-apply the autostash; only when an update
    # landed — abort/no-op paths still restore since the tree is unchanged.
    keep_stash = bool(getattr(args, "keep_stash", False))
    # --switch-branch: prefer switching over an in-place merge so an update never writes the
    # branch's history; only meaningful with parked_branch_strategy "update_in_place".
    # See #89507.
    switch_branch = bool(getattr(args, "switch_branch", False))

    # Interactive terminals always stash-and-ask; only non-interactive updates consult
    # updates.non_interactive_local_changes (auto-restore vs discard).
    discard_local_changes = False
    if gateway_mode or assume_yes or not (sys.stdin.isatty() and sys.stdout.isatty()):
        # A config read failure must never change the safe default.
        with _best_effort("Could not read updates.non_interactive_local_changes: %s"):
            _mode = str(_updates_config().get("non_interactive_local_changes", "stash")).lower()
            discard_local_changes = _mode == "discard"
    return _UpdateOptions(
        active_lazy_features=active_lazy_features,
        active_tool_dependencies=active_tool_dependencies, pre_update_version=pre_update_version,
        gw_input_fn=gw_input_fn, assume_yes=assume_yes, keep_stash=keep_stash,
        switch_branch=switch_branch, discard_local_changes=discard_local_changes)


def _begin_update_receipt_and_plan(args):
    """Open the receipt, snapshot the fleet, refuse on Windows shim holders. Returns the
    pre-update plan (None if the probe failed); ``sys.exit(2)`` when a non-gateway hermes.exe
    holds the venv shim."""
    # Structured receipt: record what this run discovers/does/skips so silent failures are diagnosable.
    with _best_effort('Update receipt unavailable: %s'):
        # See #74973, #81193, #85753, #88848, #91277.
        from hermes_cli.update_receipt import begin_update_receipt
        begin_update_receipt()

    # Plan phase: snapshot runtimes/supervisors/version (read-only; probe failure records
    # nothing). Re-read AFTER the restart phase to reconcile — the plan is the worklist.
    # Plan phase (#91277 Phase 2): snapshot the pre-update fleet — every running Hermes runtime, its
    # supervisor, and its running code version — into the receipt, so a post-mortem can compare what the
    # update SAW against what it did. ``_pre_update_plan`` is read again AFTER the restart phase to
    # reconcile every planned runtime against the phase's bookkeeping (restart via declared mechanism — the
    # plan is the worklist, not just a printout).
    _pre_update_plan = None
    with _best_effort('Update plan phase failed: %s'):
        from hermes_cli.update_inventory import collect_runtime_inventory, record_plan_in_receipt
        _pre_update_plan = collect_runtime_inventory()
        record_plan_in_receipt(_pre_update_plan)
        if _pre_update_plan.runtimes:
            _n = len(_pre_update_plan.runtimes)
            _profiles = ", ".join(sorted({r.profile for r in _pre_update_plan.runtimes}))
            print(f"→ Fleet: {_n} running service(s) across profiles: {_profiles}")

    # Windows: another hermes.exe holding the venv shim means WinError 32 spam and a
    # deferred-rename leftover or silent ZIP fallback. Positively identified gateways are
    # paused/restarted by the update instead; anything else still aborts.
    # Continuing would result in a string of WinError 32 warnings and then either a deferred-rename leftover
    # or a failed git-pull fast path that silently falls back to the slower ZIP route. See issue #26670.
    # Exception (#37039): when every concurrent instance is a gateway runtime, the pause machinery a few
    # lines below (``_pause_windows_gateways_for_update``) stops it before any file mutation, and the
    # post-update restart phase brings it back. Aborting just to make the user run the same kill manually is
    # friction without benefit. Anything not positively identified as a gateway (TUI shell, Desktop backend
    # child, unreadable cmdline) still aborts exactly as before.
    if _m()._is_windows() and not getattr(args, "force", False):
        scripts_dir = _m()._venv_scripts_dir()
        concurrent = _m()._detect_concurrent_hermes_instances(scripts_dir) if scripts_dir is not None else []
        non_gateway = _m()._filter_non_gateway_concurrent_instances(concurrent) if concurrent else []
        if non_gateway:
            print(_format_concurrent_instances_message(non_gateway, scripts_dir))
            sys.exit(2)
    return _pre_update_plan


def _prepare_git_command() -> tuple[bool, list, bool]:
    """Return ``(use_zip_update, git_cmd, is_fork)``; ``sys.exit(1)`` when not a git repo
    on a non-Windows host (Windows falls back to ZIP: broken git file I/O, AV, NTFS filters)."""
    git_dir = _m().PROJECT_ROOT / ".git"
    use_zip_update = not git_dir.exists()
    if use_zip_update and sys.platform != "win32":
        print("✗ Not a git repository. Please reinstall:")
        print("  curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash")
        sys.exit(1)

    git_cmd = _base_git_cmd()
    if sys.platform == "win32" and git_dir.exists():
        _git_run(git_cmd, ["config", "windows.appendAtomically", "false"])
    # A broken Git-for-Windows trampoline refuses every call with a "BUG (fork bomb)" guard;
    # swap in a real binary up front so git survives instead of degrading to ZIP.
    # See #87876.
    git_cmd = _ensure_non_trampoline_git(git_cmd)

    # Before stash/branch logic: npm rewrites package-lock.json non-deterministically and
    # line-ending churn is machine-made dirt; both would otherwise force an autostash every update.
    _discard_lockfile_churn(git_cmd, _m().PROJECT_ROOT)
    _normalize_managed_eol(git_cmd, _m().PROJECT_ROOT)

    origin_url = _m()._get_origin_url(git_cmd, _m().PROJECT_ROOT)
    is_fork = _is_fork(origin_url)

    if is_fork:
        print("⚠ Updating from fork:")
        print(f"  {origin_url}")
        print()
    return use_zip_update, git_cmd, is_fork


def _verify_head_after_pull(
    git_cmd, branch: str, pre_pull_sha, *, in_place_update: bool, _windows_gateway_resume
) -> str | None:
    """Return the post-pull HEAD SHA; ``sys.exit(1)`` if the pull was a no-op or landed off-branch."""
    # A detached checkout pinned to a SHA can report "N new commit(s)" and a successful
    # merge --ff-only yet stay put; surface the no-op instead of claiming "Code updated!".
    # Verify HEAD actually moved (issue #79678). ``merge --ff-only`` succeeding only means the merge
    # completed, not that the update applied: a checkout that is pinned to a raw SHA (detached HEAD) can
    # report "N new commit(s)" against origin yet still sit on the old commit afterward (the branch-switch
    # step re-detaches to the SHA). Before this guard, ``hermes update`` printed "✓ Code updated!" and
    # reinstalled deps + rebuilt the desktop app against the stale tree — no error, no warning, ``hermes
    # doctor`` healthy. Compare pre-pull and post-pull HEAD; if they match, surface the no-op instead of
    # claiming success.
    post_pull_sha = _capture_head_sha(git_cmd, _m().PROJECT_ROOT)
    if pre_pull_sha and post_pull_sha == pre_pull_sha:
        print()
        print("✗ Code did not move — update was a no-op.")
        print(
            f"  HEAD is pinned to {pre_pull_sha[:10]} (detached checkout); "
            f"origin/{branch} advanced but the working tree stayed put.")
        print(
            "  Reattach to the branch and retry: "
            f"git -C {_m().PROJECT_ROOT} checkout {branch} && hermes update")
        _m()._resume_windows_gateways_after_update(_windows_gateway_resume)
        sys.exit(1)

    # HEAD must be on the target or "Code updated!" is a lie; an IN-PLACE update is the one
    # legitimate exception (origin/<target> merged INTO the checked-out branch).
    post_pull_branch = _current_branch_name(git_cmd)
    if not in_place_update and post_pull_branch and post_pull_branch not in {branch, "HEAD"}:
        print()
        print(
            f"✗ Update pulled origin/{branch}, but the checkout is on "
            f"'{post_pull_branch}' — not claiming success.")
        print(
            "  Switch to the target branch and retry: "
            f"git -C {_m().PROJECT_ROOT} checkout {branch} && hermes update")
        _m()._resume_windows_gateways_after_update(_windows_gateway_resume)
        sys.exit(1)
    return post_pull_sha


def _current_branch_name(git_cmd, *, check: bool = False) -> str:
    """``rev-parse --abbrev-ref HEAD`` (literal "HEAD" when detached)."""
    return _git_run(git_cmd, ["rev-parse", "--abbrev-ref", "HEAD"], check=check).stdout.strip()


def _handle_update_called_process_error(
    e, args, gateway_mode: bool, had_desktop_app_before_update: bool) -> None:
    """Git/installer failure: ZIP-fallback when safe, else report and ``sys.exit(1)``."""
    stage = _format_update_failure_stage(e)
    if _should_zip_fallback_on_update_error(e):
        print(f"⚠ {stage}: {e}")
        print("→ Falling back to ZIP download...")
        print()
        desktop_build_ok = _update_via_zip(
            args, had_desktop_app_before_update=had_desktop_app_before_update)
        if gateway_mode:
            _write_gateway_update_exit_code(desktop_build_ok)
    else:
        print(f"✗ {stage}: {e}")
        _print_called_process_error_tail(e)
        if _called_process_error_is_python_dep_install(e):
            print(
                "  The git update already finished. Re-downloading the source "
                "ZIP cannot fix a dependency install error and would overwrite local files.")
            if _m()._is_windows():
                print("  Retry through the venv interpreter:")
                print(
                    '    venv\\Scripts\\python.exe -c '
                    '"from hermes_cli.main import main; main()" update --yes')
        _finalize_receipt("failed", 'Update receipt finalize failed: %s')
        sys.exit(1)


def _finalize_receipt(status: str, debug_message: str) -> None:
    """Best-effort ``finalize_update_receipt(status)``; the receipt must never break an update."""
    with _best_effort(debug_message):
        from hermes_cli.update_receipt import finalize_update_receipt
        finalize_update_receipt(status)


def _finish_already_up_to_date(
    git_cmd, branch: str, current_branch: str, _plan, *, assume_yes: bool, gateway_mode: bool,
    gw_input_fn, pre_update_snapshot_id, desktop_dir, had_desktop_app_before_update: bool,
    active_lazy_features, active_tool_dependencies, _windows_gateway_resume) -> None:
    """"Already up to date" path: restore stash/branch, repair the checkout, catch up the fleet.
    ``sys.exit(1)`` when the repair is incomplete (after gateway exit code + partial receipt)."""
    _invalidate_update_cache()

    # Restore stash and switch back if we moved. EXCEPTION: a parked branch verified clean +
    # fully merged stays on the target — re-parking on the stale branch recreates the incident.
    if _plan.auto_stash_ref is not None:
        _m()._restore_stashed_changes(
            git_cmd, _m().PROJECT_ROOT, _plan.auto_stash_ref, prompt_user=_plan.prompt_for_restore,
            input_fn=gw_input_fn)
    if _plan.parked_branch_switched:
        if _plan.switch_block_reason.startswith("unmerged:"):
            _count = _plan.switch_block_reason.split(":", 1)[1]
            print(
                f"  ✓ Checkout was parked on '{current_branch}' — switched back to {branch}; "
                f"{_count} unmerged commit(s) kept on '{current_branch}'.")
        else:
            print(f"  ✓ Checkout was parked on '{current_branch}' (fully merged) — switched back to {branch}.")
    elif current_branch not in {branch, "HEAD"}:
        _git_run(git_cmd, ["checkout", current_branch])

    current_checkout_complete = _repair_current_checkout(
        assume_yes=assume_yes, gateway_mode=gateway_mode,
        pre_update_snapshot_id=pre_update_snapshot_id, desktop_dir=desktop_dir,
        had_desktop_app_before_update=had_desktop_app_before_update,
        active_lazy_features=active_lazy_features,
        active_tool_dependencies=active_tool_dependencies, upstream_checked=_plan.upstream_checked,
        _windows_gateway_resume=_windows_gateway_resume)
    _m()._resume_windows_gateways_after_update(_windows_gateway_resume)
    if gateway_mode and not current_checkout_complete:
        _write_gateway_update_exit_code(False)
    # Finalize the receipt BEFORE the fleet-restart catch-up below: that restart calls
    # ``systemctl restart hermes-gateway``, and when this CLI process is itself a
    # descendant of that same gateway's cgroup (KillMode=mixed — e.g. a terminal spawned
    # from inside the running gateway), the restart's SIGTERM sweeps up this process too.
    # Finalizing first means a self-inflicted kill during the restart still leaves a real
    # receipt on disk instead of an orphaned .inflight.json and no closing record.
    _finalize_receipt(
        "success" if current_checkout_complete else "partial",
        'Update receipt finalize (current checkout) failed: %s')
    # A prior pull may still owe the fleet a restart; catch up here too, BEFORE the exit
    # gate so a partial outcome can't strand the fleet on stale code.
    # Catch up even on the "Already up to date" path — that early return is what left the gateway on stale
    # code for two days. Runs BEFORE the runtime-verification exit gate below: a vulnerable SQLite runtime
    # demotes the outcome to partial, but must not strand the fleet on stale code (#91277 fleet contract —
    # the pending-restart check always executes).
    _apply_pending_fleet_restart_catchup()
    if not current_checkout_complete:
        sys.exit(1)


def _apply_pulled_update(
    git_cmd, branch, pre_pull_sha, _plan, opts, *, gateway_mode, is_fork, desktop_dir,
    had_desktop_app_before_update, pre_update_snapshot_id, _pre_update_plan,
    _windows_gateway_resume) -> None:
    """Post-pull phase: verify HEAD, sync Python/Node/web/Desktop, maintenance, fleet restart."""
    _invalidate_update_cache()
    post_pull_sha = _verify_head_after_pull(
        git_cmd, branch, pre_pull_sha, in_place_update=_plan.in_place_update,
        _windows_gateway_resume=_windows_gateway_resume)

    # Gateways still serve pre-pull modules until the restart phase; an interrupt before a
    # completed restart leaves this marker so the next update catches up even when git is
    # current. Distinct from ``.update-incomplete`` (venv/install repair).
    # See #95294.
    _write_fleet_restart_pending_marker(expected_sha=post_pull_sha or "")
    # Stale .pyc would ImportError on gateway restart when new source references new names.
    _sweep_bytecode_after_update(branch)

    if is_fork and branch == "main":
        _m()._sync_with_upstream_if_needed(
            git_cmd, _m().PROJECT_ROOT, assume_yes=opts.assume_yes, input_fn=opts.gw_input_fn)

    # .[all], falling back to base + extras individually so one broken extra doesn't strip
    # the rest; the ownership preflight refuses first on foreign-owned (sudo-pip) venv files.
    _sync_python_dependencies_after_pull(
        git_cmd, branch, pre_pull_sha, active_lazy_features=opts.active_lazy_features,
        active_tool_dependencies=opts.active_tool_dependencies,
        _windows_gateway_resume=_windows_gateway_resume)

    node_failures = _update_node_dependencies()
    _m()._build_web_ui(_m().PROJECT_ROOT / "web")
    desktop_build_ok = _rebuild_desktop_after_update(
        desktop_dir, had_desktop_app_before_update=had_desktop_app_before_update)

    print()
    print(f"✓ Code updated!{_branch_head_suffix(git_cmd, _m().PROJECT_ROOT)}")

    update_complete = _run_post_update_maintenance(
        assume_yes=opts.assume_yes, gateway_mode=gateway_mode,
        pre_update_snapshot_id=pre_update_snapshot_id,
        had_desktop_app_before_update=had_desktop_app_before_update,
        node_failures=node_failures, desktop_build_ok=desktop_build_ok,
        pre_update_version=opts.pre_update_version)

    # Hard gate: a platform_toolsets entry referencing a nonexistent toolset, or a declared
    # dependency missing from the active environment, must block the fleet restart — not just
    # print a warning that scrolls past. The pre-pull rollback tag (_create_pre_reset_safety_tag,
    # taken before this checkout was touched) is left completely alone here: a preflight
    # failure means "do not restart onto this code", not "undo the pull". See the 2026-09-10
    # stale-toolset reconciliation postmortem this gate exists to prevent recurring.
    from hermes_cli.update_preflight_validation import run_update_preflight_gate
    _preflight = run_update_preflight_gate()
    if not _preflight.ok:
        print()
        print("✗ Update preflight failed — the gateway fleet will NOT be restarted.")
        if _preflight.toolset_warnings:
            print("  Stale/invalid platform_toolsets entries:")
            for w in _preflight.toolset_warnings:
                print(f"    • {w}")
        if _preflight.dependency_failures:
            print("  Missing or inconsistent Python dependencies:")
            for d in _preflight.dependency_failures:
                print(f"    • {d}")
        print(
            "  Code was pulled and is on disk, but the running gateway(s) were left "
            "on the PREVIOUS code — nothing was restarted, nothing was pushed. "
            "Fix the configuration/dependency issue above, then run `hermes update` "
            "again to retry the restart.")
        if gateway_mode:
            _write_gateway_update_exit_code(False)
        sys.exit(1)

    # Exit code *before* the restart: under --gateway this process lives in the gateway's
    # systemd cgroup and the systemctl-restart fallback SIGKILLs it (KillMode=mixed), so
    # the marker would never land and the new gateway's watcher would time out spuriously.
    if gateway_mode:
        _write_gateway_update_exit_code(update_complete)

    _restart = _restart_gateway_fleet_after_update(_pre_update_plan, gateway_mode)
    _resume_windows_gateways_and_merge_outcome(_restart, _windows_gateway_resume, gateway_mode)
    _verify_fleet_after_update(
        _restart, _pre_update_plan=_pre_update_plan, _windows_gateway_resume=_windows_gateway_resume,
        node_failures=node_failures, update_complete=update_complete)


def _cmd_update_impl(args, gateway_mode: bool):
    """Body of ``cmd_update`` — kept separate so the wrapper can always restore stdio even on
    ``sys.exit``. Self-lock deferral deliberately does NOT run here (pre-fetch it stranded users
    on the OLD checkout in an exit-2 loop); it runs right before the dependency sync."""
    opts = _resolve_update_options(args, gateway_mode)
    gw_input_fn, assume_yes = opts.gw_input_fn, opts.assume_yes

    print("⚕ Updating Hermes Agent...")
    print()

    _pre_update_plan = _begin_update_receipt_and_plan(args)

    # Backup before any git/file mutation; the snapshot id (None if disabled/failed) feeds
    # the post-update cron-jobs safety net.
    pre_update_snapshot_id = _m()._run_pre_update_backup(args)
    _record_update_step(
        "pre_update_backup", pre_update_snapshot_id is not None,
        f"snapshot={pre_update_snapshot_id}" if pre_update_snapshot_id else "disabled or failed")

    _windows_gateway_resume = _m()._pause_windows_gateways_for_update()
    if _windows_gateway_resume:
        import atexit as _atexit
        _atexit.register(_m()._resume_windows_gateways_after_update, _windows_gateway_resume)

    # Any venv python still running (typically the Desktop `hermes serve` backend) keeps .pyd
    # locked and would corrupt the sync; refuse rather than race (the app respawns a killed
    # backend). NOT bypassed by --force (desktop updater, shim guard only); --force-venv is.
    if _m()._is_windows() and not getattr(args, "force_venv", False):
        _clear_windows_venv_holders_or_exit(args, gateway_mode, _windows_gateway_resume)

    # After every fail-closed venv guard, before either path can remove the release tree.
    # Self-lock deferral moved: the venv-holder sweep above excludes this process by design (a CLI `hermes
    # update` IS the venv python), and an updater that has imported a native venv extension cannot rewrite
    # its own mapped .pyd (#83569). That check used to run HERE — before the fetch — but firing pre-fetch
    # meant a deferral stranded the user on the OLD checkout, and any startup path that eagerly loaded
    # cryptography turned every Windows update into an exit-2 loop (#86735/#86780/#86781). It now runs via
    # _abort_dependency_sync_if_self_locked() after the code swap, immediately before the dependency sync —
    # the only phase the lock can actually break — and only when the sync would truly rewrite the loaded
    # distribution.
    desktop_dir = _m().PROJECT_ROOT / "apps" / "desktop"
    had_desktop_app_before_update = _desktop_app_present(desktop_dir)

    use_zip_update, git_cmd, is_fork = _prepare_git_command()

    if use_zip_update:
        try:
            desktop_build_ok = _update_via_zip(
                args, had_desktop_app_before_update=had_desktop_app_before_update)
        finally:
            _m()._resume_windows_gateways_after_update(_windows_gateway_resume)
        if gateway_mode:
            _write_gateway_update_exit_code(desktop_build_ok)
        return

    try:
        # Scoped fetch: a bare `git fetch origin` pulls thousands of branches and can stall.
        branch = _m()._resolve_update_branch(args)

        # Self-heal abandoned .git/*.lock files (crashed fetch) or the fetch fails "File exists".
        from hermes_cli.gitlock import clear_stale_git_locks, clear_stale_tmp_packs
        cleared = clear_stale_git_locks(_m().PROJECT_ROOT)
        if cleared:
            print("  (removed stale git lock(s): %s)" % ", ".join(cleared))
        swept = clear_stale_tmp_packs(_m().PROJECT_ROOT)
        if swept:
            print("  (removed %d aborted-fetch pack temp file(s))" % len(swept))

        # Surface autostashes left by earlier updates (--keep-stash, failed restores).
        # Surface autostash entries left behind by earlier updates (#63717 problem 6) — parked --keep-stash
        # runs and failed restores preserve the stash but nothing ever mentioned it again.
        _m()._warn_orphaned_update_autostashes(git_cmd, _m().PROJECT_ROOT)

        print("→ Fetching updates...")
        fetch_result = _git_run(git_cmd, ["fetch", "origin", branch], network=True)
        if fetch_result.returncode != 0:
            _print_fetch_failure(fetch_result.stderr)
            sys.exit(1)

        current_branch = _current_branch_name(git_cmd, check=True)
        _plan = _prepare_checkout_for_update(
            git_cmd, branch, current_branch, is_fork=is_fork, assume_yes=assume_yes,
            gateway_mode=gateway_mode, gw_input_fn=gw_input_fn, switch_branch=opts.switch_branch,
            _windows_gateway_resume=_windows_gateway_resume)
        commit_count = _plan.commit_count

        if commit_count == 0:
            _finish_already_up_to_date(
                git_cmd, branch, current_branch, _plan, assume_yes=assume_yes,
                gateway_mode=gateway_mode, gw_input_fn=gw_input_fn,
                pre_update_snapshot_id=pre_update_snapshot_id, desktop_dir=desktop_dir,
                had_desktop_app_before_update=had_desktop_app_before_update,
                active_lazy_features=opts.active_lazy_features,
                active_tool_dependencies=opts.active_tool_dependencies,
                _windows_gateway_resume=_windows_gateway_resume)
            return

        if commit_count > 0:
            print(f"→ Found {commit_count} new commit(s)")
        else:
            # Shallow, exact count unrecoverable — but the tips differ, so there IS an update.
            print("→ Updates available (commit count unknown on this shallow checkout)")

        print("→ Pulling updates...")
        pre_pull_sha = _pull_updates(
            git_cmd, branch, _plan.auto_stash_ref, prompt_for_restore=_plan.prompt_for_restore,
            gw_input_fn=gw_input_fn, discard_local_changes=opts.discard_local_changes,
            keep_stash=opts.keep_stash)
        _apply_pulled_update(
            git_cmd, branch, pre_pull_sha, _plan, opts, gateway_mode=gateway_mode,
            is_fork=is_fork, desktop_dir=desktop_dir,
            had_desktop_app_before_update=had_desktop_app_before_update,
            pre_update_snapshot_id=pre_update_snapshot_id, _pre_update_plan=_pre_update_plan,
            _windows_gateway_resume=_windows_gateway_resume)
    except _shim_quarantine_error_type() as e:
        # Strict quarantine refused BEFORE any installer ran — defer via marker, exit 2, no ZIP.
        # See #87331.
        _refuse_update_for_contended_shims(e)
    except subprocess.CalledProcessError as e:
        _handle_update_called_process_error(e, args, gateway_mode, had_desktop_app_before_update)


# ---- BEGIN PLUGIN-COMPAT (revert-scheduled; see COMPAT_MANIFEST.md) ----
# Names external plugins imported from this module before the Sep 2026 decomposition.
# Internal code MUST NOT use these (scripts/check_compat_pointers.py fails CI if it does).
# The whole block is removed by reverting the commit that added it.
from typing import Optional  # noqa: F401,E402
from datetime import datetime  # noqa: F401,E402
import hashlib  # noqa: F401,E402
import json  # noqa: F401,E402
# ---- END PLUGIN-COMPAT ----
