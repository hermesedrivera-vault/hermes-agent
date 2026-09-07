"""Structured update receipts + post-update fleet version verification.

The updater must *prove* its outcome instead of assuming it. Every public entry point is
exception-swallowing so a failure inside receipts can never break an update.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_RECEIPT_KEEP = 20  # keep the last N receipts per profile home
COMMAND_BOUNDARY_STOP_REASON = "completed at command boundary"

# ``hermes update`` is a single-threaded CLI command; a module singleton lets the 7k-line updater
# record steps from any depth without threading a handle through every helper.
_current: Optional["UpdateReceipt"] = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capture_divergence_snapshot() -> dict[str, Any]:
    """Snapshot the two counts a fork-safety verification needs.

    Never raises; every field degrades to ``None`` (unverifiable) rather
    than a misleading 0/false. Reuses ``update_cmd``'s existing helpers
    (``_local_only_commits``, ``_count_commits_between``, ``_is_fork``,
    ``_has_upstream_remote``) instead of re-implementing git plumbing —
    single source of truth for what "local-only" and "behind upstream"
    mean, matching the STEP 70 reset-guard's own definitions exactly.

    Shape: ``{"is_fork": bool | None, "branch": str | None,
    "local_only_vs_origin": int | None, "fork_behind_upstream": int | None,
    "has_upstream_remote": bool | None}``. A ``None`` count means the
    check itself could not run (git failure, no upstream remote, detached
    HEAD) — callers MUST print that as "unverifiable", never as 0.
    """
    result: dict[str, Any] = {
        "is_fork": None,
        "branch": None,
        "local_only_vs_origin": None,
        "fork_behind_upstream": None,
        "has_upstream_remote": None,
    }
    try:
        from hermes_cli.main import PROJECT_ROOT
        from hermes_cli.update_cmd import (
            _count_commits_between,
            _get_origin_url,
            _has_upstream_remote,
            _is_fork,
            _local_only_commits,
        )

        git_cmd = ["git"]
        cwd = PROJECT_ROOT
        branch_result = subprocess.run(
            git_cmd + ["rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        branch = branch_result.stdout.strip()
        if branch and branch != "HEAD":  # HEAD means detached — no branch ref
            result["branch"] = branch

        origin_url = _get_origin_url(git_cmd, cwd)
        result["is_fork"] = _is_fork(origin_url) if origin_url else None

        if result["branch"]:
            commits, reason = _local_only_commits(
                git_cmd, cwd, result["branch"], f"origin/{result['branch']}"
            )
            result["local_only_vs_origin"] = len(commits) if commits is not None else None

        has_upstream = _has_upstream_remote(git_cmd, cwd)
        result["has_upstream_remote"] = has_upstream
        if has_upstream and result["is_fork"]:
            fetch = subprocess.run(
                git_cmd + ["fetch", "upstream", "main", "--quiet"],
                cwd=cwd, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            )
            if fetch.returncode == 0:
                behind = _count_commits_between(
                    git_cmd, cwd, "origin/main", "upstream/main"
                )
                result["fork_behind_upstream"] = behind if behind >= 0 else None
    except Exception as exc:  # pragma: no cover - defensive, never block update
        logger.debug("Divergence snapshot failed: %s", exc)
    return result


def format_update_integrity_line(receipt_data: dict[str, Any]) -> Optional[str]:
    """Build the one line ``hermes update`` prints proving fork safety.

    Reads ``divergence_pre``/``divergence_post`` off a finalized receipt's
    ``.data`` dict and renders a verdict the user can trust without
    needing to ask Hermes to go dig through git history by hand (2026-09-06:
    Ed's core complaint — the safety check existed but only Hermes checking
    manually surfaced it). Returns ``None`` when nothing was captured (very
    old receipt, non-git checkout) rather than fabricating a verdict.
    """
    pre = receipt_data.get("divergence_pre") or {}
    post = receipt_data.get("divergence_post") or {}
    if not pre and not post:
        return None

    lines = []
    local_pre = pre.get("local_only_vs_origin")
    local_post = post.get("local_only_vs_origin")
    if local_pre is None or local_post is None:
        lines.append("⚠ Local-commit safety: UNVERIFIABLE (git check failed — do not assume safe)")
    elif local_post < local_pre:
        lines.append(
            f"🔴 Local-commit safety: {local_pre - local_post} local-only "
            f"commit(s) DISAPPEARED this run ({local_pre} → {local_post}). "
            "Investigate immediately — this is the exact failure class that "
            "lost work before."
        )
    else:
        lines.append(
            f"✓ Local-commit safety: {local_post} commit(s) not on your fork "
            "yet, all still present — none discarded."
        )

    behind = post.get("fork_behind_upstream")
    if behind is None:
        behind = pre.get("fork_behind_upstream")
    if behind is not None:
        if behind > 0:
            plural = "commit" if behind == 1 else "commits"
            lines.append(
                f"⚠ Your fork is {behind} {plural} behind the official "
                "NousResearch/hermes-agent upstream — this update only "
                "synced with YOUR fork, not upstream. Run "
                "'git pull upstream main' to merge upstream fixes."
            )
        else:
            lines.append("✓ Fork is at parity with upstream — no missed updates.")

    return "\n".join(lines)


def _code_identity(refresh: bool = False) -> dict[str, Any]:
    """Running-code identity, or ``{}`` when the probe fails."""
    with suppress(Exception):
        from hermes_cli.build_info import get_code_identity

        return get_code_identity(refresh=refresh) or {}
    return {}


def _str_records(entries: Any, keys: tuple[str, ...], *, pid: bool = False) -> list[dict[str, Any]]:
    """Dict entries reduced to stringified ``keys`` (plus an int ``pid`` first when requested)."""
    records = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        record: dict[str, Any] = {"pid": int(entry.get("pid", 0) or 0)} if pid else {}
        record.update({key: str(entry.get(key, "")) for key in keys})
        records.append(record)
    return records


class UpdateReceipt:
    """Collects the observable facts of one ``hermes update`` run."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {
            "schema": 1, "started_at": _utc_now_iso(), "finished_at": None,
            "argv": list(sys.argv), "pid": os.getpid(),
            "outcome": "running",  # running | success | partial | failed
            "pre_update": _code_identity(), "post_update": {},
            "steps": [], "skips": [], "gateway_restart": {}, "fleet": [],
        }

        # Divergence snapshot (2026-09-06, Ed's fork-safety concern): the
        # STEP 70 guards correctly REFUSE a destructive reset that would
        # discard local-only commits, but nothing previously proved that
        # refusal to the user in hermes update's own output — only a
        # CLI-startup banner (format_fork_behind_upstream_line) that a
        # gateway/Telegram-driven session never sees. Capture BEFORE any
        # git mutation so finalize() can compare and the printed line is
        # never a guess about what "should" have happened.
        self.data["divergence_pre"] = _capture_divergence_snapshot()

    # -- recording ---------------------------------------------------------
    def step(self, name: str, ok: bool, detail: str = "") -> None:
        self.data["steps"].append({"name": name, "ok": bool(ok), "detail": detail, "at": _utc_now_iso()})

    def skip(self, name: str, reason: str) -> None:
        self.data["skips"].append({"name": name, "reason": reason, "at": _utc_now_iso()})

    def gateway_restart_result(
        self, *, restarted_services: list | None = None, relaunched_profiles: list | None = None,
        externally_supervised_profiles: list | None = None, killed_pids: list | None = None,
        failed_units: list | None = None, incomplete: bool = False, phase_error: str = "",
        fresh_recovery: dict[str, Any] | None = None,
    ) -> None:
        result: dict[str, Any] = {
            "restarted_services": list(restarted_services or []),
            "relaunched_profiles": list(relaunched_profiles or []),
            "externally_supervised_profiles": list(externally_supervised_profiles or []),
            "killed_pids": [int(p) for p in (killed_pids or [])],
            "failed_units": [str(u) for u in (failed_units or [])],
            "incomplete": bool(incomplete),
            "phase_error": phase_error,
        }
        if fresh_recovery is not None:
            # Conservative outcome vocabulary: "verified" is the only bucket allowed to claim
            # supervisor coverage; "relaunch_attempted" means the relaunch exited 0 without
            # independent supervisor observation. "skipped" preserves runtimes (manual gateways,
            # serve/dashboard entries) the pass deliberately did not touch.
            persisted: dict[str, Any] = {
                key: [str(profile) for profile in fresh_recovery.get(key, [])]
                for key in ("requested", "verified", "relaunch_attempted", "failed")
            }
            persisted["skipped"] = _str_records(
                fresh_recovery.get("skipped", []), ("profile", "kind", "supervisor", "reason")
            )
            # ``hermes serve`` hosts tui_gateway and is not a gateway profile, so neither the
            # per-profile buckets above nor the fleet-version matrix can describe it. Persist its
            # unit outcomes and any process that survived on the pre-update generation, or the
            # receipt keeps claiming a clean recovery the operator's box contradicts.
            serve_units = fresh_recovery.get("serve_units") or {}
            persisted["serve_units"] = {
                key: [str(unit) for unit in (serve_units.get(key) or [])] for key in ("verified", "failed")
            }
            persisted["stale_runtimes"] = _str_records(
                fresh_recovery.get("stale_runtimes", []), ("kind", "profile", "supervisor"), pid=True
            )
            result["fresh_recovery"] = persisted
        self.data["gateway_restart"] = result

    def finalize(self, outcome: str) -> None:
        self.data["outcome"] = outcome
        self.data["finished_at"] = _utc_now_iso()
        self.data["post_update"] = _code_identity(refresh=True)
        # Post-run divergence snapshot (see __init__): compared against
        # divergence_pre by format_update_integrity_line() to prove — not
        # assume — that no local-only commit vanished this run, and to
        # surface the fork-behind-upstream count hermes update itself
        # previously never printed (2026-09-06).
        self.data["divergence_post"] = _capture_divergence_snapshot()


_RECEIPT_DIR_NAME = "update_receipts"


def _receipt_dir() -> Path:
    from hermes_cli.config import get_hermes_home

    return get_hermes_home() / "logs" / _RECEIPT_DIR_NAME


def _inflight_snapshot_path() -> Path:
    """Sidecar file surviving a mid-run ``sys.modules`` purge.

    ``_current`` is a plain module-level global — ``_purge_stale_hermes_
    modules()`` (2026-08-20 fix, update_cmd.py) deliberately evicts every
    ``hermes_cli.*`` module mid-run so post-pull code reflects the fresh
    checkout. That import purge creates a BRAND NEW ``update_receipt``
    module object with its own fresh ``_current = None`` — silently
    orphaning whatever the pre-purge module had recorded, with no
    exception raised anywhere (confirmed 2026-09-06: ``_current is None``
    by the time ``finalize_pending_update_receipt`` runs on the
    ``_apply_pending_fleet_restart_catchup`` -> ``sys.exit(1)`` path,
    even though ``begin_update_receipt()`` definitely ran earlier in the
    same OS process). A module global cannot survive that; a file can.
    """
    from hermes_cli.config import get_hermes_home

    return get_hermes_home() / "logs" / _RECEIPT_DIR_NAME / ".inflight.json"


def _write_inflight_snapshot(divergence_pre: dict[str, Any]) -> None:
    """Best-effort persist of the one fact that must survive a purge."""
    try:
        path = _inflight_snapshot_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"pid": os.getpid(), "divergence_pre": divergence_pre},
                default=str,
            ),
            encoding="utf-8",
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not write in-flight snapshot: %s", exc)


def _read_and_clear_inflight_snapshot() -> Optional[dict[str, Any]]:
    """Read back this process's pre-purge divergence snapshot, then delete it.

    PID-scoped so a stale leftover from a crashed prior run (never
    cleaned up) is never mistaken for the current run's data. Always
    removes the file on the way out — one-shot, exactly like the
    in-memory singleton it's substituting for.
    """
    try:
        path = _inflight_snapshot_path()
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        path.unlink(missing_ok=True)
        if data.get("pid") != os.getpid():
            return None
        return data.get("divergence_pre")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not read in-flight snapshot: %s", exc)
        return None


def begin_update_receipt() -> None:
    """Start recording a new update receipt. Never raises."""
    global _current
    try:
        _current = UpdateReceipt()
        _write_inflight_snapshot(_current.data.get("divergence_pre") or {})
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not start update receipt: %s", exc)
        _current = None


def _record(method: str, what: str, *args: Any, **kwargs: Any) -> None:
    """Invoke ``method`` on the active receipt; no-op when none, never raises."""
    try:
        if _current is not None:
            getattr(_current, method)(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not record %s: %s", what, exc)


def record_step(name: str, ok: bool, detail: str = "") -> None:
    """Record one update step outcome. No-op when no receipt is active."""
    _record("step", f"update step {name}", name, ok, detail)


def record_skip(name: str, reason: str) -> None:
    """Record a skipped step WITH the reason it was skipped."""
    _record("skip", f"update skip {name}", name, reason)


def record_gateway_restart(**kwargs: Any) -> None:
    """Record the gateway restart phase outcome (see UpdateReceipt)."""
    _record("gateway_restart_result", "gateway restart result", **kwargs)


def finalize_update_receipt(outcome: str, fleet: list | None = None, stop_reason: str = "") -> Optional[Path]:
    """Finalize + persist the receipt (``success``/``partial``/``failed``/``refused``); path or None.

    Exactly-once by construction: the module singleton is popped first, so a second call (e.g. the
    command-boundary safety net after an inner path already finalized) is a no-op returning None.
    """
    global _current
    receipt = _current
    _current = None
    # Best-effort cleanup: the in-flight snapshot's job ends the moment a
    # receipt actually finalizes through the normal (non-purged) path —
    # leaving it behind risks a LATER unrelated run misreading a stale
    # snapshot if that run also hits the reconstruction path (PID reuse
    # is astronomically unlikely, but there's no reason to leave the file
    # sitting there once it's no longer needed).
    try:
        _inflight_snapshot_path().unlink(missing_ok=True)
    except Exception:
        pass
    if receipt is None:
        return None
    try:
        receipt.finalize(outcome)
        if stop_reason:
            receipt.data["stop_reason"] = stop_reason
        if fleet is not None:
            receipt.data["fleet"] = fleet
        directory = _receipt_dir()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"update_{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}.json"
        body = json.dumps(receipt.data, indent=2, default=str)
        path.write_text(body, encoding="utf-8")
        with suppress(OSError):  # stable pointer for the dashboard/desktop
            (directory / "latest.json").write_text(body, encoding="utf-8")
        _prune_old_receipts(directory)
        return path
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not write update receipt: %s", exc)
        return None


def finalize_pending_update_receipt(exit_code: Optional[int] = None, stop_reason: str = "") -> Optional[Path]:
    """Command-boundary safety net: persist a still-open receipt, if any. Never raises.

    ``hermes update`` has many early ``sys.exit`` paths (preflight refusals, venv-holder refusal,
    fetch failure) predating the inner finalize calls; finalizing here means refused/failed runs —
    where a receipt matters most — leave a record. Exit 0/None → ``success``, exit 2 → ``refused``
    (preflight convention), else → ``failed``.

    Outcome mapping: exit 0/None → ``success`` (a path that completed
    without an explicit inner finalize), exit 2 → ``refused`` (the
    updater's preflight-refusal convention), anything else → ``failed``.

    2026-09-06: ``_current`` can be ``None`` here not because no receipt
    was ever begun, but because ``_purge_stale_hermes_modules()`` (see
    ``_inflight_snapshot_path`` docstring) replaced this module with a
    fresh copy mid-run, orphaning the real singleton. When that's the
    case, the on-disk in-flight snapshot (written at ``begin_update_
    receipt()`` time, before any purge could touch it) lets us still
    write a real receipt for THIS run instead of silently reporting
    nothing — with an honest note that per-step detail was lost to the
    purge, not fabricating steps that didn't happen. No-op when no receipt
    is open (the inner paths already finalized — exactly-once via the
    popped singleton) or when recording was never started and no in-flight
    snapshot exists. See #91283.
    """
    global _current
    if _current is None:
        pre_snapshot = _read_and_clear_inflight_snapshot()
        if pre_snapshot is None:
            return None
        try:
            _current = UpdateReceipt.__new__(UpdateReceipt)
            _current.data = {
                "schema": 1,
                "started_at": _utc_now_iso(),
                "finished_at": None,
                "argv": list(sys.argv),
                "pid": os.getpid(),
                "outcome": "running",
                "pre_update": {},
                "post_update": {},
                "steps": [],
                "skips": [],
                "gateway_restart": {},
                "fleet": [],
                "divergence_pre": pre_snapshot,
                "reconstructed_after_module_purge": True,
                "reconstruction_note": (
                    "The original receipt's step/skip history was lost when "
                    "_purge_stale_hermes_modules() replaced this module "
                    "mid-run. Only the pre-run divergence snapshot (written "
                    "to disk before the purge could touch it) and a fresh "
                    "post-run snapshot survive. This is not a fabricated "
                    "receipt — every field present is real; fields this run "
                    "cannot know are simply absent."
                ),
            }
        except Exception as exc:
            logger.debug("Could not reconstruct receipt after purge: %s", exc)
            return None
    outcome = "success" if exit_code in (0, None) else "refused" if exit_code == 2 else "failed"
    if exit_code is not None:
        with suppress(Exception):
            _current.data["exit_code"] = int(exit_code)
    return finalize_update_receipt(outcome, stop_reason=stop_reason)


def _prune_old_receipts(directory: Path) -> None:
    with suppress(Exception):
        receipts = (p for p in directory.glob("update_*.json") if p.is_file())
        for stale in sorted(receipts, key=lambda p: p.stat().st_mtime, reverse=True)[_RECEIPT_KEEP:]:
            with suppress(OSError):
                stale.unlink()


def read_latest_receipt() -> Optional[dict[str, Any]]:
    """Read the most recent update receipt, or None. Never raises."""
    with suppress(Exception):
        path = _receipt_dir() / "latest.json"
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else None
    return None


def _profile_homes() -> list[tuple[str, Path]]:
    """``(profile, home)`` for the default home plus every valid named profile dir, sorted."""
    from hermes_cli.profiles import _get_default_hermes_home, _get_profiles_root, _PROFILE_ID_RE

    homes: list[tuple[str, Path]] = []
    default_home = _get_default_hermes_home()
    if default_home.is_dir():
        homes.append(("default", default_home))
    root = _get_profiles_root()
    if root.is_dir():
        homes.extend(
            (entry.name, entry)
            for entry in sorted(root.iterdir())
            if entry.is_dir() and entry.name != "default" and _PROFILE_ID_RE.match(entry.name)
        )
    return homes


def _socket_identity(home: Path) -> Optional[tuple[int, dict]]:
    """``(pid, identity)`` declared by the gateway owning ``home``'s control socket, else None.

    A live ``identify`` answer is authoritative — no PID-reuse or stale-file heuristics. Callers
    fall back to ``gateway_state.json`` for gateways that predate the socket or whose socket
    didn't bind.
    """
    try:
        # Prefer the gateway-owned control socket (#92091): identity declared by the process itself,
        # including its own supervisor provenance — no argv/PID inference. Scan fallback below.
        # Prefer the gateway-owned control socket (#92091): a live `identify` answer is authoritative — no
        # PID-reuse or stale-file heuristics.
        from gateway.control_socket import identify_gateway

        identity = identify_gateway(home)
        return (int(identity.get("pid")), identity) if identity else None
    except Exception:  # probe failure, no gateway, or an unparseable pid
        return None


def _fleet_row(
    profile: str, pid: int, code_sha: Any, code_version: Any, expected_sha: Any, state: str = "unknown"
) -> dict[str, Any]:
    if state == "unknown" and code_sha and expected_sha:
        state = "current" if str(code_sha) == str(expected_sha) else "stale"
    return {
        "profile": profile, "pid": pid, "code_sha": str(code_sha) if code_sha else None,
        "code_version": code_version, "state": state,
    }


# Runtime-status states that do not describe a gateway that should be running now — no down row.
_NOT_EXPECTED_STATES = {"stopped", "startup_failed"}


def collect_fleet_versions(*, pre_restart_pids: Optional[list[int]] = None) -> list[dict[str, Any]]:
    """Snapshot every profile's gateway code identity vs. the current tree.

    Rollout safety: ``down`` requires membership in ``pre_restart_pids`` — a stale state file from a
    long-dead gateway (machine reboot, manual kill weeks ago) must NOT fail every future update.
    Without a pre-restart snapshot (``None``/empty) dead PIDs are skipped (historical behavior).

    ``stale``   — gateway stamped a code_sha that differs from the updated checkout's HEAD (it is still
    serving pre-update modules). ``unknown`` — gateway predates the code-identity stamp (started before this
    feature landed) or identity could not be resolved. ``down``    — the gateway was ALIVE when this update
    started (``pre_restart_pids``), its runtime status still says running, but the PID is dead and no
    successor rewrote the record: the restart phase stopped it and nothing came back. Without this row a
    killed-and-never-replaced gateway produced NO entry at all and the matrix passed silently (Phase-1
    verification gap, #88848/#74973 class).
    """
    _pre_restart = {int(p) for p in (pre_restart_pids or []) if isinstance(p, int)}
    results: list[dict[str, Any]] = []
    expected_sha = _code_identity(refresh=True).get("sha")
    try:
        from gateway.status import read_runtime_status, runtime_status_pid_is_live

        for profile, home in _profile_homes():
            sock = _socket_identity(home)
            if sock is not None:
                pid, identity = sock
                row = _fleet_row(profile, pid, identity.get("code_sha"), identity.get("code_version"), expected_sha)
                results.append({**row, "source": "socket"})
                continue
            record = read_runtime_status(home / "gateway_state.json")
            if not record:
                continue
            try:
                pid = int(record.get("pid"))
            except (TypeError, ValueError):
                continue
            if runtime_status_pid_is_live(record):
                results.append(
                    _fleet_row(profile, pid, record.get("code_sha"), record.get("code_version"), expected_sha)
                )
                continue
            # Dead PID (or a live PID recycled by an unrelated process during the update's own
            # churn): a DOWN row only when this exact pid was alive at update start AND the record
            # still claims a running state — "the restart phase stopped it and nothing came back."
            # Everything else (clean stop, startup failure, long-dead stale record) keeps the no-row
            # behavior so the rollout can't false-positive. ``_pre_restart`` is a bare PID set, not
            # (pid, start_time) pairs, so a recycled PID from gateway A landing in B's stale record
            # could still mislabel B as down — inherent to the snapshot's data model.
            # See #93258.
            gw_state = record.get("gateway_state")
            if pid in _pre_restart and isinstance(gw_state, str) and gw_state and gw_state not in _NOT_EXPECTED_STATES:
                results.append(_fleet_row(profile, pid, None, record.get("code_version"), None, state="down"))
    except Exception as exc:
        logger.debug("Fleet version probe failed: %s", exc)
    return results


_FLEET_ROW_LINES = {
    "current": "  ✓ {profile} (pid {pid}) @ {short} — up to date",
    "stale": "  ✗ {profile} (pid {pid}) @ {short} — STALE (pre-update code)",
    "down": "  ✗ {profile} — DOWN (gateway was running before the update; pid {pid} is gone and nothing replaced it)",
}
_FLEET_ROW_UNKNOWN = "  ? {profile} (pid {pid}) — version unknown (gateway predates version stamping; restart to enable)"


def print_fleet_version_matrix(fleet: list[dict[str, Any]]) -> bool:
    """Print the post-update fleet version matrix.

    Returns True when at least one gateway is provably stale (still serving pre-update code) OR
    provably down (killed by the restart phase, nothing came back), so the caller can escalate.
    ``unknown`` entries are reported but do NOT fail the update: gateways started before the
    code-identity stamp existed have no sha to compare, and failing them would be a false-positive
    storm.
    """
    if not fleet:
        return False
    print()
    print("Fleet version check:")
    states = set()
    for entry in fleet:
        sha = entry.get("code_sha")
        states.add(entry.get("state"))
        print(_FLEET_ROW_LINES.get(entry.get("state"), _FLEET_ROW_UNKNOWN).format(
            profile=entry.get("profile"), pid=entry.get("pid"), short=sha[:8] if isinstance(sha, str) and sha else "?",
        ))
    any_stale, any_down = "stale" in states, "down" in states
    if any_stale or any_down:
        print()
        if any_stale:
            print("  ⚠ Stale gateways keep serving pre-update code until restarted:")
        if any_down:
            print("  ⚠ Down gateways stopped serving messaging entirely — restart them:")
        print("      hermes gateway restart                # active profile")
        print("      hermes -p <profile> gateway restart   # named profile")
    return any_stale or any_down
