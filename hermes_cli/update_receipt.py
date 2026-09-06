"""Structured update receipts + post-update fleet version verification.

Phase 1 of the fleet-update reliability plan (#91277): the updater must
*prove* its outcome instead of assuming it.

Two additive capabilities, both designed so a failure inside them can never
break an update (every public entry point is exception-swallowing):

1. **Update receipt** — a machine-readable JSON record of what one
   ``hermes update`` run discovered, did, skipped (and why), written to
   ``<HERMES_HOME>/logs/update_receipts/``. Silent-failure classes this
   makes visible: #88848 (helper died after "success" printed), #74973
   (restart silently skipped), #85753 (restart phase never ran), #81193
   (desktop shows failure for a successful update).

2. **Fleet version verification** — after the restart phase, read every
   profile's ``gateway_state.json``, compare each live gateway's stamped
   ``code_sha`` (written by ``gateway/status.py`` on every runtime-status
   write) against the freshly-updated checkout's HEAD, and print a fleet
   version matrix. Mixed-version fleets (#88654, #69754, #77553, #56717)
   become a loud, actionable report instead of a latent state.

Deployment-kind awareness (docker/image-managed installs) rides on
``hermes_cli.build_info.get_code_identity()``: an image build reports
``source="build-file"`` and the receipt records that the install is not
in-place updatable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import logging

logger = logging.getLogger(__name__)

_RECEIPT_DIR_NAME = "update_receipts"
_RECEIPT_KEEP = 20  # keep the last N receipts per profile home

# Module-level current receipt. ``hermes update`` is a single-threaded CLI
# command; a module singleton lets the 7k-line updater record steps from
# any depth without threading a handle through every helper.
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


class UpdateReceipt:
    """Collects the observable facts of one ``hermes update`` run."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {
            "schema": 1,
            "started_at": _utc_now_iso(),
            "finished_at": None,
            "argv": list(sys.argv),
            "pid": os.getpid(),
            "outcome": "running",  # running | success | partial | failed
            "pre_update": {},
            "post_update": {},
            "steps": [],
            "skips": [],
            "gateway_restart": {},
            "fleet": [],
        }
        try:
            from hermes_cli.build_info import get_code_identity

            self.data["pre_update"] = get_code_identity()
        except Exception:
            pass
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
        self.data["steps"].append(
            {"name": name, "ok": bool(ok), "detail": detail, "at": _utc_now_iso()}
        )

    def skip(self, name: str, reason: str) -> None:
        self.data["skips"].append(
            {"name": name, "reason": reason, "at": _utc_now_iso()}
        )

    def gateway_restart_result(
        self,
        *,
        restarted_services: list | None = None,
        relaunched_profiles: list | None = None,
        externally_supervised_profiles: list | None = None,
        killed_pids: list | None = None,
        failed_units: list | None = None,
        incomplete: bool = False,
        phase_error: str = "",
        fresh_recovery: dict[str, Any] | None = None,
    ) -> None:
        result: dict[str, Any] = {
            "restarted_services": list(restarted_services or []),
            "relaunched_profiles": list(relaunched_profiles or []),
            "externally_supervised_profiles": list(
                externally_supervised_profiles or []
            ),
            "killed_pids": [int(p) for p in (killed_pids or [])],
            "failed_units": [str(u) for u in (failed_units or [])],
            "incomplete": bool(incomplete),
            "phase_error": phase_error,
        }
        if fresh_recovery is not None:
            # Conservative outcome vocabulary: "verified" is the only bucket
            # allowed to claim supervisor coverage; "relaunch_attempted" means
            # the relaunch exited 0 without independent supervisor
            # observation. "skipped" preserves runtimes (manual gateways,
            # serve/dashboard entries) the pass deliberately did not touch.
            persisted: dict[str, Any] = {
                key: [str(profile) for profile in fresh_recovery.get(key, [])]
                for key in ("requested", "verified", "relaunch_attempted", "failed")
            }
            persisted["skipped"] = [
                {
                    "profile": str(entry.get("profile", "")),
                    "kind": str(entry.get("kind", "")),
                    "supervisor": str(entry.get("supervisor", "")),
                    "reason": str(entry.get("reason", "")),
                }
                for entry in fresh_recovery.get("skipped", [])
                if isinstance(entry, dict)
            ]
            result["fresh_recovery"] = persisted
        self.data["gateway_restart"] = result

    def finalize(self, outcome: str) -> None:
        self.data["outcome"] = outcome
        self.data["finished_at"] = _utc_now_iso()
        try:
            from hermes_cli.build_info import get_code_identity

            self.data["post_update"] = get_code_identity(refresh=True)
        except Exception:
            pass
        # Post-run divergence snapshot (see __init__): compared against
        # divergence_pre by format_update_integrity_line() to prove — not
        # assume — that no local-only commit vanished this run, and to
        # surface the fork-behind-upstream count hermes update itself
        # previously never printed (2026-09-06).
        self.data["divergence_post"] = _capture_divergence_snapshot()


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


def record_step(name: str, ok: bool, detail: str = "") -> None:
    """Record one update step outcome. No-op when no receipt is active."""
    try:
        if _current is not None:
            _current.step(name, ok, detail)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not record update step %s: %s", name, exc)


def record_skip(name: str, reason: str) -> None:
    """Record a skipped step WITH the reason it was skipped."""
    try:
        if _current is not None:
            _current.skip(name, reason)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not record update skip %s: %s", name, exc)


def record_gateway_restart(**kwargs: Any) -> None:
    """Record the gateway restart phase outcome (see UpdateReceipt)."""
    try:
        if _current is not None:
            _current.gateway_restart_result(**kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not record gateway restart result: %s", exc)


def finalize_update_receipt(
    outcome: str, fleet: list | None = None, stop_reason: str = ""
) -> Optional[Path]:
    """Finalize + persist the receipt. Returns the written path or None.

    ``outcome`` is one of ``success`` / ``partial`` / ``failed`` /
    ``refused``. Exactly-once by construction: the module singleton is
    popped first, so a second call (e.g. the command-boundary safety net
    after an inner path already finalized) is a no-op returning None.
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
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = directory / f"update_{stamp}_{os.getpid()}.json"
        path.write_text(
            json.dumps(receipt.data, indent=2, default=str), encoding="utf-8"
        )
        # Stable pointer for the dashboard/desktop: latest receipt.
        latest = directory / "latest.json"
        try:
            latest.write_text(
                json.dumps(receipt.data, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass
        _prune_old_receipts(directory)
        return path
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not write update receipt: %s", exc)
        return None


def finalize_pending_update_receipt(
    exit_code: Optional[int] = None, stop_reason: str = ""
) -> Optional[Path]:
    """Command-boundary safety net: persist a still-open receipt, if any.

    ``hermes update`` has many early-termination paths (Windows
    concurrent-instance preflight, venv-holder refusal, head-pinned no-op,
    fetch failure — all ``sys.exit``) that predate the inner finalize
    call sites. Any receipt still open when the update COMMAND unwinds is
    finalized here so every post-begin run leaves a record — the
    refused/failed runs are exactly the ones a receipt matters most for
    (review on #91283). No-op when no receipt is open (the inner paths
    already finalized — exactly-once via the popped singleton) or when
    recording was never started. Never raises.

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
    purge, not fabricating steps that didn't happen.
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
    if exit_code in (0, None):
        outcome = "success"
    elif exit_code == 2:
        outcome = "refused"
    else:
        outcome = "failed"
    try:
        receipt = _current
        if receipt is not None and exit_code is not None:
            receipt.data["exit_code"] = int(exit_code)
    except Exception:
        pass
    return finalize_update_receipt(outcome, stop_reason=stop_reason)


def _prune_old_receipts(directory: Path) -> None:
    try:
        receipts = sorted(
            (p for p in directory.glob("update_*.json") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for stale in receipts[_RECEIPT_KEEP:]:
            try:
                stale.unlink()
            except OSError:
                pass
    except Exception:
        pass


def read_latest_receipt() -> Optional[dict[str, Any]]:
    """Read the most recent update receipt, or None. Never raises."""
    try:
        path = _receipt_dir() / "latest.json"
        if not path.is_file():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Fleet version verification
# ---------------------------------------------------------------------------

def collect_fleet_versions(
    *, pre_restart_pids: Optional[list[int]] = None
) -> list[dict[str, Any]]:
    """Snapshot every profile's gateway code identity vs. the current tree.

    Returns one entry per profile home that has a ``gateway_state.json``
    describing a gateway that is live — or that SHOULD be live::

        {"profile": str, "pid": int, "code_sha": str|None,
         "code_version": str|None, "state": "current"|"stale"|"unknown"|"down"}

    ``stale``   — gateway stamped a code_sha that differs from the updated
                  checkout's HEAD (it is still serving pre-update modules).
    ``unknown`` — gateway predates the code-identity stamp (started before
                  this feature landed) or identity could not be resolved.
    ``down``    — the gateway was ALIVE when this update started
                  (``pre_restart_pids``), its runtime status still says
                  running, but the PID is dead and no successor rewrote the
                  record: the restart phase stopped it and nothing came
                  back. Without this row a killed-and-never-replaced gateway
                  produced NO entry at all and the matrix passed silently
                  (Phase-1 verification gap, #88848/#74973 class).

    Rollout safety: ``down`` requires membership in ``pre_restart_pids`` —
    a stale state file from a long-dead gateway (machine reboot, manual
    kill weeks ago) must NOT fail every future update. Callers that don't
    have a pre-restart snapshot (``None``/empty) get the historical
    behavior: dead PIDs are skipped.
    Never raises; a probe failure yields an empty list.
    """
    # Runtime-status states that mean "this record does not describe a
    # gateway that should be running now" — no down row for these.
    _NOT_EXPECTED_STATES = {"stopped", "startup_failed"}
    _pre_restart = {int(p) for p in (pre_restart_pids or []) if isinstance(p, int)}
    results: list[dict[str, Any]] = []
    try:
        from hermes_cli.build_info import get_code_identity

        expected_sha = (get_code_identity(refresh=True) or {}).get("sha")
    except Exception:
        expected_sha = None

    try:
        from gateway.status import read_runtime_status, runtime_status_pid_is_live
        from hermes_cli.profiles import (
            _get_default_hermes_home,
            _get_profiles_root,
            _PROFILE_ID_RE,
        )

        homes: list[tuple[str, Path]] = []
        default_home = _get_default_hermes_home()
        if default_home.is_dir():
            homes.append(("default", default_home))
        profiles_root = _get_profiles_root()
        if profiles_root.is_dir():
            for entry in sorted(profiles_root.iterdir()):
                if entry.is_dir() and entry.name != "default" and _PROFILE_ID_RE.match(entry.name):
                    homes.append((entry.name, entry))

        for profile, home in homes:
            # Prefer the gateway-owned control socket (#92091): a live
            # `identify` answer is authoritative — no PID-reuse or stale-file
            # heuristics. Fall back to gateway_state.json for gateways that
            # predate the socket or whose socket didn't bind.
            identity = None
            try:
                from gateway.control_socket import identify_gateway

                identity = identify_gateway(home)
            except Exception:
                identity = None
            if identity:
                try:
                    pid = int(identity.get("pid"))
                except (TypeError, ValueError):
                    pid = None
                if pid is not None:
                    code_sha = identity.get("code_sha")
                    if not code_sha or not expected_sha:
                        state = "unknown"
                    elif str(code_sha) == str(expected_sha):
                        state = "current"
                    else:
                        state = "stale"
                    results.append(
                        {
                            "profile": profile,
                            "pid": pid,
                            "code_sha": str(code_sha) if code_sha else None,
                            "code_version": identity.get("code_version"),
                            "state": state,
                            "source": "socket",
                        }
                    )
                    continue
            status_path = home / "gateway_state.json"
            record = read_runtime_status(status_path)
            if not record:
                continue
            pid = record.get("pid")
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                continue
            if not runtime_status_pid_is_live(record):
                # Dead PID (or a live PID recycled by an unrelated process
                # during the update's own churn — #93258): a DOWN row only
                # when this exact pid was alive at update start AND the
                # record still claims a running state — "the restart phase
                # stopped it and nothing came back." Everything else (clean
                # stop, startup failure, stale record from a long-dead
                # gateway) keeps the historical no-row behavior so the
                # feature's rollout can't false-positive.
                #
                # ``_pre_restart`` is a bare set of PIDs, not (pid, start_time)
                # pairs, so a recycled PID from gateway A landing in B's stale
                # record could still mislabel B as down if A's PID happened to
                # be in the pre-restart snapshot — inherent to the snapshot's
                # data model, not something this guard can fix on its own.
                gw_state = record.get("gateway_state")
                if (
                    pid in _pre_restart
                    and isinstance(gw_state, str)
                    and gw_state
                    and gw_state not in _NOT_EXPECTED_STATES
                ):
                    results.append(
                        {
                            "profile": profile,
                            "pid": pid,
                            "code_sha": None,
                            "code_version": record.get("code_version"),
                            "state": "down",
                        }
                    )
                continue
            code_sha = record.get("code_sha")
            if not code_sha or not expected_sha:
                state = "unknown"
            elif str(code_sha) == str(expected_sha):
                state = "current"
            else:
                state = "stale"
            results.append(
                {
                    "profile": profile,
                    "pid": pid,
                    "code_sha": str(code_sha) if code_sha else None,
                    "code_version": record.get("code_version"),
                    "state": state,
                }
            )
    except Exception as exc:
        logger.debug("Fleet version probe failed: %s", exc)
    return results


def print_fleet_version_matrix(fleet: list[dict[str, Any]]) -> bool:
    """Print the post-update fleet version matrix.

    Returns True when at least one gateway is provably stale (still
    serving pre-update code) OR provably down (was running, killed by the
    restart phase, nothing came back), so the caller can escalate.
    ``unknown`` entries are reported but do NOT fail the update: gateways
    started before the code-identity stamp existed have no sha to compare,
    and failing on them would turn this feature's own rollout into a
    false-positive storm.
    """
    if not fleet:
        return False
    any_stale = False
    any_down = False
    print()
    print("Fleet version check:")
    for entry in fleet:
        sha = entry.get("code_sha")
        short = sha[:8] if isinstance(sha, str) and sha else "?"
        state = entry.get("state")
        profile = entry.get("profile")
        pid = entry.get("pid")
        if state == "current":
            print(f"  ✓ {profile} (pid {pid}) @ {short} — up to date")
        elif state == "stale":
            any_stale = True
            print(f"  ✗ {profile} (pid {pid}) @ {short} — STALE (pre-update code)")
        elif state == "down":
            any_down = True
            print(
                f"  ✗ {profile} — DOWN (gateway was running before the "
                f"update; pid {pid} is gone and nothing replaced it)"
            )
        else:
            print(
                f"  ? {profile} (pid {pid}) — version unknown "
                "(gateway predates version stamping; restart to enable)"
            )
    if any_stale or any_down:
        print()
        if any_stale:
            print("  ⚠ Stale gateways keep serving pre-update code until restarted:")
        if any_down:
            print("  ⚠ Down gateways stopped serving messaging entirely — restart them:")
        print("      hermes gateway restart                # active profile")
        print("      hermes -p <profile> gateway restart   # named profile")
    return any_stale or any_down
