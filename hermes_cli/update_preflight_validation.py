"""Pre-restart gate for ``hermes update``: refuse to restart the fleet onto a checkout whose
``platform_toolsets`` config references a toolset that does not exist, or whose declared Python
dependencies are missing from the active environment (see the 2026-09-10 stale-toolset
reconciliation postmortem — a validator existed and warned, but nothing blocked the restart on
its findings, and a declared-but-uninstalled dependency was only caught by manually running the
test suite).

Both checks reuse the SAME machinery already used for `hermes tools`/config migration and
`hermes doctor` — this module adds no new detection logic, only a blocking gate around it.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
from dataclasses import dataclass, field
from typing import List


@dataclass
class UpdatePreflightResult:
    """Outcome of the pre-restart validation gate. ``ok`` is the sole authority the updater acts
    on; ``toolset_warnings``/``dependency_failures`` are for the printed report only."""

    ok: bool
    toolset_warnings: List[str] = field(default_factory=list)
    dependency_failures: List[str] = field(default_factory=list)


def check_platform_toolsets_before_restart() -> List[str]:
    """Re-run the same ``platform_toolsets`` validator ``hermes tools`` and config migration use,
    against the JUST-PULLED code's toolset registry. Returns the raw warning list (empty = clean).
    Never raises: an exception here must not be mistaken for zero stale references — callers
    treat an exception as a failed check, not a clean one (see ``run_update_preflight_gate``)."""
    from hermes_cli.config import read_raw_config
    from hermes_cli.toolset_scope import toolset_allowed_for_platform
    from hermes_cli.toolset_validation import validate_platform_toolsets
    from toolsets import validate_toolset

    return validate_platform_toolsets(
        read_raw_config().get("platform_toolsets"), validate_toolset, toolset_allowed_for_platform)


# Declared project dependencies that are worth confirming are actually importable before
# declaring the install healthy — the specific class of gap the 2026-09-10 reconciliation hit
# (snowballstemmer pinned in pyproject.toml, never installed in the active venv, surfaced only
# when a test file happened to import it). Import-name != PyPI-name for several of these, so the
# spec-check needs a distinct import target per dependency.
_CORE_DEPENDENCY_IMPORT_NAMES: dict = {
    "snowballstemmer": "snowballstemmer",
    "psutil": "psutil",
    "pyyaml": "yaml",
    "httpx": "httpx",
}


def check_core_dependencies_installed() -> List[str]:
    """Confirm each of ``_CORE_DEPENDENCY_IMPORT_NAMES`` actually imports in the active
    interpreter. Returns human-readable failure strings (empty = all present). Deliberately
    checks importability, not just an installed-distribution record — a partially-removed
    package can have metadata but no importable module."""
    failures: List[str] = []
    for dist_name, import_name in _CORE_DEPENDENCY_IMPORT_NAMES.items():
        try:
            spec = importlib.util.find_spec(import_name)
        except (ImportError, ValueError, ModuleNotFoundError):
            spec = None
        if spec is not None:
            continue
        try:
            declared_version = importlib.metadata.version(dist_name)
            failures.append(
                f"'{dist_name}' is declared installed (v{declared_version}) but "
                f"'{import_name}' does not import — the environment is inconsistent."
            )
        except importlib.metadata.PackageNotFoundError:
            failures.append(
                f"'{dist_name}' is not installed in the active environment "
                f"(import '{import_name}' failed)."
            )
    return failures


def run_update_preflight_gate() -> UpdatePreflightResult:
    """The single call site the updater invokes right before restarting the fleet. Failing
    closed on an unexpected exception in either check (never silently 'ok' on a broken probe)."""
    try:
        toolset_warnings = check_platform_toolsets_before_restart()
    except Exception as exc:  # noqa: BLE001 — fail closed, not a clean pass
        toolset_warnings = [f"platform_toolsets validation itself failed to run: {exc}"]

    try:
        dependency_failures = check_core_dependencies_installed()
    except Exception as exc:  # noqa: BLE001
        dependency_failures = [f"dependency validation itself failed to run: {exc}"]

    ok = not toolset_warnings and not dependency_failures
    return UpdatePreflightResult(
        ok=ok, toolset_warnings=toolset_warnings, dependency_failures=dependency_failures)
