"""Hermes config changes run from the agent's terminal: a one-operation human approval, every time.

``~/.hermes/config.yaml`` is the security policy (approvals.mode, yolo, the allowlist, curator
protections). The file tools refuse to write it and the terminal patterns gate sed/tee/cp/redirects
into it, but ``hermes config set`` reached the same file with no prompt at all. This gate closes that
door the way the protected-instruction-file gate closes its own: approval every time, no session or
permanent scope, not bypassed by --yolo, approvals.mode=off or the allowlist, and fail-closed when no
human can answer. Like every approval pattern it is a heuristic (SECURITY.md §2.4), not a boundary:
a script that writes the file itself is not detected here.
"""
from __future__ import annotations

import hashlib
import re

from tools.approval_detection import _GLOBAL_FLAGS, _command_detection_variants, _lower_preserving_flags

# `hermes [global flags] config <mutating verb>` and the module spelling `python -m hermes_cli[.main] config ...`.
# A quoted verb counts, and so does a verb the shell builds at run time (`$(...)`, `${...}`, backticks): its value
# is unknown here, and an extra prompt is cheap. get/show/path/env-path/check only read and stay ungated.
_CONFIG_MUTATION_RE = re.compile(
    r'\b(?:hermes|hermes_cli(?:\.main)?)\s+' + _GLOBAL_FLAGS
    + r'config\s+(?:["\']?(?:set|unset|edit|migrate)\b|["\']?[$`])',
    re.IGNORECASE,
)

_DESCRIPTION = (
    "Change Hermes's own configuration (config.yaml holds the approval mode, allowlist and other security "
    "settings). Approval is required every time; it is not bypassed by auto-approve.")

_BLOCKED = (
    "BLOCKED: a Hermes config change ({command}) {why} The user has NOT consented to this change. Do NOT retry "
    "it or make the same change another way (editing config.yaml, a script, execute_code). Ask the user to "
    "approve it, or to run it themselves.")
_WHY = {
    "denied": "was denied by the user.",
    "timeout": "approval prompt timed out without a user response. Silence is not consent.",
    None: "requires approval but no user can answer one here (no CLI prompt or gateway channel).",
}


def command_mutates_hermes_config(command: str) -> bool:
    """True when ``command`` runs a config-mutating ``hermes config`` subcommand in any spelling the detector sees."""
    return any(_CONFIG_MUTATION_RE.search(_lower_preserving_flags(v)) for v in _command_detection_variants(command))


def config_cli_gate(command: str) -> dict | None:
    """``None`` when ``command`` is not a config change or the user approved this one; else the block result."""
    if not command_mutates_hermes_config(command):
        return None
    from tools.once_only_approval import request_once_only_approval
    key = "hermes_config_cli:" + hashlib.sha256(command.encode("utf-8")).hexdigest()[:12]
    decision = request_once_only_approval(_DESCRIPTION, command, key)
    if decision.get("approved"):
        return None
    return {
        "approved": False,
        "description": _DESCRIPTION,
        "message": _BLOCKED.format(command=command[:200], why=_WHY.get(decision.get("outcome"), _WHY[None])),
    }
