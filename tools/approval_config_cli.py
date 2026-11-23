"""Hermes config changes run from the agent's terminal: a one-operation human approval, every time.

``~/.hermes/config.yaml`` is the security policy (approvals.mode, yolo, the allowlist, curator
protections). The file tools refuse to write it and the terminal patterns gate sed/tee/cp/redirects
into it, but ``hermes config set`` reached the same file with no prompt at all. This gate closes that
door the way the protected-instruction-file gate closes its own: approval every time, no session or
permanent scope, not bypassed by --yolo, approvals.mode=off or the allowlist, refused outright in a
delegated subagent (whose approval callback may be an auto-approver) and fail-closed when no human can
answer. Like every approval pattern it is a heuristic (SECURITY.md §2.4), not a boundary: a script that
writes the file itself, ``execute_code`` and input typed into a background shell are not seen here.
"""
from __future__ import annotations

import hashlib
import os
import re

from tools.approval_detection import (
    _command_detection_variants, _deobfuscate_shell_word_for_detection, _iter_shell_command_word_spans,
    _lower_preserving_flags, _mask_quoted_prose, detect_dangerous_command,
)

# At most eight global flags (each with an optional value, quoted or not: `-p "work"`) before the subcommand: Hermes
# has a handful, and a bound
# keeps the scan linear on adversarial input, where an unbounded run from every `hermes` start point is quadratic.
_FLAGS = r'(?:-\S++(?:\s++(?:["\'][^"\'\n]*+["\']|(?!-\S)\S++))?\s++){0,8}'
_HERMES = r'\b(?:hermes(?:\.exe)?|hermes_cli(?:[./]main(?:\.py)?)?)\s+' + _FLAGS
# A verb or subcommand word that is quoted, partly quoted (`s"e"t`) or built at run time (`$(...)`, `${...}`,
# backticks) counts too: quote-masking blanks it, its value is unknown here, and an extra prompt is cheap.
# get/show/path/env-path/check only read and stay ungated.
_VERB = r'(?:(?:set|unset|edit|migrate)\b|[^\s"\']*["\'$`])'
_CONFIG_WORD = r'(?:config|[^\s"\']*["\'][^"\'\n]*["\']\S*)'
_POLICY_WRITE_RE = re.compile(
    _HERMES + r'(?:' + _CONFIG_WORD + r'\s+' + _VERB + r'|approvals\s+suggest\b[^;|&\n]{0,200}--apply\b)'
)
# A program in command position that runs a string as code (`eval`, a shell or interpreter reading -c or stdin, ssh,
# watch, find -exec, ...): quoted text in its command may execute, so the command is matched unmasked. Elsewhere quoted
# text is data (`git commit -m "...hermes config set..."`, `grep 'hermes config set' tools/*.py`) and is masked first.
_RUNNERS = frozenset((
    "eval", "source", ".", "bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd", "cmd.exe",
    "py", "perl", "ruby", "node", "deno", "bun", "php", "awk", "gawk", "mawk", "vim", "nvim", "ssh", "watch", "su",
    "runuser", "script", "parallel", "xargs", "env", "tmux", "screen", "flock", "at", "batch", "find",
    "docker", "podman", "kubectl", "nsenter", "chroot",
))
_PYTHON_RE = re.compile(r'python[\d.]*(?:\.exe)?')


def _runs_strings(variant: str) -> bool:
    for _, _, word in _iter_shell_command_word_spans(variant):
        name = os.path.basename(_deobfuscate_shell_word_for_detection(word)).lower()
        if name in _RUNNERS or _PYTHON_RE.fullmatch(name):
            return True
    return False


_DESCRIPTION = (
    "Change Hermes's own configuration (config.yaml holds the approval mode, allowlist and other security "
    "settings). Approval is required every time; it is not bypassed by auto-approve.")

_BLOCKED = (
    "BLOCKED: this Hermes config change {why} The user has NOT consented to it. Do NOT retry it or make the same "
    "change another way (editing config.yaml, a script, execute_code). Ask the user to approve it, or to run it "
    "themselves.")
_WHY = {
    "denied": "was denied by the user.",
    "timeout": "timed out without a user response. Silence is not consent.",
    "subagent": "cannot run in a delegated subagent: only the user, in the main conversation, can approve it.",
    None: "requires approval but no user can answer one here (no CLI prompt or gateway channel).",
}


def command_mutates_hermes_config(command: str) -> bool:
    """True when ``command`` runs a Hermes subcommand that writes config (``config set|unset|edit|migrate``,
    ``approvals suggest --apply``) in any spelling the detector sees."""
    for variant in _command_detection_variants(command):
        lowered = _lower_preserving_flags(variant)
        if _POLICY_WRITE_RE.search(_mask_quoted_prose(lowered)):
            return True
        if _POLICY_WRITE_RE.search(lowered) and _runs_strings(lowered):
            return True
    return False


def config_cli_gate(command: str) -> dict | None:
    """The guard result for a command that writes Hermes config: blocked, or approved by the human. ``None`` when it
    writes no config, or when it was approved but also matches a dangerous pattern (`hermes config set a b && rm -rf
    x`): that part meets its own gate, which the config prompt's wording did not ask about."""
    if not command_mutates_hermes_config(command):
        return None
    from agent.delegation_context import is_delegated_child_process_context
    if is_delegated_child_process_context():
        return _blocked("subagent")
    from agent.redact import redact_sensitive_text
    from tools.once_only_approval import request_once_only_approval
    # The card shows the command with secrets masked (`hermes config set OPENROUTER_API_KEY sk-...`); the key hashes the
    # raw command so two different commands never share a prompt.
    key = "hermes_config_cli:" + hashlib.sha256(command.encode("utf-8")).hexdigest()[:12]
    decision = request_once_only_approval(_DESCRIPTION, redact_sensitive_text(command, force=True), key)
    if not decision.get("approved"):
        return _blocked(decision.get("outcome"))
    if detect_dangerous_command(command)[0]:
        return None
    from tools.approval import _user_approved
    from tools.approval_context import get_current_session_key
    # A human saw this exact command, so a batch's prepared decision may be reused for it at execution.
    return _user_approved(get_current_session_key(), _DESCRIPTION)


def _blocked(outcome: str | None) -> dict:
    return {"approved": False, "description": _DESCRIPTION, "message": _BLOCKED.format(why=_WHY.get(outcome, _WHY[None]))}
