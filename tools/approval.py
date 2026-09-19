"""Dangerous command approval -- the gate flow and per-session state.

Owns the session state (approvals, yolo, gateway queues, denial breaker), the three guard
entry points (``check_all_command_guards``, ``check_execute_code_guard``,
``request_tool_approval`` / ``_run_approval_gate``) and the shared human-decision engine
behind them. Leaves: ``approval_detection`` (hardline/dangerous patterns), ``approval_context``
(contextvars, config readers), ``approval_floors`` (pre-gate blocks, allowlist match),
``approval_prompt`` (CLI prompt, plugin transports, MCP elicitation), ``approval_gateway_wait``
(blocking gateway round-trip), ``approval_smart`` (guardian LLM), ``approval_human_wait``.
Leaves read facade-owned state (``_lock``, queues, denial breaker) back through ``tools.approval`` at
call time; sibling-defined names are imported from their defining module.
"""

from dataclasses import dataclass
import hashlib
import importlib
import logging
import os
import re
import threading
from typing import Optional

from utils import env_var_enabled, is_truthy_value
from tools import approval_context
from tools.approval_context import (
    _get_approval_mode, _get_session_platform, _is_cron_approval_context,
    _is_gateway_approval_context, _is_interactive_cli, _is_single_query_approval_context,
    _is_unattended_platform_approval_context, _resolve_cli_approval_callback, _should_fall_through_to_cli_approval,
    _tirith_fail_open, get_current_session_key,
    get_current_authorization_key, set_current_authorization_scope, reset_current_authorization_scope,
)
from tools.approval_detection import (
    _approval_key_aliases, _check_sudo_stdin_guard, detect_dangerous_command, detect_hardline_command,
)
from tools.approval_floors import (
    _command_matches_permanent_allowlist, _hardline_block_result, _match_user_deny_rule, _sudo_stdin_block_result,
    _user_deny_block_result,
)
from tools.approval_gateway_wait import _await_gateway_decision
from tools.approval_prompt import _present_with_selected_transport, _transport_choice, prompt_dangerous_approval
from tools.approval_smart import _smart_verdict

logger = logging.getLogger(__name__)

# Frozen at import: reading os.environ per call would let any skill running in the process set
# this and bypass every approval check (prompt-injection escalation path).
_YOLO_MODE_FROZEN: bool = is_truthy_value(os.getenv("HERMES_YOLO_MODE", ""))


# --- Per-session approval state (thread-safe) -----------------------------------------------------------------------

_lock = threading.Lock()
_pending: dict[str, dict] = {}
_session_approved: dict[str, set] = {}
_session_yolo: set[str] = set()
_permanent_approved: set = set()
# Routed multiplex profiles: one permanent allowlist per profile home (see ``_permanent_set``).
_permanent_approved_by_home: dict[str, set] = {}

# --- Consecutive-denial circuit breaker for smart approvals ---------------------------------------------------------
# Each retry of a smart-denied command burns another guardian LLM call. After ``approvals.denial_breaker_threshold``
# consecutive guardian DENY verdicts in one session (default 3; 0 disables) the deny message escalates to a hard-stop
# instruction; any approval resets the tally. Only TOOL RESULT text changes — no history surgery, no interrupts — so
# it is prompt-cache-invariant. Capped so short-lived session keys cannot grow it without bound; oldest (least
# recently denied) entries are evicted.
_denial_tally: dict[str, int] = {}
_DENIAL_TALLY_MAX_SESSIONS = 256


def _get_denial_breaker_threshold() -> int:
    """``approvals.denial_breaker_threshold``: default 3; 0 or negative disables."""
    try:
        return int(approval_context._get_approval_config().get("denial_breaker_threshold", 3))
    except (ValueError, TypeError):
        return 3


def _record_denial(session_key: str) -> int:
    """Increment and return the session's consecutive guardian-denial count. Pop-and-reinsert
    keeps actively-denying sessions at the most-recent end so eviction drops idle keys."""
    with _lock:
        count = _denial_tally.pop(session_key, 0) + 1
        _denial_tally[session_key] = count
        while len(_denial_tally) > _DENIAL_TALLY_MAX_SESSIONS:
            _denial_tally.pop(next(iter(_denial_tally)))
        return count


def _reset_denials(session_key: str) -> None:
    """Clear the session's consecutive-denial tally (an approval happened)."""
    with _lock:
        _denial_tally.pop(session_key, None)


def _denial_breaker_addendum(session_key: str) -> str:
    """Escalated hard-stop text once the breaker has tripped, else ''. Read-only: callers
    increment via :func:`_record_denial`; the text is appended verbatim to the deny message."""
    with _lock:
        count = _denial_tally.get(session_key, 0)
    threshold = _get_denial_breaker_threshold()
    if threshold <= 0 or count < threshold:
        return ""
    # WARNING (was DEBUG): a failed/blocked guardian call is a real event the operator needs to see — the
    # whole point of #82846 is that the hang was invisible. Log the elapsed time and error class too.
    logger.warning(
        "Smart-approval circuit breaker tripped for session %s: %d consecutive denials (threshold %d)",
        session_key, count, threshold,
    )
    return (
        f" CIRCUIT BREAKER: {count} consecutive commands were blocked by "
        "the security reviewer. STOP attempting variations of this "
        "operation. Report the blocked operation to the user and either ask them to run it manually or use /approve."
    )

# --- Gateway approval queue (the blocking wait loop lives in approval_gateway_wait) ---------------------------------


# Optional free-text reason supplied with an explicit deny (``/deny <reason>``) so the agent can adapt
# instead of only hearing "denied". Ported from qwibitai/nanoclaw#2832.
_gateway_queues: dict[str, list] = {}        # session_key → [_ApprovalEntry, …]
_gateway_notify_cbs: dict[str, object] = {}  # session_key → callable(approval_data)


def register_gateway_notify(session_key: str, cb) -> None:
    """Register ``cb(approval_data: dict) -> None`` for sending approval requests. The callback
    bridges sync→async: it runs in the agent thread and must schedule the send on the loop."""
    with _lock:
        _gateway_notify_cbs[session_key] = cb


def unregister_gateway_notify(session_key: str) -> None:
    """Unregister the callback and wake ALL blocked threads for this session so
    they don't hang forever (agent run finished or interrupted)."""
    with _lock:
        _gateway_notify_cbs.pop(session_key, None)
        entries = _gateway_queues.pop(session_key, [])
    for entry in entries:
        entry.event.set()


def resolve_gateway_approval(session_key: str, choice: str,
                             resolve_all: bool = False,
                             reason: Optional[str] = None,
                             request_id: Optional[str] = None) -> int:
    """Unblock waiting agent thread(s) from the gateway's /approve or /deny handler.

    *resolve_all* resolves every pending approval (``/approve all``); otherwise the oldest
    (FIFO) or the one matching *request_id*. *reason* is the ``/deny <reason>`` free text,
    relayed to the agent in the BLOCKED message. Returns the number resolved.
    """
    with _lock:
        queue = _gateway_queues.get(session_key)
        if not queue:
            return 0
        if request_id:
            targets = [entry for entry in queue if entry.data.get("request_id") == request_id]
            if not targets:
                return 0
            queue[:] = [entry for entry in queue if entry not in targets]
        elif resolve_all:
            targets = list(queue)
            queue.clear()
        else:
            targets = [queue.pop(0)]
        if not queue:
            _gateway_queues.pop(session_key, None)

    for entry in targets:
        entry.result = choice
        if reason:
            entry.reason = reason
        entry.event.set()
    return len(targets)


def list_gateway_approvals(session_key: str) -> list[dict]:
    """Return replay-safe snapshots of unresolved approvals for one session."""
    with _lock:
        return [dict(entry.data) for entry in _gateway_queues.get(session_key, [])]


def register_gateway_settle(session_key: str, request_id: str, settle) -> bool:
    """Attach ``settle(reason)`` to one pending approval; it runs once when that wait ends by any path.
    False when the request is no longer pending (the surface should withdraw its prompt itself)."""
    with _lock:
        for entry in _gateway_queues.get(session_key, []):
            if entry.data.get("request_id") == request_id:
                entry.settle = settle
                return True
    return False


def ack_gateway_approval(session_key: str, request_id: str) -> bool:
    """Record that a client received a particular pending approval request."""
    with _lock:
        for entry in _gateway_queues.get(session_key, []):
            if entry.data.get("request_id") == request_id:
                entry.acknowledged = True
                return True
    return False


def has_blocking_approval(session_key: str) -> bool:
    """Check if a session has one or more blocking gateway approvals waiting."""
    with _lock:
        return bool(_gateway_queues.get(session_key))


def get_pending_gateway_approval(session_key: str) -> dict | None:
    """Copy of the oldest unresolved gateway approval, for reconnecting clients
    to restore a prompt. Read-only snapshot — the queue stays authoritative."""
    if not session_key:
        return None
    with _lock:
        queue = _gateway_queues.get(session_key)
        if not queue:
            return None
        return dict(queue[0].data)


def submit_pending(session_key: str, approval: dict):
    """Store a pending approval request for a session."""
    with _lock:
        _pending[session_key] = approval


def approve_session(session_key: str, pattern_key: str):
    """Approve a pattern for this session only."""
    with _lock:
        _session_approved.setdefault(session_key, set()).add(pattern_key)


def _release_permission_mode_dependents(session_key: str) -> None:
    """Drop resources whose immutable mode derives from Hermes YOLO. Lazy import so approval-only
    sessions never load computer-use; releasing on BOTH edges makes enabling YOLO replace a
    standard backend and disabling it revoke a private unrestricted daemon immediately."""
    try:
        from tools.computer_use.tool import release_computer_use_session

        release_computer_use_session(session_key)
    except Exception:
        logger.debug("Failed to release permission-mode dependent resources for %s", session_key, exc_info=True)


def _set_session_yolo(session_key: str, enabled: bool) -> None:
    if not session_key:
        return
    with _lock:
        (_session_yolo.add if enabled else _session_yolo.discard)(session_key)
    _release_permission_mode_dependents(session_key)


def enable_session_yolo(session_key: str) -> None:
    """Enable YOLO bypass for a single session key."""
    _set_session_yolo(session_key, True)


def disable_session_yolo(session_key: str) -> None:
    """Disable YOLO bypass for a single session key."""
    _set_session_yolo(session_key, False)


def clear_session(session_key: str) -> None:
    """Remove all approval and yolo state for a given session."""
    if not session_key:
        return
    with _lock:
        _session_approved.pop(session_key, None)
        _session_yolo.discard(session_key)
        _pending.pop(session_key, None)
        entries = _gateway_queues.pop(session_key, [])
    for entry in entries:
        # Cancel blocked waits now so the old run unwinds instead of idling until timeout.
        entry.result = "deny"
        entry.event.set()
    _release_permission_mode_dependents(session_key)
    # Session-persistent code kernels (local and remote) share this owner key and die at the same boundary so a
    # finished conversation cannot leak a live interpreter.
    for module, shutdown in (("tools.code_kernel", "shutdown_kernels_for_owner"),
                             ("tools.code_kernel_remote", "shutdown_remote_kernels_for_owner")):
        try:
            getattr(importlib.import_module(module), shutdown)(session_key)
        except Exception:
            pass


def is_session_yolo_enabled(session_key: str) -> bool:
    """Return True when YOLO bypass is enabled for a specific session."""
    if not session_key:
        return False
    with _lock:
        return session_key in _session_yolo


def is_current_session_yolo_enabled() -> bool:
    """Return True when the active approval session has YOLO bypass enabled."""
    return is_session_yolo_enabled(get_current_session_key(default=""))


def _yolo_active() -> bool:
    """CLI ``--yolo`` (process-scoped, frozen at import) or gateway ``/yolo``
    (session-scoped). Hardline / deny-rule floors run BEFORE this everywhere."""
    return _YOLO_MODE_FROZEN or is_current_session_yolo_enabled()


def _audit_yolo_bypass(check_site: str) -> None:
    """Log an observable event when YOLO (frozen process-scoped or human-enabled
    session-scoped) specifically caused an approval bypass -- not when only
    ``approvals.mode: off`` did, which is a separate, config-driven bypass with
    no YOLO involvement. Callers pass the checking function's name as
    ``check_site`` so the event says which guard was bypassed.

    Never logs command/code contents, secrets, or environment values -- category,
    check site, and session identity only. Failure here must never affect the
    approval decision: every exception is swallowed so a logging problem can
    never turn an approved command into an unhandled error.
    """
    try:
        session_id = approval_context._approval_session_id.get() or get_current_session_key(default="") or "<none>"
        logger.warning("approval.yolo_bypass: session=%s check=%s", session_id, check_site)
    except Exception:  # noqa: BLE001 - audit emission must never break execution
        pass


def _permanent_set() -> set:
    """The permanent allowlist that governs the ACTIVE profile. Unscoped (single-profile process,
    or the multiplexer's own launch profile) → the module-level set tests and the CLI seed. A routed
    profile (HERMES_HOME override) → its own set, lazily loaded from ITS ``command_allowlist``: the
    launch profile's "always" approvals must not pre-approve commands for a secondary, nor may a
    secondary's "always" choice be written back into the launch profile's config. Callers hold ``_lock``.
    """
    from hermes_constants import get_hermes_home_override, hermes_home_key
    if get_hermes_home_override() is None:
        return _permanent_approved
    home_key = hermes_home_key()
    approved = _permanent_approved_by_home.get(home_key)
    if approved is None:
        try:
            approved = _read_permanent_allowlist()
        except Exception as e:
            logger.warning("Failed to load permanent allowlist: %s", e)
            approved = set()
        _permanent_approved_by_home[home_key] = approved
    return approved


def is_approved(session_key: str, pattern_key: str) -> bool:
    """Session-scoped or permanent approval. Accepts the canonical key and the legacy
    regex-derived key so existing command_allowlist entries survive key migrations."""
    aliases = _approval_key_aliases(pattern_key)
    with _lock:
        approved = _permanent_set() | _session_approved.get(session_key, set())
    return any(alias in approved for alias in aliases)


def approve_permanent(pattern_key: str):
    """Add a pattern to the permanent allowlist."""
    with _lock:
        _permanent_set().add(pattern_key)


def load_permanent(patterns: set):
    """Bulk-load permanent allowlist entries from config."""
    with _lock:
        governing = _permanent_set()
        governing.clear()
        governing.update(patterns)


def _persist_choice(session_key: str, choice: str, warnings: list[tuple]) -> None:
    """Persist a human ``session``/``always`` choice for each ``(key, _, is_tirith)``. Tirith
    findings are session-max by design (no broad permanent allowlisting of content-level
    findings), so ``always`` downgrades them to session. ``once`` persists nothing."""
    for key, _, is_tirith in warnings:
        if choice not in ("session", "always"):
            continue
        approve_session(session_key, key)
        if choice == "always" and not is_tirith:
            approve_permanent(key)
            with _lock:
                snapshot = set(_permanent_set())
            save_permanent_allowlist(snapshot)


# --- Config persistence for permanent allowlist ---------------------------------------------------------------------

def _read_permanent_allowlist() -> set:
    """``command_allowlist`` of the active profile's config as a set (empty on malformed input)."""
    from hermes_cli.config import load_config_readonly
    config = load_config_readonly()
    raw = config.get("command_allowlist")
    legacy = isinstance(raw, str)
    if legacy:
        # Old config-set versions serialized list values as scalar strings.
        import yaml
        try:
            raw = yaml.safe_load(raw)
        except yaml.YAMLError:
            raw = False
    if raw is None and not legacy:
        raw = []
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        logger.warning("Ignoring malformed command_allowlist; configure a list of strings.")
        return set()
    if legacy:
        logger.warning("Recovered legacy string command_allowlist; re-save it as a list of strings.")
    return set(raw)


# What ``command_allowlist`` held the last time this process synchronised with the
# file, per profile home ("" = the unscoped launch profile). Everything in the
# governing permanent set beyond it is an approval THIS process made, and is the
# only thing a save is entitled to add: the difference separates "the operator
# granted this here" from "this was on disk when we started, and may since have
# been revoked".
_permanent_baseline_by_home: dict[str, set] = {}


def _baseline_key() -> str:
    from hermes_constants import get_hermes_home_override, hermes_home_key
    return "" if get_hermes_home_override() is None else hermes_home_key()


def load_permanent_allowlist() -> set:
    """Load ``command_allowlist`` from config and sync it into the approval state
    so is_approved() honors 'always' choices from previous sessions."""
    try:
        patterns = _read_permanent_allowlist()
        load_permanent(patterns)
        with _lock:
            _permanent_baseline_by_home[_baseline_key()] = set(patterns)
        return patterns
    except Exception as e:
        logger.warning("Failed to load permanent allowlist: %s", e)
        return set()


def save_permanent_allowlist(patterns: set):
    """Save permanently allowed command patterns to config, reconciling with the file.

    ``command_allowlist`` is a file an operator edits by hand; removing an entry
    there is the documented way to withdraw a standing approval. This process read
    it once at import and ``load_permanent`` only ever unions, so writing the
    in-memory set straight back deleted entries added on disk since import and
    resurrected the ones removed. The result written is ``what is on disk now``
    plus ``what this process approved since its own baseline``; revoked entries are
    also dropped from the governing permanent set so ``is_approved()`` stops
    honouring them. Nothing re-reads the file on the approval hot path.

    ``patterns`` may only ADD: an entry left out of it is not removed, because the
    on-disk list wins for anything this process did not approve itself. Remove
    entries by editing ``command_allowlist`` in config.yaml.
    """
    try:
        from hermes_cli.config import load_config, save_config
        config = load_config()
        on_disk = set(config.get("command_allowlist", []) or [])
        with _lock:
            key = _baseline_key()
            baseline = _permanent_baseline_by_home.get(key, set())
            merged = on_disk | (set(patterns) - baseline)
            config["command_allowlist"] = sorted(merged)
            save_config(config)
            _permanent_baseline_by_home[key] = set(merged)
            governing = _permanent_set()
            governing.clear()
            governing.update(merged)
    except Exception as e:
        logger.warning("Could not save allowlist: %s", e)


# --- Bypass check (yolo / mode=off) ---------------------------------------------------------------------------------

def is_approval_bypass_active_for_session(session_key: str) -> bool:
    """Canonical three-source bypass check: process ``--yolo`` (frozen at import), the
    session-scoped gateway ``/yolo`` toggle, ``approvals.mode: off``. Pure bypass
    sub-expression only — hardline blocklist / permanent allowlist are the caller's job."""
    return (_YOLO_MODE_FROZEN or is_session_yolo_enabled(session_key) or _get_approval_mode() == "off")


def is_approval_bypass_active() -> bool:
    """Return whether the current approval context has bypass enabled."""
    return is_approval_bypass_active_for_session(get_current_session_key(default=""))


# --- Result builders shared by the gates ----------------------------------------------------------------------------

def _approved() -> dict:
    return {"approved": True, "message": None}


def _denied(message: str, *, pattern_key: str, description: str, outcome: str, **extra) -> dict:
    """Standard non-consent result: the agent must not retry or rephrase."""
    return {"approved": False, "message": message, "pattern_key": pattern_key,
            "description": description, "outcome": outcome, "user_consent": False, **extra}


def _blocked(message: str, *, pattern_key: str, description: str) -> dict:
    """Non-interactive block (cron / -q / unattended / no-human): no consent keys."""
    return {"approved": False, "message": message, "pattern_key": pattern_key, "description": description}


def _user_approved(session_key: str, description: str) -> dict:
    """A human approval (incl. ESCALATE-then-approve or a smart-DENY owner
    override) resets the consecutive-denial tally."""
    _reset_denials(session_key)
    return {"approved": True, "message": None, "user_approved": True, "description": description}


def _gateway_notify_cb(session_key: str):
    with _lock:
        return _gateway_notify_cbs.get(session_key)


def _pending_result(spec, session_key: str, *, command: str, description: str,
                    pattern_key: str, pattern_keys: list[str], body: str | None,
                    smart_denied: bool) -> dict:
    """Queue an approval nobody can answer right now (no gateway notifier, no CLI panel) for
    ``/approve`` / ``/deny`` review. Command/code gates return the backward-compatible
    ``pending_approval`` shape (``pattern_keys`` + STOP text); the action gate ``approval_required``."""
    pending = {"command": command, "pattern_key": pattern_key}
    if spec.pending_keys:
        pending["pattern_keys"] = pattern_keys
    pending["description"] = description
    if smart_denied:
        pending.update(smart_denied=True, allow_permanent=False)
    submit_pending(session_key, pending)
    if not spec.pending_keys:
        return {
            "approved": False, "pattern_key": pattern_key, "status": "approval_required",
            "command": command, "description": description,
            "message": (f"⚠️ This action is potentially dangerous ({description}). "
                        f"Asking the user for approval.\n\n**Target:**\n```\n{command}\n```"),
        }
    body = body or f"**Command:**\n```\n{command}\n```"
    result = {
        "approved": False, "pattern_key": pattern_key, "status": "pending_approval",
        "approval_pending": True, "command": command, "description": description,
        "message": (
            f"⚠️ {description}. Asking the user for approval.\n\n{body}\n\n"
            f"STOP: do NOT re-run, rephrase, or re-issue this {spec.noun} — each "
            "variant sends the user ANOTHER approval card. Wait for the "
            "user's decision; if this turn must end, report that approval is pending."
        ),
    }
    if smart_denied:
        result.update(smart_denied=True, allow_permanent=False)
    return result


# --- Unattended contexts (nobody present to answer a prompt) --------------------------------------------------------

@dataclass(frozen=True)
class _Unattended:
    """One non-interactive context and the text every gate uses to explain it."""
    name: str       # "single_query" | "cron" | "unattended"
    cfg_key: str    # approvals.<cfg_key>: approve|deny
    clause: str     # "why nobody can approve" (lower-case sentence fragment)
    scope: str      # "in cron jobs" — completes "To allow ... {scope}"
    trust: str      # execute_code: "approve only if {trust}"

    def mode(self) -> str:
        # Looked up on the defining module at call time so tests patching the getters keep working.
        return getattr(approval_context, f"_get_{self.name}_approval_mode")()

    def block_message(self, subject: str, *, noun: str, advice: str) -> str:
        return (f"BLOCKED: {subject} but {self.clause}. {advice} To allow {noun} {self.scope}, set "
                f"approvals.{self.cfg_key}: approve in config.yaml.")

    @property
    def exec_tail(self) -> str:
        return (f"{self.clause[0].upper()}{self.clause[1:]}. Use normal tools "
                f"instead, or set approvals.{self.cfg_key}: approve only if {self.trust}.")


_SINGLE_QUERY_CTX = _Unattended(
    "single_query", "single_query_mode",
    "single-query mode (-q) runs without a user present to approve it",
    "in single-query mode", "this single-query run is intentionally trusted",
)
_CRON_CTX = _Unattended(
    "cron", "cron_mode", "cron jobs run without a user present to approve it",
    "in cron jobs", "this cron profile is intentionally trusted",
)


def _unattended_contexts() -> list[_Unattended]:
    """Active unattended contexts in evaluation order: single-query first (``hermes chat -q``
    exports HERMES_INTERACTIVE=1 but nobody answers); cron beats a platform marker because
    cron binds the platform for delivery routing only."""
    contexts = []
    if _is_single_query_approval_context():
        contexts.append(_SINGLE_QUERY_CTX)
    if _is_cron_approval_context():
        contexts.append(_CRON_CTX)
    elif _is_unattended_platform_approval_context():
        contexts.append(_Unattended(
            "unattended", "unattended_mode",
            "this session runs on an unattended platform "
            f"({_get_session_platform()}) with no user present to approve it",
            "on unattended platforms", "sessions on this surface are intentionally trusted",
        ))
    return contexts


def _unattended_deny(command: str, ctx: _Unattended) -> dict | None:
    """Deny-mode handling for one unattended context (cron / -q / webhook); None = allow.

    Pattern detection first, then tirith so content-level threats (homograph URLs,
    pipe-to-interpreter, terminal injection) are caught even when the pattern detector misses.
    An un-importable tirith honours ``security.tirith_fail_open``: fail-closed means block,
    since nobody can approve.
    """
    if ctx.mode() != "deny":
        return None

    def block(subject: str) -> dict:
        return {"approved": False, "message": ctx.block_message(
            subject, noun="dangerous commands",
            advice="Find an alternative approach that avoids this command.")}

    is_dangerous, _pk, description = detect_dangerous_command(command)
    if is_dangerous:
        result = block(f"Command flagged as dangerous ({description})")
        if ctx.name == "single_query":
            result.update(pattern_key=_pk, description=description)
        return result
    try:
        from tools.tirith_security import check_command_security
        tirith = check_command_security(command)
    except ImportError:
        if _tirith_fail_open():
            return None
        return {"approved": False, "message": (
            "BLOCKED: the Tirith security scanner could not be imported and security.tirith_fail_open is false, "
            f"so this command cannot be silently allowed — and {ctx.clause}. "
            f"Find an alternative approach, install tirith, or set approvals.{ctx.cfg_key}: approve in config.yaml.")}
    if tirith.get("action") in ("block", "warn"):
        return block(_format_tirith_description(tirith))
    return None


# --- Human-decision engine shared by the three gates ----------------------------------------------------------------
# Every flagged action reaches a human the same way — selected plugin transport → gateway round-trip → pending
# fallback → CLI prompt → persist — so the consent contract (silence is not consent, deny is a hard halt, a smart-DENY
# override is one operation) cannot drift between gates. Only wording and a few policy knobs differ per flavor; they
# live in _GateSpec.

@dataclass(frozen=True)
class _GateSpec:
    noun: str                 # "command" | "code" — for the pending STOP text
    transport: bool           # offer the selected plugin transport first
    user_approved: bool       # human approval resets the denial tally
    redact_cli: bool          # CLI prompt + hooks see the redacted copy
    pending_keys: bool        # pending fallback: redacted ``pending_approval`` shape with
                              # pattern_keys (True) vs raw ``approval_required`` (False)
    # Message templates. ``{breaker}`` = the denial circuit-breaker addendum,
    # read only where a template shows it (reading it logs when tripped).
    notify_failed: str
    gateway_refused: str      # {reason}{reason_addendum}{timeout_addendum}{breaker}
    transport_denied: str     # {breaker}
    cli_timeout: str          # {breaker}
    cli_denied: str           # {description}{breaker}
    smart_log: str            # {command}{description}{session_key}


_STOP_COMMAND = (
    " The user has NOT consented to this action. Do NOT retry this command, do "
    "NOT rephrase it, and do NOT attempt the same outcome via a different "
    "command. Stop the current workflow and wait for the user to respond before "
    "taking any further destructive or irreversible action."
)
_STOP_ACTION = (
    " The user has NOT consented to this action. Do NOT retry it, do NOT "
    "rephrase it, and do NOT attempt the same outcome via a different path."
)

_COMMAND_GATE = _GateSpec(
    noun="command", transport=True, user_approved=True, redact_cli=False, pending_keys=True,
    notify_failed="BLOCKED: Failed to send approval request to user. Do NOT retry.",
    gateway_refused="BLOCKED: Command {reason}.{reason_addendum}" + _STOP_COMMAND
                    + "{timeout_addendum}{breaker}",
    transport_denied=(
        "BLOCKED: User denied this command through the selected approval "
        "transport. The user has NOT consented to this action. Do NOT retry or "
        "attempt the same outcome through another route.{breaker}"
    ),
    cli_timeout="BLOCKED: Command timed out without user response." + _STOP_COMMAND
                + " Silence is not consent.{breaker}",
    cli_denied="BLOCKED: User denied this command." + _STOP_COMMAND + "{breaker}",
    smart_log="Smart approval: auto-approved '{command}' ({description})",
)
_EXECUTE_CODE_GATE = _GateSpec(
    noun="code", transport=True, user_approved=True, redact_cli=True, pending_keys=True,
    notify_failed="BLOCKED: Failed to send execute_code approval request to user. Do NOT retry.",
    gateway_refused=(
        "BLOCKED: execute_code script {reason}.{reason_addendum} The user has "
        "NOT consented to running this code. Do NOT retry, do NOT rephrase the "
        "script, and do NOT attempt the same outcome via a different tool.{timeout_addendum}{breaker}"
    ),
    transport_denied=(
        "BLOCKED: User denied execute_code through the selected approval transport. The user has NOT consented."
    ),
    cli_timeout="BLOCKED: Action timed out without user response." + _STOP_ACTION
                + " Silence is not consent.{breaker}",
    cli_denied=(
        "BLOCKED: User denied execute_code script execution (matched "
        "'{description}'). Do NOT retry — the user has explicitly rejected it.{breaker}"
    ),
    smart_log="Smart approval: auto-approved execute_code for session {session_key}",
)
# Plugin-escalated tool calls / protected writes: no transport, no breaker,
# no user_approved marker (parity with the historical gate).
_ACTION_GATE = _GateSpec(
    noun="action", transport=False, user_approved=False, redact_cli=False, pending_keys=False,
    notify_failed="BLOCKED: Failed to send approval request to user. Do NOT retry.",
    gateway_refused="BLOCKED: Action {reason}.{reason_addendum}" + _STOP_ACTION
                    + "{timeout_addendum}",
    transport_denied="",
    cli_timeout="BLOCKED: Action timed out without user response." + _STOP_ACTION
                + " Silence is not consent.",
    cli_denied=(
        "BLOCKED: User denied this potentially dangerous action (matched "
        "'{description}'). Do NOT retry — the user has explicitly rejected it."
    ),
    smart_log="",
)


def _smart_gate(spec: _GateSpec, command: str, description: str, pattern_key: str,
                pattern_keys: list[str], session_key: str, *,
                human_present: bool) -> tuple[dict | None, bool]:
    """Guardian-LLM step -> ``(result, smart_denied_for_owner)``: a result ends the gate;
    ``smart_denied_for_owner`` means an interactive owner may still override the DENY for this
    one operation (once/deny only, nothing persists).

    APPROVE approves this command only — pattern-level persistence would let one benign
    command suppress review of later commands in the same broad detector category. A DENY
    counts toward the denial breaker even when an owner may override it. ESCALATE follows the
    normal, potentially persistent manual behavior.
    """
    verdict = _smart_verdict(command, description, pattern_key, pattern_keys, session_key)
    if verdict == "approve":
        _reset_denials(session_key)
        logger.debug(spec.smart_log.format(command=command[:60], description=description, session_key=session_key))
        return {"approved": True, "message": None, "smart_approved": True, "description": description}, False
    if verdict != "deny":
        return None, False
    _record_denial(session_key)
    if human_present:
        return None, True
    return {
        # Unattended programmatic platforms (webhook/msgraph_webhook/ api_server): respect unattended_mode
        # config. Resolves instantly — never a pending approval nobody can answer (#37284, #87509).
        "approved": False,
        "message": (f"BLOCKED by smart approval: {description}. The command was assessed as genuinely "
                    f"dangerous. Do NOT retry.{_denial_breaker_addendum(session_key)}"),
        "smart_denied": True,
    }, True


def _human_decision(spec: _GateSpec, *, command: str, description: str,
                    pattern_key: str, pattern_keys: list[str], warnings: list[tuple],
                    session_key: str, approval_callback, is_cli: bool, is_gateway: bool,
                    is_ask: bool, smart: bool = False,
                    permanent_capable: bool = True, pending_body=None) -> dict:
    """Ask a human (after the optional guardian-LLM step) and turn the answer into the gate result.

    ``warnings`` are the ``(key, _, is_tirith)`` tuples :func:`_persist_choice` stores on
    session/always. ``permanent_capable`` hides [a]lways when no key could be permanently
    allowlisted (pure-tirith prompts); a smart-DENY owner override reduces every surface to
    once/deny and persists nothing. ``pending_body`` is a thunk, built only once a human is
    actually asked, so a smart APPROVE never pays for redacting a large script.
    """
    from agent.redact import redact_sensitive_text

    smart_denied = False
    if smart:
        result, smart_denied = _smart_gate(spec, command, description, pattern_key, pattern_keys,
                                           session_key, human_present=is_cli or is_gateway or is_ask)
        if result is not None:
            return result
    pending_body = pending_body() if pending_body else None
    allow_permanent = permanent_capable and not smart_denied

    def deny(template: str, outcome: str, **fmt) -> dict:
        breaker = ""
        if "{breaker}" in template:
            breaker = _denial_breaker_addendum(session_key)
        deny_reason = fmt.pop("deny_reason", None)
        extra = {"deny_reason": deny_reason} if "reason" in fmt else {}
        return _denied(template.format(description=description, breaker=breaker, **fmt),
                       pattern_key=pattern_key, description=description,
                       outcome=outcome, **extra)

    def grant(choice: str) -> dict:
        # A smart-DENY owner override is always one operation, even if an older client returns "session" or "always".
        # A stale/malfunctioning UI or adapter returning "always" when allow_permanent is False (e.g. outbound
        # external comms, which are session-scoped at maximum per the Step 27/31 requirement) must be defensively
        # downgraded here -- never calls approve_permanent()/save_permanent_allowlist() for this category.
        effective_choice = "session" if (choice == "always" and not allow_permanent) else choice
        if not smart_denied:
            _persist_choice(session_key, effective_choice, warnings)
        if spec.user_approved:
            return _user_approved(session_key, description)
        return _approved()

    if spec.transport:
        attempt = _present_with_selected_transport(
            command=command, description=description, pattern_key=pattern_key, pattern_keys=pattern_keys,
            session_key=session_key, surface="gateway" if (is_gateway or is_ask) else "cli",
            allow_session=not smart_denied, allow_permanent=allow_permanent,
        )
        choice, denied = _transport_choice(attempt, pattern_key=pattern_key, description=description)
        if denied is not None:
            return denied
        if choice is not None:
            if choice == "deny":
                _record_denial(session_key)
                return deny(spec.transport_denied, "denied")
            return grant(choice)

    # Gateway/async approval: block the agent thread until /approve or /deny, mirroring the CLI's synchronous input()
    # flow. The agent never sees "approval_required" here — it gets output or a definitive BLOCKED.
    if is_gateway or is_ask:
        # Redacted copies for user-visible rendering only (the gateway paints them into Discord/Slack); the raw
        # command still executes after approval and persistence keys off pattern_key.
        display_command = redact_sensitive_text(command)
        display_description = redact_sensitive_text(description)
        notify_cb = _gateway_notify_cb(session_key)
        if notify_cb is not None:
            # Smart DENY overrides are one-operation decisions, so the UI must not offer a
            # permanent scope. Session approval is safe for every non-Smart-DENY prompt —
            # including pure-tirith ones, where persistence already caps scope at session.
            data = {
                "command": display_command, "pattern_key": pattern_key,
                "pattern_keys": pattern_keys, "description": display_description,
                "allow_permanent": permanent_capable and not smart_denied,
                "allow_session": not smart_denied,
            }
            if smart_denied:
                data["smart_denied"] = True
            decision = _await_gateway_decision(session_key, notify_cb, data, surface="gateway")
            if decision.get("notify_failed"):
                return _denied(spec.notify_failed, pattern_key=pattern_key,
                               description=description, outcome="notify_failed")
            # Consent contract: silence is NOT consent, and an explicit deny is a hard
            # halt — both produce a BLOCKED outcome. ``/deny <reason>`` free text is
            # relayed verbatim so the agent can adapt rather than only hearing "denied".
            choice, deny_reason = decision["choice"], decision.get("reason")
            if not decision["resolved"]:
                return deny(spec.gateway_refused, "timeout", reason="timed out without user response",
                            reason_addendum="", timeout_addendum=" Silence is not consent.",
                            deny_reason=deny_reason)
            if choice is None or choice == "deny":
                return deny(spec.gateway_refused, "denied", reason="denied by user",
                            reason_addendum=(f' Reason given by the user: "{deny_reason}".' if deny_reason else ""),
                            timeout_addendum="", deny_reason=deny_reason)
            return grant(choice)

        # No gateway callback (cron, batch, or ask-mode leaked into an interactive CLI, historically via `import
        # gateway.run`): paint the local panel when possible instead of a pending_approval that makes the agent look
        # "auto-blocked".
        if not _should_fall_through_to_cli_approval(
            is_cli=is_cli, approval_callback=approval_callback, notify_cb=notify_cb,
        ):
            if not spec.pending_keys:
                display_command, display_description = command, description
            return _pending_result(
                spec, session_key, command=display_command, description=display_description, pattern_key=pattern_key,
                pattern_keys=pattern_keys, body=pending_body, smart_denied=smart_denied,
            )

    # CLI interactive: single combined prompt, wrapped in the pre/post plugin hooks.
    prompt_command, prompt_description = command, description
    if spec.redact_cli:
        prompt_command = redact_sensitive_text(command)
        prompt_description = redact_sensitive_text(description)
    hook_kwargs = dict(command=prompt_command, description=prompt_description, pattern_key=pattern_key,
                       pattern_keys=list(pattern_keys), session_key=session_key, surface="cli")
    approval_context._fire_approval_hook("pre_approval_request", **hook_kwargs)
    choice = prompt_dangerous_approval(prompt_command, prompt_description, allow_permanent=allow_permanent,
                                       smart_denied=smart_denied, approval_callback=approval_callback)
    approval_context._fire_approval_hook("post_approval_response", **hook_kwargs, choice=choice)
    if choice == "timeout":
        return deny(spec.cli_timeout, "timeout")
    if choice == "deny":
        # No _record_denial(): the breaker counts consecutive guardian LLM
        # DENY verdicts, not deliberate human denials.
        return deny(spec.cli_denied, "denied")
    return grant(choice)


def _presence(approval_callback=None) -> tuple:
    """``(approval_callback, is_cli, is_gateway, is_ask)`` for the current context. Single-query
    (-q) exports HERMES_INTERACTIVE=1 but nobody answers prompts, and HERMES_EXEC_ASK has no
    human either — both are cleared so single_query_mode actually takes effect."""
    approval_callback = _resolve_cli_approval_callback(approval_callback)
    is_cli, is_gateway = _is_interactive_cli(), _is_gateway_approval_context()
    is_ask = env_var_enabled("HERMES_EXEC_ASK")
    if _is_single_query_approval_context():
        is_cli = is_gateway = is_ask = False
    return approval_callback, is_cli, is_gateway, is_ask


def _run_approval_gate(
    *, pattern_key: str, description: str, display_target: str, approval_callback=None,
    subject: str = "", noun: str = "flagged actions",
    advice: str = "Find an alternative approach that avoids this action.",
    cron_deny_message: str = "", single_query_deny_message: str = "", unattended_deny_message: str = "",
    autoapprove_log_prefix: str, fail_closed_when_no_human: bool = False, no_human_block_message: str = "",
    allow_permanent: bool = True,
) -> dict:
    """Shared human-approval gate for a flagged action (tool call or write): decision core for
    :func:`request_tool_approval` and the file-tool write gates.

    Order: yolo bypass → session-cache short-circuit → interactive/gateway/unattended branch →
    prompt → persistence. Input-shape checks (hardline, allowlist, pattern detection) are the
    caller's job. ``fail_closed_when_no_human``: a non-interactive, non-gateway, non-cron
    context BLOCKS instead of auto-approving, so a plugin-flagged action never runs ungated.
    Unattended deny text is ``ctx.block_message(subject, noun, advice)`` unless the caller passes
    an explicit ``*_deny_message`` (the file-tool write gates word their own).
    """
    # Hardline blocks are the caller's job BEFORE this gate, so yolo here only skips the recoverable approval layer.
    # ``approvals.mode: off`` is the third bypass source (the Desktop "Approvals: off" toggle writes it); the shell
    # guards honour it, so every action routed through this gate (computer_use, plugin rules, SSH-config writes,
    # dangerous-pattern prompts) must too, or "off" still prompts on those surfaces.
    if _yolo_active():
        _audit_yolo_bypass("_run_approval_gate")
        return _approved()
    if _get_approval_mode() == "off":
        return _approved()

    # Step 34 (Design B, closes the Step 33 finding): a pre-existing PERMANENT
    # outbound_external_comm approval must not silently satisfy the generic
    # is_approved() short-circuit below when running inside a cron job under
    # cron_mode: deny -- otherwise cron_mode: deny becomes unenforceable for any
    # recipient that was ever permanently approved (allow_permanent=False only
    # prevents NEW permanent grants; it does not affect the LOOKUP of an
    # already-existing one). Narrowly scoped to the outbound_external_comm::
    # pattern_key prefix ONLY -- it does not move the generic cron branch below,
    # does not touch is_approved(), and does not affect check_dangerous_command()/
    # request_tool_approval(), whose pattern_keys never use this prefix. Existing
    # permanent grants are NOT revoked or purged -- interactive use of the same
    # grant remains unaffected, since this check only fires under cron + deny.
    if (
        pattern_key.startswith("outbound_external_comm::")
        and _is_cron_approval_context()
        and approval_context._get_cron_approval_mode() == "deny"
    ):
        return _blocked(cron_deny_message, pattern_key=pattern_key, description=description)

    # Phase 3: composed session+task+subagent identity -- collapses to plain
    # session_key for callers not yet wired to set_current_authorization_scope.
    session_key = get_current_authorization_key()
    if is_approved(session_key, pattern_key):
        return _approved()

    approval_callback, is_cli, is_gateway, is_ask = _presence(approval_callback)
    if not is_cli and not is_gateway:
        log_args = (autoapprove_log_prefix, pattern_key, description)
        # Every unattended context resolves instantly — never a pending approval nobody can answer.
        deny_messages = {
            "single_query": single_query_deny_message, "cron": cron_deny_message,
            "unattended": unattended_deny_message,
        }
        for ctx in _unattended_contexts():
            if ctx.mode() == "deny":
                message = deny_messages[ctx.name]
                if not message and ctx.name == "unattended":
                    # Platform contexts keep the generic wording (historical shape).
                    message = ctx.block_message(f"approval required ({description})", noun="flagged actions",
                                                advice="Find an alternative approach that avoids this action.")
                elif not message:
                    message = ctx.block_message(subject, noun=noun, advice=advice)
                return _blocked(message, pattern_key=pattern_key, description=description)
            if ctx.name == "single_query":
                # Return here rather than fall through: the fail-closed branch would
                # otherwise block what single_query_mode: approve just authorized.
                logger.warning("%s (pattern: %s): %s — single-query auto-approve "
                               "(approvals.single_query_mode: approve).", *log_args)
                return _approved()
            break  # cron/unattended approve-mode: auto-approve below
        else:
            if fail_closed_when_no_human:
                logger.warning("%s (pattern: %s): %s — no interactive user/gateway present; "
                               "BLOCKED (fail-closed). Set HERMES_INTERACTIVE or "
                               "HERMES_GATEWAY_SESSION to answer the prompt.", *log_args)
                return _blocked(no_human_block_message or (
                    f"BLOCKED: approval required ({description}) but no "
                    "interactive user or gateway is present to approve it."),
                    pattern_key=pattern_key, description=description)
        logger.warning("%s (pattern: %s): %s — set HERMES_INTERACTIVE or "
                       "HERMES_GATEWAY_SESSION to require approval.", *log_args)
        return _approved()

    return _human_decision(
        _ACTION_GATE, command=display_target, description=description, pattern_key=pattern_key,
        pattern_keys=[pattern_key], warnings=[(pattern_key, None, False)], session_key=session_key,
        approval_callback=approval_callback, is_cli=is_cli, is_gateway=is_gateway, is_ask=is_ask,
        permanent_capable=allow_permanent,
    )


def _should_skip_container_guards(env_type: str, has_host_access: bool = False) -> bool:
    """True when the backend is isolated enough to skip dangerous-command prompts. Docker is the
    exception once host paths are bind-mounted: ``rm -rf /workspace`` then reaches host files."""
    if env_type == "docker":
        return not has_host_access
    return env_type in ("singularity", "modal", "daytona", "vercel_sandbox")


def _user_deny_block(command: str) -> dict | None:
    """The operator's ``approvals.deny`` rules are documented as never bypassable — not by yolo,
    not by mode=off, and not by an isolated container either: they express intent about what the
    agent may DO, not what it can reach, so they are evaluated before the container fast path."""
    deny_pattern = _match_user_deny_rule(command)
    if deny_pattern is None:
        return None
    logger.warning("User deny rule %r blocked command: %s", deny_pattern, command[:200])
    return _user_deny_block_result(deny_pattern)


def _floor_block(command: str, *, sudo_guard: bool = False) -> dict | None:
    """Unconditional floors, BEFORE yolo / mode=off / cron approve-mode so no
    session-level setting can bypass them: hardline catastrophic commands,
    password-piping to ``sudo -S`` with no SUDO_PASSWORD configured (full guard
    only), and the user's own approvals.deny rules ("never, even under yolo")."""
    is_hardline, hardline_desc = detect_hardline_command(command)
    if is_hardline:
        logger.warning("Hardline block: %s (command: %s)", hardline_desc, command[:200])
        return _hardline_block_result(hardline_desc, command)
    if sudo_guard:
        is_sudo_guess, sudo_guess_desc = _check_sudo_stdin_guard(command)
        if is_sudo_guess:
            logger.warning("Sudo stdin guard block: %s (command: %s)", sudo_guess_desc, command[:200])
            return _sudo_stdin_block_result(sudo_guess_desc)
    return _user_deny_block(command)


def check_dangerous_command(command: str, env_type: str,
                            approval_callback=None,
                            has_host_access: bool = False) -> dict:
    """Detect a dangerous command and handle approval (pattern layer only). ``has_host_access``:
    a Docker sandbox that bind-mounts host paths must not skip approval.
    Returns ``{"approved": True/False, "message": str or None, ...}``."""
    if _should_skip_container_guards(env_type, has_host_access=has_host_access):
        return _user_deny_block(command) or _approved()
    blocked = _floor_block(command)
    if blocked is not None:
        return blocked
    if _yolo_active():
        _audit_yolo_bypass("check_dangerous_command")
        return _approved()
    if _command_matches_permanent_allowlist(command):
        return _approved()
    is_dangerous, pattern_key, description = detect_dangerous_command(command)
    if not is_dangerous:
        return _approved()
    return _run_approval_gate(
        pattern_key=pattern_key, description=description, display_target=command, approval_callback=approval_callback,
        subject=f"Command flagged as dangerous ({description})", noun="dangerous commands",
        advice="Find an alternative approach that avoids this command.",
        autoapprove_log_prefix="AUTO-APPROVED dangerous command in non-interactive non-gateway context",
    )


def request_tool_approval(tool_name: str, reason: str, *, rule_key: str = "", approval_callback=None) -> dict:
    """Escalate an arbitrary tool call to the human-approval gate.

    Entry point for a plugin ``pre_tool_call`` hook returning ``{"action": "approve", ...}``:
    it asks the SAME human gate as Tier-2 dangerous shell patterns (session/permanent
    allowlist, CLI prompt, gateway pending, once/session/always/deny, timeout fail-closed), so
    the LLM cannot skip it. Cron honors ``approvals.cron_mode``; any OTHER non-interactive
    non-gateway context fails CLOSED. ``rule_key`` controls the ``[a]lways`` allowlist grain;
    when empty it is ``tool_name`` + a hash of ``reason`` so DISTINCT reasons on the same tool
    persist independently. Returns the ``check_dangerous_command`` result shape.
    """
    description = reason or f"Plugin requires approval for {tool_name}"
    if not rule_key:
        rule_key = f"{tool_name}:{hashlib.sha256(description.encode('utf-8')).hexdigest()[:12]}"
    subject = f"Tool '{tool_name}' requires approval ({description})"
    return _run_approval_gate(
        # Namespaced so plugin-rule approvals share the allowlist machinery without ever colliding with a real
        # command pattern key; the display target is a synthetic label for the display/allowlist layer.
        pattern_key=f"plugin_rule:{rule_key}", description=description,
        display_target=f"<{tool_name}> (plugin approval rule)", approval_callback=approval_callback,
        subject=subject, advice="Find an alternative approach.",
        autoapprove_log_prefix=f"plugin-escalated tool call '{tool_name}' in non-interactive non-gateway context",
        fail_closed_when_no_human=True,
        no_human_block_message=(f"BLOCKED: {subject} but no interactive user or gateway is present "
                                "to approve it. A plugin flagged this action for human confirmation."),
    )


# --- Combined pre-exec guard (tirith + dangerous command detection) -------------------------------------------------

def _format_tirith_description(tirith_result: dict) -> str:
    """Human-readable severity/title/description summary of tirith findings."""
    parts = []
    for f in tirith_result.get("findings") or []:
        severity, title, desc = f.get("severity", ""), f.get("title", ""), f.get("description", "")
        if title:
            text = f"{title}: {desc}" if desc else title
            parts.append(f"[{severity}] {text}" if severity else text)
    if not parts:
        summary = tirith_result.get("summary") or "security issue detected"
        return f"Security scan: {summary}"
    return "Security scan — " + "; ".join(parts)


def _tirith_scan(command: str) -> dict:
    """Tirith result for the interactive flow; an un-importable scanner allows
    (default) or, under fail-closed, synthesizes a HIGH warn finding that goes
    through the normal approval flow (#20733)."""
    try:
        from tools.tirith_security import check_command_security
        return check_command_security(command)
    except ImportError:
        if _tirith_fail_open():
            return {"action": "allow", "findings": [], "summary": ""}
        return {"action": "warn", "summary": "Tirith unavailable (fail-closed)", "findings": [{
            "rule_id": "tirith-import-error", "severity": "HIGH",
            "title": "Tirith security module unavailable",
            "description": ("The Tirith security scanner could not be imported. "
                            "Because security.tirith_fail_open is false, this "
                            "command cannot be silently allowed. Approve only if "
                            "you have verified the command is safe."),
        }]}


def check_all_command_guards(command: str, env_type: str,
                             approval_callback=None,
                             has_host_access: bool = False) -> dict:
    """Run all pre-exec security checks and return a single approval decision. Tirith and
    dangerous-command findings are presented as ONE combined approval request, so a gateway
    force=True replay cannot bypass one check when only the other was shown to the user.
    ``has_host_access``: a Docker sandbox with bind-mounted host paths takes the normal flow."""
    if _should_skip_container_guards(env_type, has_host_access=has_host_access):
        return _user_deny_block(command) or _approved()

    blocked = _floor_block(command, sudo_guard=True)
    if blocked is not None:
        return blocked

    approval_mode = _get_approval_mode()
    if _yolo_active():
        _audit_yolo_bypass("check_all_command_guards")
        return _approved()
    if approval_mode == "off":
        return _approved()
    if _command_matches_permanent_allowlist(command):
        return _approved()

    # Outbound-communication check runs here, BEFORE the "preserve existing
    # non-interactive behavior" early-return below. That early-return exists
    # for dangerous-command semantics (skip prompting when no human is
    # present) and would otherwise short-circuit check_outbound_comm_guard()
    # before it ever runs in a plain non-interactive/non-gateway/non-cron
    # context -- exactly the context its own fail_closed_when_no_human=True
    # is designed to catch. Running it here ensures it always participates,
    # with cron/gateway/no-human branching handled inside the gate itself
    # (via _run_approval_gate), not by this function's outer early-return.
    _outbound_decision = check_outbound_comm_guard("terminal", command)
    if not _outbound_decision.get("approved", False):
        return _outbound_decision

    approval_callback, is_cli, is_gateway, is_ask = _presence(approval_callback)
    # Outside CLI/gateway/ask flows we never block on approvals: each
    # unattended context applies its configured deny/approve mode, else allow.
    if not is_cli and not is_gateway and not is_ask:
        for ctx in _unattended_contexts():
            result = _unattended_deny(command, ctx)
            if result is not None:
                return result
        return _approved()

    # Gather findings: warnings = [(pattern_key, description, is_tirith)]. Tirith block AND warn both go through the
    # approval flow (block used to be a hard stop) so users can inspect the findings and approve.
    tirith_result = _tirith_scan(command)
    is_dangerous, pattern_key, description = detect_dangerous_command(command)
    warnings = []
    session_key = get_current_session_key()
    if tirith_result["action"] in {"block", "warn"}:
        findings = tirith_result.get("findings") or []
        rule_id = findings[0].get("rule_id", "unknown") if findings else "unknown"
        tirith_key = f"tirith:{rule_id}"
        if not is_approved(session_key, tirith_key):
            warnings.append((tirith_key, _format_tirith_description(tirith_result), True))
    if is_dangerous and not is_approved(session_key, pattern_key):
        warnings.append((pattern_key, description, False))
    if not warnings:
        return _approved()

    combined_desc = "; ".join(desc for _, desc, _ in warnings)
    primary_key = warnings[0][0]
    all_keys = [key for key, _, _ in warnings]

    # "Always" is offered when at least one warning is a dangerous-pattern key the persistence layer would actually
    # allowlist permanently. Pure-tirith findings are session-max by design, so a tirith-only prompt hides Always;
    # mixed prompts offer it (the pattern key persists, tirith downgrades to session — see _persist_choice).
    return _human_decision(
        _COMMAND_GATE, command=command, description=combined_desc,
        pattern_key=primary_key, pattern_keys=all_keys, warnings=warnings,
        session_key=session_key, approval_callback=approval_callback,
        is_cli=is_cli, is_gateway=is_gateway, is_ask=is_ask, smart=approval_mode == "smart",
        permanent_capable=any(not is_t for _, _, is_t in warnings),
    )


_EXECUTE_CODE_DESCRIPTION = (
    "execute_code script execution. The script can spawn subprocesses or "
    "mutate files without passing through terminal command approval; approval is one-shot for this run."
)


def check_execute_code_guard(code: str, env_type: str, has_host_access: bool = False) -> dict:
    """Approve an execute_code script before its child process is spawned.

    The script can call ``subprocess``/``os.system``/``ctypes`` directly, none of which pass
    through ``terminal()`` / ``DANGEROUS_PATTERNS``; in gateway/ask contexts we fail closed by
    approving the script as a whole. Same dict contract as ``check_all_command_guards``.
    Documented limitation: a purely local non-interactive non-gateway session returns approved
    (the terminal auto-approve contract); the hardline floor still blocks catastrophic
    ``terminal()`` commands the script issues.

    See #30882.
    The hardline floor still blocks catastrophic ``terminal()`` commands the script issues; running
    arbitrary code headlessly without any approval surface is trusted-by-config (set a gateway/ask surface
    or ``approvals.cron_mode`` to require approval). See #30882.
    """
    pattern_key = "execute_code"
    description = _EXECUTE_CODE_DESCRIPTION

    # Isolated backends already sandbox the child. vercel_sandbox has no host-bind concept so it stays always-skipped.
    if env_type == "vercel_sandbox":
        return _approved()
    if _should_skip_container_guards(env_type, has_host_access=has_host_access):
        return _approved()
    approval_mode = _get_approval_mode()
    if _yolo_active():
        _audit_yolo_bypass("check_execute_code_guard")
        return _approved()
    if approval_mode == "off":
        return _approved()

    # Outbound-communication content check: runs before the whole-script
    # approval flow below so an email/SMS send buried in submitted source is
    # gated on the recipient, not just on the script hash. Reuses the same
    # cron/gateway/fail-closed machinery via _run_approval_gate internally
    # (check_outbound_comm_guard -> _run_approval_gate), so cron_mode/gateway
    # behavior for THIS check is consistent even though it runs ahead of this
    # function's own cron branch below.
    _outbound_decision = check_outbound_comm_guard("execute_code", code)
    if not _outbound_decision.get("approved", False):
        return _outbound_decision

    # (-q clears the presence flags, but its unattended context resolves first anyway.)
    approval_callback, is_cli, is_gateway, is_ask = _presence()
    # No user is present to approve arbitrary code in -q / cron / unattended
    # sessions: the first active context resolves instantly from its mode.
    for ctx in _unattended_contexts():
        if ctx.mode() == "deny":
            return _denied(
                "BLOCKED: execute_code runs arbitrary local Python (including "
                "subprocess calls that bypass shell-string approval checks). " + ctx.exec_tail,
                pattern_key=pattern_key, description=description, outcome="blocked",
            )
        return _approved()

    # Only gateway/ask contexts get the one-shot whole-script approval. In an interactive CLI the script's terminal()
    # calls are guarded per-call (context propagates into the RPC thread, #33057), so a whole-script prompt would fire
    # on every execute_code call. Ask-mode still takes this path even with INTERACTIVE set (how gateway/smart tests
    # and messaging ask-mode drive whole-script approval); when that leaks into a CLI with no notify callback, the
    # engine falls through to the CLI Dangerous Command panel instead of a silent pending_approval.
    if not is_gateway and not is_ask:
        if is_cli:
            # CLI interactive: NOT the fail-open gap the 2026-08-29 fix
            # targets. A human is present; this script's own terminal()
            # calls are guarded per-call via propagated approval context
            # (#33057). A whole-script prompt here would fire redundantly
            # on every execute_code call, which is why CLI intentionally
            # reaches this branch without a whole-script gate.
            return _approved()
        # No TTY, no gateway, no ask surface, and _unattended_contexts()
        # above yielded nothing (not -q/cron/single-query either): a truly
        # bare non-interactive execute_code call. Historically this
        # auto-approved with zero logging (upstream's own #30882 scope
        # choice) -- execute_code bypasses shell-string DANGEROUS_PATTERNS
        # detection entirely (subprocess/os.system/ctypes), so that gap was
        # closed 2026-08-29 (f730da0d08): fails CLOSED by default now.
        logger.warning(
            "AUTO-APPROVED execute_code script in non-interactive "
            "non-gateway context (pattern: %s): %s -- no interactive "
            "user/gateway/cron/single-query context present; BLOCKED "
            "(fail-closed). Set approvals.execute_code_noninteractive_mode: "
            "approve in config.yaml to restore auto-approve for this "
            "specific known non-interactive execute_code workflow.",
            pattern_key, description,
        )
        if _get_execute_code_noninteractive_mode() == "approve":
            return _approved()
        return _denied(
            f"BLOCKED: {description} No interactive user, gateway, cron, or "
            "single-query context is present to approve it. execute_code "
            "runs arbitrary local Python that bypasses shell-command "
            "pattern detection entirely, so this fails closed rather than "
            "proceeding unattended. To allow this specific known "
            "non-interactive workflow, set "
            "approvals.execute_code_noninteractive_mode: approve in "
            "config.yaml.",
            pattern_key=pattern_key, description=description, outcome="blocked",
        )

    session_key = get_current_session_key()
    # Built only past the early-return gates so common paths don't copy a potentially-large script into this string.
    command = f"execute_code <<'PY'\n{code}\nPY"

    # Without this, "Approve session" / "Always" choices are stored but never
    # consulted, so every execute_code call re-prompts (#39275).
    if is_approved(session_key, pattern_key):
        return _approved()

    # Smart mode: an APPROVE only suppresses the redundant whole-script prompt; the per-call terminal() guards still
    # run independently. The gateway renders the pending payload to Discord/Slack, so the script body is redacted for
    # display; the raw code is what gets assessed and run.
    from agent.redact import redact_sensitive_text
    return _human_decision(
        _EXECUTE_CODE_GATE, command=command, description=description, pattern_key=pattern_key,
        pattern_keys=[pattern_key], warnings=[(pattern_key, None, False)], session_key=session_key,
        approval_callback=approval_callback, is_cli=is_cli, is_gateway=is_gateway, is_ask=is_ask,
        smart=approval_mode == "smart",
        pending_body=lambda: f"**Code:**\n```python\n{redact_sensitive_text(code)}\n```",
    )


# --- Outbound external communication guard (canonical, session-scoped-max approval) --------------------------------

_EMAIL_SEND_VERBS = re.compile(
    r"(\.messages\(\)\.send\s*\(|\bsendmail\s*\(|\.send_message\s*\()",
    re.IGNORECASE,
)
_EMAIL_ADDR_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SMS_SEND_VERBS = re.compile(
    r"\b(twilio|messages\.create|send_sms|sendSms)\b", re.IGNORECASE
)
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_OUTBOUND_SELF_ADDRESSES = {"ed.rivera@gmail.com", "hermes.ed.rivera@gmail.com"}


def detect_outbound_comm(text):
    """Detect an outbound EXTERNAL email/SMS send signal in free text.

    Content-based detector: catches an email/SMS send regardless of which
    tool (terminal, execute_code, send_message) carries the text. Originally
    ported from agent/provenance/approval_gate.py's detect_outbound_comm;
    that module was dead code (never wired into production) and was removed
    in commit ea5108c9a8. This is the only surviving, wired copy.
    Returns {"channel": "email"|"sms", "recipients": [...]}, or None.
    """
    if not text:
        return None
    if _EMAIL_SEND_VERBS.search(text):
        recipients = _EMAIL_ADDR_RE.findall(text)
        external = sorted({r for r in recipients if r.lower() not in _OUTBOUND_SELF_ADDRESSES})
        if external:
            return {"channel": "email", "recipients": external}
    if _SMS_SEND_VERBS.search(text):
        phones = sorted(set(_PHONE_RE.findall(text)))
        if phones:
            return {"channel": "sms", "recipients": phones}
    return None


def _normalize_recipient(channel, recipient):
    """Normalize a detected recipient to a canonical string, or None if it
    cannot be reliably normalized (caller MUST fail closed on None, never
    fall back to a channel-only approval key -- that would reintroduce the
    exact non-recipient-bound gap this design exists to close).
    """
    if not recipient or not isinstance(recipient, str):
        return None
    if channel not in ("email", "sms"):
        # Ordinary platform channels (telegram/discord/slack/etc.) are the
        # agent's normal operation, not the email/SMS-style external comms
        # this gate targets. Pass the recipient through with light
        # normalization rather than failing closed on every platform send.
        stripped = recipient.strip()
        return stripped if stripped else None
    if channel == "email":
        addr = recipient.strip().lower()
        if "@" not in addr:
            return None
        local, _, domain = addr.rpartition("@")
        if domain in ("gmail.com", "googlemail.com") and "+" in local:
            local = local.split("+", 1)[0]
        if not local or not domain:
            return None
        return f"{local}@{domain}"
    if channel == "sms":
        digits = re.sub(r"[^0-9+]", "", recipient)
        if digits.startswith("+"):
            core = digits[1:]
        else:
            core = digits
        if len(core) == 10 and core.isdigit():
            return f"+1{core}"
        if len(core) == 11 and core.startswith("1") and core.isdigit():
            return f"+{core}"
        if digits.startswith("+") and len(core) >= 10 and core.isdigit():
            return f"+{core}"
        return None
    return None  # unknown channel: fail closed, do not guess


def _get_outbound_comm_mode():
    """Read approvals.outbound_comm_mode from config; default 'shadow'.

    'shadow': detection/normalization run for real, but a would-be-blocked
    decision is logged and ALLOWED (approved=True) rather than blocked --
    used to measure false-positive rate before enforcing. 'enforce': a
    would-be-blocked decision actually blocks. This switch does NOT affect
    the fail-closed error cases below (detector exception, normalization
    failure, missing recipient, missing session identity, approval-store
    failure) -- those ALWAYS fail closed regardless of shadow/enforce; only
    the ordinary "detected, needs human approval" path is shadow-gated.
    """
    try:
        from hermes_cli.config import load_config_readonly
        config = load_config_readonly()
        mode = ((config.get("approvals", {}) or {}).get("outbound_comm_mode") or "shadow")
        return mode if mode in ("shadow", "enforce") else "shadow"
    except Exception:
        return "shadow"


def check_outbound_comm_guard(tool_name, text_for_detection, channel_recipient_override=None):
    """Canonical outbound-external-communication authorization gate.

    Detects an outbound email/SMS send in `text_for_detection` (or uses
    `channel_recipient_override=(channel, recipient)` when the caller
    already knows the target structurally, e.g. send_message's own
    platform:chat_id parsing) and requires a recipient-bound, session-scoped
    approval before allowing it. FAIL-CLOSED is non-negotiable: any
    exception, normalization failure, missing recipient, or missing session
    identity blocks the action regardless of shadow/enforce mode -- only the
    ordinary "needs human approval" path is affected by outbound_comm_mode.

    allow_permanent=False is passed to _run_approval_gate() below so a NEW
    "always" grant from the interactive prompt is defensively downgraded to
    session-only -- session-scope is this category's maximum lifetime, per
    the Step 27/31 security requirement. An already-existing PERMANENT grant
    (created before this category existed, or via direct config edit) is
    still logged as a visible warning below and not revoked.

    Returns {"approved": bool, "message": str|None, ...} -- same contract as
    check_dangerous_command/check_all_command_guards.
    """
    try:
        if channel_recipient_override is not None:
            channel, raw_recipient = channel_recipient_override
            detection = {"channel": channel, "recipients": [raw_recipient]} if raw_recipient else None
        else:
            detection = detect_outbound_comm(text_for_detection)

        if not detection:
            return {"approved": True, "message": None}

        channel = detection.get("channel")
        raw_recipients = detection.get("recipients") or []
        if not raw_recipients:
            return {
                "approved": False,
                "message": (
                    "BLOCKED: outbound communication detected but no recipient "
                    "could be extracted. Action NOT sent."
                ),
            }

        normalized = []
        for r in raw_recipients:
            n = _normalize_recipient(channel, r)
            if n is None:
                return {
                    "approved": False,
                    "message": (
                        "BLOCKED: outbound communication detected but recipient "
                        f"'{r}' could not be reliably normalized/verified. "
                        "Action NOT sent."
                    ),
                }
            normalized.append(n)

        session_key = get_current_authorization_key()
        if session_key == "default":
            return {
                "approved": False,
                "message": (
                    "BLOCKED: outbound communication authorization requires a "
                    "known session identity. No session identity was found; "
                    "action NOT sent."
                ),
            }

        recipient_key = ",".join(sorted(set(normalized)))
        pattern_key = f"outbound_external_comm::{channel}::{recipient_key}"
        description = f"Outbound {channel} communication to {recipient_key}"

        mode = _get_outbound_comm_mode()

        decision = _run_approval_gate(
            pattern_key=pattern_key,
            description=description,
            display_target=text_for_detection or recipient_key,
            allow_permanent=False,
            cron_deny_message=(
                f"BLOCKED: Outbound {channel} communication to {recipient_key} "
                "but cron jobs run without a user present to approve it. "
                "Find an alternative approach that avoids this send. "
                "To allow outbound communication in cron jobs, set "
                "approvals.cron_mode: approve in config.yaml."
            ),
            autoapprove_log_prefix="AUTO-APPROVED outbound communication in non-interactive non-gateway context",
            fail_closed_when_no_human=True,
            no_human_block_message=(
                f"BLOCKED: outbound {channel} communication to {recipient_key} "
                "requires approval but no interactive user or gateway is "
                "present to approve it. Action NOT sent."
            ),
            single_query_deny_message=(
                f"BLOCKED: Outbound {channel} communication to {recipient_key} "
                "but single-query mode (-q) runs without a user present to "
                "approve it. Find an alternative approach that avoids this "
                "send. To allow outbound communication in single-query mode, "
                "set approvals.single_query_mode: approve in config.yaml."
            ),
        )

        if not decision.get("approved", False) and mode == "shadow":
            logger.warning(
                "SHADOW MODE: outbound_comm_mode=shadow -- would have BLOCKED "
                "%s (pattern: %s): %s. Allowing because shadow mode is active.",
                tool_name, pattern_key, decision.get("message"),
            )
            return {"approved": True, "message": None, "shadow_would_have_blocked": True}

        if decision.get("approved") and pattern_key in _permanent_set():
            # KNOWN LIMITATION (accepted, non-blocking): _run_approval_gate()'s
            # gateway-interactive branch hardcodes allow_permanent=True with no
            # parameter to suppress the "always" option for this category. We
            # do not un-approve an already-granted, human-approved send -- that
            # would be its own bug -- we only log so this residual gap stays
            # visible for a future _run_approval_gate() enhancement.
            logger.warning(
                "Outbound communication pattern_key %r was granted PERMANENT "
                "('always') approval via the shared approval gateway UI. "
                "Permanent approval is not intended for outbound_external_comm "
                "(session-scope should be the maximum lifetime) but "
                "_run_approval_gate() has no parameter to suppress the 'always' "
                "option -- this is a documented, accepted residual limitation, "
                "not a bug. The already-granted approval is not revoked.",
                pattern_key,
            )

        return decision
    except Exception as exc:
        logger.exception("check_outbound_comm_guard raised -- failing CLOSED")
        return {
            "approved": False,
            "message": (
                "BLOCKED: outbound-communication authorization check failed "
                f"with an internal error ({exc}). This is a fail-closed "
                "default -- the action was NOT sent."
            ),
        }


def _cron_deliver_target_set(deliver: Optional[str]) -> frozenset:
    """Normalize a cron `deliver` string into a comparable set of tokens.

    Splits on commas, lowercases, strips whitespace. Used to compare an
    old vs. new deliver value for drift purposes -- token-set equality,
    not string equality, so re-ordering ('origin,all' -> 'all,origin')
    is not flagged as drift.
    """
    if not deliver:
        return frozenset({"local"})
    return frozenset(
        p.strip().lower() for p in str(deliver).split(",") if p.strip()
    ) or frozenset({"local"})


def check_cron_deliver_change_guard(
    job_id: Optional[str],
    old_deliver: Optional[str],
    new_deliver: Optional[str],
    is_create: bool,
) -> dict:
    """Authorization gate for a cron job's delivery-target changing to an
    external/explicit recipient the model was not already approved to
    reach for THIS job.

    Threat model (2026-09-06, weekly-honesty-scorecard opportunity #3):
    cron jobs run fully unattended -- there is no live human approving each
    fire, so gating every DELIVERY (like check_outbound_comm_guard does for
    a live send_message call) would block every legitimate scheduled report
    under approvals.cron_mode: deny. The actual threat is narrower: the
    model silently redirecting an existing job's delivery target (or
    creating a new job aimed) at an external/explicit platform:chat_id it
    was never separately authorized to reach. Human approval happens ONCE,
    at the point the deliver target is set/changed -- not on every
    subsequent unattended fire to an already-approved target.

    Safe (never gated): 'local' (no delivery at all), 'origin' (resolves to
    the CURRENT chat -- the human already present when this tool call is
    made), 'all' (every home channel the human already configured in
    config.yaml -- not a model-chosen recipient), and bot-chat targets
    (machine-local, validated separately by _validate_bot_chat_deliver).
    Gated: any explicit 'platform:chat_id[:thread_id]' token that is NEW
    relative to the job's previously-stored deliver value (create: any
    explicit token; update: only tokens not already present).

    Returns {"approved": bool, "message": str|None} -- same contract as
    check_dangerous_command/check_mcp_call_guard.
    """
    try:
        if new_deliver is None:
            return {"approved": True, "message": None}

        _SAFE_TOKENS = {"local", "origin", "all"}

        def _is_gated_token(tok: str) -> bool:
            t = tok.strip().lower()
            if not t or t in _SAFE_TOKENS:
                return False
            if t.startswith("bot-chat"):
                return False
            # Anything else (platform:chat_id[:thread_id]) is an explicit,
            # model-chosen recipient -- gated unless already-approved (see
            # drift check below).
            return True

        new_tokens = _cron_deliver_target_set(new_deliver)
        gated_new = {t for t in new_tokens if _is_gated_token(t)}
        if not gated_new:
            return {"approved": True, "message": None}

        if not is_create:
            old_tokens = _cron_deliver_target_set(old_deliver)
            gated_new = gated_new - old_tokens
            if not gated_new:
                # Every explicit target was already present before this
                # update -- no NEW recipient introduced, nothing to gate.
                return {"approved": True, "message": None}

        recipient_key = ",".join(sorted(gated_new))
        job_label = job_id or "<new job>"
        pattern_key = f"cron_deliver_change::{job_label}::{recipient_key}"
        description = (
            f"Cron job '{job_label}' {'creating' if is_create else 'changing'} "
            f"its delivery target to include: {recipient_key}"
        )

        decision = _run_approval_gate(
            pattern_key=pattern_key,
            description=description,
            display_target=recipient_key,
            cron_deny_message=(
                f"BLOCKED: cron job '{job_label}' delivery target change to "
                f"'{recipient_key}' but cron jobs run without a user present "
                "to approve it. Find an alternative approach. To allow this "
                "in cron jobs, set approvals.cron_mode: approve in config.yaml."
            ),
            autoapprove_log_prefix=(
                "AUTO-APPROVED cron delivery-target change in non-interactive "
                "non-gateway context"
            ),
            fail_closed_when_no_human=True,
            allow_permanent=False,
            no_human_block_message=(
                f"BLOCKED: cron job '{job_label}' delivery target change to "
                f"'{recipient_key}' requires approval but no interactive user "
                "or gateway is present to approve it. Change NOT applied."
            ),
            single_query_deny_message=(
                f"BLOCKED: cron job '{job_label}' delivery target change to "
                f"'{recipient_key}' but single-query mode (-q) runs without a "
                "user present to approve it. Find an alternative approach. "
                "To allow this in single-query mode, set "
                "approvals.single_query_mode: approve in config.yaml."
            ),
        )
        return decision
    except Exception as exc:
        logger.exception("check_cron_deliver_change_guard raised -- failing CLOSED")
        return {
            "approved": False,
            "message": (
                "BLOCKED: cron delivery-target authorization check failed "
                f"with an internal error ({exc}). This is a fail-closed "
                "default -- the delivery-target change was NOT applied."
            ),
        }


# Load permanent allowlist from config on module import
load_permanent_allowlist()


# ---- BEGIN PLUGIN-COMPAT (revert-scheduled; see COMPAT_MANIFEST.md) ----
# Names external plugins imported from this module before the Sep 2026 decomposition.
# Internal code MUST NOT use these (scripts/check_compat_pointers.py fails CI if it does).
# The whole block is removed by reverting the commit that added it.
import contextlib  # noqa: F401,E402
import contextvars  # noqa: F401,E402
import fnmatch  # noqa: F401,E402
import functools  # noqa: F401,E402
import re  # noqa: F401,E402
import shlex  # noqa: F401,E402
import sys  # noqa: F401,E402
import tempfile  # noqa: F401,E402
import time  # noqa: F401,E402
import unicodedata  # noqa: F401,E402
import uuid  # noqa: F401,E402


def _get_cron_approval_mode() -> str:
    """Read the cron approval mode from config. Returns 'deny' or 'approve'."""
    try:
        from hermes_cli.config import cfg_get, load_config_readonly
        config = load_config_readonly()
        mode = str(cfg_get(config, "approvals", "cron_mode", default="deny")).lower().strip()
        if mode in {"approve", "off", "allow", "yes"}:
            return "approve"
        return "deny"
    except Exception:
        return "deny"


def _get_single_query_approval_mode() -> str:
    """Read the single-query (-q) approval mode from config. Returns 'deny' or 'approve'."""
    try:
        from hermes_cli.config import cfg_get, load_config_readonly
        config = load_config_readonly()
        mode = str(cfg_get(config, "approvals", "single_query_mode", default="deny")).lower().strip()
        if mode in {"approve", "off", "allow", "yes"}:
            return "approve"
        return "deny"
    except Exception:
        return "deny"


def _get_execute_code_noninteractive_mode() -> str:
    """Read the execute_code-specific non-interactive fallback mode from
    config. Returns 'block' or 'approve'.

    Deliberately a SEPARATE config key from
    ``approvals.dangerous_command_noninteractive_mode`` (the shell-command
    opt-in). execute_code runs arbitrary local Python -- subprocess, os.system,
    ctypes, direct file/process APIs -- none of which pass through
    ``detect_dangerous_command()``'s pattern matching at all, so this branch
    has a materially higher risk profile than the shell-command fallback.
    One authorization must not silently cover both; an operator who
    intentionally trusts headless shell commands has NOT thereby also
    authorized headless arbitrary-code execution.
    """
    try:
        from hermes_cli.config import cfg_get, load_config_readonly
        config = load_config_readonly()
        mode = str(
            cfg_get(
                config, "approvals", "execute_code_noninteractive_mode",
                default="block",
            )
        ).lower().strip()
        if mode in {"approve", "off", "allow", "yes"}:
            return "approve"
        return "block"
    except Exception:
        return "block"


# check_all_command_guards/check_execute_code_guard/check_outbound_comm_guard.
# =========================================================================

# Conservative allowlist of argument-key names that may be treated as a
# stable resource/target identifier for approval binding. Deliberately
# narrow and literal: no semantic inference, no assumption that "path"
# always means a destructive filesystem target, no reliance on tool
# descriptions. If a call's arguments contain exactly one of these keys
# with a non-empty scalar value, that becomes the binding target; anything
# else falls back to a non-cacheable per-call approval (see
# check_mcp_call_guard docstring).
_MCP_TARGET_ARG_KEYS = (
    "target", "resource", "resource_id", "id",
    "path", "file_path", "filepath",
    "url", "uri",
    "recipient", "to",
)


def _extract_mcp_target(tool_args: dict) -> Optional[str]:
    """Best-effort, deliberately conservative resource/target extraction.

    Returns a normalized string when exactly one recognized target-shaped
    key is present in ``tool_args`` with a non-empty scalar value, else
    None. This is NOT a semantic safety judgment -- it only answers "is
    there something stable enough to bind an approval to so a later call
    with a DIFFERENT value doesn't silently reuse this one's approval."
    Model-generated argument content is never treated as proof an action
    is safe; it is only ever used as a binding key. Multiple candidate
    keys are treated as ambiguous and fail closed to no-target rather than
    guessing which one is authoritative.
    """
    if not isinstance(tool_args, dict):
        return None
    found = []
    for key in _MCP_TARGET_ARG_KEYS:
        if key in tool_args:
            value = tool_args[key]
            if isinstance(value, (str, int, float)) and str(value).strip():
                found.append((key, str(value).strip()))
    if len(found) != 1:
        return None
    key, value = found[0]
    return f"{key}={value}"


def check_mcp_call_guard(
    server_name: str,
    tool_name: str,
    tool_args: dict,
) -> dict:
    """Canonical authorization gate for write-capable MCP tool calls on
    servers configured ``trust: untrusted`` (readOnlyHint=True tools and
    trust=full servers never reach this function -- see
    tools/mcp_tool.py's _trust_gate_check, which is unmodified except for
    its call target in this one branch).

    Reuses the existing decision core (_run_approval_gate) and identity
    function (get_current_authorization_key) exactly as
    check_outbound_comm_guard/check_execute_code_guard do. Does NOT reuse
    check_outbound_comm_guard's (channel, recipient) data model -- per the
    Step 51 design report, an arbitrary MCP side effect (file write, cloud
    delete, SaaS setting change, financial transaction, ...) frequently has
    no communication-endpoint-shaped recipient, and forcing one through
    recipient normalization would either fail closed uninformatively or
    silently pass through the guard's comms-specific passthrough branch
    with no real target-binding value.

    Approval binding:
      - When a stable target IS extracted (see _extract_mcp_target):
        pattern_key = "mcp_action::{server}::{tool}::{target}" -- may be
        reused by a LATER call with the identical
        server+tool+target+session+task+subagent, per ordinary
        _run_approval_gate/is_approved session-cache semantics.
      - When NO stable target is extracted: pattern_key includes a random
        per-call nonce, guaranteeing this decision is never looked up nor
        stored for reuse by any other call, however identical the rest of
        the call looks. Every invocation without an extractable target
        requires fresh approval.

    Identity: get_current_authorization_key() (session+task+subagent
    composite) -- NEVER get_current_session_key(). A different task_id or
    subagent_id within the same session is treated as a different
    identity and cannot reuse another identity's approval.

    Permanent ("always") approval is explicitly disabled
    (allow_permanent=False) -- MCP side-effect approvals are session-scoped
    at maximum, matching the existing outbound_external_comm precedent.

    Cron: participates directly in the canonical cron_mode branch inside
    _run_approval_gate (fail_closed_when_no_human=True, cron_deny_message
    below) -- a cron job under cron_mode: deny is blocked immediately with
    no interactive prompt and no timeout-dependent behavior. This function
    never calls request_elicitation_consent()'s CLI/TUI fallback.

    Fail-closed: any exception, missing/invalid authorization identity, or
    inability to construct a pattern_key results in denial, never approval.

    Returns {"approved": bool, "message": str|None, ...} -- same contract
    as the other three canonical guards.
    """
    try:
        session_key = get_current_authorization_key()
        if not session_key or session_key == "default":
            return {
                "approved": False,
                "message": (
                    "BLOCKED: MCP tool call authorization requires a known "
                    "session identity. No session identity was found; "
                    f"'{tool_name}' on server '{server_name}' was NOT run."
                ),
            }

        target = _extract_mcp_target(tool_args if isinstance(tool_args, dict) else {})
        if target is not None:
            pattern_key = f"mcp_action::{server_name}::{tool_name}::{target}"
            display_target = f"{server_name}.{tool_name}({target})"
        else:
            # No confidently identifiable target: never cacheable. A random
            # nonce guarantees this pattern_key can never collide with (and
            # therefore never be satisfied by) any prior or future call,
            # however similar the rest of the call looks.
            nonce = os.urandom(8).hex()
            pattern_key = f"mcp_action::{server_name}::{tool_name}::__no_target__::{nonce}"
            display_target = f"{server_name}.{tool_name}(<no stable target>)"

        description = (
            f"MCP tool '{tool_name}' on untrusted server '{server_name}' "
            "wants to run (write-capable; no readOnlyHint=true annotation)"
        )

        decision = _run_approval_gate(
            pattern_key=pattern_key,
            description=description,
            display_target=display_target,
            cron_deny_message=(
                f"BLOCKED: MCP tool '{tool_name}' on untrusted server "
                f"'{server_name}' requires approval but cron jobs run "
                "without a user present to approve it. Find an alternative "
                "approach that avoids this call. To allow untrusted MCP "
                "write-capable calls in cron jobs, set "
                "approvals.cron_mode: approve in config.yaml."
            ),
            autoapprove_log_prefix="AUTO-APPROVED MCP call in non-interactive non-gateway context",
            fail_closed_when_no_human=True,
            allow_permanent=False,
            no_human_block_message=(
                f"BLOCKED: MCP tool '{tool_name}' on untrusted server "
                f"'{server_name}' requires approval but no interactive user "
                "or gateway is present to approve it. The call was NOT run."
            ),
            single_query_deny_message=(
                f"BLOCKED: MCP tool '{tool_name}' on untrusted server "
                f"'{server_name}' requires approval but single-query mode "
                "(-q) runs without a user present to approve it. Find an "
                "alternative approach that avoids this call. To allow "
                "untrusted MCP write-capable calls in single-query mode, set "
                "approvals.single_query_mode: approve in config.yaml."
            ),
        )
        return decision
    except Exception as exc:
        logger.exception("check_mcp_call_guard raised -- failing CLOSED")
        return {
            "approved": False,
            "message": (
                "BLOCKED: MCP call authorization check failed with an "
                f"internal error ({exc}). This is a fail-closed default -- "
                f"'{tool_name}' on server '{server_name}' was NOT run."
            ),
        }


_PLUGIN_COMPAT_LAZY = {
    'DANGEROUS_PATTERNS': ('tools.approval_detection', 'DANGEROUS_PATTERNS'),
    'DANGEROUS_PATTERNS_COMPILED': ('tools.approval_detection', 'DANGEROUS_PATTERNS_COMPILED'),
    'HARDLINE_PATTERNS': ('tools.approval_detection', 'HARDLINE_PATTERNS'),
    'HARDLINE_PATTERNS_COMPILED': ('tools.approval_detection', 'HARDLINE_PATTERNS_COMPILED'),
    'HUMAN_WAIT_MARGIN_S': ('tools.approval_human_wait', 'HUMAN_WAIT_MARGIN_S'),
    'cfg_get': ('hermes_cli.config', 'cfg_get'),
    'get_plugin_manager': ('tools.approval_prompt', 'get_plugin_manager'),
    'human_wait_ceiling': ('tools.approval_human_wait', 'human_wait_ceiling'),
    'human_wait_seconds': ('tools.approval_human_wait', 'human_wait_seconds'),
    'human_wait_window': ('tools.approval_human_wait', 'human_wait_window'),
    'is_interrupted': ('tools.interrupt', 'is_interrupted'),
    'request_elicitation_consent': ('tools.approval_prompt', 'request_elicitation_consent'),
    'reset_current_observability_context': ('tools.approval_context', 'reset_current_observability_context'),
    'reset_current_session_key': ('tools.approval_context', 'reset_current_session_key'),
    'reset_hermes_interactive_context': ('tools.approval_context', 'reset_hermes_interactive_context'),
    'set_current_observability_context': ('tools.approval_context', 'set_current_observability_context'),
    'set_current_session_key': ('tools.approval_context', 'set_current_session_key'),
    'set_hermes_interactive_context': ('tools.approval_context', 'set_hermes_interactive_context'),
}


def __getattr__(name):  # PEP 562 — lazy so no import cycles
    target = _PLUGIN_COMPAT_LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    from hermes_cli.plugin_compat import warn_once
    warn_once(__name__, name, *target)
    return getattr(importlib.import_module(target[0]), target[1])
# ---- END PLUGIN-COMPAT ----
