#!/usr/bin/env python3
"""Curator protected-content gate.

Routes background-review (curator) skill writes that touch authorization /
production-risk content — or that remove/weaken an existing guardrail phrase
— to a human-readable proposal file instead of the live skill file. Nothing
in this module ever writes to a live skill; ``_apply_skill_write_gate`` in
``skill_manager_tool.py`` is the only caller and only for
``origin == background_review`` (the curator's own fork).

Added 2026-11-17 after a curator over-generalization incident: an
unsupervised curator pass loosened an authorization-scope sentence in a
project-specific operations skill. Deployment-specific skill names and
keywords are NOT hardcoded here (this module ships in a public repo) — add
them via ``curator.protected_skills`` / ``curator.protected_keywords`` in
your own ``~/.hermes/config.yaml`` instead. See your own incident notes for
the specific skill and session involved, if any.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

from hermes_constants import get_hermes_home

# Whole-skill protection: generic, deployment-agnostic defaults only — most of
# each named skill's content is authorization/approval/production-risk
# guidance, so ANY curator write to it is proposed, never auto-applied.
# Deployment-specific skills (e.g. a client-specific ops runbook) belong in
# config.yaml's `curator.protected_skills`, not here.
DEFAULT_PROTECTED_SKILLS = ("enforced-gmail-send", "send-email-tool", "hermes-agent")

# Content-level protection: a curator write introducing one of these terms is
# proposed even on a skill not in the list above. Generic terms only — add
# deployment-specific terms (client/person names, etc.) via config.yaml's
# `curator.protected_keywords`.
DEFAULT_PROTECTED_KEYWORDS = (
    "authoriz", "approv", "merg", "push", "deploy", "rebuild", "migrat",
    "production database", "prod db", "secret", "credential", "api key",
    "send email", "hitl", "human review", "review gate",
)

# Guardrail phrases whose REMOVAL (present in the old text, gone/changed in
# the new text) signals a weakened rule — proposed regardless of skill or
# keyword lists. Ed, 2026-11-17.
WEAKEN_PATTERNS = (
    r"\bexplicit\b",
    r"\bed approves\b",
    r"\bdo not\b",
    r"\bonly when\b",
    r"\bone\b.{0,40}\bper\b",
)


def _cfg_list(key: str, default: tuple[str, ...]) -> list[str]:
    try:
        from hermes_cli.config import load_config_readonly
        from agent.curator import _subdict  # reuse the existing nested-dict helper
        cfg = _subdict(load_config_readonly(), "curator")
        value = cfg.get(key)
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return [v.strip() for v in value if v.strip()]
    except Exception:
        pass
    return list(default)


def protected_skills() -> list[str]:
    return _cfg_list("protected_skills", DEFAULT_PROTECTED_SKILLS)


def protected_keywords() -> list[str]:
    return _cfg_list("protected_keywords", DEFAULT_PROTECTED_KEYWORDS)


def is_protected_skill(name: str) -> bool:
    return (name or "").strip().lower() in {s.lower() for s in protected_skills()}


def _contains_any_keyword(text: str, keywords: list[str]) -> Optional[str]:
    low = (text or "").lower()
    for kw in keywords:
        if kw.lower() in low:
            return kw
    return None


def _weakened(old_text: str, new_text: str) -> Optional[str]:
    for pat in WEAKEN_PATTERNS:
        had = re.search(pat, old_text or "", re.IGNORECASE)
        has = re.search(pat, new_text or "", re.IGNORECASE)
        if had and not has:
            return pat
    return None


def _read_pause_state_from_disk() -> bool:
    """Read ``.curator_state`` directly rather than through
    ``agent.curator.load_state()``, which maps a MISSING file to
    ``paused: False`` by design but also silently maps a READ/PARSE ERROR to
    the exact same ``paused: False`` default — exactly backwards for a
    safety gate, since it means a corrupt state file on disk previously
    *unblocked* automated writes instead of blocking them, with no exception
    for ``_curator_is_paused``'s own try/except to ever catch.

    - missing file -> not paused (``False``): nothing has ever paused the
      curator, so there's nothing to fail closed about.
    - unreadable file, invalid JSON, a non-dict top level, or a ``paused``
      value that isn't a ``bool`` -> paused (``True``): anything that can't
      be cleanly resolved to a real boolean fails closed.
    """
    path = get_hermes_home() / "skills" / ".curator_state"
    if not path.exists():
        return False
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError:
        return True
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return True
    if not isinstance(data, dict):
        return True
    paused = data.get("paused", False)
    return True if not isinstance(paused, bool) else paused


def _curator_is_paused() -> bool:
    """True if `hermes curator pause` is in effect. Checked HERE — the single
    skill-write chokepoint — rather than only in agent/curator.py's own
    scheduler (``maybe_run_curator``/``should_run_now``), because a SECOND,
    independent subsystem (agent/background_review.py's per-turn nudge,
    default every 10 turns via `skills.creation_nudge_interval`) sets the
    exact same ``background_review`` write-origin tag and has NO relationship
    to curator.pause at all. Checking it here means the pause blocks every
    automated actor that routes through this gate — the scheduled curator
    consolidation pass, the per-turn background-review nudge, and any future
    session-end review — not just the literal ledger actor string "curator".
    A write Ed has explicitly approved goes through the SEPARATE
    ``_skill_gate_bypass``/``apply_skill_pending`` replay path in
    skill_manager_tool.py, which returns before this function is ever called
    — so an approved write is never blocked by pause.

    Ed, 2026-11-18, after a write landed on jnc-tax-engine-ops while the
    curator was paused — traced to the per-turn nudge, not the curator's own
    scheduled pass (confirmed by three more such writes landing mid-
    investigation, all while paused).

    Reads ``.curator_state`` directly via ``_read_pause_state_from_disk``
    (Ed, 2026-11-21) rather than ``agent.curator.is_paused()`` — that
    function's own ``load_state()`` swallows read/parse errors into
    ``paused: False`` internally, so a corrupt state file never raised an
    exception for this function's try/except to catch; it just silently
    reported "not paused". Reading the file directly here means a corrupt
    file genuinely fails closed instead of a false negative.

    Still fails closed on top of that: an error even from the direct-read
    path (TypeError resolving ``get_hermes_home()``, etc.) is treated as
    paused (route to proposal), never as unpaused.
    """
    try:
        return _read_pause_state_from_disk()
    except Exception:
        return True


def classify_write(name: str, action: str, *, content: str = "", old_string: str = "",
                    new_string: str = "", file_content: str = "", file_path: str = "") -> Optional[str]:
    """Return a human-readable reason to route this write to a proposal, or
    None if it may proceed through the normal (auto-apply + ledger) path."""
    if _curator_is_paused():
        return ("curator is paused (hermes curator pause) — no background-review skill "
                "write (scheduled curator pass, per-turn nudge, or any future session-end "
                "review) may land while paused")
    if action in ("delete", "remove_file"):
        return (f"action '{action}' from background review always routes to a proposal — "
                "destructive skill-library changes (deleting a skill or a supporting file) "
                "are never auto-applied, regardless of skill, keyword, or weaken-pattern checks")
    if is_protected_skill(name):
        return f"skill '{name}' is on the protected list (authorization/production-risk content)"
    new_text = content or new_string or file_content or ""
    old_text = old_string or ""
    kw = _contains_any_keyword(new_text, protected_keywords())
    if kw:
        return f"write introduces protected-content keyword '{kw}'"
    weak = _weakened(old_text, new_text)
    if weak:
        return f"write appears to remove/weaken guardrail language matching /{weak}/"
    return None


def _proposals_dir() -> Path:
    d = get_hermes_home() / "skills" / ".curator_proposals"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _render_proposal(*, name: str, action: str, reason: str, session_id: str, payload: dict[str, Any]) -> str:
    lines = [
        f"# Curator proposal — {name} ({action})",
        "",
        f"- **Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Skill:** {name}",
        f"- **Action:** {action}",
        f"- **Source session:** {session_id or '(unknown)'}",
        f"- **Reason routed to proposal:** {reason}",
        "",
        "## Proposed change",
        "",
    ]
    if action == "patch":
        lines += ["```diff", f"- {payload.get('old_string', '')}", f"+ {payload.get('new_string', '')}", "```"]
    elif action in ("create", "edit"):
        lines += ["```markdown", payload.get("content", ""), "```"]
    elif action == "write_file":
        lines += [f"File: `{payload.get('file_path', '')}`", "```", payload.get("file_content", ""), "```"]
    elif action == "remove_file":
        lines += [f"Remove file: `{payload.get('file_path', '')}`"]
    elif action == "delete":
        lines += [f"Delete skill '{name}' (absorbed_into={payload.get('absorbed_into', '') or '(none)'})"]
    else:
        lines += ["```json", str(payload), "```"]
    lines += [
        "",
        "## Approval",
        "",
        "Pending — needs Ed's explicit approval of THIS proposal in a message "
        "(one approval covers exactly one proposal). Never auto-applied by any "
        "process. To apply: a foreground agent turn re-reads this file, shows "
        "Ed the diff again if anything changed on disk since, then applies via "
        "`skill_manage` and deletes/archives this proposal file.",
    ]
    return "\n".join(lines)


def write_proposal(*, name: str, action: str, reason: str, session_id: str, payload: dict[str, Any]) -> Path:
    """Persist a human-readable proposal; never touches the live skill file."""
    date = time.strftime("%Y-%m-%d")
    base = f"{date}-{name}"
    path = _proposals_dir() / f"{base}.md"
    n = 2
    while path.exists():
        path = _proposals_dir() / f"{base}-{n}.md"
        n += 1
    path.write_text(_render_proposal(name=name, action=action, reason=reason,
                                     session_id=session_id, payload=payload), encoding="utf-8")
    return path
