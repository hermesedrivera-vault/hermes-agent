#!/usr/bin/env python3
"""Curator protected-content gate.

Routes background-review (curator) skill writes that touch authorization /
production-risk content — or that remove/weaken an existing guardrail phrase
— to a human-readable proposal file instead of the live skill file. Nothing
in this module ever writes to a live skill; ``_apply_skill_write_gate`` in
``skill_manager_tool.py`` is the only caller and only for
``origin == background_review`` (the curator's own fork).

Added 2026-11-17 after a curator over-generalization incident: an
unsupervised curator pass loosened an authorization-scope sentence in the
``jnc-tax-engine-ops`` skill. See the companion vault postmortem
(``05-Postmortems/2026-11-17-curator-ci-authorization-overgeneralization.md``).
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Optional

from hermes_constants import get_hermes_home

# Whole-skill protection: most of the skill's content is authorization/
# approval/production-risk guidance, so ANY curator write to it is proposed,
# never auto-applied. Configurable via config.yaml `curator.protected_skills`.
DEFAULT_PROTECTED_SKILLS = ("jnc-tax-engine-ops", "enforced-gmail-send", "send-email-tool")

# Content-level protection: a curator write introducing one of these terms is
# proposed even on a skill not in the list above. Configurable via
# `curator.protected_keywords`.
DEFAULT_PROTECTED_KEYWORDS = (
    "authoriz", "approv", "merg", "push", "deploy", "rebuild", "migrat",
    "production database", "prod db", "secret", "credential", "api key",
    "send email", "kenneth", "hitl", "human review", "review gate",
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

    Fails closed: an error or corrupt state reading pause status is treated
    as paused (route to proposal), never as unpaused — the safe failure for
    an approval gate is to hold the write, never to silently let it through.
    """
    try:
        from agent.curator import is_paused
        return bool(is_paused())
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
