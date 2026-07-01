"""Session brief provider (Component A of the Anthropic Playbook / Thread 2).

Produces a compact, RETRIEVED "state of play" block injected ONCE into the
volatile tier of the system prompt (agent/system_prompt.py). It kills
"Groundhog Day": the gateway session starts already knowing open threads,
today's commitments, and recent corrections — without the user re-explaining.

CACHE CONTRACT (load-bearing):
  The system prompt is cached for the AIAgent lifetime and only rebuilt on
  context compression. The brief therefore MUST be *day-stable*: identical for
  the whole calendar day given the same vault. NO minute/second timestamps, NO
  live/ticking values (e.g. a live account balance). Anything ticking belongs
  in a tool call, not the cached prefix. See agent/system_prompt.py:448-454.

FABRICATION CONTRACT:
  Every line traces to a real file read. If a source directory is missing or
  empty, the corresponding section is OMITTED — we never emit "no open threads"
  as invented reassurance. Missing == retrieval gap, not a claim.
"""
from __future__ import annotations

import os
import re
import datetime as dt
from pathlib import Path
from typing import List, Optional

# Default vault location (Ed's curated knowledge base).
_DEFAULT_VAULT = os.path.expanduser("~/Documents/Obsidian Vault")

# How many recent items to surface per section (keep the brief compact — it
# lives in the cached prefix, so every line has a token cost every session).
_MAX_PROJECTS = 5
_MAX_POSTMORTEMS = 2

# Status markers that denote an *open/active* project worth surfacing.
_OPEN_MARKERS = ("🟡", "🟢", "PENDING", "IN PROGRESS", "SCHEDULED", "ACTIVE")

# Postmortem filenames look like YYYY-MM-DD-<slug>.md
_PM_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[-_].+\.md$")


def _list_open_projects(projects_dir: Path) -> List[str]:
    """Project files whose content shows an open/active status marker."""
    out: List[tuple[str, float]] = []
    if not projects_dir.is_dir():
        return []
    for p in projects_dir.glob("*.md"):
        try:
            head = p.read_text(encoding="utf-8", errors="ignore")[:800]
        except OSError:
            continue
        if any(m in head for m in _OPEN_MARKERS):
            out.append((p.stem, p.stat().st_mtime))
    # newest first, capped
    out.sort(key=lambda t: t[1], reverse=True)
    return [name for name, _ in out[:_MAX_PROJECTS]]


def _list_recent_postmortems(pm_dir: Path, today: dt.date) -> List[str]:
    """Most recent postmortems by the date encoded in the filename."""
    if not pm_dir.is_dir():
        return []
    dated: List[tuple[dt.date, str]] = []
    for p in pm_dir.glob("*.md"):
        m = _PM_DATE_RE.match(p.name)
        if not m:
            continue
        try:
            d = dt.date.fromisoformat(m.group(1))
        except ValueError:
            continue
        if d <= today:  # never surface a future-dated file
            dated.append((d, p.stem))
    dated.sort(key=lambda t: t[0], reverse=True)
    return [stem for _, stem in dated[:_MAX_POSTMORTEMS]]


def build_session_brief(
    vault_path: Optional[str] = None,
    today: Optional[dt.date] = None,
) -> str:
    """Build the day-stable session brief string.

    Args:
        vault_path: path to the Obsidian vault. Defaults to Ed's vault.
        today: the calendar day (injected for testability / determinism).

    Returns:
        A compact markdown block, or "" when there is nothing to report
        (missing vault or no qualifying content). Never fabricates.
    """
    vault = Path(vault_path or _DEFAULT_VAULT)
    if today is None:
        today = dt.date.today()
    if not vault.is_dir():
        return ""

    projects = _list_open_projects(vault / "04-Projects")
    postmortems = _list_recent_postmortems(vault / "05-Postmortems", today)

    sections: List[str] = []
    if projects:
        lines = "\n".join(f"- {name}" for name in projects)
        sections.append(f"**Open threads / active projects:**\n{lines}")
    if postmortems:
        lines = "\n".join(f"- {name}" for name in postmortems)
        sections.append(f"**Recent corrections (postmortems — read before repeating):**\n{lines}")

    if not sections:
        return ""

    header = "## Session Brief (retrieved from vault — carry-forward context)"
    return header + "\n\n" + "\n\n".join(sections)
