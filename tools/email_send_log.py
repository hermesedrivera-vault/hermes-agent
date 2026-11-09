"""Shared append-only send log for every outbound email path.

Single source of truth for BOTH:
  - send_email()'s rate limiting (Change 2 of the v3 spec: count today's
    entries directly from this log, no separate counter file), and
  - the digest's SENT-vs-log cross-check (Change 3: a SENT message with no
    matching entry here is a bypass alert).

Every outbound path that can place a real message in
hermes.ed.rivera@gmail.com's SENT folder MUST append one record here with
the SAME schema -- send_email() and the email platform adapter
(plugins/platforms/email/adapter.py) both write through
:func:`append_log_entry`, never their own ad-hoc log.

One JSON object per line (JSONL), append-only, never rewritten in place.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

# Resolved once, but overridable per-call (tests point this at a tmp_path file
# instead of monkeypatching a module global that other imports may have
# already captured).
DEFAULT_SEND_LOG_PATH = "/home/hermes/.hermes/state/email_send_log.jsonl"

_write_lock = threading.Lock()

# Schema (keys every entry is expected to carry; extra keys are fine):
#   ts            ISO-8601 UTC timestamp of the append (not necessarily the send time)
#   message_id    Gmail Message-Id of the sent message, or None if never sent
#   to, cc, bcc   lists of lowercase recipient addresses
#   subject       str
#   from_account  "hermes" | "ed"
#   source        "send_email" | "email_adapter"  -- which path wrote this entry
#   outcome       "sent" | "denied" | "blocked_gate_unreachable"


def _resolve_path(path: Optional[str]) -> str:
    return path or DEFAULT_SEND_LOG_PATH


def append_log_entry(entry: dict[str, Any], *, path: Optional[str] = None) -> None:
    """Append one record. Append-only -- never edits or removes an existing line.

    Thread-safe within this process (SMTP sends and send_email() calls can
    race from different threads); cross-process safety relies on O_APPEND
    being atomic for writes under PIPE_BUF, which every record here is.
    """
    record = dict(entry)
    record.setdefault("ts", datetime.now(timezone.utc).isoformat())
    target = _resolve_path(path)
    with _write_lock:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")


def read_entries(*, path: Optional[str] = None) -> Iterator[dict[str, Any]]:
    """Yield every entry, oldest first. Missing file => no entries.

    A line that fails to parse is skipped (logged by the caller if it cares)
    rather than raising -- a single corrupt line must never take down rate
    limiting or the digest for every other entry.
    """
    target = _resolve_path(path)
    try:
        with open(target, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return


def _local_midnight_utc_floor(now: Optional[datetime] = None) -> datetime:
    """Start of "today" in US/Eastern (Ed's locale), expressed as a UTC instant.

    Avoids a hard dependency on a tz database package; uses a fixed -05:00
    (EST) offset per the standing convention already used elsewhere in this
    profile (UTC-05:00). DST drift (+/- 1 hour at the boundary) is an accepted
    approximation for a 20/day soft limit, not a hard legal cutover.
    """
    from datetime import timedelta, timezone as _tz

    now = now or datetime.now(timezone.utc)
    eastern = now.astimezone(_tz(timedelta(hours=-5)))
    local_midnight = eastern.replace(hour=0, minute=0, second=0, microsecond=0)
    return local_midnight.astimezone(timezone.utc)


def count_today(*, path: Optional[str] = None, now: Optional[datetime] = None,
                 outcomes: Iterable[str] = ("sent",)) -> int:
    """Count log entries at/after local midnight whose outcome is in *outcomes*.

    Default counts only successfully-sent entries (what the 20/day limit is
    about) -- denied/blocked entries never consumed a real send and must not
    count against the sender.
    """
    floor = _local_midnight_utc_floor(now)
    count = 0
    for entry in read_entries(path=path):
        ts = entry.get("ts")
        if not ts:
            continue
        try:
            entry_dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if entry_dt.tzinfo is None:
            entry_dt = entry_dt.replace(tzinfo=timezone.utc)
        if entry_dt < floor:
            continue
        if entry.get("outcome", "sent") in outcomes:
            count += 1
    return count
