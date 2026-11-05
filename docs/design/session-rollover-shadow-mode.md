# Session Auto-Rollover — Shadow Mode Design

Status: DESIGN ONLY — no behavior change. Branch: `hermes/session-rollover-shadow-mode`.
Owner: Hermes cost-optimization project (Phase 2, item 1). Approved by Ed 2026-11-05,
with changes: trigger on current context size (not cumulative cache_read), shadow
mode first, 2-3 sessions of logged-but-not-executed decisions before any real
rollover is enabled.

## Problem
Long-running interactive sessions keep appending to one ever-growing transcript.
Every turn re-reads (cheaply, via cache) and periodically re-writes (expensively,
on a cold-cache event) the whole thing. The top session this cycle: 1,058 calls,
~150M cache-read tokens, $52.92/month on its own. Session length, not any single
inefficiency, is the dominant cost driver (see Phase 1 report).

## Goal (shadow mode only, this phase)
Detect when a session crosses a context-size threshold and draft what a
handoff-and-rollover would look like — without ever actually rolling over.
Log the decision + the draft summary for Ed to review across 2-3 real sessions
before any enablement decision.

## Trigger
- Metric: **current prompt/context size for the next call**, not cumulative
  cache_read tokens (cumulative read is a cost figure, not a context-size
  figure — a session can have huge cache-read totals from many short calls
  without ever having a large live context, and vice versa).
- Threshold: 80,000-100,000 tokens of live context (configurable;
  `rollover.shadow_threshold_tokens`, default 90000).
- Token count source: reuse `agent/context_engine.py`'s existing prompt-token
  estimation (the same machinery `should_compress()` already uses for
  mid-session compaction) rather than inventing a second estimator — but this
  is a **separate decision point** from compaction: compaction trims messages
  within a session; rollover hands the whole session off to a fresh one.
  These must not fight each other. Open question for implementation: does
  shadow-mode rollover fire instead of, before, or only after compaction has
  already run and the session is still over threshold? Needs a decision before
  any code lands — flagging, not resolving, here.

## Handoff summary — required contents
Per Ed's spec, the draft summary must carry:
1. **Open tasks** — what's in progress, not yet delivered.
2. **Decisions** — what's been approved/decided in-session, with enough
   specificity that re-litigating isn't needed.
3. **Pending approvals** — anything awaiting a yes/no from Ed, called out
   explicitly so it isn't silently dropped.
4. **Active branch/commit** — exact state of any in-progress git work
   (branch name, last commit SHA, uncommitted changes if any).
5. **BLOCKING gaps** — anything the assistant doesn't know and needs to ask
   about, explicitly separated from resolved items (the "handoff template"
   failure mode: compressing away the one open question that mattered).

This is structurally close to the compaction summary format already used by
`turn_context_compaction.py`, but rollover's summary is colder-start (a brand
new session, not a trimmed version of the same one) so it needs to be more
complete, not more concise.

## Shadow-mode behavior (what actually ships this phase)
- A new log-only check, run once per turn after the context-size calculation
  is available (same point `should_compress_info()` is consulted).
- On crossing threshold: log one JSON line to
  `$HERMES_HOME/cost-tracking/rollover_shadow_log.jsonl` with: timestamp,
  session_id, context_tokens at trigger, and the **drafted handoff summary**
  (generated the same way a real rollover would generate it — this is the
  part that needs real validation, not a stub).
- **No session is ever actually ended, forked, or handed off in this phase.**
  The conversation continues completely normally; the log entry is the only
  side effect.
- Config flag: `rollover.mode: shadow | live | off`, defaulting to `off` on
  main (so nothing changes until Ed explicitly flips it to `shadow` on this
  branch for a trial, and separately to `live` only after the 2-3 session
  review).

## Review gate before "live"
Ed reviews N shadow-logged summaries against what actually happened in each
session (did the summary have everything needed to resume cold). Only after
that review does `rollover.mode: live` become a decision on the table — and
that's a separate approval, not implied by this design being accepted.

## Explicitly out of scope this phase
- Actually ending/forking a session.
- Picking which model drafts the summary (reuse main-loop model vs. a cheap
  aux call — deferred; shadow mode needs to validate quality first, not cost,
  since it never fires for real).
- Touching `context_engine.py`'s existing compaction thresholds/behavior.
- Any interaction with background_review forks (separate subsystem, separate
  trial already running).

## Open questions for Ed before implementation starts
1. Compaction-vs-rollover ordering (see Trigger section) — need a decision.
2. Should the shadow log fire once per threshold-crossing, or once per turn
   while over threshold (noisy) — recommend once per crossing with a cooldown.
3. Where should the drafted summary's *generation* happen — inline in the
   main loop (adds a real LLM call, defeating "log-only, no behavior change"
   if that call has side effects or meaningfully changes cost) vs. a detached
   best-effort call that's allowed to fail silently like the per-call log.
   Leaning toward the latter — needs explicit sign-off since it's not truly
   zero-behavior-change if it adds an LLM call per threshold-crossing.
