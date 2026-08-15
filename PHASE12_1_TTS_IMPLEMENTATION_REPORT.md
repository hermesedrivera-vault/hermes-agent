# Phase 12.1 — TTS D1-A Implementation Report

**Scope:** Implement the Step 11-approved TTS remediation (canonical general file-write authorization + non-destructive path resolution), per Ed's Step 12.1 scoping decision to gate BOTH explicit and default output paths. Step 9 Phase 3 remains frozen; none of its four production files were touched.

---

## Exact Production Files Changed

**`tools/tts_tool.py` only.** (91 insertions, 5 deletions)

No other production file was modified. The four frozen Phase-3 files (`tools/approval.py`, `tools/file_tools.py`, `agent/tool_executor.py`, `tools/delegate_tool.py`) remain byte-identical to every prior checkpoint this session — confirmed via `git diff --stat` showing the same diff sizes (103/244/36/51 lines) recorded throughout Steps 9–11.

## Exact Test Files Changed

**New:**
- `tests/tools/test_tts_output_authorization.py` — dedicated Phase 12.1 test suite (16 tests).

**Modified (existing TTS test files broken by the new fail-closed gate — same blast-radius pattern as Step 9 Phase 3's 10-file fix, same established fixture, not a weakening):**
- `tests/tools/test_tts_command_providers.py`
- `tests/tools/test_tts_speed.py`
- `tests/tools/test_tts_instructions.py`
- `tests/tools/test_tts_kittentts.py`
- `tests/tools/test_tts_max_text_length.py`
- `tests/tools/test_tts_mistral.py`
- `tests/tools/test_tts_opus_routing.py`
- `tests/tools/test_tts_piper.py`

Each received the identical, already-Ed-accepted `_grant_general_file_write_approval` autouse fixture pattern first established in `tests/tools/test_line_ending_preservation.py` during Step 9 Phase 3 — no assertion in any of these 8 files was weakened, removed, or changed; only an approval-channel fixture was added so the write can reach the behavior the test is actually about.

---

## Complete Diff Summary

### 1. New helpers (`tools/tts_tool.py`)

- `_tts_free_path(candidate: Path) -> Path` — self-contained, non-destructive collision resolution (`name.mp3` → `name-2.mp3` → ...). Independently implemented, NOT imported from `tools/flux3_video_tool.py`, per your explicit no-cross-coupling instruction.
- `_tts_authorize_destination(path: Path, task_id: str) -> tuple[Optional[Path], Optional[str]]` — resolves via `_tts_free_path()`, then calls the canonical `tools.file_tools._check_general_file_write([str(resolved)], task_id)`. Returns `(resolved_path, None)` on approval, `(None, blocked_message)` on denial.

### 2. Destructive-write elimination

- Removed `if output.exists(): output.unlink()` from `_generate_command_tts()` (formerly at lines 1334-1335) — the explicit delete Ed's Step 12 instructions specifically named.
- Confirmed (per your explicit instruction not to assume this was safely unreachable) that this function's `output_path` argument now always arrives pre-resolved to a free path by its caller, so no re-probe/delete belongs inside this function at all.
- Guarded a **second, previously unflagged** destructive-write site discovered during implementation: `_build_audio_delivery_files()`'s multi-chunk repacking step does `os.replace(source, destination)`, which silently clobbers an existing file if `destination` happens to collide with something unrelated. Added a `_tts_free_path()` check immediately before the replace.

### 3. Authorization wiring — both explicit and default paths, per your Step 12.1 scoping decision

- `_text_to_speech_single()`: gained `task_id: str = "default"` parameter. Both branches of its path-resolution block (explicit `output_path` supplied, AND the default auto-generated `audio_cache/` path) now converge on a single call to `_tts_authorize_destination()` before `mkdir()`/synthesis. A `BLOCKED` result short-circuits via `tool_error(...)`, matching the JSON-return contract every other error path in this function already uses.
- `text_to_speech_tool()` (public wrapper): gained `task_id: str = "default"` parameter, forwarded into each `_text_to_speech_single()` call. Removed its own premature `base_path.parent.mkdir()` — directory creation now only happens after the per-chunk authorization succeeds, so nothing is created before authorization runs even for the first chunk.
- Registry handler (`registry.register(name="text_to_speech", ...)`): the dispatch lambda now forwards `task_id=kw.get("task_id") or "default"` from the canonical dispatcher into `text_to_speech_tool()` — mirroring `_handle_write_file`'s existing convention exactly. This closes a real plumbing gap: the lambda previously received `task_id` via `**kw` from the dispatcher but silently dropped it.

### 4. A destructive-delete bug introduced and caught during implementation (worth flagging explicitly, per your "verify every backend" instruction)

While wiring the multi-chunk path in `text_to_speech_tool()`, my first pass added `generated_artifacts.add(str(chunk_path))` **before** calling `_text_to_speech_single()` — using the pre-resolution path. Because `_text_to_speech_single()` can now resolve `chunk_path` to a *different* free path when the original is occupied by a pre-existing file, the cleanup `finally` block would have deleted that unrelated pre-existing file (it wasn't in `final_absolute` because the actual write landed elsewhere). This was caught by `TestExistingFileNeverDestroyed` failing on first run — the exact test this phase was built to have — and fixed by moving the `generated_artifacts` tracking to occur only after the real write path (`actual_path`) is known. This is called out explicitly because it is precisely the class of self-introduced bug your instructions warned against assuming away.

---

## Tests Executed

All runs were fresh, independent `.venv/bin/python -m pytest` processes — no shared state between runs, no truncation, no exit-137, no timeout.

| Batch | Result |
|---|---|
| `test_tts_output_authorization.py` (new, 16 tests) | **16 passed** |
| `test_tts_output_authorization.py` + 3 originally-targeted TTS files | **84 passed** |
| `test_file_write_safety.py` + `test_authorization_scope_phase3.py` | **75 passed** |
| `test_flux3_video_tool.py` (regression check — confirms Flux untouched) | **75 passed** |
| Full `tests/tools/` TTS sweep (`-k "tts"`, all 28 TTS test files) | **258 passed, 7 skipped** |
| `test_file_write_safety.py` + `test_authorization_scope_phase3.py` + `test_flux3_video_tool.py` + `test_file_tools.py` + `test_line_ending_preservation.py` | **201 passed, 2 skipped** |

Zero FAIL, zero ERROR, zero UNVERIFIED across every batch.

---

## Security Properties Verified

| Property | Verified how |
|---|---|
| Existing arbitrary target survives denial | `TestExistingFileNeverDestroyed::test_existing_target_survives_denial` — byte-for-byte comparison after a denied write |
| Existing target never silently truncated/deleted on approval | `TestExistingFileNeverDestroyed::test_existing_target_survives_approval_via_free_path` — confirms original bytes unchanged AND the real write lands on a resolved sibling path, not the occupied target |
| New target creation succeeds | `TestExplicitOutputPathAuthorization::test_new_target_creation_succeeds_with_approval` |
| Explicit `output_path` requires approval | `TestExplicitOutputPathAuthorization::test_explicit_output_path_requests_approval` |
| Default auto-generated path also requires approval (your Step 12.1 scoping decision) | `TestDefaultAutoGeneratedPathAuthorization` (2 tests) |
| Approval denial blocks the write | `TestExplicitOutputPathAuthorization::test_explicit_output_path_denial_blocks_write`, `TestDefaultAutoGeneratedPathAuthorization::test_default_path_denial_blocks_write` |
| No-human-channel fails closed | `TestNoHumanChannelFailClosed::test_no_callback_registered_fails_closed` |
| `--yolo` does not bypass | `TestYoloDoesNotBypass::test_yolo_frozen_still_requires_approval` — freezes `_YOLO_MODE_FROZEN=True`, confirms the callback still fires and denial still blocks |
| `approvals.mode=off` does not bypass | `TestApprovalsModeOffDoesNotBypass::test_approvals_mode_off_still_requires_approval` — patches `_get_approval_mode` to `"off"`, confirms no effect |
| Traversal rejection intact | `TestTraversalStillBlocked::test_traversal_rejected_before_authorization` — also confirms traversal is rejected *before* the approval callback is ever consulted |
| Absolute-path behavior | `TestAbsolutePathBehavior::test_absolute_path_is_honored_and_authorized` |
| Authorized path == actually-written path | `TestFinalResolvedPathMatchesAuthorizedPath::test_authorized_path_is_exactly_the_written_path` — spies on `_check_general_file_write` and asserts the exact path list matches the final `file_path` in the result |
| Every backend covered (single choke point) | `TestEveryBackendCovered` (2 tests) — direct regression test on the ex-`unlink()` backend, plus a task_id-forwarding test proving the shared choke point covers NeuTTS and every other backend by construction, not per-backend duplication |
| Session/task/subagent authorization scope | `TestSessionTaskSubagentAuthorizationScope::test_grant_under_one_task_does_not_satisfy_another_task` — mirrors `test_authorization_scope_phase3.py`'s isolation guarantee for the TTS gate specifically |

## Remaining Findings

None new within Phase 12.1's authorized scope. All items in Ed's Step 12.1 test-requirement list are covered.

## Anything Requiring Additional Authorization

Flux video (D1-B) and send_message provenance (E1) remain unimplemented, per the explicit stop condition — Phase 12.1 is the only phase authorized at this time.

---

**PHASE 12.1 COMPLETE.** All production changes confined to `tools/tts_tool.py`. All four frozen Phase-3 files unchanged. All targeted and regression tests pass in fresh, independent processes. Fail-closed, `--yolo`, `approvals.mode=off`, traversal, path-match, and authorization-scope properties explicitly verified, not assumed. One self-introduced destructive-delete regression was found and fixed during this same implementation pass, before being reported as complete.
