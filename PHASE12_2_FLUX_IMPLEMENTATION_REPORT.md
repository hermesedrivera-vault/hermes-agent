# Phase 12.2 — Flux Video D1-B: Combined Design + Implementation Report

**Scope:** Implement the Step 11-recommended Flux remediation (Option 4 — canonical general file-write authorization only, no separate destructive-write fix needed since `_free_path()` already closes that half). Step 9 Phase 3 remains frozen; Phase 12.1 (TTS) remains unaltered.

---

## Design Summary (combined with implementation per your Step 12.2 instruction)

**Confirmed call chain (read before editing):** `_handle_get_result(args, **kwargs)` → `_poll_until_done(url, save_to, started)` → `_save_if_ready(raw, save_to, started)` → `_download_video(url, save_to, started)` → `_resolve_destination(save_to, filename)` (path resolution only, via `_free_path()`) → `partial.open("wb")` (the actual write).

**Why Option 4 alone is sufficient here (unlike TTS's hybrid):** `_resolve_destination()`/`_free_path()` already guarantee the destructive-overwrite half is closed — confirmed unchanged in this diff. The only residual risk per Step 10.1/Step 11 was arbitrary-path *creation* with no authorization owner. Wiring the canonical gate in front of the already-resolved, already-collision-free `target` path closes that gap completely, with no additional destructive-write remediation required.

**Where authorization was inserted:** Immediately after `_resolve_destination()` returns the final, non-colliding path and before the `.part` file is opened for writing, inside `_download_video()`. This guarantees the exact path authorized is the exact path written — no transformation happens between the check and the write.

**Plumbing:** `task_id` threaded through the full chain — `_handle_get_result` extracts `kwargs.get("task_id") or "default"` (the registry dispatcher already passes this via `**kwargs`, confirmed at `agent/tool_executor.py:684`, same mechanism Phase 12.1 relied on for TTS) — down through `_poll_until_done` → `_save_if_ready` → `_download_video` → `_check_general_file_write()`.

---

## Exact Production Files Changed

**`tools/flux3_video_tool.py` only.** (25 insertions, 6 deletions)

No other production file was modified. The four frozen Phase-3 files remain byte-identical to every prior checkpoint (confirmed via `git diff --stat`: 103/244/36/51 lines, unchanged). `tools/tts_tool.py` (Phase 12.1) was not touched this phase.

## Exact Test Files Changed

**New:**
- `tests/tools/test_flux3_output_authorization.py` — dedicated Phase 12.2 test suite (9 tests).

**Modified (blast radius from the new fail-closed gate, same established fixture pattern used in Phase 12.1 and Step 9 Phase 3):**
- `tests/tools/test_flux3_video_tool.py` — added the identical `_grant_general_file_write_approval` autouse fixture; no assertion removed or weakened.

---

## Complete Diff Summary

1. `_download_video()`: added `task_id: str = "default"` parameter. Immediately after `_resolve_destination()` resolves the target path, calls `tools.file_tools._check_general_file_write([str(target)], task_id)`. A `BLOCKED` result raises `ValueError(blocked)`, which the existing exception handler in `_save_if_ready()` already surfaces as a "saving it failed... poll again to retry" message — no new error-handling path needed, and a retry after a denial simply re-asks for authorization (safe).
2. `_save_if_ready()`, `_poll_until_done()`: gained `task_id: str = "default"` parameters, threaded through their respective downstream calls.
3. `_handle_get_result()`: extracts `task_id = kwargs.get("task_id") or "default"` and passes it into `_poll_until_done()`.
4. No change to `_resolve_destination()` or `_free_path()` — both remain exactly as they were; this phase adds authorization in front of them, not a replacement.

---

## Tests Executed

All fresh, independent `.venv/bin/python -m pytest` processes.

| Batch | Result |
|---|---|
| `test_flux3_output_authorization.py` (new, 9 tests) | **9 passed** |
| `test_flux3_output_authorization.py` + `test_flux3_video_tool.py` | **84 passed** |
| `test_file_write_safety.py` + `test_authorization_scope_phase3.py` | **75 passed** |
| Full TTS regression sweep (confirms Phase 12.1 untouched) | **258 passed, 7 skipped** |

Zero FAIL, zero ERROR, zero UNVERIFIED.

---

## Security Properties Verified

| Property | Verified how |
|---|---|
| Explicit `save_to` requires approval | `TestExplicitSaveToAuthorization::test_...val` |
| Default path (no `save_to`) also requires approval | `TestDefaultPathAuthorization::test_...val` |
| Approval denial blocks the download, no file written | `TestExplicitSaveToAuthorization::test_...oad` |
| No-human-channel fails closed | `TestNoHumanChannelFailClosed::test_no_callback_registered_fails_closed` |
| `--yolo` does not bypass | `TestYoloDoesNotBypass::test_yolo_frozen_still_requires_approval` |
| `approvals.mode=off` does not bypass | `TestApprovalsModeOffDoesNotBypass::test_approvals_mode_off_still_requires_approval` |
| Pre-existing `_free_path()` non-destructive guarantee still holds with authorization in front of it | `TestExistingFileStillNeverOverwritten::test_existing_target_survives_approval_via_free_path` — confirms original bytes at the occupied path are untouched and the actual saved path differs |
| Authorized path == actually-written path | `TestFinalResolvedPathMatchesAuthorizedPath::test_authorized_path_is_exactly_the_written_path` — spies on `_check_general_file_write`, asserts exact match against `saved_path` |
| Session/task/subagent authorization scope | `TestSessionTaskSubagentAuthorizationScope::test_grant_under_one_task_does_not_satisfy_another_task` |

## Note on a test-writing mistake caught and fixed before reporting

An early version of `test_explicit_save_to_denial_blocks_download`/`test_no_callback_registered_fails_closed` asserted `not any(tmp_path.iterdir())`, which failed — not because of a production bug, but because an unrelated ambient `hermes_test` directory (from a separate, unrelated fixture in the test environment) was present in `tmp_path`. Verified via a standalone manual repro that the actual download correctly wrote zero files and returned `BLOCKED` on denial; the assertion was then narrowed to `not any(tmp_path.glob("*.mp4"))`, which is what the test actually needs to prove. Flagged here for the same reason the Phase 12.1 report flagged its self-caught bug: distinguishing a real regression from a test artifact, not silently loosening an assertion to make it pass.

## Remaining Findings

None new within Phase 12.2's authorized scope.

## Anything Requiring Additional Authorization

send_message provenance (E1) remains unimplemented, per the standing stop condition from Step 12's structure — no further phase is authorized without your explicit go-ahead.

---

**PHASE 12.2 COMPLETE.** Production changes confined to `tools/flux3_video_tool.py`. All four frozen Phase-3 files and Phase 12.1's `tools/tts_tool.py` unchanged. Fail-closed, `--yolo`, `approvals.mode=off`, non-destructive-overwrite, path-match, and authorization-scope properties explicitly verified.
