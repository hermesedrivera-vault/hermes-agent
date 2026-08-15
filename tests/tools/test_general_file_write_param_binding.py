"""Step 16 (Finding A+B fix): regression coverage for general file-write
parameter binding.

Companion to ``tests/tools/test_file_write_safety.py::TestGeneralFileWriteApproval``.
Proves the composite-key design (operation_type + canonical resolved-path
hash, folded into the pattern_key and looked up via
``get_current_authorization_key()``) actually closes the two findings:

  Finding A: session-key-only lookup bypassed Phase-3 task/subagent scoping.
  Finding B: fixed ``"general_file_write"`` pattern_key had no path/
             operation binding, so one approval covered every future write.

The feature is gated behind ``approvals.general_file_write_param_binding_enabled``
(default False). These tests monkeypatch
``tools.file_tools._general_file_write_param_binding_enabled`` directly
rather than the config chain, since it's a self-contained boolean check.
"""
import json

import pytest


class _ApprovalHarness:
    """Shared CLI-approval-callback mock + session-state reset, mirroring
    TestGeneralFileWriteApproval's fixtures in test_file_write_safety.py.
    """

    @pytest.fixture
    def approvals(self, monkeypatch):
        from tools.terminal_tool import set_approval_callback
        state = {"calls": [], "answer": "deny"}

        def cb(command, description, **kwargs):
            state["calls"].append(
                {"command": command, "description": description, **kwargs}
            )
            return state["answer"]

        set_approval_callback(cb)
        yield state
        set_approval_callback(None)

    @pytest.fixture(autouse=True)
    def _reset_session_approvals(self):
        import tools.approval as A
        session_key = A.get_current_session_key()
        auth_key = A.get_current_authorization_key()
        A.clear_session(session_key)
        if auth_key != session_key:
            A.clear_session(auth_key)
        yield
        A.clear_session(A.get_current_session_key())
        auth_key2 = A.get_current_authorization_key()
        if auth_key2 != A.get_current_session_key():
            A.clear_session(auth_key2)

    def _write(self, path, content="ordinary content"):
        from tools.file_tools import write_file_tool
        return json.loads(write_file_tool(str(path), content))

    def _patch_replace(self, path, old, new):
        from tools.file_tools import patch_tool
        return json.loads(patch_tool(
            mode="replace", path=str(path), old_string=old, new_string=new,
        ))

    def _patch_v4a(self, patch_text):
        from tools.file_tools import patch_tool
        return json.loads(patch_tool(mode="patch", patch=patch_text))


class TestPatternKeyUnit:
    """Direct unit tests on _general_file_write_pattern_key — no I/O,
    no approval flow. Covers determinism/dedup/ordering/operation-binding
    (matrix items 7, 8, 9).
    """

    def test_deterministic_same_inputs_same_hash(self):
        from tools.file_tools import _general_file_write_pattern_key as key
        k1 = key(["/tmp/a.txt"], "default", "write_file")
        k2 = key(["/tmp/a.txt"], "default", "write_file")
        assert k1 == k2

    def test_different_path_different_hash(self):
        from tools.file_tools import _general_file_write_pattern_key as key
        k_a = key(["/tmp/a.txt"], "default", "write_file")
        k_b = key(["/tmp/b.txt"], "default", "write_file")
        assert k_a != k_b

    def test_different_operation_type_different_hash(self):
        from tools.file_tools import _general_file_write_pattern_key as key
        k_write = key(["/tmp/a.txt"], "default", "write_file")
        k_replace = key(["/tmp/a.txt"], "default", "patch_replace")
        k_v4a = key(["/tmp/a.txt"], "default", "patch_v4a")
        assert len({k_write, k_replace, k_v4a}) == 3

    def test_ordering_is_deterministic(self):
        """Item 7: paths [B, A] and [A, B] must hash identically."""
        from tools.file_tools import _general_file_write_pattern_key as key
        k_ba = key(["/tmp/b.txt", "/tmp/a.txt"], "default", "patch_v4a")
        k_ab = key(["/tmp/a.txt", "/tmp/b.txt"], "default", "patch_v4a")
        assert k_ba == k_ab

    def test_duplicate_paths_do_not_change_identity(self):
        """Item 8: a path listed twice must hash identically to once."""
        from tools.file_tools import _general_file_write_pattern_key as key
        k_dup = key(["/tmp/a.txt", "/tmp/a.txt", "/tmp/b.txt"],
                    "default", "patch_v4a")
        k_single = key(["/tmp/a.txt", "/tmp/b.txt"], "default", "patch_v4a")
        assert k_dup == k_single

    def test_move_source_and_destination_both_bound(self):
        """Item 9: a Move's source and destination are both part of the
        identity — omitting either changes the hash."""
        from tools.file_tools import _general_file_write_pattern_key as key
        both = key(["/tmp/src.txt", "/tmp/dst.txt"], "default", "patch_v4a")
        src_only = key(["/tmp/src.txt"], "default", "patch_v4a")
        dst_only = key(["/tmp/dst.txt"], "default", "patch_v4a")
        assert both != src_only
        assert both != dst_only
        assert src_only != dst_only

    def test_content_is_never_part_of_the_hash(self):
        """The hash contract only ever receives paths + operation_type —
        confirmed by the function signature itself accepting no content
        argument at all. This test documents that contract explicitly:
        two calls with identical paths/operation always match regardless
        of what the caller intends to write."""
        from tools.file_tools import _general_file_write_pattern_key as key
        k1 = key(["/tmp/a.txt"], "default", "write_file")
        k2 = key(["/tmp/a.txt"], "default", "write_file")
        assert k1 == k2  # no content parameter exists to vary


class TestParamBindingEnabled(_ApprovalHarness):
    """Flag ON — the new, fixed behavior. Matrix items 1-4, 6, 10, 11, 14."""

    @pytest.fixture(autouse=True)
    def _flag_on(self, monkeypatch):
        import tools.file_tools as ft
        monkeypatch.setattr(
            ft, "_general_file_write_param_binding_enabled", lambda: True
        )
        yield

    def test_path_a_approval_does_not_authorize_path_b(self, tmp_path, approvals):
        """Item 1: approve write to A, then write to B must re-prompt."""
        approvals["answer"] = "session"
        target_a = tmp_path / "a.txt"
        target_b = tmp_path / "b.txt"
        res_a = self._write(target_a, "content-a")
        assert not res_a.get("error"), res_a
        assert len(approvals["calls"]) == 1

        res_b = self._write(target_b, "content-b")
        assert not res_b.get("error"), res_b
        assert len(approvals["calls"]) == 2, (
            "path B must trigger a SECOND prompt, not reuse path A's grant"
        )

    def test_same_path_same_operation_reuses_session_approval(self, tmp_path, approvals):
        """Item 2: session-approve write to A, then a second write to the
        IDENTICAL path must skip re-prompting."""
        approvals["answer"] = "session"
        target = tmp_path / "a.txt"
        res1 = self._write(target, "first")
        assert not res1.get("error"), res1
        assert len(approvals["calls"]) == 1

        res2 = self._write(target, "second")
        assert not res2.get("error"), res2
        assert len(approvals["calls"]) == 1, (
            "second write to the same path must NOT re-prompt"
        )
        assert target.read_text(encoding="utf-8") == "second"

    def test_write_file_approval_does_not_authorize_patch_replace(self, tmp_path, approvals):
        """Item 3: approve write_file(A), then patch_replace(A) must
        re-prompt — different operation_type, different identity."""
        target = tmp_path / "a.txt"
        target.write_text("before\n", encoding="utf-8")
        approvals["answer"] = "session"

        res_write = self._write(target, "written")
        assert not res_write.get("error"), res_write
        assert len(approvals["calls"]) == 1

        target.write_text("before\n", encoding="utf-8")
        res_patch = self._patch_replace(target, "before", "after")
        assert not res_patch.get("error"), res_patch
        assert len(approvals["calls"]) == 2, (
            "patch_replace must re-prompt even for the same path already "
            "approved for write_file"
        )

    def test_patch_replace_approval_does_not_authorize_patch_v4a(self, tmp_path, approvals):
        """Item 4: approve patch_replace(A), then a V4A patch touching A
        must re-prompt — different operation_type."""
        target = tmp_path / "a.txt"
        target.write_text("before\n", encoding="utf-8")
        approvals["answer"] = "session"

        res_replace = self._patch_replace(target, "before", "after")
        assert not res_replace.get("error"), res_replace
        assert len(approvals["calls"]) == 1

        target.write_text("line1\n", encoding="utf-8")
        v4a = (
            "*** Begin Patch\n"
            f"*** Update File: {target}\n"
            "@@\n"
            "-line1\n"
            "+line1-changed\n"
            "*** End Patch\n"
        )
        res_v4a = self._patch_v4a(v4a)
        assert not res_v4a.get("error"), res_v4a
        assert len(approvals["calls"]) == 2, (
            "patch_v4a must re-prompt even for the same path already "
            "approved for patch_replace"
        )

    def test_always_choice_still_degrades_to_path_operation_bound_grant(
        self, tmp_path, approvals
    ):
        """Item 5 (resolved by investigation): _request_general_file_write_
        approval always passes allow_permanent=False to both the CLI and
        gateway approval surfaces, and its choice-handling treats
        "session" and "always" identically (both call approve_session,
        never approve_permanent). So there is no true global permanent
        tier reachable through this specific gate — "always" is really
        just a synonym for "session" here. This test proves that even
        when the callback answers "always", the resulting grant is STILL
        exactly as path/operation-bound as a "session" grant: it does
        NOT authorize a different path."""
        approvals["answer"] = "always"
        target_a = tmp_path / "a.txt"
        target_b = tmp_path / "b.txt"

        res_a = self._write(target_a, "content-a")
        assert not res_a.get("error"), res_a
        assert len(approvals["calls"]) == 1

        res_b = self._write(target_b, "content-b")
        assert not res_b.get("error"), res_b
        assert len(approvals["calls"]) == 2, (
            "'always' must not blanket-authorize a different path — this "
            "gate has no true permanent tier, so 'always' behaves as a "
            "path-bound session grant"
        )

    def test_v4a_authorization_includes_every_affected_path(self, tmp_path, approvals):
        """Item 6: approving a V4A patch touching paths {A, B} must NOT
        cover a later V4A patch touching {A, C} (a different path set)."""
        target_a = tmp_path / "a.txt"
        target_b = tmp_path / "b.txt"
        target_c = tmp_path / "c.txt"
        target_a.write_text("a1\n", encoding="utf-8")
        target_b.write_text("b1\n", encoding="utf-8")
        target_c.write_text("c1\n", encoding="utf-8")
        approvals["answer"] = "session"

        v4a_ab = (
            "*** Begin Patch\n"
            f"*** Update File: {target_a}\n"
            "@@\n-a1\n+a2\n"
            f"*** Update File: {target_b}\n"
            "@@\n-b1\n+b2\n"
            "*** End Patch\n"
        )
        res1 = self._patch_v4a(v4a_ab)
        assert not res1.get("error"), res1
        assert len(approvals["calls"]) == 1

        target_a.write_text("a2\n", encoding="utf-8")
        v4a_ac = (
            "*** Begin Patch\n"
            f"*** Update File: {target_a}\n"
            "@@\n-a2\n+a3\n"
            f"*** Update File: {target_c}\n"
            "@@\n-c1\n+c2\n"
            "*** End Patch\n"
        )
        res2 = self._patch_v4a(v4a_ac)
        assert not res2.get("error"), res2
        assert len(approvals["calls"]) == 2, (
            "a V4A patch touching a DIFFERENT path set ({A,C} vs {A,B}) "
            "must re-prompt, proving the full affected-path set is bound"
        )

    def test_symlink_target_is_gated_without_error(self, tmp_path, approvals):
        """Item 10: writing through a symlink still works — no crash, no
        silent bypass, resolution stays consistent with
        _resolve_path_for_task's existing (unchanged) behavior."""
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        real_target = real_dir / "target.txt"
        link = tmp_path / "link.txt"
        link.symlink_to(real_target)
        approvals["answer"] = "once"

        res = self._write(link, "via symlink")
        assert not res.get("error"), res
        assert len(approvals["calls"]) == 1

    def test_authorization_identity_matches_actual_write_path(self, tmp_path, approvals, monkeypatch):
        """Item 11: the resolved path fed into the hash is the same one
        that ends up written to disk."""
        import tools.file_tools as ft
        target = tmp_path / "a.txt"
        approvals["answer"] = "once"

        captured = {}
        real_key_fn = ft._general_file_write_pattern_key

        def spy(paths, task_id, operation_type):
            captured["paths"] = list(paths)
            return real_key_fn(paths, task_id, operation_type)

        monkeypatch.setattr(ft, "_general_file_write_pattern_key", spy)
        res = self._write(target, "content")
        assert not res.get("error"), res
        assert captured.get("paths") == [str(target)]
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "content"

    def test_flag_enabled_causes_reprompt_for_different_path(self, tmp_path, approvals):
        """Item 14: with the flag ON, path B must re-prompt (the direct
        counterpart to the flag-OFF test in TestParamBindingDisabled)."""
        approvals["answer"] = "session"
        target_a = tmp_path / "a.txt"
        target_b = tmp_path / "b.txt"
        self._write(target_a, "a")
        assert len(approvals["calls"]) == 1
        self._write(target_b, "b")
        assert len(approvals["calls"]) == 2

    def test_protected_instruction_gate_still_controls_agents_md_when_flag_on(
        self, tmp_path, approvals, monkeypatch
    ):
        """Item 15: AGENTS.md-class targets remain governed by the
        separate, stricter protected-instruction gate even with the
        param-binding flag on — the general gate never even sees them."""
        import tools.file_tools as ft
        monkeypatch.setattr(
            ft, "_protected_instruction_config", lambda: (True, [])
        )
        target = tmp_path / "AGENTS.md"
        approvals["answer"] = "deny"
        res = self._write(target, "malicious instruction change")
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert not target.exists()

    def test_fail_closed_when_pattern_key_computation_raises(self, tmp_path, monkeypatch):
        """Item 12: if the new hashing helper blows up, the write must
        fail closed (clean BLOCKED, no raw exception, file never
        written) — same contract as the pre-existing approval-subsystem-
        unavailable test in test_file_write_safety.py."""
        import tools.file_tools as ft

        def _boom(*a, **kw):
            raise RuntimeError("hash computation exploded")

        monkeypatch.setattr(ft, "_general_file_write_pattern_key", _boom)
        target = tmp_path / "a.txt"
        res = self._write(target, "x")  # must NOT raise
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert not target.exists()


class TestParamBindingDisabled(_ApprovalHarness):
    """Flag OFF (default) — must reproduce the exact pre-fix behavior for
    a safe, reversible rollout. Matrix item 13."""

    @pytest.fixture(autouse=True)
    def _flag_off(self, monkeypatch):
        import tools.file_tools as ft
        monkeypatch.setattr(
            ft, "_general_file_write_param_binding_enabled", lambda: False
        )
        yield

    def test_flag_disabled_preserves_old_cross_path_reuse_behavior(self, tmp_path, approvals):
        """Item 13: with the flag OFF, approving write to A and then
        writing to B in the same session must NOT re-prompt — this is the
        OLD (defective) behavior, intentionally preserved while disabled
        so the rollout is safe and reversible."""
        approvals["answer"] = "session"
        target_a = tmp_path / "a.txt"
        target_b = tmp_path / "b.txt"

        res_a = self._write(target_a, "content-a")
        assert not res_a.get("error"), res_a
        assert len(approvals["calls"]) == 1

        res_b = self._write(target_b, "content-b")
        assert not res_b.get("error"), res_b
        assert len(approvals["calls"]) == 1, (
            "with the flag OFF, path B must reuse path A's session grant "
            "(old, pre-fix behavior) — proving the rollback path works"
        )

    def test_flag_disabled_write_file_and_patch_share_one_grant(self, tmp_path, approvals):
        """With the flag OFF, write_file and patch also share the same
        bare pattern_key — confirms disabled behavior is byte-for-byte
        the pre-fix code, including the operation-type blindness."""
        target = tmp_path / "a.txt"
        target.write_text("before\n", encoding="utf-8")
        approvals["answer"] = "session"

        res_write = self._write(target, "written")
        assert not res_write.get("error"), res_write
        assert len(approvals["calls"]) == 1

        target.write_text("before\n", encoding="utf-8")
        res_patch = self._patch_replace(target, "before", "after")
        assert not res_patch.get("error"), res_patch
        assert len(approvals["calls"]) == 1, (
            "flag OFF must preserve the old operation-blind reuse too"
        )


# Item 16 (cross-profile / sensitive-path protections): untouched by this
# fix — those gates run BEFORE _check_general_file_write in write_file_tool/
# patch_tool and are already covered by test_cross_profile_guard.py and
# test_file_write_safety.py's TestCheckSensitivePathMacOSBypass. Not
# re-tested here to keep this file focused on the parameter-binding change.


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
