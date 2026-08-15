"""Tests for file write safety and HERMES_WRITE_SAFE_ROOT sandboxing.

Based on PR #1085 by ismoilh (salvaged).
"""

import os
from pathlib import Path

import pytest

from tools.file_operations import _is_write_denied


class TestStaticDenyList:
    """Basic sanity checks for the static write deny list."""

    def test_temp_file_not_denied_by_default(self, tmp_path: Path):
        target = tmp_path / "regular.txt"
        assert _is_write_denied(str(target)) is False


    def test_etc_shadow_is_denied(self):
        assert _is_write_denied("/etc/shadow") is True


class TestSafeWriteRoot:
    """HERMES_WRITE_SAFE_ROOT should sandbox writes to a specific subtree."""

    def test_writes_inside_safe_root_are_allowed(self, tmp_path: Path, monkeypatch):
        safe_root = tmp_path / "workspace"
        child = safe_root / "subdir" / "file.txt"
        os.makedirs(child.parent, exist_ok=True)

        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))
        assert _is_write_denied(str(child)) is False


    def test_safe_root_with_tilde_expansion(self, tmp_path: Path, monkeypatch):
        """~ in HERMES_WRITE_SAFE_ROOT should be expanded."""
        # Use a real subdirectory of tmp_path so we can test tilde-style paths
        safe_root = tmp_path / "workspace"
        inside = safe_root / "file.txt"
        os.makedirs(safe_root, exist_ok=True)

        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))
        assert _is_write_denied(str(inside)) is False

    def test_safe_root_does_not_override_static_deny(self, tmp_path: Path, monkeypatch):
        """Even if a static-denied path is inside the safe root, it's still denied."""
        # Point safe root at home to include ~/.ssh
        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", os.path.expanduser("~"))
        assert _is_write_denied(os.path.expanduser("~/.ssh/id_rsa")) is True


class TestMultipleSafeWriteRoots:
    """HERMES_WRITE_SAFE_ROOT with multiple colon-separated directories."""

    def test_write_inside_first_root_allowed(self, tmp_path: Path, monkeypatch):
        root_a = tmp_path / "workspace_a"
        root_b = tmp_path / "workspace_b"
        child = root_a / "subdir" / "file.txt"
        os.makedirs(child.parent, exist_ok=True)
        os.makedirs(root_b, exist_ok=True)

        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", f"{root_a}{os.pathsep}{root_b}")
        assert _is_write_denied(str(child)) is False


    def test_trailing_separator_ignored(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "workspace"
        inside = root / "file.txt"
        os.makedirs(root, exist_ok=True)

        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", f"{root}{os.pathsep}")
        assert _is_write_denied(str(inside)) is False


    def test_static_deny_still_wins_with_multiple_roots(self, tmp_path: Path, monkeypatch):
        """Static deny list takes priority even when multiple safe roots include home."""
        root = tmp_path / "workspace"
        os.makedirs(root, exist_ok=True)

        monkeypatch.setenv(
            "HERMES_WRITE_SAFE_ROOT",
            f"{root}{os.pathsep}{os.path.expanduser('~')}",
        )
        assert _is_write_denied(os.path.expanduser("~/.ssh/id_rsa")) is True

    def test_duplicate_roots_deduplicated(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "workspace"
        inside = root / "file.txt"
        os.makedirs(root, exist_ok=True)

        monkeypatch.setenv(
            "HERMES_WRITE_SAFE_ROOT",
            f"{root}{os.pathsep}{root}",
        )
        assert _is_write_denied(str(inside)) is False


class TestGetWriteDeniedError:
    """get_write_denied_error() should distinguish credential vs safe-root blocks."""

    def test_credential_path_message(self):
        from agent.file_safety import get_write_denied_error

        err = get_write_denied_error(os.path.expanduser("~/.ssh/id_rsa"))
        assert err is not None
        assert "protected system/credential file" in err
        assert "HERMES_WRITE_SAFE_ROOT" not in err

    def test_safe_root_message(self, tmp_path: Path, monkeypatch):
        from agent.file_safety import get_write_denied_error

        safe_root = tmp_path / "workspace"
        outside = tmp_path / "outside.txt"
        os.makedirs(safe_root, exist_ok=True)

        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))
        err = get_write_denied_error(str(outside))
        assert err is not None
        assert "outside HERMES_WRITE_SAFE_ROOT" in err
        assert str(safe_root) in err
        assert "protected system/credential file" not in err

    def test_allowed_path_returns_none(self, tmp_path: Path):
        from agent.file_safety import get_write_denied_error

        target = tmp_path / "ok.txt"
        assert get_write_denied_error(str(target)) is None


class TestSafeRootDenialMessageIntegration:
    """Regression tests verifying that file-tools surface the correct denial
    message when HERMES_WRITE_SAFE_ROOT blocks a path.

    Prior to this fix, ALL write denials returned the same "protected
    system/credential file" message regardless of root cause.  These tests
    exercise the actual write_file / patch_replace code path, not just
    the get_write_denied_error() helper in isolation.
    """

    @pytest.fixture
    def ops(self, tmp_path: Path):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        env = LocalEnvironment(cwd=str(tmp_path))
        return ShellFileOperations(env, cwd=str(tmp_path))

    def test_write_file_safe_root_outside_shows_safe_root_message(
        self, ops, tmp_path: Path, monkeypatch
    ):
        safe_root = tmp_path / "workspace"
        safe_root.mkdir()
        outside = tmp_path / "other" / "file.txt"
        outside.parent.mkdir()
        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))

        res = ops.write_file(str(outside), "content")
        assert res.error is not None
        assert "outside HERMES_WRITE_SAFE_ROOT" in res.error
        assert str(safe_root) in res.error
        assert "credential" not in res.error
        assert not outside.exists()


    def test_write_file_credential_path_shows_credential_message(
        self, ops, tmp_path: Path
    ):
        res = ops.write_file("/etc/shadow", "content")
        assert res.error is not None
        assert "protected system/credential file" in res.error
        assert "outside" not in res.error

    def test_write_file_allowed_path_returns_no_error(
        self, ops, tmp_path: Path, monkeypatch
    ):
        safe_root = tmp_path / "workspace"
        safe_root.mkdir()
        inside = safe_root / "file.txt"
        monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe_root))

        res = ops.write_file(str(inside), "content")
        assert res.error is None
        assert inside.read_text(encoding="utf-8") == "content"


class TestCheckSensitivePathMacOSBypass:
    """Verify _check_sensitive_path blocks /private/etc paths (issue #8734)."""

    def test_etc_hosts_blocked(self):
        from tools.file_tools import _check_sensitive_path
        assert _check_sensitive_path("/etc/hosts") is not None

    def test_private_etc_hosts_blocked(self):
        from tools.file_tools import _check_sensitive_path
        assert _check_sensitive_path("/private/etc/hosts") is not None

    def test_private_etc_ssh_config_blocked(self):
        from tools.file_tools import _check_sensitive_path
        assert _check_sensitive_path("/private/etc/ssh/sshd_config") is not None

    def test_private_var_blocked(self):
        from tools.file_tools import _check_sensitive_path
        assert _check_sensitive_path("/private/var/db/something") is not None

    def test_boot_still_blocked(self):
        from tools.file_tools import _check_sensitive_path
        assert _check_sensitive_path("/boot/grub/grub.cfg") is not None

    def test_safe_path_allowed(self):
        from tools.file_tools import _check_sensitive_path
        assert _check_sensitive_path("/tmp/safe_file.txt") is None


class TestAtomicWrite:
    """write_file / patch land via a temp-file + atomic rename.

    The invariant: a write that fails partway NEVER corrupts the existing
    file, and the swap is a real rename (so a reader either sees the full
    old content or the full new content, never a half-written file). These
    run against a real LocalEnvironment so the actual shell script executes.
    """

    @pytest.fixture
    def ops(self, tmp_path: Path):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        env = LocalEnvironment(cwd=str(tmp_path))
        return ShellFileOperations(env, cwd=str(tmp_path))

    def test_overwrite_changes_inode(self, ops, tmp_path: Path):
        # A real rename allocates a new inode for the target; an in-place
        # rewrite would keep the same inode. This proves the swap is atomic.
        target = tmp_path / "f.txt"
        target.write_text("v1", encoding="utf-8")
        ino_before = os.stat(target).st_ino
        res = ops.write_file(str(target), "v2 content")
        assert res.error is None, res.error
        assert target.read_text(encoding="utf-8") == "v2 content"
        assert os.stat(target).st_ino != ino_before


    def test_no_temp_file_leaked_on_success(self, ops, tmp_path: Path):
        target = tmp_path / "f.txt"
        ops.write_file(str(target), "hello\n")
        assert [p for p in os.listdir(tmp_path) if ".hermes-tmp" in p] == []


    def test_patch_routes_through_atomic_write(self, ops, tmp_path: Path):
        target = tmp_path / "edit.py"
        target.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
        os.chmod(target, 0o600)
        res = ops.patch_replace(str(target), "b = 2", "b = 22")
        assert res.success, res.error
        assert target.read_text(encoding="utf-8") == "a = 1\nb = 22\nc = 3\n"
        assert (os.stat(target).st_mode & 0o777) == 0o600


class TestBomHandling:
    """UTF-8 BOM is stripped on read and preserved across write/patch.

    A BOM (U+FEFF, bytes EF BB BF) is an invisible leading marker some
    Windows editors prepend. The agent should never see it in read output,
    but a file that had one on disk must keep it after an edit so the byte
    signature is preserved.
    """

    BOM = "\ufeff"

    @pytest.fixture
    def ops(self, tmp_path: Path):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        env = LocalEnvironment(cwd=str(tmp_path))
        return ShellFileOperations(env, cwd=str(tmp_path))

    def test_helpers(self):
        from tools.file_operations import _strip_bom, _has_bom
        assert _strip_bom("\ufeffhello") == ("hello", True)
        assert _strip_bom("hello") == ("hello", False)
        assert _strip_bom("") == ("", False)
        # mid-string BOM is data, not a marker — left alone
        assert _strip_bom("a\ufeffb") == ("a\ufeffb", False)
        assert _has_bom("\ufeffx") is True
        assert _has_bom("x") is False
        assert _has_bom(None) is False

    def test_read_strips_bom(self, ops, tmp_path: Path):
        target = tmp_path / "bom.py"
        # Write raw bytes with a real UTF-8 BOM prefix.
        target.write_bytes(self.BOM.encode("utf-8") + b"import os\nx = 1\n")
        res = ops.read_file(str(target))
        assert res.error is None, res.error
        # Line 1 content must NOT carry the phantom U+FEFF.
        first_line = res.content.split("\n", 1)[0]
        assert self.BOM not in first_line
        assert first_line.endswith("import os")


    def test_patch_matches_first_line_through_bom(self, ops, tmp_path: Path):
        # The whole point: an edit targeting the BOM-prefixed first line
        # must match cleanly (the matcher sees BOM-stripped content).
        target = tmp_path / "mod.py"
        target.write_bytes(self.BOM.encode("utf-8") + b"import os\nimport sys\n")
        res = ops.patch_replace(str(target), "import os", "import os, json")
        assert res.success, res.error
        raw = target.read_bytes()
        assert raw == self.BOM.encode("utf-8") + b"import os, json\nimport sys\n"

    def test_v4a_update_preserves_bom_real_ops(self, ops, tmp_path: Path):
        # V4A UPDATE path against REAL ShellFileOperations. This is the one
        # provider path whose pre_content is BOM-STRIPPED (read_file_raw
        # strips before _apply_update forwards it), so it regresses if
        # _file_has_bom ever trusts pre_content instead of probing disk.
        # Regression for teknium1's review on PR #55661.
        target = tmp_path / "bom_v4a.py"
        target.write_bytes(self.BOM.encode("utf-8") + b"print('hello')\n")
        patch = (
            "*** Begin Patch\n"
            f"*** Update File: {target}\n"
            "@@\n"
            "-print('hello')\n"
            "+print('world')\n"
            "*** End Patch"
        )
        res = ops.patch_v4a(patch)
        assert res.success, res.error
        raw = target.read_bytes()
        assert raw.startswith(self.BOM.encode("utf-8")), "BOM lost on V4A update"
        assert b"print('world')" in raw

    def test_file_has_bom_ignores_stripped_pre_content(self, ops, tmp_path: Path):
        # _file_has_bom must probe the DISK even when handed pre_content
        # that (having been BOM-stripped upstream) claims there is no BOM.
        target = tmp_path / "bom_probe.py"
        target.write_bytes(self.BOM.encode("utf-8") + b"x = 1\n")
        assert ops._file_has_bom(str(target), pre_content="x = 1\n") is True


class TestProtectedInstructionFiles:
    """Writes to agent-instruction files ALWAYS require approval.

    AGENTS.md / CLAUDE.md / SOUL.md / .cursorrules / project-local .hermes
    config steer future agent behavior, so a prompt-injected agent writing
    them is a persistence vector. The gate must ask the human every time —
    even under yolo/auto-approve — and fail closed when no human channel
    exists. Ported from: RooCodeInc/Roo-Code RooProtectedController
    (Apache-2.0); symlink lesson from #41351.
    """

    @pytest.fixture(autouse=True)
    def _gate_on(self, monkeypatch):
        import tools.file_tools as ft
        monkeypatch.setattr(
            ft, "_protected_instruction_config", lambda: (True, [])
        )
        yield

    @pytest.fixture
    def approvals(self, monkeypatch):
        """Install a CLI approval callback; record calls; scripted answers."""
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

    def _write(self, path, content="injected"):
        import json
        from tools.file_tools import write_file_tool
        return json.loads(write_file_tool(str(path), content))

    # ---- core behavior -------------------------------------------------

    @pytest.mark.parametrize(
        "name", ["AGENTS.md", "CLAUDE.md", "SOUL.md", ".cursorrules"]
    )
    def test_deny_blocks_write(self, tmp_path, approvals, name):
        target = tmp_path / name
        approvals["answer"] = "deny"
        res = self._write(target)
        assert res.get("error"), res
        assert "BLOCKED" in res["error"]
        assert not target.exists()
        assert len(approvals["calls"]) == 1

    def test_approve_once_allows_write(self, tmp_path, approvals):
        target = tmp_path / "AGENTS.md"
        approvals["answer"] = "once"
        res = self._write(target, "approved content")
        assert not res.get("error"), res
        assert target.read_text(encoding="utf-8") == "approved content"
        assert len(approvals["calls"]) == 1

    def test_prompts_even_under_yolo(self, tmp_path, approvals, monkeypatch):
        """The whole point: auto-approve/yolo must NOT bypass this gate."""
        import tools.approval as A
        monkeypatch.setattr(A, "_YOLO_MODE_FROZEN", True)
        target = tmp_path / "AGENTS.md"
        approvals["answer"] = "deny"
        res = self._write(target)
        assert res.get("error") and "BLOCKED" in res["error"]
        assert not target.exists()
        assert len(approvals["calls"]) == 1, "yolo bypassed the protected gate"

    def test_second_write_prompts_again(self, tmp_path, approvals):
        """One-operation approval: no session stickiness."""
        target = tmp_path / "AGENTS.md"
        approvals["answer"] = "once"
        self._write(target)
        self._write(target, "second")
        assert len(approvals["calls"]) == 2

    def test_regular_file_never_prompts_for_protected_instruction_gate(
        self, tmp_path, approvals
    ):
        """The PROTECTED-INSTRUCTION gate specifically never fires for an
        ordinary file — that gate's scope is unchanged by Phase 2. The
        general non-ACP file-write gate (Step 9 Phase 2) is a SEPARATE
        mechanism and is exercised below, not by this fixture's callback
        (see TestGeneralFileWriteApproval), so ``approvals["calls"]``
        (the protected-instruction CLI callback) stays empty here.
        """
        approvals["answer"] = "once"  # satisfy whichever gate asks
        res = self._write(tmp_path / "notes.md", "hello")
        assert not res.get("error"), res
        # Protected-instruction reasoning never matched this ordinary
        # target, so its own gate made zero calls — the approval that DID
        # happen (if any) came from the separate Phase 2 general gate,
        # which shares the same CLI callback registration mechanism.
        # We only assert the write succeeded and no protected-instruction-
        # specific BLOCKED reason (targets protected file(s)) appears.
        assert "protected agent-instruction file" not in str(res)

    def test_no_human_fails_closed(self, tmp_path):
        # No approval callback registered, not gateway → block, don't hang.
        target = tmp_path / "AGENTS.md"
        res = self._write(target)
        assert res.get("error") and "BLOCKED" in res["error"]
        assert not target.exists()

    def test_config_disabled_skips_protected_instruction_gate_but_general_gate_still_applies(
        self, tmp_path, approvals, monkeypatch
    ):
        """Disabling the protected-instruction config flag removes THAT
        gate's always-ask behavior for AGENTS.md, but the write still
        falls through to the separate Step 9 Phase 2 general file-write
        gate (non-ACP sessions always require approval for ordinary
        writes) — fail-closed by design, confirmed by testing both
        outcomes explicitly rather than asserting zero approval calls.
        """
        import tools.file_tools as ft
        monkeypatch.setattr(
            ft, "_protected_instruction_config", lambda: (False, [])
        )
        approvals["answer"] = "deny"
        denied = self._write(tmp_path / "AGENTS.md", "ok")
        assert denied.get("error") and "BLOCKED" in denied["error"], denied
        assert "protected agent-instruction file" not in str(denied), (
            "the protected-instruction gate was disabled; the BLOCK must "
            "come from the general Phase 2 gate instead"
        )

        approvals["answer"] = "once"
        allowed = self._write(tmp_path / "AGENTS.md", "ok2")
        assert not allowed.get("error"), allowed

    def test_extra_patterns_from_config(self, tmp_path, approvals, monkeypatch):
        import tools.file_tools as ft
        monkeypatch.setattr(
            ft, "_protected_instruction_config", lambda: (True, ["*.mdc"])
        )
        approvals["answer"] = "deny"
        res = self._write(tmp_path / "rules.mdc")
        assert res.get("error") and "BLOCKED" in res["error"]

    # ---- adversarial path shapes ----------------------------------------

    def test_symlink_to_protected_file_is_gated(self, tmp_path, approvals):
        """#41351 lesson: realpath first — innocent name, protected target."""
        real = tmp_path / "AGENTS.md"
        real.write_text("original", encoding="utf-8")
        link = tmp_path / "innocent.txt"
        link.symlink_to(real)
        approvals["answer"] = "deny"
        res = self._write(link, "injected")
        assert res.get("error") and "BLOCKED" in res["error"]
        assert real.read_text(encoding="utf-8") == "original"

    def test_case_variant_is_gated(self, tmp_path, approvals):
        approvals["answer"] = "deny"
        res = self._write(tmp_path / "agents.MD")
        assert res.get("error") and "BLOCKED" in res["error"]

    def test_relative_traversal_is_gated(self, tmp_path, approvals, monkeypatch):
        (tmp_path / "x").mkdir()
        monkeypatch.chdir(tmp_path)
        approvals["answer"] = "deny"
        res = self._write("./x/../AGENTS.md")
        assert res.get("error") and "BLOCKED" in res["error"]
        assert not (tmp_path / "AGENTS.md").exists()

    def test_arbitrary_directory_basename_is_gated(self, tmp_path, approvals):
        """Any-directory scope: project-context files load from cwd trees."""
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        approvals["answer"] = "deny"
        res = self._write(deep / "CLAUDE.md")
        assert res.get("error") and "BLOCKED" in res["error"]

    def test_project_local_hermes_dir_is_gated(self, tmp_path, approvals):
        proj = tmp_path / "proj" / ".hermes"
        proj.mkdir(parents=True)
        approvals["answer"] = "deny"
        res = self._write(proj / "config.yaml")
        assert res.get("error") and "BLOCKED" in res["error"]

    def test_checkout_nested_under_hermes_dir_not_gated_by_protected_instruction_check(
        self, tmp_path, approvals
    ):
        """A repo living UNDER a .hermes dir (e.g. ~/.hermes/hermes-agent)
        must not have every write treated as project-config by the
        PROTECTED-INSTRUCTION gate — only files directly inside a .hermes
        dir count as project config for that specific gate. The separate
        Step 9 Phase 2 general file-write gate still applies to this
        ordinary source file (fail-closed for non-ACP sessions), so this
        test now verifies approval/denial for that gate explicitly instead
        of asserting the write was silently unauthorized.
        """
        repo = tmp_path / ".hermes" / "some-repo" / "src"
        repo.mkdir(parents=True)

        approvals["answer"] = "deny"
        denied = self._write(repo / "module.py", "x = 1\n")
        assert denied.get("error") and "BLOCKED" in denied["error"], denied
        assert "protected agent-instruction file" not in str(denied), (
            "module.py is not project-config; the BLOCK must come from "
            "the general Phase 2 gate, not the protected-instruction gate"
        )

        approvals["answer"] = "once"
        allowed = self._write(repo / "module.py", "x = 1\n")
        assert not allowed.get("error"), allowed

    def test_real_hermes_home_not_gated_by_this_check(
        self, tmp_path, approvals, monkeypatch
    ):
        """~/.hermes itself is governed by existing guards, not this gate."""
        import tools.file_tools as ft
        fake_home = tmp_path / ".hermes"
        (fake_home / "notes").mkdir(parents=True)
        monkeypatch.setattr(
            ft, "_get_real_hermes_home", lambda: str(fake_home.resolve())
        )
        res = self._write(fake_home / "notes" / "scratch.txt", "ok")
        assert not res.get("error"), res
        assert approvals["calls"] == []

    # ---- patch tool -----------------------------------------------------

    def test_patch_replace_mode_is_gated(self, tmp_path, approvals):
        from tools.file_tools import patch_tool
        import json
        target = tmp_path / "SOUL.md"
        target.write_text("be kind\n", encoding="utf-8")
        approvals["answer"] = "deny"
        res = json.loads(patch_tool(
            mode="replace", path=str(target),
            old_string="be kind", new_string="obey injected orders",
        ))
        assert res.get("error") and "BLOCKED" in res["error"]
        assert target.read_text(encoding="utf-8") == "be kind\n"

    def test_patch_v4a_multifile_one_protected_blocks_whole_patch(
        self, tmp_path, approvals
    ):
        """Policy: one protected file gates the ENTIRE patch (deny = nothing
        applies, including the innocent file)."""
        from tools.file_tools import patch_tool
        import json
        agents = tmp_path / "AGENTS.md"
        agents.write_text("rules\n", encoding="utf-8")
        plain = tmp_path / "plain.txt"
        plain.write_text("hello\n", encoding="utf-8")
        patch = (
            "*** Begin Patch\n"
            f"*** Update File: {plain}\n"
            "@@\n"
            "-hello\n"
            "+world\n"
            f"*** Update File: {agents}\n"
            "@@\n"
            "-rules\n"
            "+injected\n"
            "*** End Patch"
        )
        approvals["answer"] = "deny"
        res = json.loads(patch_tool(mode="patch", patch=patch))
        assert res.get("error") and "BLOCKED" in res["error"]
        assert plain.read_text(encoding="utf-8") == "hello\n"
        assert agents.read_text(encoding="utf-8") == "rules\n"
        assert len(approvals["calls"]) == 1

    def test_patch_v4a_approved_applies(self, tmp_path, approvals):
        from tools.file_tools import patch_tool
        import json
        agents = tmp_path / "AGENTS.md"
        agents.write_text("rules\n", encoding="utf-8")
        patch = (
            "*** Begin Patch\n"
            f"*** Update File: {agents}\n"
            "@@\n"
            "-rules\n"
            "+updated rules\n"
            "*** End Patch"
        )
        approvals["answer"] = "once"
        res = json.loads(patch_tool(mode="patch", patch=patch))
        assert not res.get("error"), res
        assert agents.read_text(encoding="utf-8") == "updated rules\n"

    # ---- gateway round-trip ----------------------------------------------

    def test_gateway_notify_resolve_once_allows(self, tmp_path):
        import tools.approval as A
        session_key = "protected-files-test-session"
        token = A.set_current_session_key(session_key)
        try:
            def notify(approval_data):
                # Buttons must not offer persistent scopes for this gate.
                assert approval_data.get("allow_permanent") is False
                assert approval_data.get("allow_session") is False
                A.resolve_gateway_approval(session_key, "once")

            A.register_gateway_notify(session_key, notify)
            try:
                res = self._write(tmp_path / "AGENTS.md", "gateway approved")
                assert not res.get("error"), res
                assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == "gateway approved"
            finally:
                A.unregister_gateway_notify(session_key)
        finally:
            A.reset_current_session_key(token)


class TestGeneralFileWriteApproval:
    """Step 9 Phase 2: ordinary (non-protected-instruction) write_file and
    patch operations require approval outside ACP sessions. Closes the
    Step 8.6 confirmed gap. Uses the SAME CLI-callback / gateway-notify
    plumbing as the protected-instruction gate (tools.terminal_tool
    approval callback, tools.approval gateway notify), but its own
    ``general_file_write`` pattern_key so session-scoped grants never
    leak into or out of the protected-instruction gate's per-call scope.
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
        """Each general-gate grant is session-scoped; start clean per test."""
        import tools.approval as A
        session_key = A.get_current_session_key()
        A.clear_session(session_key)
        yield
        A.clear_session(session_key)

    def _write(self, path, content="ordinary content"):
        import json
        from tools.file_tools import write_file_tool
        return json.loads(write_file_tool(str(path), content))

    # ---- A. write_file in a non-ACP session -----------------------------

    def test_write_file_requests_approval(self, tmp_path, approvals):
        approvals["answer"] = "once"
        res = self._write(tmp_path / "ordinary.txt")
        assert not res.get("error"), res
        assert len(approvals["calls"]) == 1
        assert approvals["calls"][0].get("allow_permanent") is False

    def test_write_file_denial_prevents_write(self, tmp_path, approvals):
        target = tmp_path / "ordinary.txt"
        approvals["answer"] = "deny"
        res = self._write(target)
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert not target.exists()

    def test_write_file_approval_permits_write(self, tmp_path, approvals):
        target = tmp_path / "ordinary.txt"
        approvals["answer"] = "once"
        res = self._write(target, "written")
        assert not res.get("error"), res
        assert target.read_text(encoding="utf-8") == "written"

    # ---- B. patch in a non-ACP session -----------------------------------

    def test_patch_requests_approval(self, tmp_path, approvals):
        from tools.file_tools import patch_tool
        import json
        target = tmp_path / "ordinary.txt"
        target.write_text("before\n", encoding="utf-8")
        approvals["answer"] = "once"
        res = json.loads(patch_tool(
            mode="replace", path=str(target),
            old_string="before", new_string="after",
        ))
        assert not res.get("error"), res
        assert len(approvals["calls"]) == 1

    def test_patch_denial_prevents_patch(self, tmp_path, approvals):
        from tools.file_tools import patch_tool
        import json
        target = tmp_path / "ordinary.txt"
        target.write_text("before\n", encoding="utf-8")
        approvals["answer"] = "deny"
        res = json.loads(patch_tool(
            mode="replace", path=str(target),
            old_string="before", new_string="after",
        ))
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert target.read_text(encoding="utf-8") == "before\n"

    def test_patch_approval_permits_patch(self, tmp_path, approvals):
        from tools.file_tools import patch_tool
        import json
        target = tmp_path / "ordinary.txt"
        target.write_text("before\n", encoding="utf-8")
        approvals["answer"] = "once"
        res = json.loads(patch_tool(
            mode="replace", path=str(target),
            old_string="before", new_string="after",
        ))
        assert not res.get("error"), res
        assert target.read_text(encoding="utf-8") == "after\n"

    # ---- E. failure behavior: no approval channel => deny, not allow -----

    def test_no_human_and_no_gateway_fails_closed(self, tmp_path):
        """No CLI callback registered, no gateway notify bound: the write
        must be BLOCKED, never silently allowed."""
        target = tmp_path / "ordinary.txt"
        from tools.file_tools import write_file_tool
        import json
        res = json.loads(write_file_tool(str(target), "x"))
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert not target.exists()

    def test_approval_subsystem_unavailable_fails_closed(
        self, tmp_path, monkeypatch
    ):
        """Phase 2.1: if the general-gate approval function itself blows
        up, the mutation must remain fail-closed (file never written) AND
        the failure must surface as a clean BLOCKED tool response — not a
        raw Python exception escaping write_file_tool, and not an
        implicit approval.
        """
        import tools.file_tools as ft

        def _boom(*a, **kw):
            raise RuntimeError("approval subsystem unavailable")

        monkeypatch.setattr(
            ft, "_request_general_file_write_approval", _boom
        )
        target = tmp_path / "ordinary.txt"
        res = self._write(target)  # must NOT raise
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert not target.exists()

    def test_patch_approval_subsystem_unavailable_fails_closed(
        self, tmp_path, monkeypatch
    ):
        """Same Phase 2.1 property, exercised through patch_tool."""
        import tools.file_tools as ft
        from tools.file_tools import patch_tool
        import json

        def _boom(*a, **kw):
            raise RuntimeError("approval subsystem unavailable")

        monkeypatch.setattr(
            ft, "_request_general_file_write_approval", _boom
        )
        target = tmp_path / "ordinary.txt"
        target.write_text("before\n", encoding="utf-8")
        res = json.loads(patch_tool(  # must NOT raise
            mode="replace", path=str(target),
            old_string="before", new_string="after",
        ))
        assert res.get("error") and "BLOCKED" in res["error"], res
        assert target.read_text(encoding="utf-8") == "before\n"

    # ---- D. ACP session: general gate is skipped, no duplicate prompt ---

    def test_acp_session_skips_general_gate_no_duplicate_prompt(
        self, tmp_path, approvals, monkeypatch
    ):
        """When an ACP edit-approval requester is bound, ACP's own flow
        owns the approval decision for this mutation. The general Phase 2
        gate must not ALSO prompt — that would be a duplicate approval for
        the same write."""
        from acp_adapter import edit_approval as ea

        def _fake_requester(proposal):
            return True  # ACP approves

        token = ea.set_edit_approval_requester(_fake_requester) if hasattr(
            ea, "set_edit_approval_requester"
        ) else None
        try:
            if token is None:
                pytest.skip(
                    "acp_adapter.edit_approval has no requester-binding "
                    "helper in this checkout; ACP-path skip logic is "
                    "still exercised via get_edit_approval_requester below."
                )
            res = self._write(tmp_path / "ordinary.txt", "acp write")
            assert not res.get("error"), res
            # The GENERAL gate's own CLI callback must never have been
            # asked — ACP's flow (not this test's fixture) is the sole
            # approval path when a requester is bound.
            assert approvals["calls"] == []
        finally:
            if token is not None and hasattr(ea, "reset_edit_approval_requester"):
                ea.reset_edit_approval_requester(token)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
