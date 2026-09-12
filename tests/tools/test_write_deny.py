"""Tests for _is_write_denied() — verifies deny list blocks sensitive paths on all platforms."""

import os

from pathlib import Path
from unittest.mock import patch

from agent.file_safety import is_write_denied as _is_write_denied


class TestWriteDenyExactPaths:
    def test_etc_shadow(self):
        assert _is_write_denied("/etc/shadow") is True


    def test_ssh_authorized_keys(self):
        assert _is_write_denied("~/.ssh/authorized_keys") is True


    def test_ssh_id_ed25519(self):
        path = os.path.join(str(Path.home()), ".ssh", "id_ed25519")
        assert _is_write_denied(path) is True


    def test_hermes_root_env_when_running_under_profile(self, tmp_path, monkeypatch):
        """Top-level ``<root>/.env`` stays write-denied even when running under
        a profile (#15981).

        Before the fix, ``build_write_denied_paths`` only added
        ``<active_profile>/.env`` to the deny list, so the global
        ``~/.hermes/.env`` (whose credentials are inherited by every profile)
        could be silently overwritten by ``write_file`` while a profile was
        active.
        """
        root = tmp_path / "hermes_root"
        profile_home = root / "profiles" / "coder"
        profile_home.mkdir(parents=True)
        global_env = root / ".env"
        global_env.write_text("OPENAI_API_KEY=sk-real\n")

        monkeypatch.setenv("HERMES_HOME", str(profile_home))

        # Sanity check: HERMES_HOME does point to the profile dir, not the root.
        from hermes_constants import get_hermes_home, get_default_hermes_root
        assert get_hermes_home() == profile_home
        assert get_default_hermes_root() == root

        assert _is_write_denied(str(global_env)) is True

    def test_shell_profiles_are_writable(self):
        home = str(Path.home())
        for name in [".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile"]:
            assert _is_write_denied(os.path.join(home, name)) is False, f"{name} should be writable"

    def test_credential_config_files_denied(self):
        home = str(Path.home())
        for name in [".netrc", ".pgpass", ".npmrc", ".pypirc"]:
            assert _is_write_denied(os.path.join(home, name)) is True, f"{name} should be denied"


class TestWriteDenyPrefixes:
    def test_ssh_prefix(self):
        path = os.path.join(str(Path.home()), ".ssh", "some_key")
        assert _is_write_denied(path) is True


    def test_systemd_prefix(self, tmp_path):
        # On NixOS, /etc/systemd is a symlink into /nix/store, so
        # realpath() resolves it to a store path that doesn't match
        # the /etc/systemd/ prefix.  Build a real directory tree so
        # realpath is a no-op and prefix matching works.
        fake_etc = tmp_path / "etc" / "systemd" / "system"
        fake_etc.mkdir(parents=True)
        target = str(fake_etc / "evil.service")
        # Patch the prefix builder to include our tmp_path prefix
        import agent.file_safety as _fs
        _orig = _fs.build_write_denied_prefixes
        _extra_prefix = str(tmp_path / "etc" / "systemd") + os.sep
        def _patched(home):
            return _orig(home) + [_extra_prefix]
        with patch.object(_fs, "build_write_denied_prefixes", _patched):
            assert _is_write_denied(target) is True


class TestWriteAllowed:
    def test_tmp_file(self):
        assert _is_write_denied("/tmp/safe_file.txt") is False


    def test_hermes_control_files_requested_writable(self):
        from hermes_constants import get_hermes_home

        home = get_hermes_home()
        for name in ["auth.json", "config.yaml", "webhook_subscriptions.json"]:
            assert _is_write_denied(str(home / name)) is False, f"{name} should be writable"


class TestProtectedSourceFiles:
    """Hermes's own authorization/security-critical source files are hard-denied
    (same tier as credential files, not the routine approval gate): a
    prompt-injected or self-modifying agent must not be able to weaken the
    write/approval/provenance guards by editing their own implementation.
    """

    @staticmethod
    def _fake_source_tree(tmp_path):
        """Build a throwaway ``<root>/agent/file_safety.py`` + siblings tree and
        return its root, so tests never touch the real repo checkout."""
        root = tmp_path / "hermes-agent"
        for rel in [
            os.path.join("tools", "approval.py"),
            os.path.join("tools", "approval_detection.py"),
            os.path.join("tools", "file_tools_write_guards.py"),
            os.path.join("agent", "file_safety.py"),
            os.path.join("agent", "provenance", "gate.py"),
            os.path.join("agent", "provenance", "store.py"),
            os.path.join("hermes_cli", "config.py"),
            os.path.join("gateway", "run.py"),
            os.path.join("gateway", "config.py"),
            os.path.join("agent", "unrelated_module.py"),  # ordinary source, must stay writable
        ]:
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# placeholder\n")
        return root

    def test_ordinary_source_file_unaffected(self, tmp_path):
        """A normal workspace/source file is not touched by this new tier at all."""
        root = self._fake_source_tree(tmp_path)
        assert _is_write_denied(str(root / "agent" / "unrelated_module.py")) is False

    def test_approval_py_denied(self, tmp_path):
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "tools" / "approval.py")) is True

    def test_approval_detection_py_denied(self, tmp_path):
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "tools" / "approval_detection.py")) is True

    def test_file_tools_write_guards_py_denied(self, tmp_path):
        """Self-protection: the write-guard module itself is a protected path."""
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "tools" / "file_tools_write_guards.py")) is True

    def test_file_safety_py_self_protected(self, tmp_path):
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "agent" / "file_safety.py")) is True

    def test_provenance_gate_py_denied(self, tmp_path):
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "agent" / "provenance" / "gate.py")) is True

    def test_provenance_store_py_denied(self, tmp_path):
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "agent" / "provenance" / "store.py")) is True

    def test_config_loader_files_denied(self, tmp_path):
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            for rel in (
                os.path.join("hermes_cli", "config.py"),
                os.path.join("gateway", "run.py"),
                os.path.join("gateway", "config.py"),
            ):
                assert _is_write_denied(str(root / rel)) is True, f"{rel} should be denied"

    def test_dotdot_traversal_still_caught(self, tmp_path):
        """A ``../`` path that resolves onto a protected file is still denied —
        the guard compares realpath, not the literal string, so traversal
        cannot bypass it."""
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            traversal_path = str(root / "tools" / "unrelated" / ".." / "approval.py")
            assert _is_write_denied(traversal_path) is True

    def test_symlink_to_protected_file_still_caught(self, tmp_path):
        """A symlink pointing at a protected file resolves (realpath) to the
        same target, so it is denied too — path-shape tricks don't bypass this."""
        root = self._fake_source_tree(tmp_path)
        symlink_path = tmp_path / "alias_approval.py"
        try:
            symlink_path.symlink_to(root / "tools" / "approval.py")
        except (OSError, NotImplementedError):
            import pytest
            pytest.skip("symlinks not supported in this test environment")
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(symlink_path)) is True

    def test_redundant_separators_still_caught(self, tmp_path):
        """Double slashes / redundant separators normalize away under realpath."""
        root = self._fake_source_tree(tmp_path)
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            messy_path = str(root) + os.sep + os.sep + "tools" + os.sep + "approval.py"
            assert _is_write_denied(messy_path) is True

    def test_not_bypassed_by_yolo_mode_env(self, tmp_path, monkeypatch):
        """``is_write_denied`` takes no approval-mode/YOLO input at all — it is
        checked unconditionally in tools/file_operations.py before any approval
        logic runs, so setting HERMES_YOLO_MODE cannot weaken this tier."""
        root = self._fake_source_tree(tmp_path)
        monkeypatch.setenv("HERMES_YOLO_MODE", "1")
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "tools" / "approval.py")) is True

    def test_not_bypassed_by_approvals_mode_off(self, tmp_path, monkeypatch):
        """Same guarantee under approvals.mode='off' — is_write_denied has no
        dependency on the approvals config at all, so this must still deny."""
        root = self._fake_source_tree(tmp_path)
        monkeypatch.setenv("HERMES_APPROVALS_MODE", "off")
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: root):
            assert _is_write_denied(str(root / "agent" / "provenance" / "gate.py")) is True

    def test_config_yaml_regression_still_denied(self, tmp_path, monkeypatch):
        """Regression: the pre-existing config.yaml hard-deny (a DIFFERENT
        mechanism, tools/file_tools_write_guards.py's _check_sensitive_path)
        is unaffected by this change — verified here via the .env-style
        HERMES_HOME deny path this module owns directly."""
        root = tmp_path / "hermes_root"
        profile_home = root / "profiles" / "coder"
        profile_home.mkdir(parents=True)
        global_env = root / ".env"
        global_env.write_text("DUMMY_KEY=placeholder\n")
        monkeypatch.setenv("HERMES_HOME", str(profile_home))
        assert _is_write_denied(str(global_env)) is True

    def test_env_regression_still_denied(self, tmp_path, monkeypatch):
        """Regression: .env protection (pre-existing in this module) is unaffected."""
        home = tmp_path / "hermes_home"
        home.mkdir(parents=True)
        env_file = home / ".env"
        env_file.write_text("DUMMY_KEY=placeholder\n")
        monkeypatch.setenv("HERMES_HOME", str(home))
        assert _is_write_denied(str(env_file)) is True

    def test_missing_source_root_fails_safe_not_crash(self):
        """If the source root can't be resolved (e.g. packaged install), the new
        tier degrades to an empty set rather than raising — build_write_denied_paths
        must never throw."""
        import agent.file_safety as _fs
        with patch.object(_fs, "_hermes_source_root", lambda: None):
            assert _fs.build_protected_source_paths() == set()
            # Ordinary deny-list behavior for unrelated paths still works.
            assert _is_write_denied("/tmp/still_safe.txt") is False
