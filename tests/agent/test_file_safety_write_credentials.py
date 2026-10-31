"""Secret stores under HERMES_HOME are write-denied; control files stay writable (#110464).

``get_read_block_error`` refuses every credential store. The write side is deliberately
narrower — #45947 freed ``auth.json`` / ``config.yaml`` / ``webhook_subscriptions.json`` so
the user can ask to edit them — but the secret *material* it meant to keep blocked had
drifted: ``auth/google_oauth.json``, the plaintext Bitwarden cache, ``vault/`` and
``browser-profile/`` were writable through ``write_file`` / ``patch``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import agent.file_safety as fs

SECRET_STORES = (
    "auth/google_oauth.json", "cache/bws_cache.json", "vault/vault.key", "browser-profile/Default/Cookies",
)
WRITABLE_CONTROL_FILES = ("auth.json", "config.yaml", "webhook_subscriptions.json")


@pytest.fixture()
def hermes_layout(tmp_path, monkeypatch):
    """Profile HERMES_HOME plus a distinct global root, both patched."""
    root = tmp_path / "hermes_root"
    profile = root / "profiles" / "coder"
    profile.mkdir(parents=True)
    monkeypatch.setattr(fs, "_hermes_home_path", lambda: profile)
    monkeypatch.setattr(fs, "_hermes_root_path", lambda: root)
    return root, profile


def _touch(base: Path, rel: str) -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("dummy", encoding="utf-8")
    return p


def test_read_denied_secret_stores_are_write_denied_on_profile_and_root(hermes_layout):
    root, profile = hermes_layout
    for base in (profile, root):
        for rel in SECRET_STORES:
            path = _touch(base, rel)
            assert fs.get_read_block_error(str(path)), f"fixture drift: not read-denied: {path}"
            assert fs.is_write_denied(str(path)), f"write allowed: {path}"


def test_control_files_and_lookalikes_outside_home_stay_writable(hermes_layout, tmp_path):
    root, profile = hermes_layout
    for base in (profile, root):
        for rel in WRITABLE_CONTROL_FILES:
            assert fs.is_write_denied(str(_touch(base, rel))) is False, f"#45947 regression: {rel}"
    assert fs.is_write_denied(str(_touch(tmp_path / "myproject", "cache/bws_cache.json"))) is False
    assert fs.is_write_denied(str(_touch(tmp_path / "myproject", "vault/vault.key"))) is False


class TestProfileHomeProcessHome:
    """With the process HOME pinned to ``{HERMES_HOME}/home`` (TERMINAL_HOME_MODE=profile,
    containers, spawned workers) the write guards must still cover every home a write can
    land in: the OS user's real home, the profile home and ``~name`` accounts."""

    @pytest.fixture()
    def profile_home_env(self, tmp_path, monkeypatch):
        profile = tmp_path / "profile"
        (profile / "home").mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(profile))
        monkeypatch.setenv("HOME", str(profile / "home"))
        monkeypatch.setattr(fs, "_hermes_home_path", lambda: profile)
        monkeypatch.setattr(fs, "_hermes_root_path", lambda: profile.parent)
        return profile

    def test_every_home_is_guarded(self, profile_home_env):
        import pwd

        real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for rel in (".aws/credentials", ".ssh/id_ed25519", ".netrc", ".config/gh/hosts.yml"):
            assert fs.is_write_denied(str(real_home / rel)), rel
            assert fs.is_write_denied(str(profile_home_env / "home" / rel)), rel
        assert fs.is_write_denied("~/.aws/credentials")
        assert fs.is_write_denied("~root/.ssh/authorized_keys")
        # ``~/.ssh/config`` stays approval-gated (not hard-denied) on the real home too.
        assert fs.is_write_approval_required(str(real_home / ".ssh" / "config"))
        assert fs.is_write_denied(str(real_home / ".ssh" / "config")) is False

    def test_benign_paths_stay_writable(self, profile_home_env, tmp_path):
        import pwd

        real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for benign in (tmp_path / "scratch" / "notes.txt", real_home / "projects" / "notes.md"):
            assert fs.is_write_denied(str(benign)) is False, benign
            assert fs.is_write_approval_required(str(benign)) is False, benign
        assert fs.is_write_denied("~nosuchuser-hopefully/.ssh/authorized_keys") is False


class TestOtherProfileConfigWriteApproval:
    """2026-10-31 (cycle3): profiles/*/config.yaml for ANY profile -- not just kenneth-rosa --
    requires approval to write. Found live: a default-profile write to
    profiles/kenneth-rosa/config.yaml landed with zero approval prompt before this fix, even
    though that profile's own config.yaml controls its toolset lockdown. The acting profile's
    OWN config.yaml stays unguarded (see #45947's WRITABLE_CONTROL_FILES carve-out above) --
    this only covers a DIFFERENT profile's config, which only another profile (e.g. the
    default/account-owner one, since a locked-down profile has ``file`` denied outright
    anyway) could ever reach."""

    def test_other_profile_config_requires_approval(self, tmp_path, monkeypatch):
        home = tmp_path / "hermes_home"
        other_profile_dir = home / "profiles" / "kenneth-rosa"
        other_profile_dir.mkdir(parents=True)
        cfg_path = other_profile_dir / "config.yaml"
        cfg_path.write_text("agent:\n  disabled_toolsets: []\n")
        monkeypatch.setattr(fs, "_hermes_home_path", lambda: home)
        monkeypatch.setattr(fs, "_hermes_root_path", lambda: home.parent)

        assert fs.is_write_approval_required(str(cfg_path)), (
            "profiles/kenneth-rosa/config.yaml must require approval to write"
        )
        assert fs.is_write_denied(str(cfg_path)) is False, (
            "approval-gated, not hard-denied -- the user can still approve the edit"
        )

    def test_new_profile_config_covered_without_restart(self, tmp_path, monkeypatch):
        """build_write_approval_paths globs fresh each call -- a profile created mid-session
        (no code reload needed) is covered the first time its config.yaml exists on disk."""
        home = tmp_path / "hermes_home"
        (home / "profiles").mkdir(parents=True)
        monkeypatch.setattr(fs, "_hermes_home_path", lambda: home)
        monkeypatch.setattr(fs, "_hermes_root_path", lambda: home.parent)

        new_profile_dir = home / "profiles" / "brand-new-profile"
        new_profile_dir.mkdir()
        new_cfg = new_profile_dir / "config.yaml"
        new_cfg.write_text("agent: {}\n")

        assert fs.is_write_approval_required(str(new_cfg))
