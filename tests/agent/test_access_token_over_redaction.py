"""Regression tests for the 2026-11-12 access_token over-redaction bug.

register_known_secret_values()'s strong-keyword path used to register ANY
value >= 8 chars once the key looked credential-y (``token``, ``secret``,
...), with no check that the value itself looked like a real secret. An
unfilled placeholder equal to its own key name (``access_token: "access_token"``)
got registered verbatim, then globally substring-replaced everywhere in tool
output -- including the bare word in unrelated code.

Fix: keep the strong-keyword bypass (short/plain-looking real secrets like a
16-char Gmail app password must still register), but gate it with
``_looks_like_placeholder`` so an obvious non-secret (same as its key name,
a known placeholder literal, an ``<...>``/``${...}`` template slot, or pure
snake_case words) never gets registered.

All fake values below are synthetic test fixtures, never real credentials.
"""

import pytest

import agent.redact as redact_mod
from agent.redact import (
    _looks_like_placeholder,
    clear_vault_redaction_values,
    redact_registered_vault_values,
    register_known_secret_values,
)


@pytest.fixture(autouse=True)
def _clean_vault_registry():
    clear_vault_redaction_values()
    yield
    clear_vault_redaction_values()


def _register_with_env(monkeypatch, env_dict):
    monkeypatch.setattr(redact_mod, "logger", redact_mod.logger)  # no-op, keeps import path warm
    import hermes_cli.config as config_mod

    monkeypatch.setattr(config_mod, "load_env", lambda: dict(env_dict))
    monkeypatch.setattr(config_mod, "load_config_readonly", lambda: {})
    return register_known_secret_values()


# ── _looks_like_placeholder unit coverage ───────────────────────────────


def test_placeholder_equal_to_own_key_name():
    assert _looks_like_placeholder("access_token", "access_token")
    assert _looks_like_placeholder("ACCESS_TOKEN", "access_token")


def test_placeholder_known_literals_and_templates():
    assert _looks_like_placeholder("api_key", "changeme")
    assert _looks_like_placeholder("api_key", "your_token_here")
    assert _looks_like_placeholder("api_key", "xxxxxxxx")
    assert _looks_like_placeholder("api_key", "<your-api-key>")
    assert _looks_like_placeholder("api_key", "${API_KEY}")


def test_placeholder_pure_snake_case_words():
    assert _looks_like_placeholder("some_token", "access_token")
    assert _looks_like_placeholder("some_token", "your_api_key")


def test_not_a_placeholder_real_looking_values():
    # Fake values only -- shapes, not real secrets.
    assert not _looks_like_placeholder("api_key", "abcdefghijklmnop")  # fake 16-char app pw
    assert not _looks_like_placeholder("api_key", "ghp_1234567890abcdef1234567890abcdef1234")
    assert not _looks_like_placeholder(
        "api_key", "sk-FAKE1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )


# ── register_known_secret_values() end-to-end (the real registration path) ──


def test_placeholder_access_token_not_registered_word_stays_visible(monkeypatch):
    count = _register_with_env(monkeypatch, {"ACCESS_TOKEN": "access_token"})
    assert count == 0
    text = "def f(*, access_token):\n    return {'access_token': access_token}"
    out = redact_registered_vault_values(text)
    assert out == text
    assert "access_token" in out


def test_fake_16_letter_app_password_still_registered(monkeypatch):
    fake_app_password = "abcdefghijklmnop"  # fake 16-letter value, Gmail-app-password shape
    count = _register_with_env(monkeypatch, {"GMAIL_APP_PASSWORD": fake_app_password})
    assert count == 1
    out = redact_registered_vault_values(f"password is {fake_app_password} today")
    assert fake_app_password not in out


def test_fake_40_char_token_still_registered(monkeypatch):
    fake_token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"  # 40 chars, fake
    count = _register_with_env(monkeypatch, {"API_TOKEN": fake_token})
    assert count == 1
    out = redact_registered_vault_values(f"token={fake_token}")
    assert fake_token not in out


# ── Real tool-output path (not just the gating function in isolation) ──────


def test_real_terminal_tool_path_leaves_placeholder_word_visible(monkeypatch):
    """Drives the actual terminal_tool() result path, not redact_registered_vault_values
    directly -- confirms the fix holds through the real output-redaction wiring a cron/
    terminal result travels through, matching how the bug first surfaced."""
    from tools import terminal_tool

    _register_with_env(monkeypatch, {"ACCESS_TOKEN": "access_token"})

    class Env:
        env = {}

        def execute(self, command, **kwargs):
            return {"output": "def f(*, access_token):\n    pass\n", "returncode": 0}

    monkeypatch.setattr(terminal_tool, "_active_environments", {"default": Env()})
    monkeypatch.setattr(terminal_tool, "_last_activity", {"default": 0})
    monkeypatch.setattr(terminal_tool, "_task_env_overrides", {})
    monkeypatch.setattr(
        terminal_tool,
        "_get_env_config",
        lambda: {
            "env_type": "local",
            "cwd": "/tmp",
            "timeout": 1,
            "host_cwd": None,
            "modal_mode": "auto",
            "docker_image": "",
            "modal_image": "",
            "daytona_image": "",
        },
    )
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(terminal_tool, "_resolve_container_task_id", lambda value: value or "default")
    monkeypatch.setattr(
        terminal_tool,
        "_check_all_guards",
        lambda command, env_type, **kwargs: {"approved": True},
    )

    import json

    result = json.loads(terminal_tool.terminal_tool(command="echo ok"))
    assert result["exit_code"] == 0
    assert "access_token" in result["output"]
