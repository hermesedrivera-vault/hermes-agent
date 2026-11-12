"""Twilio/SendGrid credential-shaped values must not leak through the REAL
terminal-tool output path, not just redact_sensitive_text() in isolation.
Fake values only -- synthetic test fixtures, never real credentials."""

import json

from tools import terminal_tool


def _minimal_terminal_config(cwd="/tmp"):
    return {
        "env_type": "local",
        "cwd": cwd,
        "timeout": 1,
        "host_cwd": None,
        "modal_mode": "auto",
        "docker_image": "",
        "modal_image": "",
        "daytona_image": "",
    }


def _patch_common(monkeypatch, env):
    monkeypatch.setattr(terminal_tool, "_active_environments", {"default": env})
    monkeypatch.setattr(terminal_tool, "_last_activity", {"default": 0})
    monkeypatch.setattr(terminal_tool, "_task_env_overrides", {})
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: _minimal_terminal_config())
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(terminal_tool, "_resolve_container_task_id", lambda value: value or "default")
    monkeypatch.setattr(
        terminal_tool,
        "_check_all_guards",
        lambda command, env_type, **kwargs: {"approved": True},
    )


def test_real_terminal_tool_path_redacts_twilio_api_key_sid(monkeypatch):
    fake_sid = "SK" + "0123456789abcdef" * 2  # fake 32-hex Twilio API Key SID

    class Env:
        env = {}

        def execute(self, command, **kwargs):
            return {"output": f"TWILIO_API_KEY_SID={fake_sid}\n", "returncode": 0}

    _patch_common(monkeypatch, Env())
    result = json.loads(terminal_tool.terminal_tool(command="echo ok"))
    assert result["exit_code"] == 0
    assert "0123456789abcdef" * 2 not in result["output"]


def test_real_terminal_tool_path_redacts_sendgrid_key(monkeypatch):
    fake_sg = "SG." + "AbCdEfGhIjKlMnOpQrSt" + "." + "UvWxYz0123456789abcdef"

    class Env:
        env = {}

        def execute(self, command, **kwargs):
            return {"output": f"SENDGRID_API_KEY={fake_sg}\n", "returncode": 0}

    _patch_common(monkeypatch, Env())
    result = json.loads(terminal_tool.terminal_tool(command="echo ok"))
    assert result["exit_code"] == 0
    assert "AbCdEfGhIjKlMnOpQrSt" not in result["output"]
    assert "UvWxYz0123456789abcdef" not in result["output"]
