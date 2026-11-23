"""A Hermes config change run from the agent's terminal asks a human every time (tools/approval_config_cli.py).

Driven through the real guard entry points against a temp HERMES_HOME (tools/AGENTS.md). Only the human's
answer is stubbed, at ``request_once_only_approval``, the seam the gate asks; the fail-closed test uses the
real helper with no human channel at all.
"""
import pytest

import hermes_cli.config as hc
import tools.once_only_approval as once
from tools import approval
from tools.approval import check_all_command_guards, check_dangerous_command
from tools.approval_config_cli import command_mutates_hermes_config

MUTATING = [
    "hermes config set approvals.mode off",
    "hermes -p work config unset curator.protected_skills",
    "hermes --profile=work config set a b",
    "hermes config edit",
    "hermes config migrate",
    "python -m hermes_cli.main config set a b",
    "/usr/local/bin/hermes config set a b",
    "cd /tmp && hermes config set a b",
    'bash -c "hermes config set a b"',
    'hermes config "set" a b',
    "hermes config $(echo set) a b",
    "HERMES CONFIG SET a b",
]
READ_ONLY = [
    "hermes config",
    "hermes config show",
    "hermes config get approvals.mode",
    "hermes config check",
    "hermes config path",
    "git config set user.name x",
    "ls -la",
]


@pytest.fixture
def break_glass_home(tmp_path, monkeypatch):
    """Approvals off and --yolo on: the settings this gate must NOT be bypassed by."""
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        "model:\n  default: test-model\n"
        'approvals:\n  mode: "off"\n  timeout: 300\n  cron_mode: approve\n'
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", True)
    hc._LOAD_CONFIG_CACHE.clear()
    yield home
    hc._LOAD_CONFIG_CACHE.clear()


@pytest.fixture
def human(monkeypatch):
    """Records each prompt and answers with ``answer["value"]``."""
    asked, answer = [], {"value": {"approved": False, "outcome": "denied"}}

    def answer_prompt(description, display, pattern_key):
        asked.append((display, pattern_key))
        return answer["value"]

    monkeypatch.setattr(once, "request_once_only_approval", answer_prompt)
    return asked, answer


@pytest.mark.parametrize("command", MUTATING)
def test_mutating_spellings_are_detected(command):
    assert command_mutates_hermes_config(command)


@pytest.mark.parametrize("command", READ_ONLY)
def test_reads_and_unrelated_commands_run_without_asking(command, break_glass_home, human):
    asked, _ = human
    assert check_all_command_guards(command, "local")["approved"] is True
    assert asked == []


def test_asks_every_time_even_under_yolo_and_approvals_off(break_glass_home, human):
    asked, answer = human
    answer["value"] = {"approved": True, "outcome": "approved"}
    command = "hermes config set approvals.mode off"
    assert check_all_command_guards(command, "local")["approved"] is True
    assert check_all_command_guards(command, "local")["approved"] is True
    assert [display for display, _ in asked] == [command, command]  # nothing persisted between the two


@pytest.mark.parametrize("outcome, phrase", [("denied", "denied by the user"), ("timeout", "Silence is not consent")])
def test_a_refusal_blocks_the_command(outcome, phrase, break_glass_home, human):
    _, answer = human
    answer["value"] = {"approved": False, "outcome": outcome}
    result = check_all_command_guards("hermes config unset curator.protected_skills", "local")
    assert result["approved"] is False
    assert phrase in result["message"]


def test_no_human_channel_fails_closed(break_glass_home):
    result = check_all_command_guards("hermes config set approvals.mode off", "local")
    assert result["approved"] is False
    assert "no user can answer" in result["message"]


def test_the_pattern_layer_entry_point_asks_too(break_glass_home, human):
    asked, _ = human
    assert check_dangerous_command("hermes config set a b", "local")["approved"] is False
    assert len(asked) == 1


def test_a_sandboxed_backend_is_not_asked(break_glass_home, human):
    """Inside a container without host mounts the CLI cannot reach this profile's config.yaml."""
    asked, _ = human
    assert check_all_command_guards("hermes config set a b", "docker")["approved"] is True
    assert asked == []
