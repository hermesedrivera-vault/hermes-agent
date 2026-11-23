"""A Hermes config change run from the agent's terminal asks a human every time (tools/approval_config_cli.py).

Driven through the real guard entry points against a temp HERMES_HOME (tools/AGENTS.md). Only the human's
answer is stubbed, at ``request_once_only_approval``, the seam the gate asks; the fail-closed test uses the
real helper with no human channel at all.
"""
import time

import pytest

import hermes_cli.config as hc
import tools.once_only_approval as once
from agent.delegation_context import DELEGATED_CHILD_ENV_MARKER
from hermes_cli.approvals_test import evaluate_command
from tools import approval
from tools.approval import check_all_command_guards, check_dangerous_command
from tools.approval_config_cli import command_mutates_hermes_config

MUTATING = [
    "hermes config set approvals.mode off",
    "hermes -p work config unset curator.protected_skills",
    "hermes --profile=work config set a b",
    "hermes config edit",
    "hermes config migrate",
    "hermes approvals suggest --apply 1,3",
    "python -m hermes_cli.main config set a b",
    "python hermes_cli/main.py config set a b",
    "/usr/local/bin/hermes config set a b",
    "hermes.exe config set a b",
    "cd /tmp && hermes config set a b",
    "sudo hermes config set a b",
    'bash -c "hermes config set a b"',
    'eval "hermes config set a b"',
    'printf "hermes config set a b" | sh',
    'ssh box "hermes config set a b"',
    'hermes config "set" a b',
    'hermes config s"e"t a b',
    "hermes 'config' set a b",
    "hermes config $(echo set) a b",
    "HERMES CONFIG SET a b",
]
NOT_GATED = [
    "hermes config",
    "hermes config show",
    "hermes config get approvals.mode",
    'hermes config get "approvals.mode"',
    "hermes config check",
    "hermes config path",
    "hermes approvals suggest",
    "git config set user.name x",
    "ls -la",
    # Quoted text a command only reads or passes along is data, not a command.
    "grep -r 'hermes config set' docs/",
    'git commit -m "docs: hermes config set now asks"',
    'echo "hermes config set a b"',
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
    monkeypatch.delenv(DELEGATED_CHILD_ENV_MARKER, raising=False)
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", True)
    hc._LOAD_CONFIG_CACHE.clear()
    yield home
    hc._LOAD_CONFIG_CACHE.clear()


@pytest.fixture
def human(monkeypatch):
    """Records each prompt's display text and answers with ``answer["value"]``."""
    asked, answer = [], {"value": {"approved": False, "outcome": "denied"}}

    def answer_prompt(description, display, pattern_key):
        asked.append(display)
        return answer["value"]

    monkeypatch.setattr(once, "request_once_only_approval", answer_prompt)
    return asked, answer


@pytest.mark.parametrize("command", MUTATING)
def test_config_writing_spellings_are_detected(command):
    assert command_mutates_hermes_config(command)


@pytest.mark.parametrize("command", NOT_GATED)
def test_reads_quoted_mentions_and_unrelated_commands_run_without_asking(command, break_glass_home, human):
    asked, _ = human
    assert not command_mutates_hermes_config(command)
    assert check_all_command_guards(command, "local")["approved"] is True
    assert asked == []


def test_asks_every_time_even_under_yolo_and_approvals_off(break_glass_home, human):
    asked, answer = human
    answer["value"] = {"approved": True, "outcome": "approved"}
    command = "hermes config set approvals.mode off"
    first = check_all_command_guards(command, "local")
    second = check_all_command_guards(command, "local")
    assert first["approved"] and first["user_approved"]  # a batch may reuse a decision a human made
    assert second["approved"]
    assert asked == [command, command]  # nothing persisted between the two


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


def test_a_subagent_is_refused_without_asking(break_glass_home, human, monkeypatch):
    """A delegated child's approval callback may auto-approve, so the gate never asks from one."""
    asked, answer = human
    answer["value"] = {"approved": True, "outcome": "approved"}
    monkeypatch.setenv(DELEGATED_CHILD_ENV_MARKER, "1")
    result = check_all_command_guards("hermes config set approvals.mode off", "local")
    assert result["approved"] is False
    assert "subagent" in result["message"]
    assert asked == []


def test_secrets_are_masked_on_the_prompt_and_absent_from_the_refusal(break_glass_home, human):
    asked, _ = human
    key = "sk-or-v1-" + "0123456789abcdef" * 4
    result = check_all_command_guards(f"hermes config set OPENROUTER_API_KEY {key}", "local")
    assert len(asked) == 1 and key not in asked[0]
    assert key not in result["message"]


def test_the_rest_of_an_approved_command_still_meets_its_own_gate(break_glass_home, human, monkeypatch):
    asked, answer = human
    answer["value"] = {"approved": True, "outcome": "approved"}
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    (break_glass_home / "config.yaml").write_text(
        "model:\n  default: test-model\napprovals:\n  mode: manual\n  timeout: 300\n  cron_mode: deny\n")
    hc._LOAD_CONFIG_CACHE.clear()
    result = check_all_command_guards("hermes config set a b && rm -rf /tmp/stuff", "local")
    assert len(asked) == 1
    assert not result.get("user_approved")  # the config prompt did not approve the delete


def test_the_pattern_layer_entry_point_asks_too(break_glass_home, human):
    asked, _ = human
    assert check_dangerous_command("hermes config set a b", "local")["approved"] is False
    assert len(asked) == 1


def test_a_sandboxed_backend_is_not_asked(break_glass_home, human):
    """Inside a container without host mounts the CLI cannot reach this profile's config.yaml."""
    asked, _ = human
    assert check_all_command_guards("hermes config set a b", "docker")["approved"] is True
    assert asked == []


def test_the_dry_run_reports_the_prompt_even_under_yolo(break_glass_home):
    verdict = evaluate_command("hermes config set approvals.mode off")
    assert verdict["verdict"] == "ask-approval"
    assert verdict["rule"] == "Hermes config change"


def test_detection_stays_linear_on_adversarial_input():
    command = "hermes " + "-a; hermes " * 11000
    start = time.monotonic()
    command_mutates_hermes_config(command)
    assert time.monotonic() - start < 10
