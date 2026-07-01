"""Test the approval_gate config->env bridge in gateway/config.py (Thread2 B4).

Mirrors the provenance bridge: `approval_gate.<tool>` in config.yaml is mapped
to APPROVAL_GATE_<TOOL> env at gateway load, unless the env is already set
(env wins). This lets `hermes config set approval_gate.send_message shadow`
control the gate mode without editing .env.
"""
import os
import importlib
import textwrap

import pytest


@pytest.fixture()
def temp_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes_home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    # Clear any inherited approval-gate env so the bridge is what sets it.
    monkeypatch.delenv("APPROVAL_GATE_SEND_MESSAGE", raising=False)
    monkeypatch.delenv("APPROVAL_GATE_TERMINAL", raising=False)
    return home


def _write_config(home, body: str):
    (home / "config.yaml").write_text(textwrap.dedent(body), encoding="utf-8")


def _load(monkeypatch):
    import gateway.config as gc
    importlib.reload(gc)
    return gc.load_gateway_config()


def test_bridge_maps_send_message_mode(temp_home, monkeypatch):
    _write_config(temp_home, """
        approval_gate:
          send_message: shadow
          terminal: enforce
    """)
    _load(monkeypatch)
    assert os.environ.get("APPROVAL_GATE_SEND_MESSAGE") == "shadow"
    assert os.environ.get("APPROVAL_GATE_TERMINAL") == "enforce"


def test_env_wins_over_config(temp_home, monkeypatch):
    # If the env is already set, the bridge must NOT override it.
    monkeypatch.setenv("APPROVAL_GATE_SEND_MESSAGE", "enforce")
    _write_config(temp_home, """
        approval_gate:
          send_message: shadow
    """)
    _load(monkeypatch)
    assert os.environ.get("APPROVAL_GATE_SEND_MESSAGE") == "enforce"


def test_no_approval_section_is_harmless(temp_home, monkeypatch):
    _write_config(temp_home, """
        agent:
          session_brief_enabled: false
    """)
    # Should not raise and should not invent a value.
    _load(monkeypatch)
    assert os.environ.get("APPROVAL_GATE_SEND_MESSAGE") is None
