"""Integration test for A3: session brief wired into the volatile tier.

Proves build_system_prompt_parts() injects the brief when the agent flag is on,
omits it when off, and that the brief lands in the VOLATILE tier (never the
stable/cached-identity tier).
"""
import importlib
import types
import datetime as dt

import pytest


@pytest.fixture()
def sp_mod():
    mod = importlib.import_module("agent.system_prompt")
    importlib.reload(mod)
    return mod


def _fake_agent(brief_enabled: bool):
    """Minimal agent stub with just the attributes build_system_prompt_parts reads."""
    a = types.SimpleNamespace()
    a.load_soul_identity = False
    a.skip_context_files = True
    a.valid_tool_names = set()          # no tool guidance blocks
    a._task_completion_guidance = False
    a._parallel_tool_call_guidance = False
    a._session_brief_enabled = brief_enabled
    a._memory_store = None
    a._memory_enabled = False
    a._user_profile_enabled = False
    a._memory_manager = None
    a.context_compressor = None
    a.pass_session_id = False
    a.session_id = None
    a.model = None
    a.provider = None
    a._tool_use_enforcement = False
    a._kanban_worker_guidance = None
    a.platform = None
    a.coding_context = None
    a.environment_probe = None
    a.file_safety = None
    a.prompt_builder = None
    a._cached_system_prompt = None
    return a


def test_brief_absent_when_flag_off(sp_mod, monkeypatch):
    monkeypatch.setattr(
        "agent.session_brief.build_session_brief",
        lambda *a, **k: "## Session Brief (retrieved from vault — carry-forward context)\nSENTINEL",
    )
    parts = sp_mod.build_system_prompt_parts(_fake_agent(brief_enabled=False))
    assert "SENTINEL" not in parts["volatile"]
    assert "SENTINEL" not in parts["stable"]


def test_brief_present_in_volatile_when_flag_on(sp_mod, monkeypatch):
    monkeypatch.setattr(
        "agent.session_brief.build_session_brief",
        lambda *a, **k: "## Session Brief (retrieved from vault — carry-forward context)\nSENTINEL",
    )
    parts = sp_mod.build_system_prompt_parts(_fake_agent(brief_enabled=True))
    # Must be in volatile tier, NOT the stable (cached-identity) tier.
    assert "SENTINEL" in parts["volatile"]
    assert "SENTINEL" not in parts["stable"]


def test_brief_failure_does_not_break_assembly(sp_mod, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("vault exploded")
    monkeypatch.setattr("agent.session_brief.build_session_brief", _boom)
    # Should not raise — brief failure is non-fatal.
    parts = sp_mod.build_system_prompt_parts(_fake_agent(brief_enabled=True))
    assert isinstance(parts["volatile"], str)
