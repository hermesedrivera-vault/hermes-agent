"""Tests for agent.session_brief — the gateway session-brief provider.

Component A of the "Anthropic Playbook" (Thread 2). The brief is injected
ONCE into the volatile tier of the system prompt (see agent/system_prompt.py),
so it MUST be day-stable (no minute timestamps, no live/ticking values) to
preserve prompt caching.
"""
import os
import tempfile
import importlib
import datetime as dt

import pytest


@pytest.fixture()
def brief_mod():
    mod = importlib.import_module("agent.session_brief")
    importlib.reload(mod)
    return mod


@pytest.fixture()
def fake_vault(tmp_path):
    """Build a minimal Obsidian-vault-shaped tree with dated content."""
    vault = tmp_path / "Obsidian Vault"
    (vault / "04-Projects").mkdir(parents=True)
    (vault / "05-Postmortems").mkdir(parents=True)
    today = dt.date(2026, 7, 1)
    # A project with a commitment dated today
    (vault / "04-Projects" / "House-Painting.md").write_text(
        "# House Painting\n**Status:** 🟢 ESTIMATES SCHEDULED\n"
        "## Estimates — Wednesday, July 1, 2026\n"
        "| 10:30 AM | Higgs | phone |\n",
        encoding="utf-8",
    )
    # A recent postmortem (a correction/lesson)
    (vault / "05-Postmortems" / "2026-07-01-fabricated-appointment-confirmation.md").write_text(
        "# Postmortem — Fabricated Appointment Confirmation\nLesson: cite sources.\n",
        encoding="utf-8",
    )
    return vault, today


def test_build_session_brief_returns_string(brief_mod, fake_vault):
    vault, today = fake_vault
    out = brief_mod.build_session_brief(vault_path=str(vault), today=today)
    assert isinstance(out, str)


def test_brief_includes_recent_postmortem_title(brief_mod, fake_vault):
    vault, today = fake_vault
    out = brief_mod.build_session_brief(vault_path=str(vault), today=today)
    assert "fabricated-appointment-confirmation" in out.lower() or "fabricated" in out.lower()


def test_brief_includes_open_project(brief_mod, fake_vault):
    vault, today = fake_vault
    out = brief_mod.build_session_brief(vault_path=str(vault), today=today)
    assert "House-Painting" in out or "House Painting" in out


def test_brief_is_day_stable_no_minute_timestamp(brief_mod, fake_vault):
    """Cache-safety invariant: two calls the same day == identical string."""
    vault, today = fake_vault
    a = brief_mod.build_session_brief(vault_path=str(vault), today=today)
    b = brief_mod.build_session_brief(vault_path=str(vault), today=today)
    assert a == b, "brief must be deterministic within a day (prompt-cache safety)"
    # no HH:MM:SS wall-clock stamp that would change per rebuild
    import re
    assert not re.search(r"\b\d{2}:\d{2}:\d{2}\b", a), "brief must not embed second-precision timestamps"


def test_brief_missing_vault_returns_empty_not_fabricated(brief_mod, tmp_path):
    """No vault -> empty string. NEVER fabricate 'no open threads'."""
    out = brief_mod.build_session_brief(vault_path=str(tmp_path / "nonexistent"), today=dt.date(2026, 7, 1))
    assert out == "" or out.strip() == ""


def test_brief_empty_vault_omits_sections(brief_mod, tmp_path):
    """Vault exists but empty -> no fabricated section content."""
    vault = tmp_path / "Obsidian Vault"
    (vault / "04-Projects").mkdir(parents=True)
    (vault / "05-Postmortems").mkdir(parents=True)
    out = brief_mod.build_session_brief(vault_path=str(vault), today=dt.date(2026, 7, 1))
    # With no files, there is nothing to report; must not invent entries
    assert "Higgs" not in out
