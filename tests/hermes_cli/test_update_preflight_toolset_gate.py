"""Tests for the pre-restart update preflight gate (hermes_cli.update_preflight_validation).

Root cause this guards against (2026-09-10 reconciliation): ``platform_toolsets`` already had a
validator (``hermes_cli.toolset_validation.validate_platform_toolsets``) and it correctly flagged
stale entries — but nothing ever BLOCKED the fleet restart on its findings; the warning only
printed during config migration and scrolled past. A missing ``snowballstemmer`` dependency was
separately only caught by manually running the test suite, not by the updater itself.

These tests exercise the gate function directly (no real git/subprocess), confirming:
(a) a config referencing a nonexistent toolset is detected, (b) the gate reports not-ok, (c) a
clean config with all-valid toolsets and present dependencies reports ok, (d) an exception inside
either underlying check fails CLOSED (not silently ok).
"""

from __future__ import annotations

from hermes_cli.update_preflight_validation import (
    check_core_dependencies_installed,
    check_platform_toolsets_before_restart,
    run_update_preflight_gate,
)


# ---------------------------------------------------------------------------
# check_platform_toolsets_before_restart — real registry, real config reader
# ---------------------------------------------------------------------------

def test_nonexistent_toolset_reference_is_detected(monkeypatch):
    """The exact regression class: a platform_toolsets entry naming a toolset that was removed
    (or never existed) must be flagged, with no hardcoded name list — any bogus name works."""
    monkeypatch.setattr(
        "hermes_cli.config.read_raw_config",
        lambda: {"platform_toolsets": {"cli": ["totally_made_up_toolset_xyz"]}},
    )
    warnings = check_platform_toolsets_before_restart()
    assert any("totally_made_up_toolset_xyz" in w for w in warnings)


def test_clean_config_produces_no_warnings(monkeypatch):
    """A platform_toolsets mapping using only real, currently-registered toolset names must not
    be flagged — the gate must not false-positive on ordinary valid configuration."""
    monkeypatch.setattr(
        "hermes_cli.config.read_raw_config",
        lambda: {"platform_toolsets": {"cli": ["terminal", "web"]}},
    )
    warnings = check_platform_toolsets_before_restart()
    assert warnings == []


def test_absent_platform_toolsets_key_produces_no_warnings(monkeypatch):
    """No platform_toolsets configured at all (fresh install, all platform defaults) must not be
    treated as a failure — the validator already special-cases this; confirm the gate agrees."""
    monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {})
    assert check_platform_toolsets_before_restart() == []


# ---------------------------------------------------------------------------
# check_core_dependencies_installed
# ---------------------------------------------------------------------------

def test_missing_dependency_is_detected(monkeypatch):
    """A declared dependency whose import fails (the snowballstemmer class of gap) must be
    reported by name, not silently ignored."""
    import hermes_cli.update_preflight_validation as mod

    monkeypatch.setattr(mod, "_CORE_DEPENDENCY_IMPORT_NAMES", {"snowballstemmer": "snowballstemmer"})
    monkeypatch.setattr(mod.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(
        mod.importlib.metadata, "version",
        lambda name: (_ for _ in ()).throw(mod.importlib.metadata.PackageNotFoundError(name)),
    )
    failures = check_core_dependencies_installed()
    assert any("snowballstemmer" in f and "not installed" in f for f in failures)


def test_present_dependency_is_not_flagged(monkeypatch):
    """A dependency that imports cleanly must produce zero failures."""
    import hermes_cli.update_preflight_validation as mod

    monkeypatch.setattr(mod, "_CORE_DEPENDENCY_IMPORT_NAMES", {"os": "os"})
    assert check_core_dependencies_installed() == []


def test_inconsistent_environment_reports_metadata_vs_import_mismatch(monkeypatch):
    """A distribution record exists but the module fails to import (partial removal / broken
    install) — must be reported distinctly from a fully-missing package, since the fix differs
    (reinstall vs. install)."""
    import hermes_cli.update_preflight_validation as mod

    monkeypatch.setattr(mod, "_CORE_DEPENDENCY_IMPORT_NAMES", {"snowballstemmer": "snowballstemmer"})
    monkeypatch.setattr(mod.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(mod.importlib.metadata, "version", lambda name: "3.1.1")
    failures = check_core_dependencies_installed()
    assert any("does not import" in f and "3.1.1" in f for f in failures)


# ---------------------------------------------------------------------------
# run_update_preflight_gate — the single call site the updater actually uses
# ---------------------------------------------------------------------------

def test_gate_reports_not_ok_when_toolset_check_fails(monkeypatch):
    import hermes_cli.update_preflight_validation as mod

    monkeypatch.setattr(mod, "check_platform_toolsets_before_restart", lambda: ["bogus toolset warning"])
    monkeypatch.setattr(mod, "check_core_dependencies_installed", lambda: [])
    result = mod.run_update_preflight_gate()
    assert result.ok is False
    assert result.toolset_warnings == ["bogus toolset warning"]
    assert result.dependency_failures == []


def test_gate_reports_not_ok_when_dependency_check_fails(monkeypatch):
    import hermes_cli.update_preflight_validation as mod

    monkeypatch.setattr(mod, "check_platform_toolsets_before_restart", lambda: [])
    monkeypatch.setattr(mod, "check_core_dependencies_installed", lambda: ["missing dep"])
    result = mod.run_update_preflight_gate()
    assert result.ok is False
    assert result.dependency_failures == ["missing dep"]


def test_gate_reports_ok_when_both_checks_are_clean(monkeypatch):
    import hermes_cli.update_preflight_validation as mod

    monkeypatch.setattr(mod, "check_platform_toolsets_before_restart", lambda: [])
    monkeypatch.setattr(mod, "check_core_dependencies_installed", lambda: [])
    result = mod.run_update_preflight_gate()
    assert result.ok is True
    assert result.toolset_warnings == []
    assert result.dependency_failures == []


def test_gate_fails_closed_when_toolset_check_raises(monkeypatch):
    """An unexpected exception inside the toolset check must never be mistaken for 'zero stale
    references' — the updater must refuse to restart, not proceed as if everything were clean."""
    import hermes_cli.update_preflight_validation as mod

    def _boom():
        raise RuntimeError("registry import exploded")

    monkeypatch.setattr(mod, "check_platform_toolsets_before_restart", _boom)
    monkeypatch.setattr(mod, "check_core_dependencies_installed", lambda: [])
    result = mod.run_update_preflight_gate()
    assert result.ok is False
    assert any("registry import exploded" in w for w in result.toolset_warnings)


def test_gate_fails_closed_when_dependency_check_raises(monkeypatch):
    import hermes_cli.update_preflight_validation as mod

    def _boom():
        raise RuntimeError("importlib exploded")

    monkeypatch.setattr(mod, "check_platform_toolsets_before_restart", lambda: [])
    monkeypatch.setattr(mod, "check_core_dependencies_installed", _boom)
    result = mod.run_update_preflight_gate()
    assert result.ok is False
    assert any("importlib exploded" in d for d in result.dependency_failures)
