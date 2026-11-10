"""Ed's review (11/10/26): the prior registration tests (see
test_send_email_tool_registration.py) checked PROXIES -- the dispatch
table, the static toolsets.py list membership -- not the REAL capability
surface. All three proxies can be green while send_email is still
uncallable by any model, anywhere, which is exactly what happened on the
11/9 deploy. These tests check the real things:

  (a) discover_builtin_tools() actually includes "send_email"
  (b) the REAL per-platform resolver (hermes_cli.tools_config._get_platform_tools,
      the same function the live gateway calls) exposes the "email" toolset
      for telegram + cli, not for signal, and nowhere for the kenneth-rosa
      profile (which has "email" in agent.disabled_toolsets)
  (c) the REAL schema-build function (model_tools.get_tool_definitions),
      called with telegram's resolved toolsets, actually contains a
      "send_email" function definition

Every one of these must FAIL on current main (pre-fix) -- that is the
point: a passing dispatch-table/toolsets-list test proves nothing about
whether the model can actually call the tool.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root

# Imported at module/collection time, like test_send_email_tool_registration.py
# does -- the home_io_guard only activates for test EXECUTION, not collection,
# and this module's CANONICAL_ENFORCED_GMAIL_PATH constant resolves a real,
# hardcoded ~/.hermes path at import time by design (it must never be
# redirectable, even under a sandboxed HERMES_HOME). Importing inside a test
# function body instead trips the guard; importing here at the top does not.
import tools.send_email_tool  # noqa: F401,E402
from tools.registry import discover_builtin_tools, registry  # noqa: E402


def test_discover_builtin_tools_includes_send_email():
    """discover_builtin_tools() returns MODULE names (e.g. 'tools.send_email_tool'),
    not registered tool names -- the real proof that the module's
    registry.register() call actually ran is a ToolEntry named 'send_email'
    in the registry itself after discovery, which is what makes the tool
    resolvable by toolset at all downstream."""
    module_names = discover_builtin_tools()
    assert "tools.send_email_tool" in module_names, (
        f"tools.send_email_tool missing from discover_builtin_tools() "
        f"({len(module_names)} modules found) -- the module itself was never imported."
    )
    registered_names = {e.name for e in registry.get_all_entries()}
    assert "send_email" in registered_names, (
        f"send_email module was imported but no ToolEntry named 'send_email' exists in the "
        f"registry ({len(registered_names)} tools registered) -- this means "
        "tools/send_email_tool.py never calls registry.register() at module level, so no "
        "schema is ever produced for ANY platform even though the module itself loads fine."
    )


def test_real_platform_resolution_telegram_and_cli_yes_signal_no():
    """Uses the exact function the live gateway calls to resolve a platform's
    toolset list -- not a hand-rolled stand-in.

    Passing an empty config ({}) would resolve PLATFORM DEFAULTS, not the
    live install's actual platform_toolsets -- "email" is deliberately
    opt-in (not a platform default), so this test mirrors the real,
    verified ~/.hermes/config.yaml platform_toolsets block instead (read
    directly outside pytest on 2026-11-10, lines 616-645: cli explicitly
    lists "email"; telegram explicitly lists ["hermes-telegram", "email"];
    signal lists only ["hermes-signal"], no "email"). home_io_guard forbids
    reading the real config file from inside a test -- see the
    kenneth-rosa test below for the same constraint."""
    from hermes_cli.tools_config import _get_platform_tools

    # Verbatim snapshot of the real config.yaml's platform_toolsets block --
    # see docstring. If this list changes, a human must re-verify outside
    # the sandbox and update this constant.
    live_config = {
        "platform_toolsets": {
            "cli": [
                "browser", "clarify", "code_execution", "connections", "cronjob",
                "delegation", "email", "file", "image_gen", "memory",
                "session_search", "skills", "terminal", "todo", "tts", "vision", "web",
            ],
            "telegram": ["hermes-telegram", "email"],
            "signal": ["hermes-signal"],
        },
    }

    telegram_toolsets = _get_platform_tools(live_config, "telegram", include_default_mcp_servers=False)
    cli_toolsets = _get_platform_tools(live_config, "cli", include_default_mcp_servers=False)
    signal_toolsets = _get_platform_tools(live_config, "signal", include_default_mcp_servers=False)

    assert "email" in telegram_toolsets, (
        f"'email' toolset not resolved for telegram (got {sorted(telegram_toolsets)}) -- "
        "send_email is not exposed to the telegram gateway with default config."
    )
    assert "email" in cli_toolsets, (
        f"'email' toolset not resolved for cli (got {sorted(cli_toolsets)})"
    )
    assert "email" not in signal_toolsets, (
        f"'email' toolset unexpectedly resolved for signal (got {sorted(signal_toolsets)}) -- "
        "signal must never expose send_email per Ed's standing rule (Kenneth's chat is the "
        "default profile's Signal home channel)."
    )


def test_real_platform_resolution_kenneth_rosa_never_resolves_email():
    """kenneth-rosa's own profile config explicitly disables the 'email' toolset
    (SECURITY LOCKDOWN 2026-10-31 + the 11/9/26 send_email v3 deploy note).

    This suite's home_io_guard refuses ANY file I/O against the real
    ~/.hermes tree during test execution (by design -- see tests/conftest.py)
    so this test cannot read_file() the real kenneth-rosa/config.yaml itself.
    Instead it uses the exact disabled_toolsets list read directly from that
    file outside pytest on 2026-11-10 (full line: `disabled_toolsets:
    ["terminal", "code_execution", "file", "web", "browser", "connections",
    "delegation", "computer_use", "skills", "kanban", "cronjob", "email"]`,
    config.yaml line 57) and feeds it into the REAL resolver
    (_get_platform_tools) the same way the live gateway would. If that line
    ever changes, this snapshot goes stale -- a human must re-verify it
    outside the sandbox and update the constant below, which is why the
    exact source line is quoted in this docstring rather than silently
    trusted."""
    from hermes_cli.tools_config import _get_platform_tools

    # Verbatim snapshot, not a derived guess -- see docstring.
    kenneth_rosa_config = {
        "toolsets": ["hermes-cli"],
        "agent": {
            "disabled_toolsets": [
                "terminal", "code_execution", "file", "web", "browser",
                "connections", "delegation", "computer_use", "skills",
                "kanban", "cronjob", "email",
            ],
        },
    }

    assert "email" in kenneth_rosa_config["agent"]["disabled_toolsets"]

    for platform in ("telegram", "cli", "signal"):
        resolved = _get_platform_tools(kenneth_rosa_config, platform, include_default_mcp_servers=False)
        assert "email" not in resolved, (
            f"'email' toolset resolved for kenneth-rosa on platform={platform} "
            f"(got {sorted(resolved)}) -- his profile's disabled_toolsets should "
            "subtract it regardless of platform."
        )


def test_real_schema_build_for_telegram_session_contains_send_email(tmp_path, monkeypatch):
    """The actual function that builds the API-facing tool list
    (model_tools.get_tool_definitions) -- not a mock, not the toolsets.py
    static declaration -- must contain send_email's function schema when
    called with telegram's resolved enabled_toolsets.

    check_fn (check_send_email_requirements) does os.path.exists() against
    the real protected paths -- redirected to tmp_path stand-ins here, same
    seam test_requirements_gate_is_callable_and_boolean uses, so this test
    verifies registration/toolset/schema wiring, not whether the real
    protected files happen to exist on this box."""
    from hermes_cli.tools_config import _get_platform_tools
    from model_tools import get_tool_definitions
    import tools.send_email_tool as se

    approved = tmp_path / "approved.json"
    approved.write_text("{}")
    script = tmp_path / "enforced_gmail_send.py"
    script.write_text("# stand-in\n")
    monkeypatch.setattr(se, "DEFAULT_APPROVED_LIST_PATH", str(approved))
    monkeypatch.setattr(se, "CANONICAL_ENFORCED_GMAIL_PATH", str(script))

    # Same verified live config.yaml snapshot as the test above (opt-in
    # "email" toolset is not a platform default).
    live_config = {
        "platform_toolsets": {
            "telegram": ["hermes-telegram", "email"],
        },
    }

    telegram_toolsets = sorted(_get_platform_tools(live_config, "telegram", include_default_mcp_servers=False))
    defs = get_tool_definitions(enabled_toolsets=telegram_toolsets, quiet_mode=False,
                                 skip_tool_search_assembly=True)
    names = {d["function"]["name"] for d in defs if d.get("type") == "function"}

    assert "send_email" in names, (
        f"send_email absent from the real schema list built for telegram "
        f"({len(names)} tool defs produced). This is the actual proof the model can "
        "call it -- everything else (dispatch table, toolsets.py membership, "
        "platform_toolsets config) is a proxy for this one fact."
    )
