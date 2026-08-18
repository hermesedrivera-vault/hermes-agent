"""Tests for MCP tool trust-tier gating via readOnlyHint annotations.

Security boundary under test: write-capable MCP tools (anything whose
``readOnlyHint`` annotation is not exactly ``True``) on servers configured
``trust: untrusted`` must route through the existing dangerous-approval
path before the RPC fires. Read-only tools and tools on trusted servers
pass straight through.

Adversarial notes encoded in these tests:
- ``readOnlyHint`` is a HINT supplied by the (potentially hostile) server.
  It can only ever RELAX gating on a server the operator already marked
  untrusted; the trust tier itself is operator-side config, so a lying
  server can at worst skip approval for a tool it claims is read-only —
  which is why the trust key is per-server and gating is fail-closed for
  missing/unknown metadata.
- Missing annotations ⇒ write-capable (fail closed).
- Unknown/garbage ``trust`` values ⇒ treated as untrusted (fail closed).
"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import tools.approval as approval
from tools import mcp_tool


class _FakeContentBlock:
    def __init__(self, text: str, block_type: str = "text"):
        self.text = text
        self.type = block_type


class _FakeCallToolResult:
    def __init__(self, content, is_error=False, structuredContent=None):
        self.content = content
        self.isError = is_error
        self.structuredContent = structuredContent


def _fake_run_on_mcp_loop(coro_or_factory, timeout=30):
    coro = coro_or_factory() if callable(coro_or_factory) else coro_or_factory
    loop = asyncio.new_event_loop()
    try:
        async def _install_lock_and_run():
            for srv in list(mcp_tool._servers.values()):
                if getattr(srv, "_rpc_lock", None) is None:
                    srv._rpc_lock = asyncio.Lock()
            return await coro
        return loop.run_until_complete(_install_lock_and_run())
    finally:
        loop.close()


@pytest.fixture
def fake_session():
    """Patch a fake connected server + MCP loop; yield its session mock."""
    session = MagicMock()
    session.call_tool = AsyncMock(
        return_value=_FakeCallToolResult(content=[_FakeContentBlock("ok")])
    )
    server = SimpleNamespace(session=session, _rpc_lock=None)
    with patch.dict(mcp_tool._servers, {"srv": server}), \
         patch("tools.mcp_tool._run_on_mcp_loop",
               side_effect=_fake_run_on_mcp_loop), \
         patch.dict(mcp_tool._server_error_counts, {}, clear=True):
        yield session


@pytest.fixture(autouse=True)
def _clean_trust_state():
    """Isolate the module-level trust metadata between tests."""
    with patch.dict(mcp_tool._server_trust_levels, {}, clear=True), \
         patch.dict(mcp_tool._tool_read_only_hints, {}, clear=True):
        yield


def _set_trust(server: str, trust: str):
    mcp_tool._server_trust_levels[server] = trust


def _set_read_only(server: str, tool: str, value: bool):
    mcp_tool._tool_read_only_hints.setdefault(server, {})[tool] = value


class TestTrustGateAtCallTime:
    """The handler preamble consults the approval path when required."""

    def test_write_capable_on_untrusted_server_requires_approval(
        self, fake_session
    ):
        """Approval consulted; approved=True lets the RPC through."""
        _set_trust("srv", "untrusted")
        # No readOnlyHint recorded for delete_repo → write-capable.
        handler = mcp_tool._make_tool_handler("srv", "delete_repo", 30.0)
        with patch(
            "tools.approval.check_mcp_call_guard",
            return_value={"approved": True, "message": None},
        ) as consent:
            raw = handler({"repo": "x"})
        consent.assert_called_once()
        assert json.loads(raw) == {"result": "ok"}
        fake_session.call_tool.assert_awaited_once()

    def test_denied_approval_blocks_rpc(self, fake_session):
        """approved=False blocks the call — the RPC must never fire."""
        _set_trust("srv", "untrusted")
        handler = mcp_tool._make_tool_handler("srv", "delete_repo", 30.0)
        with patch(
            "tools.approval.check_mcp_call_guard",
            return_value={"approved": False, "message": "did not approve this call"},
        ):
            raw = handler({"repo": "x"})
        fake_session.call_tool.assert_not_awaited()
        assert "error" in json.loads(raw)
        assert "did not approve" in json.loads(raw)["error"]

    def test_read_only_tool_on_untrusted_server_skips_approval(
        self, fake_session
    ):
        """readOnlyHint=True tools pass without consulting approval."""
        _set_trust("srv", "untrusted")
        _set_read_only("srv", "list_repos", True)
        handler = mcp_tool._make_tool_handler("srv", "list_repos", 30.0)
        with patch(
            "tools.approval.request_elicitation_consent"
        ) as consent:
            raw = handler({})
        consent.assert_not_called()
        assert json.loads(raw) == {"result": "ok"}

    def test_trusted_server_skips_approval_for_write_tools(
        self, fake_session
    ):
        """trust: full (and the default) never consults approval."""
        _set_trust("srv", "full")
        handler = mcp_tool._make_tool_handler("srv", "delete_repo", 30.0)
        with patch(
            "tools.approval.request_elicitation_consent"
        ) as consent:
            raw = handler({"repo": "x"})
        consent.assert_not_called()
        assert json.loads(raw) == {"result": "ok"}

    def test_unconfigured_server_defaults_to_full_trust(self, fake_session):
        """Backward compat: servers with no trust key behave as before."""
        handler = mcp_tool._make_tool_handler("srv", "delete_repo", 30.0)
        with patch(
            "tools.approval.request_elicitation_consent"
        ) as consent:
            raw = handler({"repo": "x"})
        consent.assert_not_called()
        assert json.loads(raw) == {"result": "ok"}

    def test_read_only_false_hint_is_gated(self, fake_session):
        """An explicit readOnlyHint=False is write-capable."""
        _set_trust("srv", "untrusted")
        _set_read_only("srv", "write_file", False)
        handler = mcp_tool._make_tool_handler("srv", "write_file", 30.0)
        with patch(
            "tools.approval.check_mcp_call_guard",
            return_value={"approved": False, "message": "denied"},
        ) as consent:
            handler({"path": "/etc/passwd"})
        consent.assert_called_once()
        fake_session.call_tool.assert_not_awaited()

    def test_approval_exception_fails_closed(self, fake_session):
        """Any exception in the consent path blocks the call."""
        _set_trust("srv", "untrusted")
        handler = mcp_tool._make_tool_handler("srv", "delete_repo", 30.0)
        with patch(
            "tools.approval.check_mcp_call_guard",
            side_effect=RuntimeError("approval backend down"),
        ):
            raw = handler({"repo": "x"})
        fake_session.call_tool.assert_not_awaited()
        assert "error" in json.loads(raw)


class TestTrustNormalization:
    def test_unknown_trust_value_treated_as_untrusted(self):
        """Garbage trust strings fail closed to untrusted."""
        assert mcp_tool._normalize_server_trust("banana") == "untrusted"

    def test_known_values(self):
        assert mcp_tool._normalize_server_trust("full") == "full"
        assert mcp_tool._normalize_server_trust("UNTRUSTED") == "untrusted"
        assert mcp_tool._normalize_server_trust("  Full ") == "full"
        # Missing key → default full (backward compatible; documented).
        assert mcp_tool._normalize_server_trust(None) == "full"


class TestAnnotationCaptureAtDiscovery:
    """_register_server_tools records trust + readOnlyHint metadata."""

    def _make_tool(self, name, annotations=None):
        return SimpleNamespace(
            name=name, description="", inputSchema=None,
            annotations=annotations,
        )

    def test_registration_records_hints_and_trust(self):
        from tools.registry import ToolRegistry

        server = mcp_tool.MCPServerTask("srv")
        server.session = MagicMock()
        server._tools = [
            self._make_tool(
                "list_repos", SimpleNamespace(readOnlyHint=True)
            ),
            self._make_tool(
                "delete_repo", SimpleNamespace(readOnlyHint=False)
            ),
            self._make_tool("no_annotations", None),
        ]
        config = {
            "trust": "untrusted",
            "tools": {"resources": False, "prompts": False},
        }
        with patch("tools.registry.registry", ToolRegistry()), \
             patch("tools.mcp_tool._track_mcp_tool_server"):
            mcp_tool._register_server_tools("srv", server, config)

        assert mcp_tool._server_trust_levels["srv"] == "untrusted"
        hints = mcp_tool._tool_read_only_hints["srv"]
        assert hints.get("list_repos") is True
        # Anything not exactly True is write-capable.
        assert not hints.get("delete_repo")
        assert not hints.get("no_annotations")

    def test_dict_annotations_supported(self):
        """Cached/JSON annotations arrive as plain dicts."""
        assert mcp_tool._annotation_read_only_hint(
            SimpleNamespace(annotations={"readOnlyHint": True})
        ) is True
        assert mcp_tool._annotation_read_only_hint(
            SimpleNamespace(annotations={"readOnlyHint": "yes"})
        ) is False  # non-bool truthy → NOT read-only (hint must be True)
        assert mcp_tool._annotation_read_only_hint(
            SimpleNamespace(annotations=None)
        ) is False
        assert mcp_tool._annotation_read_only_hint(
            SimpleNamespace()
        ) is False


class TestCronDenialEndToEnd:
    """Step 60/61: proves the cron-deny -> RPC-unreachable chain as ONE
    uninterrupted path, closing the gap identified in the STEP 59/60 review
    where cron denial was only tested up to the check_mcp_call_guard()
    boundary in isolation.

    This test does NOT mock check_mcp_call_guard() -- it exercises the REAL
    check_mcp_call_guard() -> REAL _trust_gate_check() -> REAL
    _make_tool_handler._handler() chain, with only the cron-context
    predicates and the MCP session/transport mocked (same fake_session
    fixture already used by every other test in this file). Proves
    server.session.call_tool() is never awaited when approvals.cron_mode is
    'deny'.
    """

    def test_cron_mode_deny_blocks_rpc_end_to_end(self, fake_session):
        _set_trust("srv", "untrusted")
        # No readOnlyHint recorded for delete_repo -> write-capable, so the
        # real guard is actually reached (not short-circuited by an
        # exemption before ever calling check_mcp_call_guard).
        handler = mcp_tool._make_tool_handler("srv", "delete_repo", 30.0)

        tokens = approval.set_current_authorization_scope(
            session_key="cron-e2e-session", task_id="", subagent_id=""
        )
        try:
            with patch("tools.approval._is_cron_approval_context", return_value=True), \
                 patch("tools.approval._get_cron_approval_mode", return_value="deny"), \
                 patch("tools.approval._is_interactive_cli", return_value=False), \
                 patch("tools.approval._is_gateway_approval_context", return_value=False), \
                 patch(
                     "tools.approval.prompt_dangerous_approval"
                 ) as prompt:
                # Real check_mcp_call_guard() is NOT mocked here -- this is
                # the whole point of the test. Real _trust_gate_check() is
                # NOT mocked. Only the cron-context predicates (so this
                # test process doesn't need a real cron env var) and the
                # human-prompt function (which must NEVER be called on this
                # path) are patched.
                raw = handler({"repo": "x"})
        finally:
            approval.reset_current_authorization_scope(tokens)

        # The critical assertion: the real RPC call site inside _handler()
        # was never reached.
        fake_session.call_tool.assert_not_awaited()
        # No interactive prompt was ever consulted -- the cron-deny branch
        # inside the real _run_approval_gate() returns immediately, before
        # any prompt logic.
        prompt.assert_not_called()
        # And the denial message reflects the cron-specific reason, proving
        # the real cron_deny_message from check_mcp_call_guard() propagated
        # all the way through _trust_gate_check()'s tool_error() wrapping.
        assert "cron" in json.loads(raw)["error"].lower()
