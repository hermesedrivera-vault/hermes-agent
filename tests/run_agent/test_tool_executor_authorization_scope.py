"""Regression guard: authorization scope wiring in
``_run_agent_tool_execution_middleware`` (Phase 3 fix).

``tools/approval.py`` already defines a correct composite authorization
identity (``session::task=<task>::sub=<subagent>``) via
``set_current_authorization_scope`` / ``reset_current_authorization_scope`` /
``get_current_authorization_key``, but until this fix nothing in the
runtime ever called the setter — so
``tools.file_tools``'s general-write approval gate
(``approvals.general_file_write_param_binding_enabled``) always collapsed
to the bare session key in production, regardless of which task/subagent
was actually executing the tool.

This suite proves the fix at the real dispatch boundary,
``agent.tool_executor._run_agent_tool_execution_middleware``, mirroring the
fixture/call-signature conventions already used in
``tests/run_agent/test_tool_activity_heartbeat.py`` and the
ContextVar-propagation style used in
``tests/run_agent/test_tool_executor_contextvar_propagation.py``.
"""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _isolate_hermes(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    (tmp_path / ".hermes").mkdir(exist_ok=True)


def _make_agent(monkeypatch, *, subagent_id: str | None = None):
    """Minimal AIAgent-like stub, mirroring test_tool_activity_heartbeat.py."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    monkeypatch.setenv("HERMES_INFERENCE_PROVIDER", "")
    import run_agent as _ra  # noqa: F401  (side-effect import, matches sibling test)

    class _Stub:
        _interrupt_requested = False
        _interrupt_message = None
        log_prefix = ""
        quiet_mode = True
        verbose_logging = False
        log_prefix_chars = 200
        _checkpoint_mgr = MagicMock(enabled=False)
        tool_progress_callback = None
        tool_start_callback = None
        tool_complete_callback = None
        tool_progress_mode = "off"
        _todo_store = MagicMock()
        _session_db = None
        valid_tool_names = set()
        _turns_since_memory = 0
        _iters_since_skill = 0
        _current_tool = None
        _last_activity = 0.0
        session_id = ""
        _current_turn_id = ""
        _current_api_request_id = ""

        def __init__(self):
            self._tool_worker_threads: set = set()
            self._tool_worker_threads_lock = threading.Lock()
            self._active_children_lock = threading.Lock()

        def _touch_activity(self, desc):
            self._last_activity = time.time()

        def _vprint(self, msg, force=False):
            pass

        def _safe_print(self, msg):
            pass

        def _should_emit_quiet_tool_messages(self):
            return False

    agent = _Stub()
    agent._tool_guardrails = MagicMock(
        before_call=lambda name, args: MagicMock(allows_execution=True)
    )
    if subagent_id is not None:
        agent._subagent_id = subagent_id
    return agent


def _dispatch(agent, *, effective_task_id: str, execute, tool_call_id: str = "tc1"):
    import agent.tool_executor as te

    return te._run_agent_tool_execution_middleware(
        agent,
        function_name="terminal",
        function_args={"command": "true"},
        effective_task_id=effective_task_id,
        tool_call_id=tool_call_id,
        execute=execute,
        display_index=1,
    )


def test_top_level_execution_gets_empty_subagent_scope(monkeypatch):
    """No ``agent._subagent_id`` -> composite key has an empty sub= component."""
    from tools import approval as _approval

    agent = _make_agent(monkeypatch)  # no _subagent_id set
    observed: dict = {}

    def execute(final_args):
        observed["key"] = _approval.get_current_authorization_key()
        return json.dumps({"ok": True})

    _dispatch(agent, effective_task_id="task-top", execute=execute)

    assert observed.get("key") == "default::task=task-top::sub=", (
        f"expected top-level composite key with empty sub=, got {observed.get('key')!r}"
    )


def test_delegated_subagent_execution_scopes_by_subagent_id(monkeypatch):
    """``agent._subagent_id`` set -> composite key carries that subagent id."""
    from tools import approval as _approval

    agent = _make_agent(monkeypatch, subagent_id="sa-0-abcd1234")
    observed: dict = {}

    def execute(final_args):
        observed["key"] = _approval.get_current_authorization_key()
        return json.dumps({"ok": True})

    _dispatch(agent, effective_task_id="task-sub", execute=execute)

    assert observed.get("key") == "default::task=task-sub::sub=sa-0-abcd1234", (
        f"expected subagent-scoped composite key, got {observed.get('key')!r}"
    )


def test_scope_restored_after_successful_dispatch(monkeypatch):
    """After the middleware returns normally, prior authorization identity
    (bare session key — no task scope was bound before this call) is
    restored; scope does not leak into subsequent unrelated calls."""
    from tools import approval as _approval

    agent = _make_agent(monkeypatch, subagent_id="sa-0-leaktest")
    before_key = _approval.get_current_authorization_key()

    def execute(final_args):
        return json.dumps({"ok": True})

    _dispatch(agent, effective_task_id="task-restore", execute=execute)

    after_key = _approval.get_current_authorization_key()
    assert after_key == before_key, (
        f"authorization scope leaked after successful dispatch: "
        f"before={before_key!r} after={after_key!r}"
    )


def test_scope_restored_after_dispatch_raises(monkeypatch):
    """If ``execute()`` raises, the authorization scope MUST still be
    reset (finally-safe) — a crashed tool must not leave a stale
    task/subagent identity bound for whatever runs next on this thread."""
    from tools import approval as _approval

    agent = _make_agent(monkeypatch, subagent_id="sa-0-crashtest")
    before_key = _approval.get_current_authorization_key()

    def execute(final_args):
        raise RuntimeError("tool exploded")

    with pytest.raises(RuntimeError):
        _dispatch(agent, effective_task_id="task-crash", execute=execute)

    after_key = _approval.get_current_authorization_key()
    assert after_key == before_key, (
        f"authorization scope leaked after execute() raised: "
        f"before={before_key!r} after={after_key!r}"
    )


def test_concurrent_dispatches_do_not_cross_contaminate_scope(monkeypatch):
    """Two tool dispatches on different threads, with different
    task_id/subagent_id, must each observe only their own composite key
    inside ``execute()`` — mirrors
    test_two_concurrent_tool_batches_keep_session_keys_isolated's style
    for the session-key ContextVar, but for the new task/subagent scope."""
    from tools import approval as _approval

    results: dict = {}

    def run_one(label: str, task_id: str, subagent_id: str) -> None:
        agent = _make_agent(monkeypatch, subagent_id=subagent_id)

        def execute(final_args):
            time.sleep(0.05)  # widen the window for a real race to show up
            results[label] = _approval.get_current_authorization_key()
            return json.dumps({"ok": True})

        _dispatch(agent, effective_task_id=task_id, execute=execute)

    t_a = threading.Thread(
        target=run_one, args=("A", "task-A", "sa-0-AAAA")
    )
    t_b = threading.Thread(
        target=run_one, args=("B", "task-B", "sa-0-BBBB")
    )
    t_a.start()
    t_b.start()
    t_a.join(timeout=10)
    t_b.join(timeout=10)

    assert results.get("A") == "default::task=task-A::sub=sa-0-AAAA", (
        f"thread A observed {results.get('A')!r}"
    )
    assert results.get("B") == "default::task=task-B::sub=sa-0-BBBB", (
        f"thread B observed {results.get('B')!r}"
    )
