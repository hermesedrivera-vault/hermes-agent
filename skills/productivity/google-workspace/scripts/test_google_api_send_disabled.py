"""Tests (Ed's decision, 11/11/26): the hermes-agent repo's google_api.py
TEMPLATE (bundled skill source, pulled on fresh installs/updates) must also
refuse gmail send/reply -- both at CLI dispatch and at the function body
directly -- matching the deployed profile copies, so a future install never
reintroduces the uncontrolled send path."""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "google_api.py"


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_main(module, argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", argv)
    return module.main()


def test_send_subcommand_refuses_with_exit_2(monkeypatch):
    module = _load_module("gapi_template_send")
    with pytest.raises(SystemExit) as exc_info:
        _run_main(module, ["google_api.py", "gmail", "send", "--to", "x@example.com",
                            "--subject", "s", "--body", "b"], monkeypatch)
    assert exc_info.value.code == 2


def test_reply_subcommand_refuses_with_exit_2(monkeypatch):
    module = _load_module("gapi_template_reply")
    with pytest.raises(SystemExit) as exc_info:
        _run_main(module, ["google_api.py", "gmail", "reply", "some-id", "--body", "b"], monkeypatch)
    assert exc_info.value.code == 2


def test_refusal_message_names_send_email(monkeypatch, capsys):
    module = _load_module("gapi_template_msg")
    with pytest.raises(SystemExit):
        _run_main(module, ["google_api.py", "gmail", "send", "--to", "x@example.com",
                            "--subject", "s", "--body", "b"], monkeypatch)
    assert "send_email()" in capsys.readouterr().err


def test_gmail_send_function_itself_refuses_on_direct_call():
    module = _load_module("gapi_template_directcall_send")
    args = argparse.Namespace(to="x@example.com", subject="s", body="b", cc="",
                               html=False, thread_id="", from_header="")
    with pytest.raises(SystemExit) as exc_info:
        module.gmail_send(args)
    assert exc_info.value.code == 2


def test_gmail_reply_function_itself_refuses_on_direct_call():
    module = _load_module("gapi_template_directcall_reply")
    args = argparse.Namespace(message_id="some-id", body="b", html=False, from_header="")
    with pytest.raises(SystemExit) as exc_info:
        module.gmail_reply(args)
    assert exc_info.value.code == 2


def test_search_subcommand_still_reaches_real_gmail_search_not_refusal(monkeypatch):
    module = _load_module("gapi_template_search")

    class _Sentinel(Exception):
        pass

    def fake_gmail_search(args):
        raise _Sentinel("real gmail_search was called")

    module.gmail_search = fake_gmail_search
    with pytest.raises(_Sentinel):
        _run_main(module, ["google_api.py", "gmail", "search", "is:unread"], monkeypatch)
