"""Cycle 3 (2026-10-31) negative tests: secrets deny rule + redaction extension.

Replays the shapes of the 2026-09-06 kenneth-rosa incident (msgs 57/59/61/63/65/67 of
session 20260906_175615_6ea66d23) and the 2026-10-31 config-clone echo, using DUMMY
secret values only -- never real ones. Each must be DENIED or REDACTED, not silently
allowed through.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools.approval import _floor_block  # noqa: E402
from agent.redact import (  # noqa: E402
    redact_terminal_output,
    register_vault_redaction_value,
    redact_sensitive_text,
    clear_vault_redaction_values,
)
from agent.file_safety import get_read_block_error  # noqa: E402

DUMMY_KEY = "GOCSPX-REALDUMMYSECRETVALUE0001"


def test_msg57_curl_env_var_is_not_itself_denied_by_floor_but_is_a_separate_concern():
    # msg 57 piped $OPENROUTER_API_KEY into curl -- a variable reference, not a direct
    # file read, so this floor (file reads) correctly does not fire on it; it is covered
    # by the existing dangerous-command classifier/approval path instead, not this rule.
    assert _floor_block('curl -H "Authorization: Bearer $OPENROUTER_API_KEY" https://x') is None


def test_msg59_65_find_for_env_paths_not_overblocked():
    # find only lists paths, never reads content -- must stay allowed (over-blocking
    # find would break completely unrelated, legitimate searches for every profile).
    assert _floor_block("find / -iname '*.env*' 2>/dev/null") is None


def test_msg61_search_files_style_grep_on_env_is_denied():
    r = _floor_block("grep -n OPENROUTER .hermes/.env")
    assert r is not None, "grep reading .env must be DENIED, not approval-prompted"


def test_msg63_read_file_style_cat_on_hermes_config_secret_key_names_is_denied():
    r = _floor_block("cat /home/hermes/.hermes/.env")
    assert r is not None


def test_msg67_grep_extracting_key_value_from_env_is_denied():
    r = _floor_block("grep -o '^OPENROUTER_API_KEY=.*' /home/hermes/.hermes/.env | head -c 40")
    assert r is not None, "the actual value-extraction attempt must be DENIED outright"


def test_today_config_clone_echo_is_now_redacted():
    # Reproduces the exact gap: a python3 -c invocation followed, on a new line, by a
    # grep that reads a secret-bearing config.yaml line. Before the _command_segments
    # newline fix, this skipped assignment redaction entirely.
    sample = "660:client_secret: " + DUMMY_KEY
    combined_cmd = 'python3 -c "import yaml; print(1)"\ngrep -n "^[a-zA-Z_]" config.yaml'
    # force=True isolates this test from other tests' HERMES_REDACT_SECRETS /
    # HERMES_HOME monkeypatching (module-level _REDACT_ENABLED_BY_HOME cache in
    # agent/redact.py is NOT reset between tests) -- what this test actually
    # verifies is the _command_segments newline fix, not the on/off toggle, which
    # is covered separately in tests/agent/test_redact.py.
    out = redact_terminal_output(sample, command=combined_cmd, force=True)
    assert DUMMY_KEY not in out, f"secret value leaked uncaught: {out!r}"


def test_registered_value_redaction_catches_it_even_if_pattern_matching_fails():
    clear_vault_redaction_values()
    try:
        register_vault_redaction_value(DUMMY_KEY)
        leaked = f"some unrelated line with {DUMMY_KEY} embedded, no KEY: VALUE shape at all"
        out = redact_sensitive_text(leaked, code_file=True)
        assert DUMMY_KEY not in out
    finally:
        clear_vault_redaction_values()


def test_generic_secret_and_token_json_basenames_denied_for_read():
    assert get_read_block_error("/tmp/my_api_secret.txt") is not None
    assert get_read_block_error("/tmp/service_token_prod.json") is not None
    # false-positive guards must still pass through
    assert get_read_block_error("/tmp/notes_secretary.txt") is None
    assert get_read_block_error("/tmp/token_bucket.py") is None


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception:
            print(f"ERROR {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
