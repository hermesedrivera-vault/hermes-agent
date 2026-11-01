"""SSN/ITIN/EIN pattern masking tests (agent/redact.py).

Every digit string in this file is a fabricated test fixture, never a real
SSN/ITIN/EIN. Added 2026-11-01, Ed's SSN/backup remediation item (b).
"""
import agent.redact as redact_mod
from agent.redact import redact_sensitive_text, _redact_ssn_itin_ein

FAKE_SSN = "123-45-6789"
FAKE_SSN_2 = "987-65-4321"
FAKE_ITIN = "912-70-1234"  # ITIN shares SSN shape; first digit 9 is the only distinguisher
FAKE_EIN = "12-3456789"


def test_bare_ssn_shape_always_redacted():
    assert _redact_ssn_itin_ein(f"SSN on file: {FAKE_SSN}") == "SSN on file: [SSN-REDACTED]"


def test_itin_same_shape_as_ssn_redacted():
    assert _redact_ssn_itin_ein(f"ITIN: {FAKE_ITIN}") == "ITIN: [SSN-REDACTED]"


def test_two_ssns_in_one_string_both_redacted():
    got = _redact_ssn_itin_ein(f"Ed: {FAKE_SSN}, Tanya: {FAKE_SSN_2}")
    assert got == "Ed: [SSN-REDACTED], Tanya: [SSN-REDACTED]"


def test_ein_shape_without_keyword_left_alone():
    text = f"invoice ref {FAKE_EIN} shipped"
    assert _redact_ssn_itin_ein(text) == text


def test_ein_shape_with_ein_keyword_redacted():
    assert _redact_ssn_itin_ein(f"Company EIN: {FAKE_EIN}") == "Company EIN: [EIN-REDACTED]"


def test_ein_shape_with_employer_identification_keyword_redacted():
    got = _redact_ssn_itin_ein(f"employer identification number {FAKE_EIN} on file")
    assert got == "employer identification number [EIN-REDACTED] on file"


def test_ein_shape_with_tax_id_keyword_redacted():
    assert _redact_ssn_itin_ein(f"client tax ID is {FAKE_EIN}") == "client tax ID is [EIN-REDACTED]"


def test_ein_shape_far_from_keyword_left_alone():
    text = ("EIN on this client's old filing many years ago in a prior engagement that is long "
            f"since closed and totally unrelated now, reference number: {FAKE_EIN}")
    assert _redact_ssn_itin_ein(text) == text


def test_date_like_string_untouched():
    text = "meeting on 2026-11-01 at the office"
    assert _redact_ssn_itin_ein(text) == text


def test_full_entry_point_catches_ssn():
    got = redact_sensitive_text(f"Found SSN {FAKE_SSN} in postmortem", force=True)
    assert got == "Found SSN [SSN-REDACTED] in postmortem"


def test_space_separated_ssn_also_redacted():
    got = _redact_ssn_itin_ein("SSN 123 45 6789 on file")
    assert got == "SSN [SSN-REDACTED] on file"


# --- Early-return paths: none may bypass SSN masking (Ed, review item (3)) ---

def test_none_input_returns_none_not_a_bypass():
    # Trivial: no text, nothing to leak.
    assert redact_sensitive_text(None) is None


def test_empty_string_returns_empty_not_a_bypass():
    # Trivial: no text, nothing to leak.
    assert redact_sensitive_text("") == ""


def test_ssn_masked_with_force_false_default():
    out = redact_sensitive_text(f"SSN: {FAKE_SSN}", force=False)
    assert "[SSN-REDACTED]" in out and FAKE_SSN not in out


def test_ssn_masked_with_code_file_true():
    out = redact_sensitive_text(f"SSN: {FAKE_SSN}", force=False, code_file=True)
    assert "[SSN-REDACTED]" in out and FAKE_SSN not in out


def test_ssn_masked_with_secret_file_true():
    out = redact_sensitive_text(f"SSN: {FAKE_SSN}", force=False, secret_file=True)
    assert "[SSN-REDACTED]" in out and FAKE_SSN not in out


def test_ssn_masked_with_file_read_true():
    out = redact_sensitive_text(f"SSN: {FAKE_SSN}", force=False, file_read=True)
    assert "[SSN-REDACTED]" in out and FAKE_SSN not in out


def test_ssn_masked_even_when_redact_secrets_globally_disabled(monkeypatch):
    # security.redact_secrets: false only gates the secret-redaction passes (API keys, etc.);
    # SSN/ITIN/EIN masking is a hard model-egress boundary like vault secrets and must still fire.
    monkeypatch.setattr(redact_mod, "_redact_enabled", lambda: False)
    out = redact_sensitive_text(f"SSN: {FAKE_SSN}", force=False)
    assert "[SSN-REDACTED]" in out and FAKE_SSN not in out
