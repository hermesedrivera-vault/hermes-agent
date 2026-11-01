"""Fake-number-only tests for SSN/ITIN/EIN redaction (agent/redact.py).

Every digit string in this file is a fabricated test fixture, never a real
SSN/ITIN/EIN. Added 2026-11-01, Ed's SSN/backup remediation item (b).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.redact import redact_sensitive_text, _redact_ssn_itin_ein  # noqa: E402

FAKE_SSN = "123-45-6789"
FAKE_SSN_2 = "987-65-4321"
FAKE_ITIN = "912-70-1234"  # ITIN shares SSN shape; first digit 9 is the only distinguisher
FAKE_EIN = "12-3456789"


def check(label, got, expect):
    ok = got == expect
    print(f"{'OK  ' if ok else 'FAIL'} | {label} | got={got!r}")
    return ok


def main():
    results = []

    results.append(check(
        "bare SSN shape -> always redacted",
        _redact_ssn_itin_ein(f"SSN on file: {FAKE_SSN}"),
        "SSN on file: [SSN-REDACTED]",
    ))
    results.append(check(
        "ITIN (same shape as SSN) -> redacted",
        _redact_ssn_itin_ein(f"ITIN: {FAKE_ITIN}"),
        "ITIN: [SSN-REDACTED]",
    ))
    results.append(check(
        "two SSNs in one string -> both redacted",
        _redact_ssn_itin_ein(f"Ed: {FAKE_SSN}, Tanya: {FAKE_SSN_2}"),
        "Ed: [SSN-REDACTED], Tanya: [SSN-REDACTED]",
    ))
    results.append(check(
        "EIN shape alone, no keyword nearby -> NOT redacted (too many false positives)",
        _redact_ssn_itin_ein(f"invoice ref {FAKE_EIN} shipped"),
        f"invoice ref {FAKE_EIN} shipped",
    ))
    results.append(check(
        "EIN shape + 'EIN' keyword nearby -> redacted",
        _redact_ssn_itin_ein(f"Company EIN: {FAKE_EIN}"),
        "Company EIN: [EIN-REDACTED]",
    ))
    results.append(check(
        "EIN shape + 'employer identification' keyword -> redacted",
        _redact_ssn_itin_ein(f"employer identification number {FAKE_EIN} on file"),
        "employer identification number [EIN-REDACTED] on file",
    ))
    results.append(check(
        "EIN shape + 'tax ID' keyword -> redacted",
        _redact_ssn_itin_ein(f"client tax ID is {FAKE_EIN}"),
        "client tax ID is [EIN-REDACTED]",
    ))
    results.append(check(
        "EIN shape near keyword >80 chars away -> NOT redacted (window bound)",
        _redact_ssn_itin_ein(
            "EIN on this client's old filing many years ago in a prior engagement that is long since closed "
            + f"and totally unrelated now, reference number: {FAKE_EIN}"
        ),
        "EIN on this client's old filing many years ago in a prior engagement that is long since closed "
        + f"and totally unrelated now, reference number: {FAKE_EIN}",
    ))
    results.append(check(
        "non-SSN-shaped date-like string untouched",
        _redact_ssn_itin_ein("meeting on 2026-11-01 at the office"),
        "meeting on 2026-11-01 at the office",
    ))
    results.append(check(
        "full redact_sensitive_text() entry point also catches SSN (integration)",
        redact_sensitive_text(f"Found SSN {FAKE_SSN} in postmortem", force=True),
        "Found SSN [SSN-REDACTED] in postmortem",
    ))

    out = redact_sensitive_text(f"SSN: {FAKE_SSN}", force=False)
    results.append(check(
        "SSN redaction is unconditional (fires even with force=False)",
        "[SSN-REDACTED]" in out and FAKE_SSN not in out,
        True,
    ))

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
