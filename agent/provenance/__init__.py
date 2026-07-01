"""
Provenance and attestation system for Hermes.

Prevents fabrication by requiring cryptographic receipts for all external claims.

Core principle: Model proposes, trusted code disposes.
The agent can REQUEST actions but cannot CERTIFY their safety.
"""

from .store import EvidenceStore, ProvenanceToken
from .errors import (
    ProvenanceError,
    CountMismatchError,
    FalseAbsenceError,
)

__all__ = [
    "EvidenceStore",
    "ProvenanceToken",
    "ProvenanceError",
    "CountMismatchError",
    "FalseAbsenceError",
]
