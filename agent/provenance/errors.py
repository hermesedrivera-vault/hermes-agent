"""Custom exceptions for provenance system."""


class ProvenanceError(Exception):
    """Base exception for provenance failures."""

    pass


class TokenNotFoundError(ProvenanceError):
    """Token does not exist in evidence store."""

    pass


class InvalidSignatureError(ProvenanceError):
    """Token signature verification failed."""

    pass


class CrossSessionError(ProvenanceError):
    """Attempted to use token from different session."""

    pass


class StaleTokenError(ProvenanceError):
    """Token has expired (exceeds TTL)."""

    pass


class ClaimMismatchError(ProvenanceError):
    """Token claim_id does not match the claim being verified."""

    pass


class ContentTamperedError(ProvenanceError):
    """Content hash does not match token - data was altered."""

    pass
