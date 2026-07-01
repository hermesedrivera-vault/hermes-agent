"""
Evidence store for provenance tokens.

This is the ONLY code that can mint provenance tokens.
The agent cannot call mint() - tokens are created as side effects of real tool execution.
"""

import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from .errors import (
    ClaimMismatchError,
    ContentTamperedError,
    CrossSessionError,
    InvalidSignatureError,
    ProvenanceError,
    StaleTokenError,
    TokenNotFoundError,
)


@dataclass(frozen=True)
class ProvenanceToken:
    """Immutable provenance token minted by trusted code."""

    token_id: str
    claim_id: str  # "portfolio.TSLA.qty" or "fusion.recommendation"
    source_uri: str  # "broker_api://positions" or "fusion://run/<uuid>"
    content_hash: str  # sha256(canonical_json(data))
    timestamp: float
    session_id: str
    ttl_seconds: int  # Force fresh retrieval for stale data
    tool_name: str
    signature: str  # HMAC(secret, signable_fields)

    def signable(self) -> bytes:
        """Data that is signed with HMAC."""
        return f"{self.claim_id}|{self.source_uri}|{self.content_hash}|{self.timestamp}".encode()


class EvidenceStore:
    """
    Provenance token store backed by SQLite.
    
    SECURITY BOUNDARY: The agent CANNOT call mint(). Only tool implementation code can.
    The agent CAN call verify(), but verification logic is deterministic and unforgeable.
    """

    def __init__(self, db_path: str, secret: bytes, secret_previous: Optional[bytes] = None):
        """
        Initialize evidence store.
        
        Args:
            db_path: Path to SQLite database
            secret: Current HMAC secret (32 bytes)
            secret_previous: Previous HMAC secret for rotation support (optional)
        """
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._secret_current = secret
        self._secret_previous = secret_previous
        self._init_schema()

    def _init_schema(self):
        """Create tables if they don't exist."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                token_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL,
                source_uri TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                timestamp REAL NOT NULL,
                session_id TEXT NOT NULL,
                ttl_seconds INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                signature TEXT NOT NULL
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_session 
            ON evidence(session_id, timestamp)
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_claim 
            ON evidence(claim_id, timestamp)
        """)

        # Immutable audit log - agent cannot write here
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event TEXT NOT NULL,
                tool TEXT,
                reason TEXT,
                mode TEXT,
                session_id TEXT,
                blocked BOOLEAN,
                details TEXT
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
            ON audit_log(timestamp DESC)
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_session 
            ON audit_log(session_id, timestamp)
        """)

        self.db.commit()

    def mint(
        self,
        claim_id: str,
        source_uri: str,
        content: Any,
        session_id: str,
        tool_name: str,
        ttl_seconds: int = 3600,
    ) -> ProvenanceToken:
        """
        MINT a provenance token. ONLY trusted code can call this.
        
        This is the security boundary - the agent must never be able to call this function.
        Tokens are minted as side effects of real tool execution.
        
        Args:
            claim_id: Unique identifier for this claim (e.g. "portfolio.TSLA.qty")
            source_uri: Where the data came from (e.g. "broker_api://positions")
            content: The actual data being attested
            session_id: Current session ID
            tool_name: Which tool minted this
            ttl_seconds: How long token is valid (default 1 hour)
            
        Returns:
            ProvenanceToken with cryptographic signature
        """
        token_id = f"tok_{uuid.uuid4().hex[:16]}"

        # Canonical hash of content
        content_hash = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()

        timestamp = time.time()

        # Create signable data
        signable = f"{claim_id}|{source_uri}|{content_hash}|{timestamp}".encode()

        # Sign with current secret
        signature = hmac.new(self._secret_current, signable, hashlib.sha256).hexdigest()

        token = ProvenanceToken(
            token_id=token_id,
            claim_id=claim_id,
            source_uri=source_uri,
            content_hash=content_hash,
            timestamp=timestamp,
            session_id=session_id,
            ttl_seconds=ttl_seconds,
            tool_name=tool_name,
            signature=signature,
        )

        # Store in database
        self.db.execute(
            """
            INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                token.token_id,
                token.claim_id,
                token.source_uri,
                token.content_hash,
                token.timestamp,
                token.session_id,
                token.ttl_seconds,
                token.tool_name,
                token.signature,
            ),
        )
        self.db.commit()

        self.audit(
            event="TOKEN_MINTED",
            tool=tool_name,
            reason=f"Minted {token_id} for {claim_id}",
            session_id=session_id,
            mode="mint",
            blocked=False,
        )

        return token

    def get(self, token_id: str) -> Optional[ProvenanceToken]:
        """Retrieve token by ID."""
        row = self.db.execute("SELECT * FROM evidence WHERE token_id = ?", (token_id,)).fetchone()

        if not row:
            return None

        return ProvenanceToken(
            token_id=row["token_id"],
            claim_id=row["claim_id"],
            source_uri=row["source_uri"],
            content_hash=row["content_hash"],
            timestamp=row["timestamp"],
            session_id=row["session_id"],
            ttl_seconds=row["ttl_seconds"],
            tool_name=row["tool_name"],
            signature=row["signature"],
        )

    def _verify_signature(self, token: ProvenanceToken) -> bool:
        """Verify token signature against current and previous secrets."""
        expected_sig_current = hmac.new(
            self._secret_current, token.signable(), hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(token.signature, expected_sig_current):
            return True

        # Try previous secret if available (for rotation support)
        if self._secret_previous:
            expected_sig_previous = hmac.new(
                self._secret_previous, token.signable(), hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(token.signature, expected_sig_previous):
                return True

        return False

    def verify(
        self, token_id: str, claim_id: str, content: Any, session_id: str, now: Optional[float] = None
    ) -> ProvenanceToken:
        """
        VERIFY a provenance token. This is called by gates before allowing dangerous actions.
        
        Checks:
        1. Token exists
        2. Signature is valid
        3. Session matches
        4. Token is not stale
        5. Claim ID matches
        6. Content hash matches
        
        Args:
            token_id: Token to verify
            claim_id: Expected claim ID
            content: Content being verified
            session_id: Current session ID
            now: Current time (for testing)
            
        Returns:
            ProvenanceToken if all checks pass
            
        Raises:
            ProvenanceError subclass if any check fails
        """
        # 1. Token exists
        token = self.get(token_id)
        if token is None:
            self.audit(
                event="VERIFY_FAILED",
                tool="gate",
                reason=f"Token {token_id} not found",
                session_id=session_id,
                blocked=True,
            )
            raise TokenNotFoundError(f"Token {token_id} does not exist")

        # 2. Signature valid
        if not self._verify_signature(token):
            self.audit(
                event="VERIFY_FAILED",
                tool="gate",
                reason=f"Invalid signature for {token_id}",
                session_id=session_id,
                blocked=True,
            )
            raise InvalidSignatureError(f"Token {token_id} has invalid signature")

        # 3. Session matches (prevent token reuse across sessions)
        if token.session_id != session_id:
            self.audit(
                event="VERIFY_FAILED",
                tool="gate",
                reason=f"Cross-session token: {token.session_id} != {session_id}",
                session_id=session_id,
                blocked=True,
            )
            raise CrossSessionError(
                f"Token {token_id} from session {token.session_id}, current session {session_id}"
            )

        # 4. Token not stale (force fresh retrieval)
        current_time = now if now is not None else time.time()
        age = current_time - token.timestamp
        if age > token.ttl_seconds:
            self.audit(
                event="VERIFY_FAILED",
                tool="gate",
                reason=f"Stale token: age={age:.0f}s, ttl={token.ttl_seconds}s",
                session_id=session_id,
                blocked=True,
            )
            raise StaleTokenError(
                f"Token {token_id} expired {age - token.ttl_seconds:.0f}s ago (TTL={token.ttl_seconds}s)"
            )

        # 5. Claim ID matches
        if token.claim_id != claim_id:
            self.audit(
                event="VERIFY_FAILED",
                tool="gate",
                reason=f"Claim mismatch: expected {claim_id}, token has {token.claim_id}",
                session_id=session_id,
                blocked=True,
            )
            raise ClaimMismatchError(
                f"Token {token_id} is for claim {token.claim_id}, not {claim_id}"
            )

        # 6. Content hash matches (detect tampering)
        content_hash = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
        if token.content_hash != content_hash:
            self.audit(
                event="VERIFY_FAILED",
                tool="gate",
                reason=f"Content tampered: hash mismatch for {claim_id}",
                session_id=session_id,
                blocked=True,
            )
            raise ContentTamperedError(
                f"Content hash mismatch for {token_id}: data was altered after minting"
            )

        # All checks passed
        self.audit(
            event="VERIFY_PASSED",
            tool="gate",
            reason=f"Token {token_id} verified for {claim_id}",
            session_id=session_id,
            blocked=False,
        )

        return token

    def audit(
        self,
        event: str,
        tool: str,
        reason: str,
        session_id: str,
        mode: str = "shadow",
        blocked: bool = False,
        details: Optional[str] = None,
    ):
        """
        IMMUTABLE AUDIT LOG - agent cannot write here.
        
        This is append-only and outside the agent's write scope.
        Used for measurement and forensics.
        """
        self.db.execute(
            """
            INSERT INTO audit_log (timestamp, event, tool, reason, mode, session_id, blocked, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (time.time(), event, tool, reason, mode, session_id, blocked, details),
        )
        self.db.commit()

    def get_audit_log(self, session_id: Optional[str] = None, limit: int = 100) -> list[dict]:
        """Retrieve audit log entries."""
        if session_id:
            rows = self.db.execute(
                """
                SELECT * FROM audit_log 
                WHERE session_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            """,
                (session_id, limit),
            ).fetchall()
        else:
            rows = self.db.execute(
                """
                SELECT * FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT ?
            """,
                (limit,),
            ).fetchall()

        return [dict(row) for row in rows]

    def close(self):
        """Close database connection."""
        self.db.close()
