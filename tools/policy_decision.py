"""PolicyDecision — typed compatibility shim over existing gate return values.

This is NOT a new policy/approval system. It changes nothing about how
``tools.approval._run_approval_gate`` or ``agent.provenance.gate.apply_provenance_gate``
decide anything, and no existing caller of either function is touched by this
module. It exists purely so future code (Control Plane Commit 5+) can look at
one typed shape instead of hand-rolling ``dict.get(...)``/``is not None`` checks
against two different raw return conventions:

- ``_run_approval_gate()`` returns ``{"approved": bool, "message": str|None, ...}``.
- ``apply_provenance_gate()`` returns ``None`` (pass) or a JSON error string (block).

``PolicyDecision.from_approval_gate_result()`` / ``.from_provenance_gate_result()``
wrap those raw values losslessly (the original value is always kept on ``.raw``)
without redesigning either decision core.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class PolicyDecision:
    """Typed, read-only view of a gate's decision.

    Attributes:
        approved: Whether the action is allowed to proceed.
        message: Human-facing reason/denial text, if any.
        source: Which gate produced this decision — ``"approval_gate"`` or
            ``"provenance_gate"``. Purely descriptive; not used for dispatch.
        raw: The original, unmodified return value from the wrapped function
            (the ``dict`` from ``_run_approval_gate`` or the ``str|None`` from
            ``apply_provenance_gate``). Always present so wrapping never loses
            information the original caller could see.
    """

    approved: bool
    message: Optional[str]
    source: str
    raw: Any

    @classmethod
    def from_approval_gate_result(cls, result: dict) -> "PolicyDecision":
        """Wrap a ``_run_approval_gate()`` return value.

        Does not call or modify ``_run_approval_gate`` — the caller runs the
        real gate exactly as before and passes its already-computed result in.
        """
        return cls(
            approved=bool(result.get("approved")),
            message=result.get("message"),
            source="approval_gate",
            raw=result,
        )

    @classmethod
    def from_provenance_gate_result(cls, result: Optional[str]) -> "PolicyDecision":
        """Wrap an ``apply_provenance_gate()`` return value.

        ``None`` means the gate passed (approved); a non-``None`` string is the
        JSON-encoded block message the gate already produced. Does not call or
        modify ``apply_provenance_gate``.
        """
        return cls(
            approved=result is None,
            message=result,
            source="provenance_gate",
            raw=result,
        )
