"""
reasons.py — the machine-readable outcome vocabulary for authorization decisions.

Every policy evaluation in delegation-guard produces a `Decision`: a bool-coercible
result carrying zero or more `Reason`s. A denial without a reason is a bug (see
docs/DEVX-REVIEW.md principle 2) — so every deny path in this library attaches at
least one `Reason` with a stable, machine-readable `code` from `ReasonCode`.

`Decision`/`Reason` are pure value objects: no dependency on Authority, Chain, or
Guard, so they can be imported by wire.py, scenarios.py, and adapters without
pulling in the rest of the core (and so audit/wire code can serialize them without
a cycle back into policy logic).
"""
from __future__ import annotations

from dataclasses import dataclass, field


class ReasonCode:
    """Stable string constants for machine-readable denial reasons.

    These strings — not Python exception types — are the contract: they are
    what the audit ledger stores, what wire/scenario assertions match against
    (`because: "scope_not_granted"`), and what survives a process boundary.
    Never rename an existing value; add new ones instead.
    """
    SCOPE_NOT_GRANTED = "scope_not_granted"
    CEILING_EXCEEDED = "ceiling_exceeded"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INTEGRITY = "integrity"
    DEPTH_EXCEEDED = "depth_exceeded"
    FANOUT_EXCEEDED = "fanout_exceeded"
    UNMETERED = "unmetered"
    UNKNOWN_CONSTRAINT = "unknown_constraint"   # fail-closed on unknown ceiling type
    NO_AUTHORITY = "no_authority"               # principal holds no Authority at all in this chain
                                                # (adapter-level: unknown/undelegated agent, unmapped
                                                # tool, unparseable args) — upstream of scope/ceilings


@dataclass(frozen=True)
class Reason:
    """One specific cause of a denial (or, in principle, an informational
    note on an allow — but every built-in emitter here only attaches Reasons
    on deny)."""
    code: str
    constraint: str | None = None     # e.g. "max_rows" — which ceiling/dimension
    limit: object = None              # the bound that applied
    requested: object = None          # the value/action that violated it
    message: str = ""                 # free-text, human-readable detail

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "constraint": self.constraint,
            "limit": self.limit,
            "requested": self.requested,
            "message": self.message,
        }

    def __str__(self) -> str:
        bits = [self.code]
        if self.constraint is not None:
            bits.append(f"constraint={self.constraint}")
        if self.limit is not None:
            bits.append(f"limit={self.limit}")
        if self.requested is not None:
            bits.append(f"requested={self.requested}")
        line = " ".join(bits)
        return f"{line}: {self.message}" if self.message else line


@dataclass(frozen=True)
class Decision:
    """The result of a policy evaluation. Bool-coercible (`if decision:`),
    so it reads naturally at call sites while still carrying full structured
    detail for logging/explainability.

    `determining_node` names the chain node whose state was decisive — for
    a single-node evaluation (this library) that's simply the node that was
    asked; a future multi-hop verifier can use the same field to name which
    hop in the chain caused the denial (mirrors Cedar's `reason()`).
    """
    allowed: bool
    reasons: tuple[Reason, ...] = ()
    determining_node: str | None = None

    def __bool__(self) -> bool:
        return self.allowed

    def explain(self) -> str:
        """A single human-readable line — for logs, CLIs, and error messages."""
        if self.allowed:
            return "allowed"
        if not self.reasons:
            return "denied"
        return "denied: " + "; ".join(str(r) for r in self.reasons)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reasons": [r.to_dict() for r in self.reasons],
            "determining_node": self.determining_node,
        }

    @classmethod
    def allow(cls, node: str | None = None) -> "Decision":
        return cls(True, (), node)

    @classmethod
    def deny(cls, *reasons: Reason, node: str | None = None) -> "Decision":
        return cls(False, tuple(reasons), node)
