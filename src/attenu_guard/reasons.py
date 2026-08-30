"""
reasons.py — the machine-readable outcome vocabulary for authorization decisions.

Every policy evaluation in attenu-guard produces a `Decision`: a bool-coercible
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
    # Structural failures — the `reason` strings `AuthorityError` carries when a
    # DELEGATION is refused (Chain.delegation_error). Values are the published
    # v0.1 audit vocabulary and must not change; the constants exist so adapters
    # can map them without a lookup table.
    CHAIN_REVOKED = "chain_revoked"
    AGENT_BANNED = "agent_banned"
    TTL_EXPIRED = "ttl_expired"
    MAX_DEPTH = "max_depth"
    MAX_FANOUT = "max_fanout"
    CHAIN_CEILING = "chain_ceiling"
    NO_AUTHORITY = "no_authority"               # principal holds no Authority at all in this chain
                                                # (adapter-level: unknown/undelegated agent, unmapped
                                                # tool, unparseable args) — upstream of scope/ceilings
    # 0.9.0 execution-binding transition (schema_version=2 chains only — see guard.py):
    NODE_FINALIZED = "node_finalized"           # check() refused: the node already called complete()
    CALL_ID_UNAVAILABLE = "call_id_unavailable"  # the OS CSPRNG failed while allocating call_id;
                                                 # fail-closed — the call is denied and nothing is written


class Disposition:
    """WHY a denied scope was not in the node's authority — the ledger's answer to "held, or over-reach?".

    The shim records what its caller states; it never derives. The default for a policy deny with
    `scope_not_granted` is OUT_OF_AUTHORITY, which is literally true for the shim (the scope was not
    held by this node). An authority source (e.g. a derivation engine) states the richer reason it
    knows: held pending an operator grant, withheld tier-2, or an unresolved tool. Held means
    "waiting on you"; out_of_authority means "we stopped something". Never rename a value.
    """
    HELD_PENDING_GRANT = "held_pending_grant"   # known, curated, waiting on a human decision
    WITHHELD_TIER2 = "withheld_tier2"           # resolvable only to a tier-2 heuristic that is never granted
    UNRESOLVED = "unresolved"                   # no authority known for this tool at all
    OUT_OF_AUTHORITY = "out_of_authority"       # resolved and grantable, but not held by THIS node — real over-reach
    ALL = frozenset({HELD_PENDING_GRANT, WITHHELD_TIER2, UNRESOLVED, OUT_OF_AUTHORITY})


class Capture:
    """What the adapter's code path WILL observe for a given `check()`ed call — recorded on the
    `allow` entry alongside `adapter` (module/version/hook_path). Describes observation CAPABILITY
    only, never a claim of quality (docs/execution-binding spec section 2): a verifier routes a
    call into observed/unobserved reporting from this label, never trusts it as evidence on its own.
    """
    WRAPPER_SYNC = "wrapper_sync"                 # the adapter's wrapper calls the body itself, synchronously
    WRAPPER_ASYNC = "wrapper_async"                # ... and awaits it
    FRAMEWORK_POST_HOOK = "framework_post_hook"    # the framework itself calls back after the body runs
    PRE_HOOK_ONLY = "pre_hook_only"                # the adapter sees the call authorized but never observes it finish
    ALL = frozenset({WRAPPER_SYNC, WRAPPER_ASYNC, FRAMEWORK_POST_HOOK, PRE_HOOK_ONLY})


class BodyState:
    """The `outcome` record's observation of how a body-owning wrapper's call ended (docs/
    execution-binding spec section 3) — an OBSERVATION, not a judgment about the world. There is no
    `executed`/`blocked`/`timeout`/`cancelled` at this layer; each of those words claims knowledge a
    wrapper does not always have. Adapters emitting into a richer outcome vocabulary own that mapping."""
    RETURNED = "returned"     # the body returned to the wrapper
    RAISED = "raised"         # it raised (error_code required, from the exception's class name)
    ABANDONED = "abandoned"   # the wrapper stopped observing while the body may still run
    DEFERRED = "deferred"     # the wrapper returned a generator/stream/future it does not itself consume
    ALL = frozenset({RETURNED, RAISED, ABANDONED, DEFERRED})


@dataclass(frozen=True)
class CompletionResult:
    """`Guard.complete()`'s return value (docs/execution-binding spec section 1): whether the node
    was actually finalized, and — when it refused because calls are still pending an outcome — the
    `call_id`s it is waiting on. Bool-coercible so `if guard.complete():` keeps reading naturally;
    `is True`/`is False` identity checks do NOT survive this change (`complete()` used to return a
    bare bool) — that is a deliberate, documented break, not an oversight.
    """
    completed: bool
    pending_call_ids: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.completed


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
    call_id: str | None = None    # 0.9.0 execution binding: set only on a schema_version=2 chain
                                   # (Guard.check()/record_denial()); None on v1 chains and on any
                                   # Decision built outside a Guard transition (would_allow(), tests).

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
            "call_id": self.call_id,
        }

    @classmethod
    def allow(cls, node: str | None = None) -> "Decision":
        return cls(True, (), node)

    @classmethod
    def deny(cls, *reasons: Reason, node: str | None = None) -> "Decision":
        return cls(False, tuple(reasons), node)
