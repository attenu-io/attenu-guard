"""
Authority — the core value object.

An Authority is an immutable capability: a set of scopes plus a tuple of typed
`Ceiling` bounds and a TTL. The single most important operation is `meet`:
computing the greatest authority that is within BOTH a parent's authority and a
requested authority. A child of a delegation can never hold more than the meet —
attenuation is a lattice operation, enforced in code, not a convention.

Design guarantee (the property everything else rests on):
    meet(parent, requested) <= parent   for ALL requested.
There is no code path by which a derived/child authority can exceed its parent.
This is what makes model-proposed authority safe: the proposal is only ever an
input to `meet`, and `meet` can only shrink.

v0.2 change from v0.1: `ceilings` is now a tuple of typed `Ceiling` objects
(see ceilings.py) instead of a `{"max_rows": 1000}` dict of bare numbers. Every
ceiling now knows its own narrowing rule (`Ceiling.narrow`) and its own
admission check (`Ceiling.permits`), so `Authority` no longer needs a hardcoded
table of "numeric vs. enum" semantics — and, critically, a ceiling type this
build doesn't recognise fails closed (see ceilings.ceiling_from_wire) instead
of being silently dropped or silently unbounded.

`is_narrower_than` is exactly the wire protocol's subsumption relation
(draft-asor-wimse-agent-delegation-chain-01 {{subsumption}}): the library
relation and the token relation are the *same* relation, so a chain that
verifies offline is one the library would have permitted, and vice versa.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Mapping

from .ceilings import Ceiling, ceiling_from_wire
from .reasons import Decision, Reason, ReasonCode


_SCOPE_RE = re.compile(
    r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*\.(?:[a-z][a-z0-9_-]*|\*)$"
)


def _validate_scope(scope: str) -> None:
    """Validate the agent_delegation scope grammar defined by the I-D."""
    if not isinstance(scope, str) or _SCOPE_RE.fullmatch(scope) is None:
        raise ValueError(
            f"invalid scope {scope!r}: expected lowercase dot-separated segments; "
            "'*' is permitted only as the complete final segment after a dot"
        )


class AuthorityError(Exception):
    """Raised for STRUCTURAL failures (bad input / invalid chain state) —
    e.g. delegating from a revoked or expired node, or a chain depth/fanout
    overflow. Deliberately distinct from a policy *denial*: those are a
    normal outcome, expressed as a `Decision`/`AuthorityDenied` (see
    guard.py), not an exception. A structural error means the caller did
    something invalid; a denial means the caller asked for something the
    authority model legitimately refuses.
    """

    def __init__(self, message: str, *, reason: str, detail: dict | None = None):
        super().__init__(message)
        self.reason = reason
        self.detail = detail or {}


@dataclass(frozen=True)
class Authority:
    """An immutable capability grant.

    scopes:   set of lowercase, dot-separated permission strings, e.g.
              {"crm.read", "mail.send"}. A terminal prefix wildcard such as
              "crm.*" covers every depth below the dotted "crm." boundary,
              but not bare "crm" or the adjacent namespace "crmx.read". A
              child requesting "crm.read" under a parent holding "crm.*" is
              allowed; the reverse is not. Bare or non-terminal "*" is invalid.
    ceilings: a tuple of typed `Ceiling` objects (RowLimit, SpendCap, ...,
              or any custom Ceiling implementation). Construction accepts any
              iterable of Ceiling and normalises it to a tuple with at most
              one ceiling per `.key` (last one wins), sorted by key for a
              deterministic wire form / integrity seal. A dimension with no
              ceiling present is unbounded on that dimension unless a parent
              in the chain bounds it (attenuation can only add/tighten
              bounds, never remove one — see `meet`).
    ttl:      seconds this authority remains valid from issuance. meet takes
              the min. None = unbounded (discouraged; templates set a default).
    """

    scopes: frozenset = field(default_factory=frozenset)
    ceilings: tuple = field(default_factory=tuple)
    ttl: int | None = None

    def __post_init__(self):
        # Normalise to immutable, comparable, deterministically-ordered forms.
        scopes = frozenset(self.scopes)
        for scope in scopes:
            _validate_scope(scope)
        object.__setattr__(self, "scopes", scopes)
        by_key: dict[str, Ceiling] = {}
        for c in self.ceilings:
            by_key[c.key] = c  # last-one-wins on a duplicate key
        object.__setattr__(self, "ceilings", tuple(by_key[k] for k in sorted(by_key)))

    # ---- ceiling lookup --------------------------------------------------
    def _by_key(self) -> dict:
        """Index ceilings by `.key` for pairwise comparison in meet/subsumption.
        Recomputed on demand rather than cached: `ceilings` tuples are small
        (a handful of bounds), and Authority must stay a plain frozen
        dataclass (hashable, trivially comparable) rather than carry mutable
        cache state.
        """
        return {c.key: c for c in self.ceilings}

    def ceiling(self, key: str):
        """Convenience accessor: the Ceiling bound to `key`, or None."""
        return self._by_key().get(key)

    # ---- scope helpers -----------------------------------------------------
    @staticmethod
    def _scope_covers(held: str, requested: str) -> bool:
        """Exact match, or a terminal `x.*` prefix at the retained dot boundary."""
        if held == requested:
            return True
        if held.endswith(".*"):
            prefix = held[:-1]  # keep the dot: "crm."
            return requested.startswith(prefix)
        return False

    def covers_scope(self, requested: str) -> bool:
        return any(self._scope_covers(h, requested) for h in self.scopes)

    # ---- the lattice ---------------------------------------------------
    def meet(self, other: "Authority") -> "Authority":
        """Greatest authority within BOTH self and other (the attenuation).

        This is the *only* way a child authority is constructed. It is
        commutative and can only ever shrink relative to either input.
        """
        # scopes: keep a requested scope only if self covers it; expand self's
        # own concrete scopes that other covers. Net effect: intersection with
        # wildcard awareness, never larger than either side's coverage.
        new_scopes = set()
        for s in other.scopes:
            if self.covers_scope(s):
                new_scopes.add(s)
        for s in self.scopes:
            if other.covers_scope(s):
                new_scopes.add(s)
        # Remove only REDUNDANT scopes: a scope covered by a *broader* wildcard
        # that is also present. This keeps the broadest legitimately-granted
        # authority (never drops it) and only trims duplicates — so a wildcard
        # granted by both sides survives the meet (v0.1 false-deny fix).
        wildcards = {s for s in new_scopes if s.endswith(".*")}
        pruned = {
            s for s in new_scopes
            if not any(w != s and self._scope_covers(w, s) for w in wildcards)
        }

        # ceilings: union of keys; where BOTH sides bound a key, narrow() it;
        # where only ONE side bounds it, carry that bound through unchanged.
        # A ceiling therefore only ever appears-or-tightens across a meet,
        # never disappears — exactly the property is_narrower_than checks.
        self_by_key = self._by_key()
        other_by_key = other._by_key()
        new_ceilings = []
        for k in sorted(set(self_by_key) | set(other_by_key)):
            a = self_by_key.get(k)
            b = other_by_key.get(k)
            new_ceilings.append(a.narrow(b) if (a is not None and b is not None)
                                 else (a if a is not None else b))

        # ttl: strictest (min) of the two, ignoring None
        ttls = [t for t in (self.ttl, other.ttl) if t is not None]
        new_ttl = min(ttls) if ttls else None

        return Authority(frozenset(pruned), tuple(new_ceilings), new_ttl)

    def is_narrower_than(self, other: "Authority") -> bool:
        """self <= other: is self provably no more powerful than other in
        every dimension? TRUE iff:

          1. every scope of self is covered by other (wildcard-aware);
          2. for every ceiling in `other` there is a ceiling of the same key
             in self that `other`'s ceiling subsumes (self is at least as
             restrictive); a ceiling in `other` ABSENT in self means self is
             UNBOUNDED on that dimension, i.e. self is MORE powerful there,
             so this is False — this holds for ANY ceiling key, including
             ones outside the built-in registry, which is what makes the
             relation sound for custom ceilings too;
          3. self.ttl is not None and (other.ttl is None or self.ttl <= other.ttl).

        This is exactly the wire subsumption relation (subsumption in the
        I-D) — the library relation and the token relation MUST be
        identical, so anything the library would delegate is exactly what an
        offline verifier would accept, and vice versa.
        """
        if not all(other.covers_scope(s) for s in self.scopes):
            return False

        self_by_key = self._by_key()
        for k, other_ceiling in other._by_key().items():
            self_ceiling = self_by_key.get(k)
            if self_ceiling is None:
                return False  # unbounded on self where other bounds it -> more powerful
            if not other_ceiling.subsumes(self_ceiling):
                return False

        if other.ttl is not None:
            if self.ttl is None or self.ttl > other.ttl:
                return False
        return True

    # `<=` as sugar for is_narrower_than — kept for readability in property
    # tests/assertions ("child <= parent" reads as a lattice-order check)
    # and as a defensive re-assertion inside chain.py.
    def __le__(self, other: "Authority") -> bool:
        return self.is_narrower_than(other)

    # ---- policy evaluation ------------------------------------------------
    def permits(self, scope: str, ctx: Mapping | None = None) -> Decision:
        """Is `scope` permitted under this authority, given a request
        context `ctx` (e.g. {"rows": 5000, "egress": "none"})?

        Aggregates: checks scope coverage AND every ceiling this authority
        holds, and collects every failing Reason (not just the first) so a
        single evaluation can explain everything wrong with a request, not
        just the first violation it happened to notice. Ceilings whose
        relevant ctx field is absent are not asserting anything this call
        and are treated as satisfied (mirrors v0.1: an omitted quantity
        simply isn't checked).
        """
        ctx = ctx or {}
        reasons: list[Reason] = []

        if not self.covers_scope(scope):
            reasons.append(Reason(
                ReasonCode.SCOPE_NOT_GRANTED, requested=scope,
                message=f"scope {scope!r} not covered by held scopes {sorted(self.scopes)}"))

        # Reserved key so SCOPED ceilings (CallLimit(applies_to=...)) can tell whether they apply.
        cctx = dict(ctx); cctx.setdefault("_scope", scope)
        for c in self.ceilings:
            decision = c.permits(cctx)
            if not decision:
                reasons.extend(decision.reasons)

        if reasons:
            return Decision.deny(*reasons)
        return Decision.allow()

    def with_ttl(self, ttl: int) -> "Authority":
        return replace(self, ttl=ttl)

    # ---- wire form ----------------------------------------------------
    def to_wire(self) -> dict:
        return {
            "scopes": sorted(self.scopes),
            "constraints": [c.to_wire() for c in self.ceilings],
            "ttl": self.ttl,
        }

    @classmethod
    def from_wire(cls, d: Mapping) -> "Authority":
        scopes = d.get("scopes", ())
        constraints = d.get("constraints", ())
        ceilings = tuple(ceiling_from_wire(c) for c in constraints)
        return cls(frozenset(scopes), ceilings, d.get("ttl"))

    # continuity aliases (v0.1 called these to_dict/from_dict)
    to_dict = to_wire
    from_dict = from_wire

    def describe(self) -> str:
        """Stable, human-readable one-liner (sorted scopes, ceilings via
        `ceilings.describe`). `repr`/`str` are unchanged."""
        from .ceilings import describe as _describe   # local import: no cycle at load
        scopes = ", ".join(sorted(self.scopes))
        cs = ", ".join(sorted(_describe(c) for c in self.ceilings))
        return f"scopes=[{scopes}] ceilings=[{cs}] ttl={self.ttl}"

    def __repr__(self) -> str:
        constraints = [c.to_wire() for c in self.ceilings]
        return f"Authority(scopes={sorted(self.scopes)}, ceilings={constraints}, ttl={self.ttl})"
