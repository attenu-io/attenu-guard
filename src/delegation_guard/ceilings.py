"""
ceilings.py — typed, self-narrowing, self-enforcing bounds on an Authority.

v0.1 kept ceilings as a stringly-typed `{"max_rows": 1000}` dict: nothing
validated it, nothing defined how two ceilings combine, and a ceiling the
enforcement code didn't specifically know about (e.g. a custom "max_widgets")
was carried through attenuation but silently *never enforced* — a real
red-team finding. v0.2 closes that gap: a `Ceiling` is a small typed object
that knows how to (a) check itself against a request context, (b) narrow
itself against a sibling ceiling of the same kind, (c) state whether it
admits a superset of what another ceiling of its kind admits, and (d) read
and write its own wire form. `Authority` no longer needs to know the
semantics of any particular ceiling — it just calls these methods.

The most important property here is the one demanded by the Internet-Draft's
constraint vocabulary (docs/draft-asor-wimse-agent-delegation-chain-00.md
{{constraints}}): "a verifier that encounters an unknown constraint type MUST
treat the action as denied (fail-closed), never as unconstrained." That is
implemented by `ceiling_from_wire`: an unrecognised wire constraint becomes a
`_UnknownCeiling`, whose `permits()` always denies. There is no code path by
which an unrecognised bound is silently dropped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol, runtime_checkable

from .reasons import Decision, Reason, ReasonCode

# Ordered enum for egress: index 0 is the strictest. A value outside this
# vocabulary is treated as *maximally permissive-requested* (worst case), so
# a garbage/unknown egress value fails closed rather than silently passing.
_EGRESS_ORDER = ("none", "internal", "any")


def _egress_rank(value: object) -> int:
    try:
        return _EGRESS_ORDER.index(value)
    except ValueError:
        return len(_EGRESS_ORDER)


@runtime_checkable
class Ceiling(Protocol):
    """The shape every ceiling (built-in or custom) must implement.

    `key` identifies the *dimension* being bounded (e.g. "max_rows") and is
    how `Authority.meet`/`is_narrower_than` pair up ceilings from two sides.
    """
    key: str

    # OPTIONAL (deliberately NOT part of the runtime-checkable protocol, so
    # existing custom ceilings stay valid): a `ctx_field: str` attribute
    # naming the request-context field this ceiling reads (RowLimit reads
    # ctx["rows"] while its `key` is "max_rows"). Consumers must go through
    # `ctx_field_of(ceiling)` below, which falls back to `field`, then `key`.
    # `Guard(strict_metering=True)` uses it to tell whether a metered call
    # DECLARED the dimension. Custom metered ceilings whose ctx field differs
    # from their key should set it, or strict metering will look for `key`.

    def permits(self, ctx: Mapping) -> Decision:
        """Does this ceiling admit the given request context? A ctx that
        doesn't mention this ceiling's dimension at all is treated as "not
        asserting anything here" and permitted — mirrors v0.1, where a
        quantity kwarg that wasn't passed simply wasn't checked."""
        ...

    def narrow(self, other: "Ceiling") -> "Ceiling":
        """Return the MORE restrictive of self and other (same key). Must
        satisfy: result.permits(ctx) implies both self.permits(ctx) and
        other.permits(ctx) — i.e. the result's admitted set is a subset of
        both inputs'. This is what makes `Authority.meet` sound."""
        ...

    def subsumes(self, other: "Ceiling") -> bool:
        """True iff self admits a superset of what `other` admits (self is
        at least as permissive). The inverse of narrow: `a.narrow(b) == a`
        iff `b.subsumes(a)`."""
        ...

    def to_wire(self) -> dict:
        """-> a constraint object per the I-D's Constraint Vocabulary."""
        ...

    @classmethod
    def from_wire(cls, d: dict) -> "Ceiling":
        ...


def ctx_field_of(ceiling) -> str:
    """The request-context field a ceiling reads. Prefers an explicit
    `ctx_field`, then the caller-keyed `field` (Allow/Deny/Prefix), then the
    ceiling's `key` — the convention every built-in follows, so this is
    correct for them and a sane default for custom ceilings."""
    explicit = getattr(ceiling, "ctx_field", None)
    if explicit:
        return explicit
    field_name = getattr(ceiling, "field", None)
    return field_name if field_name else ceiling.key


def describe(ceiling) -> str:
    """Uniform human-readable rendering of ANY ceiling: uses the ceiling's own
    `describe()` when it has one (all built-ins do), else `key=<wire form>`.
    For dashboards, demos and parent-vs-child diffs; never parsed back."""
    fn = getattr(ceiling, "describe", None)
    if callable(fn):
        return fn()
    return f"{ceiling.key}={ceiling.to_wire()}"


def is_metered(ceiling) -> bool:
    """A METERED ceiling bounds a consumed quantity the caller must declare
    (rows read, spend, calls) — by convention its key starts with "max_".
    Rank/membership ceilings (egress, allow/deny/prefix) are not metered:
    omitting them from a context means "not asserting anything here", not
    "consuming an undeclared amount". `Guard(strict_metering=True)` refuses a
    metered call that omits ANY held metered ceiling's `ctx_field`."""
    return bool(getattr(ceiling, "metered", False)) or str(ceiling.key).startswith("max_")


# =========================================================================
# Built-in ceilings — fixed-key numeric/enum caps.
#
# For these four, the wire "key" IS the type discriminator (there is exactly
# one Ceiling class per key), so `key` is excluded from __init__ (it's not a
# choice the caller makes) and the registry can route on "key" alone.
# =========================================================================

@dataclass(frozen=True)
class RowLimit:
    """Per-call cap on rows read/returned. ctx field: "rows"."""
    max_rows: int
    key: str = field(default="max_rows", init=False, repr=False)
    ctx_field: str = field(default="rows", init=False, repr=False, compare=False)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get("rows")
        if n is None or n <= self.max_rows:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_rows, n))

    def describe(self) -> str:
        return f"{self.key}<={self.max_rows}"

    def narrow(self, other: "RowLimit") -> "RowLimit":
        return RowLimit(min(self.max_rows, other.max_rows))

    def subsumes(self, other: "RowLimit") -> bool:
        return self.max_rows >= other.max_rows

    def to_wire(self) -> dict:
        return {"key": self.key, "max": self.max_rows}

    @classmethod
    def from_wire(cls, d: Mapping) -> "RowLimit":
        return cls(d["max"])


@dataclass(frozen=True)
class SpendCap:
    """Per-call cap on spend (currency-agnostic). ctx field: "spend"."""
    max_spend: float
    key: str = field(default="max_spend", init=False, repr=False)
    ctx_field: str = field(default="spend", init=False, repr=False, compare=False)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get("spend")
        if n is None or n <= self.max_spend:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_spend, n))

    def describe(self) -> str:
        return f"{self.key}<={self.max_spend}"

    def narrow(self, other: "SpendCap") -> "SpendCap":
        return SpendCap(min(self.max_spend, other.max_spend))

    def subsumes(self, other: "SpendCap") -> bool:
        return self.max_spend >= other.max_spend

    def to_wire(self) -> dict:
        return {"key": self.key, "max": self.max_spend}

    @classmethod
    def from_wire(cls, d: Mapping) -> "SpendCap":
        return cls(d["max"])


@dataclass(frozen=True)
class CallLimit:
    """Per-call cap on a call count. ctx field: "calls"."""
    max_calls: int
    key: str = field(default="max_calls", init=False, repr=False)
    ctx_field: str = field(default="calls", init=False, repr=False, compare=False)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get("calls")
        if n is None or n <= self.max_calls:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_calls, n))

    def describe(self) -> str:
        return f"{self.key}<={self.max_calls}"

    def narrow(self, other: "CallLimit") -> "CallLimit":
        return CallLimit(min(self.max_calls, other.max_calls))

    def subsumes(self, other: "CallLimit") -> bool:
        return self.max_calls >= other.max_calls

    def to_wire(self) -> dict:
        return {"key": self.key, "max": self.max_calls}

    @classmethod
    def from_wire(cls, d: Mapping) -> "CallLimit":
        return cls(d["max"])


@dataclass(frozen=True)
class EgressRank:
    """Ordered-enum egress ceiling: none < internal < any. ctx field: "egress"."""
    level: str
    key: str = field(default="egress", init=False, repr=False)
    ctx_field: str = field(default="egress", init=False, repr=False, compare=False)

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get("egress")
        if val is None or _egress_rank(val) <= _egress_rank(self.level):
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.level, val))

    def describe(self) -> str:
        return f"{self.key}<={self.level}"

    def narrow(self, other: "EgressRank") -> "EgressRank":
        stricter = self.level if _egress_rank(self.level) <= _egress_rank(other.level) else other.level
        return EgressRank(stricter)

    def subsumes(self, other: "EgressRank") -> bool:
        return _egress_rank(self.level) >= _egress_rank(other.level)

    def to_wire(self) -> dict:
        return {"key": self.key, "rank": self.level}

    @classmethod
    def from_wire(cls, d: Mapping) -> "EgressRank":
        return cls(d["rank"])


# =========================================================================
# Built-in ceilings — generic, caller-keyed set membership / prefix bounds.
#
# `key` here IS a caller choice (e.g. "region", "tool"), so it cannot double
# as the wire type discriminator; these carry an explicit "type" on the wire
# and are pre-registered under that type tag (see the registry below).
# `field` is the ctx lookup name when it differs from `key` (defaults to
# `key` itself, so the common case — ctx field == dimension name — needs no
# extra argument).
# =========================================================================

@dataclass(frozen=True)
class Allow:
    """Membership allow-list: the ctx value MUST be one of `one_of`."""
    key: str
    one_of: frozenset
    field: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "one_of", frozenset(self.one_of))

    def _field(self) -> str:
        return self.field if self.field is not None else self.key

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get(self._field())
        if val is None or val in self.one_of:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key,
                                     sorted(self.one_of, key=str), val))

    def describe(self) -> str:
        return f"{self.key} in [{', '.join(sorted(map(str, self.one_of)))}]"

    def narrow(self, other: "Allow") -> "Allow":
        # admits fewer values -> stricter: set intersection.
        return Allow(self.key, self.one_of & frozenset(other.one_of), self.field)

    def subsumes(self, other: "Allow") -> bool:
        return frozenset(other.one_of) <= self.one_of

    def to_wire(self) -> dict:
        d = {"key": self.key, "type": "allow", "one_of": sorted(self.one_of, key=str)}
        if self.field is not None and self.field != self.key:
            d["field"] = self.field
        return d

    @classmethod
    def from_wire(cls, d: Mapping) -> "Allow":
        return cls(d["key"], frozenset(d.get("one_of", ())), d.get("field"))


@dataclass(frozen=True)
class Deny:
    """Membership deny-list: the ctx value MUST NOT be one of `not_one_of`."""
    key: str
    not_one_of: frozenset
    field: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "not_one_of", frozenset(self.not_one_of))

    def _field(self) -> str:
        return self.field if self.field is not None else self.key

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get(self._field())
        if val is None or val not in self.not_one_of:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key,
                                     sorted(self.not_one_of, key=str), val))

    def describe(self) -> str:
        return f"{self.key} not in [{', '.join(sorted(map(str, self.not_one_of)))}]"

    def narrow(self, other: "Deny") -> "Deny":
        # denying MORE values is stricter: set union.
        return Deny(self.key, self.not_one_of | frozenset(other.not_one_of), self.field)

    def subsumes(self, other: "Deny") -> bool:
        # self admits a superset of other's admitted set iff self forbids a
        # subset of what other forbids.
        return self.not_one_of <= frozenset(other.not_one_of)

    def to_wire(self) -> dict:
        d = {"key": self.key, "type": "deny", "not_one_of": sorted(self.not_one_of, key=str)}
        if self.field is not None and self.field != self.key:
            d["field"] = self.field
        return d

    @classmethod
    def from_wire(cls, d: Mapping) -> "Deny":
        return cls(d["key"], frozenset(d.get("not_one_of", ())), d.get("field"))


@dataclass(frozen=True)
class Prefix:
    """String-prefix bound: the ctx value MUST start with `prefix`."""
    key: str
    prefix: str
    field: str | None = None

    def _field(self) -> str:
        return self.field if self.field is not None else self.key

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get(self._field())
        if val is None or str(val).startswith(self.prefix):
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.prefix, val))

    def describe(self) -> str:
        return f"{self.key} startswith {self.prefix}"

    def narrow(self, other: "Prefix") -> "Prefix":
        # If one prefix is a prefix of the other, the longer (more specific)
        # one admits the subset and is the sound meet.
        if self.prefix.startswith(other.prefix):
            return self
        if other.prefix.startswith(self.prefix):
            return other
        # Incomparable prefixes (e.g. "eu-" and "us-"): no real value can
        # start with both, so the mathematically sound meet admits nothing.
        # Encode "admits nothing" as a prefix containing a NUL byte, which
        # cannot be a genuine prefix of any realistic ctx string -> permits()
        # will (soundly) deny every real request rather than us picking one
        # side arbitrarily and silently admitting values the other side
        # would have rejected.
        return Prefix(self.key, self.prefix + "\x00" + other.prefix, self.field)

    def subsumes(self, other: "Prefix") -> bool:
        return other.prefix.startswith(self.prefix)

    def to_wire(self) -> dict:
        d = {"key": self.key, "type": "prefix", "prefix": self.prefix}
        if self.field is not None and self.field != self.key:
            d["field"] = self.field
        return d

    @classmethod
    def from_wire(cls, d: Mapping) -> "Prefix":
        return cls(d["key"], d["prefix"], d.get("field"))


# =========================================================================
# Registry — the extension seam. Maps a wire discriminator ("type" if
# present, else "key") to the Ceiling class that knows how to rebuild
# itself from that wire shape. Fail-closed: an unrecognised discriminator
# never resolves to "unbounded" — it resolves to a ceiling that denies.
# =========================================================================

_REGISTRY: dict[str, type] = {}


def register_ceiling(key: str, cls: type) -> None:
    """Register a Ceiling class's `from_wire` under a wire discriminator.

    For the fixed-key built-ins the discriminator is the ceiling's own key
    ("max_rows" -> RowLimit); for generic/custom ceilings it should be a
    "type" tag (e.g. "allow", or a custom type name), since their `key` is
    chosen per-instance by the caller and can't double as a class selector.
    Re-registering a discriminator replaces the previous mapping — callers
    may shadow a built-in deliberately, but should do so knowingly.
    """
    _REGISTRY[key] = cls


@dataclass(frozen=True)
class _UnknownCeiling:
    """Fail-closed placeholder for a wire constraint this build does not
    recognise. Per the I-D: "a verifier that encounters an unknown
    constraint type MUST treat the action as denied (fail-closed), never as
    unconstrained." Every method here reflects that:

      * permits()  -> ALWAYS denies with UNKNOWN_CONSTRAINT (never silently
                       permits, no matter what ctx is asked about).
      * narrow()    -> meeting with anything stays an (still-denying)
                       unknown ceiling; it can never resolve to something
                       more permissive than "deny everything".
      * subsumes()  -> can never be proven true against a *different*
                       constraint (we don't understand its semantics), so
                       it only subsumes an identical unknown ceiling —
                       just enough reflexivity for is_narrower_than(self).
      * to_wire()   -> preserves the original bytes losslessly, so a chain
                       that merely forwards tokens (without needing to
                       interpret every constraint type) can still do so.
    """
    key: object
    raw: Mapping = field(default_factory=dict)

    def permits(self, ctx: Mapping) -> Decision:
        return Decision.deny(Reason(
            ReasonCode.UNKNOWN_CONSTRAINT, self.key,
            message=f"unrecognised constraint type for key={self.key!r}; fail-closed"))

    def narrow(self, other: "Ceiling") -> "_UnknownCeiling":
        return self

    def subsumes(self, other: "Ceiling") -> bool:
        return isinstance(other, _UnknownCeiling) and dict(other.raw) == dict(self.raw)

    def to_wire(self) -> dict:
        return dict(self.raw)

    @classmethod
    def from_wire(cls, d: Mapping) -> "_UnknownCeiling":
        return cls(d.get("key"), dict(d))


def ceiling_from_wire(d: Mapping) -> "Ceiling":
    """Reconstruct a Ceiling from its wire form.

    Routes on "type" when present (required to disambiguate generic
    ceilings like Allow/Deny/Prefix), else falls back to "key" (sufficient
    for the fixed built-ins, where key IS the type). An unrecognised
    discriminator fails closed via `_UnknownCeiling` — see its docstring.
    """
    discriminator = d.get("type", d.get("key"))
    cls = _REGISTRY.get(discriminator)
    if cls is None:
        return _UnknownCeiling.from_wire(d)
    return cls.from_wire(d)


# Pre-register the built-ins.
register_ceiling("max_rows", RowLimit)
register_ceiling("max_spend", SpendCap)
register_ceiling("max_calls", CallLimit)
register_ceiling("egress", EgressRank)
register_ceiling("allow", Allow)
register_ceiling("deny", Deny)
register_ceiling("prefix", Prefix)
