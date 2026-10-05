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
constraint vocabulary (docs/draft-asor-wimse-agent-delegation-chain-01.md
{{constraints}}): "a verifier that encounters an unknown constraint type MUST
treat the action as denied (fail-closed), never as unconstrained." That is
implemented by `ceiling_from_wire`: an unrecognised wire constraint becomes a
`_UnknownCeiling`, whose `permits()` always denies. There is no code path by
which an unrecognised bound is silently dropped.
"""
from __future__ import annotations

import collections.abc
import math
import numbers
from dataclasses import dataclass, field
from typing import Mapping, Protocol, runtime_checkable

from . import canonical
from .canonical import MAX_SAFE_INTEGER
from .reasons import Decision, Reason, ReasonCode


def _validate_safe_number(key: str, value) -> None:
    """Reject a ceiling bound whose magnitude can't survive the signing surface intact.

    RFC 8785 numbers are binary64: an int past ±(2**53-1) can collide with a
    neighbouring integer once canonicalized (see canonical.UnsafeIntegerError),
    so a ceiling built from one would silently admit or deny a different value
    than the one the caller constructed. Fail at construction, not at signing —
    mirrors authority.py's `_validate_scope`."""
    if type(value) is int and abs(value) > MAX_SAFE_INTEGER:
        raise ValueError(
            f"{key} value {value!r} exceeds the safe integer range "
            f"±{MAX_SAFE_INTEGER} for a binary64 signing surface (RFC 8785)"
        )

# Ordered enum for egress: index 0 is the strictest. A value outside this
# vocabulary is treated as *maximally permissive-requested* (worst case), so
# a garbage/unknown egress value fails closed rather than silently passing.
_EGRESS_ORDER = ("none", "internal", "any")


def _egress_rank(value: object) -> int:
    try:
        return _EGRESS_ORDER.index(value)
    except ValueError:
        return len(_EGRESS_ORDER)


#: The JSON kinds a ceiling compares, as `_json_kind` names them.
_NUMBER = ("a number",)
_STRING = ("a string",)
_SCALAR = ("a string", "a number", "a boolean")


def _json_kind(value) -> str:
    """`value`'s JSON type as a refusal names it: null, a boolean, a number, a string, an array or
    an object, or "a value that is not JSON" for anything else passed in-process (a set, bytes).
    A boolean is never a number here, although Python's bool is an int, and a complex is no JSON
    number. The TypeScript implementation names the same values the same way."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, numbers.Number) and not isinstance(value, complex):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, (list, tuple)):
        return "an array"
    if isinstance(value, collections.abc.Mapping):
        return "an object"
    return "a value that is not JSON"


def _wrong_kind(value, accepted: tuple) -> str | None:
    """`_json_kind(value)` when a ceiling that compares `accepted` cannot compare `value`, else None.

    Every built-in ceiling refuses such a request value rather than coercing it (attenu-ops#110):
    `"50"` raised TypeError against a row cap, `True` passed one as 1 and a prefix as the text
    "True", and the TypeScript implementation read `["/tmp/x"]` as the path "/tmp/x"."""
    kind = _json_kind(value)
    return None if kind in accepted else kind


def _refusal(kind: str | None, against: str) -> str:
    """A denial's message: none when the value had the right type, as before; for one of the wrong
    type, `<kind> cannot be compared with <against>; refused`, one wording per ceiling kind, and
    the TypeScript implementation's too."""
    return "" if kind is None else f"{kind} cannot be compared with {against}; refused"


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

    def __post_init__(self):
        _validate_safe_number(self.key, self.max_rows)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get("rows")
        if n is None:
            return Decision.allow()
        kind = _wrong_kind(n, _NUMBER)
        if kind is None and n <= self.max_rows:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_rows, n,
                                    _refusal(kind, "a maximum")))

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

    def __post_init__(self):
        _validate_safe_number(self.key, self.max_spend)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get("spend")
        if n is None:
            return Decision.allow()
        kind = _wrong_kind(n, _NUMBER)
        if kind is None and n <= self.max_spend:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_spend, n,
                                    _refusal(kind, "a maximum")))

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
    """Cap on a call COUNT. ctx field: "calls" (the running count including this call).

    `applies_to` (optional) makes the ceiling SCOPED: it only bites requests for that scope
    (wildcards as in scopes: "fs.write", "web.*"). A scoped limit is its own dimension —
    `key` becomes "max_calls[<applies_to>]" — so an unscoped and a scoped limit coexist in one
    Authority and pair independently in meet/is_narrower_than.

    Metering: `Guard.check()` supplies `calls` itself, per (node, scope), when the caller does
    not — so adapters need no counting logic; an explicit `calls` in the context still wins.
    `Authority.permits` passes the requested scope as ctx["_scope"] (reserved) so scoped
    ceilings can tell whether they apply.
    """
    max_calls: int
    applies_to: str | None = None
    key: str = field(default="max_calls", init=False, repr=False)
    ctx_field: str = field(default="calls", init=False, repr=False, compare=False)

    def __post_init__(self):
        _validate_safe_number(self.key, self.max_calls)
        if self.applies_to:
            object.__setattr__(self, "key", f"max_calls[{self.applies_to}]")
            object.__setattr__(self, "ctx_field", f"calls[{self.applies_to}]")   # own meter, coexists with unscoped `calls`

    @property
    def meter_key(self) -> str:
        """What this ceiling counts: the pattern it applies to, or "*" (every call of the node)."""
        return self.applies_to or "*"

    def applies_to_scope(self, scope: str | None) -> bool:
        if not self.applies_to or scope is None:
            return True
        held = self.applies_to
        return held == scope or (held.endswith(".*") and str(scope).startswith(held[:-1]))

    def permits(self, ctx: Mapping) -> Decision:
        if not self.applies_to_scope(ctx.get("_scope")):
            return Decision.allow()
        n = ctx.get(self.ctx_field)
        if n is None:
            return Decision.allow()
        kind = _wrong_kind(n, _NUMBER)
        if kind is None and n <= self.max_calls:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_calls, n,
                                    _refusal(kind, "a maximum")))

    def describe(self) -> str:
        return f"{self.key}<={self.max_calls}"

    def narrow(self, other: "CallLimit") -> "CallLimit":
        return CallLimit(min(self.max_calls, other.max_calls), self.applies_to)

    def subsumes(self, other: "CallLimit") -> bool:
        return self.max_calls >= other.max_calls

    def to_wire(self) -> dict:
        if not self.applies_to:
            return {"key": self.key, "max": self.max_calls}                       # unchanged v0.2 wire form
        return {"key": self.key, "type": "max_calls", "max": self.max_calls, "applies_to": self.applies_to}

    @classmethod
    def from_wire(cls, d: Mapping) -> "CallLimit":
        return cls(d["max"], d.get("applies_to"))


@dataclass(frozen=True)
class EgressRank:
    """Ordered-enum egress ceiling: none < internal < any. ctx field: "egress"."""
    level: str
    key: str = field(default="egress", init=False, repr=False)
    ctx_field: str = field(default="egress", init=False, repr=False, compare=False)

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get("egress")
        if val is None:
            return Decision.allow()
        kind = _wrong_kind(val, _STRING)
        if kind is None and _egress_rank(val) <= _egress_rank(self.level):
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.level, val,
                                    _refusal(kind, "an egress rank")))

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

def _member_key(value) -> tuple:
    """A `one_of` / `not_one_of` member as JSON tells members apart: its JSON type, then its value.

    Python has `True == 1` and `hash(True) == hash(1)`, so a frozenset of the raw members merged
    the two (attenu-ops#110): `one_of: [1]` admitted `true`, and the same signed
    `not_one_of: ["secret", true, 1]` held two members here and three in the TypeScript
    implementation, whose Set keeps them apart. Keyed by type, a boolean is never a number, a
    string is never the number it spells, and null is its own kind. A number, any
    `numbers.Number`, is its numeric value, so `1.0` is 1, as in JavaScript and in RFC 8785. Any
    other value outside the JSON data model is a kind of its own, compared by Python's equality.
    A list or an object raises TypeError here, `unhashable type: 'list'`, which is how a member
    that is one was always refused."""
    if value is None:
        return ("null", None)
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, numbers.Number):
        return ("number", value)
    hash(value)   # raises for a list or an object, in the same words on every Python version
    return ("other", value)


def _member_text(value) -> str:
    """A member as `describe()` and a finding print it, and the text the wire form sorts by.

    The TypeScript implementation's `strOf` of the member its Set holds, so the two print and
    order the same members the same way: Python's `str` of a string, a boolean or null, and a
    number the way JavaScript holds it, which has no separate float. An integral number prints in
    decimal with no `.0` (`1.0` prints 1, the integral-number rule), and that includes -0.0,
    which a JavaScript Set stores as 0. Any other number prints as Python's `repr`, the same
    digits."""
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value))
        return repr(value)
    return value if isinstance(value, str) else str(value)


def _not_an_array(values) -> str | None:
    """What a refusal calls a `one_of` / `not_one_of` that is not a list of members, or None for
    one that is: a JSON array, or in-process any other collection of members (a set, a tuple).

    The draft defines both as an array. An object used to be read by its keys and a string by its
    characters, so `{"us": 1}` became the allow-list `["us"]`; null, a number and a boolean raised
    TypeError. Each is malformed now, as in the TypeScript implementation: a token carrying one is
    refused as malformed, and a bundle reports the authority unreadable."""
    if values is None:
        return "null"
    if isinstance(values, bool):
        return "a boolean"
    if isinstance(values, numbers.Number):
        return "a number"
    if isinstance(values, str):
        return "a string"
    if isinstance(values, collections.abc.Mapping):
        return "an object"
    if isinstance(values, (bytes, bytearray)) or not isinstance(values, collections.abc.Iterable):
        return "a value that is not an array"
    return None


def _members_of(key, list_name: str, values) -> "_Members":
    """`values` as the members of an `Allow` or a `Deny`. Raises ValueError naming the list and
    the key when `values` is not a list of members (`_not_an_array`)."""
    kind = _not_an_array(values)
    if kind is not None:
        raise ValueError(f"{list_name} of constraint {key!r} is {kind}, not an array")
    return _Members(values)


def _in_wire_order(members) -> list:
    """`members` as the wire form, a denial's `limit` and `describe()` list them: sorted by
    `_member_text`, which is the order the TypeScript implementation emits. Members that print
    alike (`"1"` and 1) keep the order they arrived in, as a stable sort over a JavaScript Set
    does, so the same signed bytes re-emit the same bytes in both implementations."""
    return sorted(members, key=_member_text)


class _Members(collections.abc.Set):
    """The members of an `Allow` or a `Deny`: a set of JSON values told apart by `_member_key`.

    Holds the first value given for each key, in the order given, which is what a JavaScript Set
    holds. Read-only and hashable, and a `collections.abc.Set`, so `in`, `len`, iteration, `<=`,
    `&` and `|` work as they did on the frozenset this replaces, with members compared by type.
    Compared against a plain set or frozenset, the plain set's own equality decides, and that
    still merges `true` and 1."""

    __slots__ = ("_values", "_keys")

    def __init__(self, values=()):
        by_key: dict = {}
        for value in values:
            by_key.setdefault(_member_key(value), value)
        self._values = tuple(by_key.values())
        self._keys = frozenset(by_key)

    def __contains__(self, value) -> bool:
        try:
            return _member_key(value) in self._keys
        except TypeError:   # a list or an object: no member is one, as in a JavaScript Set
            return False

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other):
        if isinstance(other, _Members):
            return self._keys == other._keys
        return super().__eq__(other)

    def __hash__(self) -> int:
        # The hash of a frozenset of the same values, so this and a plain set it compares equal
        # to hash alike. `true` and 1 share a hash without being equal, which a hash allows.
        return hash(frozenset(self._values))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({list(self._values)!r})"

    def __reduce__(self):
        return (type(self), (self._values,))


@dataclass(frozen=True)
class Allow:
    """Membership allow-list: the ctx value MUST be one of `one_of`.

    A member is its JSON type plus its value (`_member_key`): `one_of: [1]` admits 1 and 1.0,
    and refuses `true` and `"1"`. A ctx value that is not a JSON scalar is refused
    (`_wrong_kind`)."""
    key: str
    one_of: _Members
    field: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "one_of", _members_of(self.key, "one_of", self.one_of))

    def _field(self) -> str:
        return self.field if self.field is not None else self.key

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get(self._field())
        if val is None:
            return Decision.allow()
        kind = _wrong_kind(val, _SCALAR)
        if kind is None and val in self.one_of:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, _in_wire_order(self.one_of),
                                    val, _refusal(kind, "one_of members")))

    def describe(self) -> str:
        return f"{self.key} in [{', '.join(map(_member_text, _in_wire_order(self.one_of)))}]"

    def narrow(self, other: "Allow") -> "Allow":
        # admits fewer values -> stricter: set intersection, in self's order.
        return Allow(self.key, [v for v in self.one_of if v in other.one_of], self.field)

    def subsumes(self, other: "Allow") -> bool:
        return all(v in self.one_of for v in other.one_of)

    def to_wire(self) -> dict:
        d = {"key": self.key, "type": "allow", "one_of": _in_wire_order(self.one_of)}
        if self.field is not None and self.field != self.key:
            d["field"] = self.field
        return d

    @classmethod
    def from_wire(cls, d: Mapping) -> "Allow":
        return cls(d["key"], d.get("one_of", ()), d.get("field"))


@dataclass(frozen=True)
class Deny:
    """Membership deny-list: the ctx value MUST NOT be one of `not_one_of`.

    A member is its JSON type plus its value (`_member_key`): `not_one_of: [1]` refuses 1 and
    1.0, and does not refuse `true` or `"1"`. A ctx value that is not a JSON scalar is refused
    as well (`_wrong_kind`): a deny-list never waves through a value it cannot compare, since
    waving `["rm"]` through because it is not the string "rm" would fail open."""
    key: str
    not_one_of: _Members
    field: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "not_one_of", _members_of(self.key, "not_one_of", self.not_one_of))

    def _field(self) -> str:
        return self.field if self.field is not None else self.key

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get(self._field())
        if val is None:
            return Decision.allow()
        kind = _wrong_kind(val, _SCALAR)
        if kind is None and val not in self.not_one_of:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, _in_wire_order(self.not_one_of),
                                    val, _refusal(kind, "not_one_of members")))

    def describe(self) -> str:
        return f"{self.key} not in [{', '.join(map(_member_text, _in_wire_order(self.not_one_of)))}]"

    def narrow(self, other: "Deny") -> "Deny":
        # denying MORE values is stricter: set union, self's members first.
        return Deny(self.key, [*self.not_one_of, *other.not_one_of], self.field)

    def subsumes(self, other: "Deny") -> bool:
        # self admits a superset of other's admitted set iff self forbids a
        # subset of what other forbids.
        return all(v in other.not_one_of for v in self.not_one_of)

    def to_wire(self) -> dict:
        d = {"key": self.key, "type": "deny", "not_one_of": _in_wire_order(self.not_one_of)}
        if self.field is not None and self.field != self.key:
            d["field"] = self.field
        return d

    @classmethod
    def from_wire(cls, d: Mapping) -> "Deny":
        return cls(d["key"], d.get("not_one_of", ()), d.get("field"))


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
        if val is None:
            return Decision.allow()
        kind = _wrong_kind(val, _STRING)
        if kind is None and val.startswith(self.prefix):
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.prefix, val,
                                    _refusal(kind, "a prefix")))

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
                       Identical means the same RFC 8785 bytes, which is
                       equality as JSON: `true` is not 1, `1.0` is 1, and
                       key order is no difference at any depth. A value
                       RFC 8785 cannot write is identical to nothing.
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
        # Compared as RFC 8785 bytes, as the TypeScript implementation compares them, never by
        # Python's `==`: `{"v": [true]}` == `{"v": [1]}` there (attenu-ops#110).
        if not isinstance(other, _UnknownCeiling):
            return False
        try:
            return canonical.dumps(dict(other.raw)) == canonical.dumps(dict(self.raw))
        except canonical.CanonicalizationError:
            return False

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
