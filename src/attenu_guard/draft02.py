"""
draft02.py — the rules draft-asor-wimse-agent-delegation-chain-02 adds, as one module.

The -01 rules stay where they are (ceilings.py, authority.py, wire.py) and stay the DEFAULT:
every existing caller, adapter, test and the twenty published -01 vectors verify exactly as
before. The -02 rules are opted into by a profile selector — `Authority(..., profile="02")`,
`wire.load(..., draft="02")`, `wire.serialize_chain(..., draft="02")` — and this module holds
what differs:

  * the three-form scope grammar (Section 4.1): literal, wildcard, and opaque scopes, classified
    by their bytes alone in that order, with the covering relation per form;
  * the constraint vocabulary of Section 4.2 as generic, key-addressed ceilings: `max`, `min`,
    `max_lifetime`, `max_subtree`, and `rank` with its `order` member;
  * the constraint-object rules: closed members, one typed value, one constraint per
    (key, type), unknown types fail closed;
  * the measurement-scope rule of step 8: a cumulative constraint (`max_lifetime`,
    `max_subtree`) is satisfied only where the running total it is measured over is held, so a
    request context that carries no total for it DENIES, never passes.

Request-context fields read by the generic ceilings (so that a chain minted from the library's
own fixed-key ceilings keeps reading the same context after a -02 round trip):

    key            per-action field   lifetime total     subtree total
    max_rows       rows               rows_total         rows_subtree_total
    max_spend      spend              spend_total        spend_subtree_total
    max_calls      calls              calls              calls_subtree_total
    max_calls[P]   calls[P]           calls[P]           calls[P]_subtree_total
    egress         egress             -                  -
    anything else  <key>              <key>_total        <key>_subtree_total

`max_calls` is the one key whose per-action field IS the running total: the library has always
metered call counts as "the count including this call" under `calls`, and the guard fills that
field itself (`Guard._auto_meter`), so a -02 `max_lifetime` on `max_calls` reads `calls` and is
held by the guard. Every other cumulative total is supplied by the component that holds it, or
the constraint denies.
"""
from __future__ import annotations

import collections.abc
import re
from dataclasses import dataclass, field
from typing import Mapping

from . import canonical
from .ceilings import (
    MAX_SAFE_INTEGER, _ABSENT, _NUMBER, _STRING, _check_key, _json_kind, _malformed, _refusal,
    _validate_safe_number, _wrong_kind, _UnknownCeiling, Allow, Deny, Prefix,
)
from .reasons import Decision, Reason, ReasonCode

__all__ = [
    "PROFILE_01", "PROFILE_02", "PROFILES",
    "classify_scope", "scope_covers", "validate_scope",
    "Max", "Min", "MaxLifetime", "MaxSubtree", "Rank",
    "CONSTRAINT_TYPES", "CUMULATIVE_TYPES", "draft_type_of",
    "ceiling_from_wire_02", "ceiling_to_wire_02",
]

PROFILE_01 = "01"
PROFILE_02 = "02"
PROFILES = (PROFILE_01, PROFILE_02)


def check_profile(profile) -> str:
    if profile not in PROFILES:
        raise ValueError(f"unknown draft profile {profile!r}; expected one of {PROFILES}")
    return profile


# =========================================================================
# Scope grammar — Section 4.1 of the -02
# =========================================================================

#: literal-scope  = segment "." segment *("." segment)
_LITERAL_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$")
#: wildcard-scope = segment *("." segment) ".*"
_WILDCARD_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*\.\*$")
#: opaque-scope   = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )   ; RFC 6749 scope-token minus "*"
_OPAQUE_RE = re.compile(r"^[\x21\x23-\x29\x2B-\x5B\x5D-\x7E]+$")

LITERAL, WILDCARD, OPAQUE = "literal", "wildcard", "opaque"


def classify_scope(scope) -> str | None:
    """The form of `scope` under the -02 grammar, by its bytes alone and in the draft's order:
    literal, then wildcard, then opaque; None when it matches none of the three (so it is
    invalid and the token carrying it is malformed). No case folding at any step."""
    if not isinstance(scope, str):
        return None
    # fullmatch, never match: `$` accepts a string ending in a newline, so "crm.read\n" would
    # classify as a literal and verify under crm.* (security review of 2026-10-07, finding 4).
    if _LITERAL_RE.fullmatch(scope):
        return LITERAL
    if _WILDCARD_RE.fullmatch(scope):
        return WILDCARD
    if _OPAQUE_RE.fullmatch(scope):
        return OPAQUE
    return None


def validate_scope(scope) -> None:
    if classify_scope(scope) is None:
        raise ValueError(
            f"invalid scope {scope!r}: not a literal scope, a wildcard scope, or an opaque "
            "scope (RFC 6749 scope-token without '*'); '*' is permitted only as the complete "
            "final segment after a dot")


def scope_covers(held: str, requested: str) -> bool:
    """The -02 covering relation. A literal covers only an identical literal; a wildcard covers
    any literal or wildcard that begins with its value minus the final '*' (the dot retained);
    an opaque scope covers only a byte-identical opaque scope, and no wildcard covers an opaque
    scope. Each side is classified by its own bytes, so `drive.*` does not cover `drive.Read`:
    the uppercase R makes the child opaque."""
    held_form = classify_scope(held)
    req_form = classify_scope(requested)
    if held_form is None or req_form is None:
        return False
    if held_form == WILDCARD:
        return req_form in (LITERAL, WILDCARD) and requested.startswith(held[:-1])
    return held == requested


# =========================================================================
# Generic ceilings — the -02 constraint vocabulary, addressed by key
# =========================================================================

#: The -02 constraint types this build implements, by their wire member name.
CONSTRAINT_TYPES = ("max", "min", "max_lifetime", "max_subtree", "one_of", "not_one_of",
                    "prefix", "rank")
CUMULATIVE_TYPES = ("max_lifetime", "max_subtree")

#: The context field a key's PER-ACTION value is read from (see the module docstring).
_LEGACY_FIELDS = {"max_rows": "rows", "max_spend": "spend", "max_calls": "calls"}


def _per_action_field(key: str) -> str:
    if key in _LEGACY_FIELDS:
        return _LEGACY_FIELDS[key]
    if key.startswith("max_calls["):
        return "calls" + key[len("max_calls"):]
    return key


def _lifetime_field(key: str) -> str:
    base = _per_action_field(key)
    if base == "calls" or base.startswith("calls["):
        return base                                   # the guard's own meter IS the running total
    return base + "_total"


def _subtree_field(key: str) -> str:
    return _per_action_field(key) + "_subtree_total"


def _check_number(key, member, value) -> None:
    if value is _ABSENT or _json_kind(value) != "a number":
        raise _malformed(key, member, value, "a number")
    _validate_safe_number(key, value)


@dataclass(frozen=True)
class Max:
    """Per-action numeric ceiling (`max`): the quantity in ONE authorized action MUST NOT exceed
    `value`. Nothing in this type aggregates across actions, tokens, siblings or a subtree."""
    key: str
    value: float
    draft_type: str = field(default="max", init=False, repr=False, compare=False)
    metered: bool = field(default=True, init=False, repr=False, compare=False)

    def __post_init__(self):
        _check_key(self.key)
        # A per-action cap on a COUNT caps nothing (every action is one call), and it is exactly
        # what a -01 producer emits as a call cap. This library meters `max_calls` as a running
        # count, so under the -02 a count bound is `max_lifetime` or `max_subtree`; a `max` on
        # that key is refused, in-process and at load (library profile restriction, not a rule
        # of the draft, which reserves no key names).
        if isinstance(self.key, str) and (self.key == "max_calls" or self.key.startswith("max_calls[")):
            raise ValueError(f"a per-action 'max' on the count key {self.key!r} bounds nothing; use "
                             "max_lifetime or max_subtree for a call count")
        _check_number(self.key, "max", self.value)

    @property
    def ctx_field(self) -> str:
        return _per_action_field(self.key)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get(self.ctx_field)
        if n is None:
            return Decision.allow()
        kind = _wrong_kind(n, _NUMBER)
        if kind is None and n <= self.value:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.value, n,
                                    _refusal(kind, "a maximum")))

    def describe(self) -> str:
        return f"{self.key}<={self.value}"

    def narrow(self, other: "Max") -> "Max":
        return Max(self.key, min(self.value, other.value))

    def subsumes(self, other) -> bool:
        return type(other) is type(self) and other.key == self.key and self.value >= other.value

    def to_wire(self) -> dict:
        return {"key": self.key, "max": self.value}

    @classmethod
    def from_wire(cls, d: Mapping) -> "Max":
        return cls(d.get("key", _ABSENT), d.get("max", _ABSENT))


@dataclass(frozen=True)
class Min:
    """Per-action numeric floor (`min`): the quantity MUST NOT be less than `value`. A child
    tightens a floor UPWARD, so narrowing takes the larger value."""
    key: str
    value: float
    draft_type: str = field(default="min", init=False, repr=False, compare=False)

    def __post_init__(self):
        _check_key(self.key)
        _check_number(self.key, "min", self.value)

    @property
    def ctx_field(self) -> str:
        return _per_action_field(self.key)

    def permits(self, ctx: Mapping) -> Decision:
        n = ctx.get(self.ctx_field)
        if n is None:
            return Decision.allow()
        kind = _wrong_kind(n, _NUMBER)
        if kind is None and n >= self.value:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.value, n,
                                    _refusal(kind, "a minimum")))

    def describe(self) -> str:
        return f"{self.key}>={self.value}"

    def narrow(self, other: "Min") -> "Min":
        return Min(self.key, max(self.value, other.value))

    def subsumes(self, other) -> bool:
        return type(other) is type(self) and other.key == self.key and self.value <= other.value

    def to_wire(self) -> dict:
        return {"key": self.key, "min": self.value}

    @classmethod
    def from_wire(cls, d: Mapping) -> "Min":
        return cls(d.get("key", _ABSENT), d.get("min", _ABSENT))


class _Cumulative:
    """Shared behaviour of the two cumulative types. `permits` reads the RUNNING TOTAL from the
    context field named by `ctx_field`; a context that carries no total is a component that does
    not hold it, and step 8 of the -02 says such a component MUST deny."""
    key: str
    value: float
    draft_type: str
    metered = True

    @property
    def meter_key(self) -> str:
        """What a `max_calls` lifetime bound counts, for `Guard._auto_meter`: the scope pattern
        in `max_calls[<pattern>]`, or "*" for every call of the node."""
        if self.key.startswith("max_calls[") and self.key.endswith("]"):
            return self.key[len("max_calls["):-1]
        return "*"

    def applies_to_scope(self, scope) -> bool:
        pattern = self.meter_key
        if pattern == "*" or scope is None:
            return True
        return scope_covers(pattern, scope) or pattern == scope

    def permits(self, ctx: Mapping) -> Decision:
        if self.key.startswith("max_calls") and not self.applies_to_scope(ctx.get("_scope")):
            return Decision.allow()
        n = ctx.get(self.ctx_field)
        if n is None:
            return Decision.deny(Reason(
                ReasonCode.CEILING_EXCEEDED, self.key, self.value, None,
                f"no running total for {self.ctx_field!r} is held here; a cumulative "
                "constraint is checked only where its total is held; refused"))
        kind = _wrong_kind(n, _NUMBER)
        if kind is None and n <= self.value:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.value, n,
                                    _refusal(kind, "a maximum")))

    def describe(self) -> str:
        return f"{self.key}<={self.value} ({self.draft_type})"

    def narrow(self, other):
        return type(self)(self.key, min(self.value, other.value))

    def subsumes(self, other) -> bool:
        return type(other) is type(self) and other.key == self.key and self.value >= other.value

    def to_wire(self) -> dict:
        return {"key": self.key, self.draft_type: self.value}


@dataclass(frozen=True)
class MaxLifetime(_Cumulative):
    """`max_lifetime`: the SUM of the quantity over every action authorized under the token
    carrying it (its `jti`) MUST NOT exceed `value`. Read from the lifetime-total field."""
    key: str
    value: float
    draft_type: str = field(default="max_lifetime", init=False, repr=False, compare=False)

    def __post_init__(self):
        _check_key(self.key)
        _check_number(self.key, "max_lifetime", self.value)

    @property
    def ctx_field(self) -> str:
        return _lifetime_field(self.key)

    @classmethod
    def from_wire(cls, d: Mapping) -> "MaxLifetime":
        return cls(d.get("key", _ABSENT), d.get("max_lifetime", _ABSENT))


@dataclass(frozen=True)
class MaxSubtree(_Cumulative):
    """`max_subtree`: the SUM over the token and every token descended from it MUST NOT exceed
    `value`. The total spans tokens, so it is held by accounting outside any one chain (Section
    9.4 of the -02); a context carrying none denies."""
    key: str
    value: float
    draft_type: str = field(default="max_subtree", init=False, repr=False, compare=False)

    def __post_init__(self):
        _check_key(self.key)
        _check_number(self.key, "max_subtree", self.value)

    @property
    def ctx_field(self) -> str:
        return _subtree_field(self.key)

    @classmethod
    def from_wire(cls, d: Mapping) -> "MaxSubtree":
        return cls(d.get("key", _ABSENT), d.get("max_subtree", _ABSENT))


def _check_order(key, order) -> tuple:
    if order is _ABSENT or not isinstance(order, (list, tuple)):
        raise _malformed(key, "order", order, "an array")
    if len(order) < 2 or any(not isinstance(o, str) for o in order) or len(set(order)) != len(order):
        raise ValueError(f"order of constraint {key!r} must list two or more distinct strings")
    return tuple(order)


@dataclass(frozen=True)
class Rank:
    """`rank` with its `order`: `order` lists an enumeration from least to most permissive and
    travels with the constraint, so a verifier needs no registry entry per key. The request value
    MUST be a member of `order` at a position not above `rank`'s; a value outside `order` is
    refused. A child's `order` MUST be identical to its parent's, element for element."""
    key: str
    rank: str
    order: tuple
    draft_type: str = field(default="rank", init=False, repr=False, compare=False)

    def __post_init__(self):
        _check_key(self.key)
        object.__setattr__(self, "order", _check_order(self.key, self.order))
        if not isinstance(self.rank, str) or self.rank not in self.order:
            raise _malformed(self.key, "rank", self.rank, "a member of order",
                             repr(self.rank) if isinstance(self.rank, str) else None)

    @property
    def ctx_field(self) -> str:
        return _per_action_field(self.key)

    def _index(self, value) -> int:
        return self.order.index(value)

    def permits(self, ctx: Mapping) -> Decision:
        val = ctx.get(self.ctx_field)
        if val is None:
            return Decision.allow()
        kind = _wrong_kind(val, _STRING)
        if kind is None and val in self.order and self._index(val) <= self._index(self.rank):
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.rank, val,
                                    _refusal(kind, "a rank")))

    def describe(self) -> str:
        return f"{self.key}<={self.rank} in [{', '.join(self.order)}]"

    def narrow(self, other: "Rank") -> "Rank":
        if other.order != self.order:
            raise ValueError(f"rank orderings differ on {self.key!r}; neither narrows the other")
        stricter = self.rank if self._index(self.rank) <= self._index(other.rank) else other.rank
        return Rank(self.key, stricter, self.order)

    def subsumes(self, other) -> bool:
        return (type(other) is type(self) and other.key == self.key and other.order == self.order
                and self._index(other.rank) <= self._index(self.rank))

    def to_wire(self) -> dict:
        return {"key": self.key, "rank": self.rank, "order": list(self.order)}

    @classmethod
    def from_wire(cls, d: Mapping) -> "Rank":
        return cls(d.get("key", _ABSENT), d.get("rank", _ABSENT), d.get("order", _ABSENT))


# =========================================================================
# Constraint objects on the -02 wire
# =========================================================================

_GENERIC = {"max": Max, "min": Min, "max_lifetime": MaxLifetime, "max_subtree": MaxSubtree,
            "rank": Rank, "one_of": Allow, "not_one_of": Deny, "prefix": Prefix}
#: Members a type's definition adds beside "key" and the type member itself.
_EXTRA_MEMBERS = {"rank": ("order",)}


def draft_type_of(ceiling) -> object:
    """The -02 type of a ceiling (the wire member name that carries its value), used to pair
    constraints by (key, type). Legacy fixed-key ceilings declare it; an unknown constraint pairs
    by the set of members it carries, so two unknown constraints of different shapes are two
    constraints."""
    t = getattr(ceiling, "draft_type", None)
    if t is not None:
        return t
    if isinstance(ceiling, _UnknownCeiling):
        return ("unknown",) + tuple(sorted(k for k in ceiling.raw if k != "key"))
    return type(ceiling).__name__


def ceiling_from_wire_02(d):
    """One -02 constraint object -> a ceiling. The object is closed: `key`, exactly one type
    member, and the members that type adds (`order` for `rank`). Anything else is malformed. A
    single member this build does not implement is an unknown constraint, kept whole and failing
    closed (unknown types deny every action and subsume only an identical one)."""
    if not isinstance(d, collections.abc.Mapping):
        raise ValueError(f"a constraint is {_json_kind(d)}, not an object")
    _check_key(d.get("key", _ABSENT))
    key = d["key"]
    members = [m for m in d if m != "key"]
    known = [m for m in members if m in _GENERIC]
    if len(known) > 1:
        raise ValueError(f"constraint {key!r} carries {len(known)} typed values ({', '.join(sorted(known))}); "
                         "a constraint carries exactly one")
    if not known:
        if len(members) == 1:
            return _UnknownCeiling.from_wire(d)      # one unimplemented type: fail closed, not malformed
        raise ValueError(f"constraint {key!r} carries no typed value this build implements and "
                         f"{len(members)} other members; a constraint carries exactly one typed value")
    ctype = known[0]
    allowed = {"key", ctype, *_EXTRA_MEMBERS.get(ctype, ())}
    extra = sorted(set(d) - allowed)
    if extra:
        raise ValueError(f"constraint {key!r} of type {ctype!r} carries members this type does not "
                         f"define: {', '.join(map(repr, extra))}; a constraint object is closed")
    return _GENERIC[ctype].from_wire(d)


def ceiling_to_wire_02(c) -> dict:
    """The -02 wire form of any ceiling: the generic and legacy classes that know their -02 shape
    emit it; the library's membership and prefix ceilings drop their `type` discriminator, which
    the -02's closed constraint object does not admit; an unknown constraint re-emits its bytes.
    A `field` that differs from the key cannot be expressed on the -02 wire and is refused."""
    w = c.to_wire_02() if hasattr(c, "to_wire_02") else dict(c.to_wire())
    if isinstance(c, _UnknownCeiling):
        return w
    w.pop("type", None)
    if "field" in w:
        if w["field"] != w.get("key"):
            raise ValueError(f"constraint {c.key!r} reads context field {w['field']!r}, which the "
                             "-02 wire cannot express; the key names the field there")
        del w["field"]
    return w


def check_integer_safe(value) -> None:
    """The -02 Section 3 rule: an integer whose magnitude exceeds 2^53-1 is malformed."""
    if type(value) is int and abs(value) > MAX_SAFE_INTEGER:
        raise ValueError(f"integer {value!r} exceeds the safe range for a binary64 signing surface")


def is_identical_unknown(a, b) -> bool:
    try:
        return canonical.dumps(dict(a.raw)) == canonical.dumps(dict(b.raw))
    except canonical.CanonicalizationError:
        return False
