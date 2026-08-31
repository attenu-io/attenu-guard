"""
attenu_guard.adapters._snapshot — the ONE argument-snapshotting sanitizer every adapter in this
package shares, so every adapter's execution-binding `authorized_params`/`invoked_params`
commitment rests on the same, once-reviewed implementation instead of 18 independently-drifting
copies (release-gate review, architectural finding: consolidate).

`freeze(value)` is a genuinely immutable, fully decoupled rebuild of `value` -- it NEVER calls a
copy protocol (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back
itself (or another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is
independent of the live object graph, so a "snapshot" built that way can silently change out from
under the commitment when the tool body (or the framework itself) later mutates the original in
place. Containers are always rebuilt from scratch as fresh builtins (`dict`/`list`, recursively);
only already-immutable leaf types (`str`/`int`/`float`/`bool`/`None`) are kept as-is -- sharing an
immutable value carries no aliasing risk regardless of what protocol it does or does not
implement. Everything else -- anything this function cannot represent as one of those leaf types
or rebuild as a fresh container -- becomes `UNSUPPORTED` (below): never `repr()`, never `str()`,
never any other protocol invoked on it.

RELEASE-GATE CORRECTION: every adapter's own `_freeze()` (17 identical copies, one per adapter
module, before this consolidation) recursed into `Mapping`/`(list, tuple, set, frozenset)` with NO
cycle guard at all -- a self-referential container raised `RecursionError`, contradicting this
package's own CHANGELOG claim that `_freeze()` "never raises." Fixed here, once, with PATH-ACTIVE
cycle tracking: `_active` is the set of container `id()`s on the CURRENT recursion path from the
root call down to this one, passed as a new set at each recursive call (never mutated in place and
shared across siblings) -- so a container that appears TWICE as sibling values in a DAG (the SAME
dict referenced from two different keys, not a cycle) is frozen independently both times, never
mislabeled circular.

RE-GATE CORRECTION (HIGH, symmetry with the TS adapter's own re-gate fix): the `except Exception:
return repr(value)`-adjacent leaf handling above executed attacker-controlled code BEFORE
authorization, and its own fallback was a JSON-representable sentinel with the same collision
property TS's `"<accessor>"` had. Reproduced directly, both ways, before this fix:

  1. `repr(value)` invokes the value's own `__repr__` -- a hostile class's override runs
     unconditionally, every time a snapshot is taken, regardless of whether the call is ever
     authorized. Reproduced: a class whose `__repr__` prints a marker and returns a
     plausible-looking string had that `__repr__` genuinely execute during `freeze()`.
  2. The `except Exception: return f"<unrepresentable {type(value).__name__}>"` branch is a
     STRING -- and a real dict value that happens to equal that exact literal freezes to itself
     unchanged (strings pass through verbatim, above), producing the IDENTICAL frozen shape, and
     therefore the identical `params_c14n_v1` commitment, as the exotic value it was meant to
     stand in for. Reproduced directly: `freeze({"arg": Explodes()})` (a class whose `__repr__`
     raises) and `freeze({"arg": "<unrepresentable Explodes>"})` (an ordinary string argument)
     produced the exact same output.

Fixed the same way the TS adapter's `freeze()` was: anything whose EXACT type is not
`str`/`int`/`float`/`bool` (not `None`, checked separately) and is not a `Mapping`/`list`/
`tuple`/`set`/`frozenset` becomes `UNSUPPORTED` -- a module-private sentinel object, never a
string -- without calling `repr()`, `str()`, or any other protocol on it. FINAL-CHECK
CORRECTION: this originally read `isinstance(value, (str, int, float, bool))`, which admits a
SUBCLASS of any of those too -- and a subclass instance can carry its own mutable attributes,
aliased straight through by that fast path (reproduced directly: `freeze(boxed) is boxed` was
`True` for a `str` subclass with a mutable list attribute). `params.commit()`'s own disposition
was never wrong either way -- `canonical.dumps` already gates on EXACT type, not `isinstance`,
so a subclass already fell through to `UnsupportedTypeError`/`"unsupported"` downstream -- but
the raw snapshot itself retained a live, mutable reference, violating the never-alias invariant
every leaf here is supposed to hold. Fixed by matching `canonical.dumps`'s own domain exactly:
`type(value) in (str, int, float, bool)`. `bytes` is deliberately included in that "everything
else": it is outside the `params_c14n_v1` JSON domain regardless (`canonical.dumps` already
rejects it via
`UnsupportedTypeError` -- `_text()`'s type dispatch has no `bytes` case -- so this changes nothing
about the final commit outcome, only stops the raw snapshot from retaining a live `bytes`
reference for no purpose; checked directly that no shipped adapter inspects the raw snapshot for
anything besides handing it to `params.commit()`). The whole container walk (the `Mapping`/
`list`-family branches, including the `.items()`/iteration itself) now runs inside one
`try`/`except`, degrading ANY reflection or iteration failure to `UNSUPPORTED` too, rather than
letting an unanticipated exception propagate out of a snapshot taken before authorization was
decided. A genuine cycle's own leaf value is `UNSUPPORTED` now as well, not the literal string
`"<circular>"` -- audited for the identical collision class as `"<unrepresentable ...>"` above (a
self-referential container and a plain container holding the literal string `"<circular>"` would
otherwise commit identically), and there is no reason a cycle's position makes that collision any
less real, so it gets the same fix.

Once `UNSUPPORTED` reaches `params.commit()` anywhere inside the frozen tree -- a value, nested at
any depth, same as any other leaf -- `canonical.dumps`'s `_text()` hits its own exact-type
dispatch, finds no case for `UNSUPPORTED`'s type, and raises `UnsupportedTypeError`, which
`commit()` already turns into `params_hash_reason: "unsupported"` for the WHOLE params value (see
`params.py`'s own module docstring): the identical mechanism `canonical.dumps` already used to
reject an out-of-domain number, and the identical disposition the TS adapter's `freeze()` now
produces for the same exotic-value classes -- the two languages agree again.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Mapping, Optional

__all__ = ["freeze", "UNSUPPORTED"]


class _Unsupported:
    """The type of `UNSUPPORTED` (below) -- a private, unique sentinel class. Nothing outside
    this module constructs an instance of it, so `UNSUPPORTED` cannot equal any real call
    argument by construction, unlike a JSON-representable string sentinel (see this module's own
    RE-GATE CORRECTION above for the collision that caused)."""

    __slots__ = ()


#: `freeze()`'s sentinel for "could not be represented as an immutable JSON-shaped leaf" -- an
#: exotic value (anything whose EXACT type -- not merely an `isinstance` match, see `freeze()`'s
#: own FINAL-CHECK CORRECTION -- is not `None`/`str`/`int`/`float`/`bool` and not a plain
#: `Mapping`/list-family container), a genuine cycle, `bytes` (outside the `params_c14n_v1`
#: domain regardless), or an
#: unanticipated reflection/iteration failure. NEVER a string: see the RE-GATE CORRECTION above
#: for why a JSON-representable sentinel (`"<circular>"`, `"<unrepresentable ...>"`) is itself a
#: commitment-collision defect, not a fix. Exported alongside `freeze` for the same reason: not
#: part of this package's semantic contract, but its own tests need to assert a given leaf became
#: this EXACT sentinel (by identity) rather than inferring it indirectly.
UNSUPPORTED = _Unsupported()


def freeze(value: Any, _active: Optional[FrozenSet[int]] = None) -> Any:
    # Final-check correction: `isinstance(value, (str, int, float, bool))` admits a SUBCLASS of
    # any of those too -- and a subclass instance can carry its own mutable attributes (or
    # override __eq__/__hash__/anything else) that this fast path would otherwise pass through
    # completely unchanged, aliasing the live object. Reproduced directly: a `str` subclass with
    # a mutable list attribute passed `freeze(boxed) is boxed` (True) before this fix.
    # `params.commit()`'s disposition was never wrong (`canonical.dumps` already gates on EXACT
    # type -- `type(value) is str`, not `isinstance` -- so a subclass already fell through to
    # `UnsupportedTypeError`/"unsupported" downstream), but the raw snapshot itself retained a
    # live, mutable reference, violating the never-alias invariant every leaf here is supposed
    # to hold. Fixed by gating on `type(value) in (...)` -- exact type only, matching
    # `canonical.dumps`'s own domain exactly -- so a subclass instance now falls through to
    # `UNSUPPORTED` below like any other exotic value, never aliased.
    if value is None or type(value) in (str, int, float, bool):
        return value
    active = _active or frozenset()
    try:
        if isinstance(value, Mapping):
            key = id(value)
            if key in active:
                return UNSUPPORTED  # a genuine cycle -- see this module's RE-GATE CORRECTION
            with_self = active | {key}
            return {k: freeze(v, with_self) for k, v in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            key = id(value)
            if key in active:
                return UNSUPPORTED  # a genuine cycle -- see this module's RE-GATE CORRECTION
            with_self = active | {key}
            return [freeze(v, with_self) for v in value]
    except Exception:
        # A reflection or iteration failure inside the walk above -- degrade the same way as
        # everything else this function cannot represent; never let a snapshot taken BEFORE
        # authorization propagate an exception.
        return UNSUPPORTED
    # `bytes`, a function, a class instance, or anything else that is not a safe JSON-primitive
    # leaf and not a plain Mapping/list-family container -- never `repr()`d, never `str()`d,
    # never handed through any other protocol (see this module's RE-GATE CORRECTION: a hostile
    # `__repr__` override ran attacker code exactly once per snapshot, reproduced directly,
    # BEFORE authorization had been decided) and never the live reference either.
    return UNSUPPORTED
