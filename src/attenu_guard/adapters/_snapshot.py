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
only already-immutable leaf types (`str`/`int`/`float`/`bool`/`None`/`bytes`) are kept as-is --
sharing an immutable value carries no aliasing risk regardless of what protocol it does or does
not implement. Everything else becomes its `repr()` -- a brand-new, independent string -- rather
than being handed through any copy protocol that could return a live reference.

RELEASE-GATE CORRECTION: every adapter's own `_freeze()` (17 identical copies, one per adapter
module, before this consolidation) recursed into `Mapping`/`(list, tuple, set, frozenset)` with NO
cycle guard at all -- a self-referential container raised `RecursionError`, contradicting this
package's own CHANGELOG claim that `_freeze()` "never raises." Fixed here, once, with PATH-ACTIVE
cycle tracking: `_active` is the set of container `id()`s on the CURRENT recursion path from the
root call down to this one, passed as a new set at each recursive call (never mutated in place and
shared across siblings) -- so a container that appears TWICE as sibling values in a DAG (the SAME
dict referenced from two different keys, not a cycle) is frozen independently both times, never
mislabeled circular, while a container that is its OWN ancestor on the current path (a genuine
cycle) is caught and reported as `"<circular>"` instead of recursing forever.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Mapping, Optional

__all__ = ["freeze"]


def freeze(value: Any, _active: Optional[FrozenSet[int]] = None) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    active = _active or frozenset()
    if isinstance(value, Mapping):
        key = id(value)
        if key in active:
            return "<circular>"
        with_self = active | {key}
        return {k: freeze(v, with_self) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        key = id(value)
        if key in active:
            return "<circular>"
        with_self = active | {key}
        return [freeze(v, with_self) for v in value]
    try:
        return repr(value)
    except Exception:
        return f"<unrepresentable {type(value).__name__}>"
