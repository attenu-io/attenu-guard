"""
adapters/langgraph.py — a thin LangGraph integration for attenu-guard.

LangGraph is not installed in every environment that uses attenu-guard
(it isn't installed in this repo's own test/dev environment either), so this
module is built in two layers:

  1. The AUTHORIZATION-WRAPPING LOGIC — `guard_node()` and
     `DelegatedToolNode` — is pure Python: it wraps an arbitrary callable
     (any function taking `*args, **kwargs` and returning something) so
     that every call is authorized through a `Guard` first. It does not
     import, require, or even reference the `langgraph` package at all.
     That's deliberate: a LangGraph *node* is, by LangGraph's own
     convention, "just a callable" (typically `def node(state: dict) ->
     dict`, sometimes `def node(state, config) -> dict`), so wrapping "any
     callable" is sufficient to wrap a LangGraph node or a plain tool
     function alike — and it means this logic is fully unit-testable with
     zero third-party dependencies (see tests/test_langgraph_adapter.py).

  2. The handful of spots that actually touch the `langgraph` package
     itself (right now: `is_langgraph_available()`, and the duck-typed
     `graph.add_node(...)` call inside `add_guarded_node()`, which never
     needs to *import* langgraph because the graph object is handed to it
     already-constructed by the caller) import it lazily, from inside the
     function that needs it — never at module import time. Importing this
     module, and calling `guard_node`/`DelegatedToolNode`, never requires
     langgraph to be installed.

Typical usage, wiring a per-delegation Guard into a real LangGraph graph:

    from langgraph.graph import StateGraph
    from attenu_guard import Authority, RowLimit
    from adapters.langgraph import guard_node, DelegatedToolNode

    # Each agent in the graph gets its OWN attenuated Guard, minted at the
    # point you'd otherwise wire up the LangGraph node for it — never the
    # orchestrator's own (broader) Guard.
    summarizer_guard = orchestrator_guard.delegate(
        "summarizer", Authority({"crm.read"}, [RowLimit(100)], ttl=900),
        task="summarize Q3 pipeline")

    # Option A: decorate a plain node function.
    @guard_node(summarizer_guard, "crm.read",
                context_fn=lambda state: {"rows": state.get("expected_rows", 0)})
    def summarize(state: dict) -> dict:
        rows = crm_client.query(state["query"])
        return {"summary": summarize_rows(rows)}

    # Option B: wrap it as an object (same result, class-based call site).
    summarize_node = DelegatedToolNode(
        summarizer_guard, "crm.read", summarize_impl,
        context_fn=lambda state: {"rows": state.get("expected_rows", 0)})

    graph = StateGraph(MyState)
    graph.add_node("summarize", summarize)          # or: summarize_node
    graph.add_edge("planner", "summarize")

If the delegated Guard denies the call (wrong scope, ceiling exceeded,
revoked, expired, ...), the wrapper raises `AuthorityDenied` — from
`attenu_guard`, the SAME exception `Guard.enforce()` raises — *before*
the wrapped node/tool function ever runs, so a poisoned instruction or a
runaway plan never reaches the tool call it isn't authorized to make. A
LangGraph graph can catch `AuthorityDenied` around `graph.invoke(...)`, or
route around it with LangGraph's own conditional-edge error handling — this
adapter doesn't prescribe which; it only guarantees the tool body never
executes on a denial.

Execution binding (0.9.0, reference wiring for this adapter): when `guard`'s
chain was issued with `schema_version=2` (see `Guard.issue`), `guard_node`
also passes `capture`/`adapter`/`authorized_params` to `check()` and calls
`guard.record_outcome()` once the wrapped callable's observation ends —
`wrapper_sync` for a plain callable, `wrapper_async` for an async one
(`await`ed by this wrapper's own async variant, so it observes completion
directly). `authorized_params`/`invoked_params` are BOTH taken from ONE
immutable snapshot of `{"args": [...], "kwargs": {...}}`, deep-copied
BEFORE the wrapped callable runs and never re-read from `args`/`kwargs`
afterward — so a callable that mutates its own inputs in place cannot make
this adapter claim it observed two different values for what was actually
one call's arguments. A generator/async-generator/future/task return value
is reported `deferred`, not `returned` (this wrapper does not consume it);
an `asyncio.CancelledError` on the async path is reported `abandoned`, not
`raised`, and still re-raised so cancellation propagates normally.

On a `schema_version=1` chain (the default), this adapter is BYTE-AND-TYPE
IDENTICAL to every release before 0.9.0 — including for an async callable:
`wrapped` stays a plain SYNC function that returns `fn(*args, **kwargs)`
UNAWAITED (the caller awaits the result, as it always has); only on a
`schema_version=2` chain does wrapping an async callable change `wrapped`
itself into an async function, which is required to observe the callable's
actual completion for `record_outcome()`. Every other framework adapter is
unchanged in this release — this is the one reference wiring; see
CHANGELOG.md.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import inspect
import time
from typing import Callable, Mapping, Optional

from .. import AuthorityDenied, __version__
from ..reasons import Capture, BodyState
from ._snapshot import freeze as _freeze

__all__ = ["guard_node", "DelegatedToolNode", "add_guarded_node", "is_langgraph_available"]


def _is_async_callable(fn) -> bool:
    """True for an `async def` function/method AND for an object whose `__call__` is one — a
    plain `inspect.iscoroutinefunction(fn)` misses the second case (an async callable OBJECT),
    which then gets driven synchronously and returns an unawaited coroutine instead of a result."""
    if inspect.iscoroutinefunction(fn):
        return True
    call = getattr(fn, "__call__", None)
    return call is not None and inspect.iscoroutinefunction(call)


def _is_deferred_result(result) -> bool:
    """True if `result` is a generator/async-generator/future/task whose consumption this
    wrapper does not itself observe — spec's `deferred`: "the record covers the call, not the
    eventual exhaustion." """
    if inspect.isgenerator(result) or inspect.isasyncgen(result):
        return True
    if isinstance(result, (asyncio.Future, concurrent.futures.Future)):
        return True
    return False


def _body_state_for(result) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _snapshot_params(args, kwargs) -> dict:
    """An IMMUTABLE snapshot of the call's arguments, taken BEFORE the wrapped callable runs and
    reused for BOTH authorized_params (check()) and invoked_params (record_outcome()) — so a
    callable that mutates its own inputs in place cannot make this adapter observe two different
    values for what was actually one call's arguments.

    RELEASE-GATE CORRECTION: this used to be `copy.deepcopy(raw)`, falling back to the raw
    (live) dict on failure -- the same aliasing gap every OTHER adapter's `_freeze()` was built
    to close, but this file (the original reference wiring, never touched by either adversarial-
    review batch) never got the fix. A hostile `__deepcopy__` reproduced `snapshot["args"][0] is
    live` and a later mutation changed the "snapshot". Fixed by routing through the same shared
    `attenu_guard.adapters._snapshot.freeze()` every other adapter now uses (see that module's
    own doc comment for why `deepcopy` succeeding is not proof of independence)."""
    return _freeze({"args": list(args), "kwargs": dict(kwargs)})


# =========================================================================
# The testable core: wraps an arbitrary callable. No langgraph import,
# anywhere in this section.
# =========================================================================

def guard_node(guard, tool_scope: str, *, context_fn: Optional[Callable] = None,
               tool: Optional[str] = None, disposition: Optional[str] = None):
    """Return a decorator that authorizes every call to the wrapped
    callable through `guard` before letting it run.

    Parameters
    ----------
    guard : attenu_guard.Guard
        The (typically already-delegated, already-attenuated) Guard to
        check against. Use the Guard for the SPECIFIC agent/node this
        callable belongs to — not the orchestrator's broader one — so a
        denial reflects that node's actual, narrowed authority.
    tool_scope : str
        The scope this callable needs, e.g. `"crm.read"`.
    context_fn : callable, optional
        Called with the exact `*args, **kwargs` the wrapped callable is
        invoked with, and must return a context mapping for
        `guard.check()` (e.g. `{"rows": 5000, "egress": "none"}`). If
        omitted, an empty context (`{}`) is used — fine for a scope-only
        check with no ceilings to evaluate against a quantity.
    tool : str, optional
        The `tool=` label recorded on the underlying `guard.check()` call
        (shows up in the audit log). Defaults to the wrapped callable's
        `__name__`, so audit entries are attributable to the specific tool
        function without extra plumbing.

    Behavior
    --------
    On call: `context = context_fn(*args, **kwargs) if context_fn else {}`;
    `decision = guard.check(tool_scope, context=context, tool=tool)`. If
    `not decision`, raises `AuthorityDenied(decision)` and the wrapped
    callable is NEVER invoked. Otherwise, calls through to the wrapped
    callable with the original `*args, **kwargs` and returns its result
    unchanged. On a `schema_version=2` guard, also binds the call's outcome
    via `guard.record_outcome()` — see the module docstring's "Execution
    binding" section.
    """
    def decorator(fn):
        resolved_tool = tool if tool is not None else getattr(fn, "__name__", None)
        is_async_fn = _is_async_callable(fn)
        # guard.schema_version never changes for a guard's lifetime, so it's safe (and correct:
        # a wrapper's sync-vs-async SHAPE must be fixed at definition time, not per-call) to
        # decide it once, here, at decoration time.
        v2 = guard.schema_version == 2
        capture = Capture.WRAPPER_ASYNC if is_async_fn else Capture.WRAPPER_SYNC
        adapter_info = {"module": __name__, "version": __version__,
                        "hook_path": f"{getattr(fn, '__module__', '?')}.{getattr(fn, '__qualname__', resolved_tool)}"}

        def _authorize(args, kwargs, snapshot):
            context: Mapping = context_fn(*args, **kwargs) if context_fn else {}
            extra = dict(capture=capture, adapter=adapter_info, authorized_params=snapshot) if v2 else {}
            decision = guard.check(tool_scope, context=context, tool=resolved_tool,
                                   disposition=disposition, **extra)
            if not decision:
                raise AuthorityDenied(decision)
            return decision

        if is_async_fn and v2:
            @functools.wraps(fn)
            async def wrapped(*args, **kwargs):
                snapshot = _snapshot_params(args, kwargs)
                decision = _authorize(args, kwargs, snapshot)
                start = time.monotonic()
                try:
                    result = await fn(*args, **kwargs)
                except asyncio.CancelledError:
                    # The wrapper stopped observing while the body may still run -- exactly
                    # spec's `abandoned`, not `raised`. Still re-raised: cancellation must
                    # propagate normally.
                    guard.record_outcome(decision.call_id, BodyState.ABANDONED,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                    raise
                except Exception as exc:
                    guard.record_outcome(decision.call_id, BodyState.RAISED,
                                         error_code=type(exc).__name__,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                    raise
                guard.record_outcome(decision.call_id, _body_state_for(result),
                                     invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                return result
        elif is_async_fn:
            # v1 (schema_version=1, the default): EXACTLY the pre-0.9.0 shape -- a plain SYNC
            # wrapper that authorizes, then returns fn(*args, **kwargs) UNAWAITED. The caller
            # awaits the returned coroutine itself, as it always has; `wrapped` is never itself
            # a coroutine function on v1, even when `fn` is async.
            @functools.wraps(fn)
            def wrapped(*args, **kwargs):
                _authorize(args, kwargs, None)
                return fn(*args, **kwargs)
        else:
            @functools.wraps(fn)
            def wrapped(*args, **kwargs):
                if not v2:
                    _authorize(args, kwargs, None)
                    return fn(*args, **kwargs)
                snapshot = _snapshot_params(args, kwargs)
                decision = _authorize(args, kwargs, snapshot)
                start = time.monotonic()
                try:
                    result = fn(*args, **kwargs)
                except Exception as exc:
                    guard.record_outcome(decision.call_id, BodyState.RAISED,
                                         error_code=type(exc).__name__,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                    raise
                guard.record_outcome(decision.call_id, _body_state_for(result),
                                     invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                return result

        # Introspection hooks -- useful for tooling/tests, harmless otherwise.
        wrapped.guard = guard
        wrapped.tool_scope = tool_scope
        wrapped.__wrapped__ = fn
        return wrapped
    return decorator


class DelegatedToolNode:
    """An object-shaped equivalent of `guard_node` for attaching a
    per-delegation `Guard` to a LangGraph node, when you want a handle you
    can hold onto (introspect `.guard`/`.tool_scope`, re-wrap, log,
    ...) rather than a bare decorated function.

    `DelegatedToolNode` is built ENTIRELY out of `guard_node` (below) --
    same authorization semantics, same "raise AuthorityDenied before the
    wrapped callable runs" guarantee -- so the two never drift apart.
    It needs no `langgraph` import: LangGraph nodes only need to be
    callable, and instances of this class are (`__call__` delegates to the
    wrapped callable), which is why this class is fully testable without
    langgraph installed (see tests/test_langgraph_adapter.py).

    Attach it to a real graph exactly like a plain function:

        node = DelegatedToolNode(summarizer_guard, "crm.read", summarize_impl,
                                  context_fn=lambda state: {"rows": state["n"]})
        graph.add_node("summarize", node)      # LangGraph calls node(state)

    or via the `add_guarded_node` convenience below, which does the
    `graph.add_node(...)` call for you.
    """

    def __init__(self, guard, tool_scope: str, fn: Callable, *,
                 context_fn: Optional[Callable] = None, tool: Optional[str] = None,
                 disposition: Optional[str] = None):
        self.guard = guard
        self.tool_scope = tool_scope
        self.fn = fn
        self.context_fn = context_fn
        self.tool = tool if tool is not None else getattr(fn, "__name__", None)
        self.disposition = disposition
        self._call = guard_node(guard, tool_scope, context_fn=context_fn, tool=tool,
                                disposition=disposition)(fn)

    def __call__(self, *args, **kwargs):
        return self._call(*args, **kwargs)

    def __repr__(self) -> str:
        fn_name = getattr(self.fn, "__name__", repr(self.fn))
        return (f"DelegatedToolNode(node_id={self.guard.node_id!r}, "
                f"tool_scope={self.tool_scope!r}, fn={fn_name})")


# =========================================================================
# The langgraph-touching edge: lazy-imported, never at module load time.
# =========================================================================

def is_langgraph_available() -> bool:
    """True iff the `langgraph` package is importable in this environment.
    Performs the import lazily, right here, only when called -- so merely
    importing this adapter module (or using `guard_node`/`DelegatedToolNode`)
    never requires langgraph to be installed."""
    try:
        import langgraph  # noqa: F401  (existence check only)
    except ImportError:
        return False
    return True


def add_guarded_node(graph, name: str, guard, tool_scope: str, fn: Callable, *,
                     context_fn: Optional[Callable] = None, tool: Optional[str] = None,
                     disposition: Optional[str] = None):
    """Convenience one-liner for real LangGraph usage: build the guarded
    wrapper and register it on a graph in one call.

        add_guarded_node(graph, "summarize", summarizer_guard, "crm.read",
                         summarize, context_fn=lambda state: {"rows": state["n"]})
        # equivalent to:
        #   graph.add_node("summarize", DelegatedToolNode(
        #       summarizer_guard, "crm.read", summarize, context_fn=...))

    `graph` is duck-typed: it only needs an `.add_node(name, callable)`
    method, which is `langgraph.graph.StateGraph`'s real, stable signature
    -- so this helper needs no `import langgraph` of its own (the graph
    object is already constructed by the caller) and stays testable with a
    plain fake graph object, no langgraph install required (see
    tests/test_langgraph_adapter.py).
    """
    node = DelegatedToolNode(guard, tool_scope, fn, context_fn=context_fn, tool=tool,
                            disposition=disposition)
    graph.add_node(name, node)
    return node
