"""
attenu_guard.adapters.pydantic_ai — a thin attenu-guard integration for Pydantic AI.

Tested against pydantic-ai-slim 2.31.1 and re-verified against 2.37.0 (Python >= 3.10);
line numbers below are as of 2.37.0.

HOOK POINTS USED
----------------
1. Child creation / delegation — `GuardedDeps.delegate(...)`.
   Pydantic AI's documented multi-agent pattern is "agent delegation": a tool on
   the parent agent calls `child_agent.run(..., usage=ctx.usage)`. There is no
   framework callback at that moment, so the integration sits at the construction
   site: the parent's deps carry its `Guard`, and the delegating tool mints the
   child's attenuated `Guard` and passes it down as the child run's `deps`.
   `RunContext.deps` (`pydantic_ai/_run_context.py:64`) is the carrier.

2. Tool invocation — `DelegationGuard.wrap_tool_execute(...)`, a subclass of
   `pydantic_ai.capabilities.AbstractCapability`
   (`pydantic_ai/capabilities/abstract.py:209`), registered with
   `Agent(capabilities=[...])`. Since 0.10.0 this is the ONLY hook `DelegationGuard`
   overrides — it does not touch `before_tool_execute` at all, so the inherited
   no-op passthrough runs there (see `get_ordering()`/`for_agent()`'s docstrings
   for why authorization and outcome-recording were collapsed into one call).
   `ToolManager._run_execute_hooks` awaits (the no-op) `before_tool_execute` at
   `pydantic_ai/tool_manager.py:460`, and only afterwards calls
   `wrap_tool_execute(..., handler=do_execute)` at
   `pydantic_ai/tool_manager.py:464`, where `do_execute` is the only path to
   `toolset.call_tool` (`pydantic_ai/tool_manager.py:1009`). Raising from
   `wrap_tool_execute` (or simply never calling `handler`) therefore provably
   prevents the tool body from running. `get_ordering()` declares
   `position="innermost", wrapped_by=[AbstractCapability]`, and that `wrapped_by`
   edge names every sibling at once, so the sorter settles this capability LAST in
   the chain in every list order -- `handler` is the raw tool body, not another
   capability's wrapping (the class docstring's "ORDERING" has the mechanism, the
   version floor and the one case it cannot cover). This is agent-wide: it covers
   function tools, `Toolset`s, and MCP servers alike, with one registration.

   `GuardedToolset` is the alternative, narrower hook: a
   `pydantic_ai.toolsets.WrapperToolset` whose `call_tool` authorizes before
   delegating to `self.wrapped.call_tool` (`pydantic_ai/toolsets/wrapper.py:67`).
   Use it to guard one specific (e.g. third-party or MCP) toolset rather than
   every tool the agent can reach.

USAGE
-----
Give each agent a policy map from tool name to the authority that tool consumes,
register `DelegationGuard` as a capability, and run the agent with `GuardedDeps`
carrying its `Guard`. Inside a delegating tool, call `ctx.deps.delegate(...)` to
mint the sub-agent's narrower `Guard` and pass the result as the sub-run's
`deps`. Every tool call is then checked against *that* agent's authority before
its body runs, and every allow/deny lands in the chain's hash-chained audit log.

    POLICIES = {"crm_query": ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]}),
                "crm_export": ToolPolicy("crm.export", context=lambda a: {"egress": "any"})}
    agent = Agent(model, deps_type=GuardedDeps, capabilities=[DelegationGuard(POLICIES)])
    await agent.run(prompt, deps=GuardedDeps(guard=child_guard, app=my_deps))

This module is deliberately dependency-light: it imports `pydantic_ai` and
`attenu_guard`, and nothing else. Copy it into your project as-is.

Execution binding (0.10.0, on a `schema_version=2` chain — see `Guard.issue`):
BOTH hook points here are genuine WRAPPER capture (`Capture.WRAPPER_ASYNC`) — unlike
most other framework adapters, this one calls the tool body itself and awaits it, the
same way `adapters.langgraph`'s reference wiring does:

  * `DelegationGuard.wrap_tool_execute`: authorization and outcome-recording are ONE
    operation, entirely inside this single hook -- there is no `before_tool_execute`
    override and no cross-hook `_pending` map any more (an earlier version stashed the
    allowed `Decision` there for `wrap_tool_execute` to close out, correlated by
    `id(call)`; see the class docstring's "WHY ONE OPERATION, NOT TWO" for why that was
    replaced). On a v2 chain it passes `capture`/`adapter`/`authorized_params` through to
    `guard.check()` directly and records the outcome around `handler(args)` in the same
    call; on `schema_version=1` it authorizes the same way and calls `handler` unrecorded.
  * `GuardedToolset.call_tool`: a `WrapperToolset.call_tool` override that already calls
    `self.wrapped.call_tool(...)` directly -- no cross-hook correlation needed at all;
    authorization and the wrapper capture live in the same method, exactly like
    `adapters.langgraph`'s `guard_node`.

Both report `BodyState.RAISED` (with `error_code`) on a genuine exception from the tool
body -- pydantic-ai does not swallow it before either hook runs -- and `BodyState.ABANDONED`
on `asyncio.CancelledError` (still re-raised, so cancellation propagates normally).
`UNGUARDED` tools (`policy.scope is None`) never call `guard.check()` at all, so there is
nothing to bind an outcome to.
"""
from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Literal, Mapping, Optional, TypeVar

from pydantic_ai.capabilities.abstract import AbstractCapability, CapabilityOrdering
from pydantic_ai.capabilities.combined import CombinedCapability
from pydantic_ai.exceptions import ToolFailed, UserError
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.tools import RunContext, ToolDefinition
from pydantic_ai.toolsets.abstract import ToolsetTool
from pydantic_ai.toolsets.wrapper import WrapperToolset

from attenu_guard import Authority, AuthorityDenied, Decision, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.DelegationGuard.wrap_tool_execute",
}


def _is_deferred_result(result: Any) -> bool:
    return inspect.isgenerator(result) or inspect.isasyncgen(result)


def _body_state_for(result: Any) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


from ._snapshot import freeze as _freeze


def _snapshot_params(args: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    the tool body runs -- and reused for both `authorized_params` and `invoked_params`."""
    return _freeze(dict(args))

__all__ = [
    "ToolPolicy",
    "UNGUARDED",
    "GuardedDeps",
    "DelegationGuard",
    "GuardedToolset",
    "MissingGuardError",
    "UnmappedToolError",
    "authorize_tool_call",
]

AppDepsT = TypeVar("AppDepsT")

OnDenial = Literal["raise", "tool_failed"]
"""What to do when the Guard denies a call.

`"raise"`      — re-raise `attenu_guard.AuthorityDenied`. `_run_execute_hooks` does
                 route it through the generic `except Exception` -> `on_tool_execute_error`
                 path (`pydantic_ai/tool_manager.py:470-471`), but that hook's default
                 implementation is `raise error` (`capabilities/abstract.py:1068`), and
                 the outer `except (ValidationError, ModelRetry)` / `except ToolFailed`
                 clauses (`pydantic_ai/tool_manager.py:478-490`) don't match it either, so
                 it still propagates uncaught and aborts the whole agent run. Deterministic
                 hard stop; the default, because a denied action is a security event, not a
                 conversational hiccup.
`"tool_failed"` — raise `pydantic_ai.exceptions.ToolFailed`, which Pydantic AI turns
                 into a failed tool result the model sees and can adapt to, WITHOUT
                 consuming the tool's retry budget (so the model cannot grind
                 against the wall). The tool body still never runs. Use this when
                 the agent should degrade gracefully instead of dying.
"""


class MissingGuardError(UserError):
    """No `Guard` could be found on `RunContext.deps`.

    Fail-closed: a missing Guard means the delegation chain was not wired, which
    would otherwise silently disable enforcement for the whole run.
    """


class UnmappedToolError(UserError):
    """A tool was called that has no `ToolPolicy`.

    Fail-closed by default: an unmapped tool is one whose authority cost nobody
    declared, so it cannot be shown to be within the agent's authority. Pass
    `on_unmapped="allow"` if you have a reason to let unmapped tools through.
    """


# ==========================================================================
# Policy: what authority does this tool consume?
#
# attenu-guard deliberately does not decide this for you — the integrator
# declares it, once, per tool.
# ==========================================================================

@dataclass(frozen=True)
class ToolPolicy:
    """The authority a single tool consumes.

    scope:   the scope string checked against the agent's `Authority`, e.g.
             `"crm.read"`. `None` marks the tool as explicitly not
             authority-bearing (see `UNGUARDED`).
    context: maps the tool's validated arguments to the context mapping the
             ceilings are evaluated against, e.g.
             `lambda args: {"rows": args["rows"], "egress": "none"}`.
             Omit for a scope-only check.
    metered: forwarded to `Guard.check(metered=...)`. With a Guard issued
             `strict_metering=True`, a metered call that supplies no context at
             all is refused rather than treated as free.
    """

    scope: str | None
    context: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None
    metered: bool = False
    disposition: str | None = None        # see attenu_guard.Disposition


UNGUARDED = ToolPolicy(scope=None)
"""Explicit opt-out for a tool that consumes no authority of its own.

The canonical case is a *delegation* tool: the act of delegating is already
recorded by `Guard.delegate` as a `spawn` entry in the audit log, and the child's
authority is bounded by construction, so re-checking a scope here would be
ceremony. Being explicit keeps the default (deny) fail-closed.
"""


# ==========================================================================
# Hook point 1 — deps that carry the Guard down a delegation chain
# ==========================================================================

@dataclass
class GuardedDeps(Generic[AppDepsT]):
    """Agent deps = this agent's `Guard` + whatever deps your app already had.

    `guard` is the authority THIS agent run holds. `app` is untouched and reachable
    from your tools as `ctx.deps.app`.
    """

    guard: Guard
    app: AppDepsT = None  # type: ignore[assignment]

    def delegate(
        self,
        agent_id: str,
        request: Authority,
        task: str,
        *,
        app: Any = None,
    ) -> "GuardedDeps[Any]":
        """Mint a sub-agent's deps, carrying an attenuated child `Guard`.

        Call this inside the delegating tool and pass the result as the sub-agent
        run's `deps`:

            child = ctx.deps.delegate("summarizer", Authority(...), task=...)
            result = await summarizer.run(q, deps=child, usage=ctx.usage)

        The child's authority is `parent.meet(request)` — it can only shrink, and
        `Guard.delegate` raises `AuthorityError` if the parent is revoked, expired,
        or the chain's depth/fanout ceiling is hit.
        """
        return GuardedDeps(
            guard=self.guard.delegate(agent_id, request, task),
            app=self.app if app is None else app,
        )


def _default_get_guard(ctx: RunContext[Any]) -> Guard | None:
    """Find the Guard on the run's deps: `deps.guard`, or the deps themselves."""
    deps = ctx.deps
    if isinstance(deps, Guard):
        return deps
    guard = getattr(deps, "guard", None)
    return guard if isinstance(guard, Guard) else None


# ==========================================================================
# The shared authorization core (used by BOTH hook points)
# ==========================================================================

def authorize_tool_call(
    guard: Guard,
    policy: ToolPolicy,
    tool_name: str,
    args: Mapping[str, Any],
    *,
    on_denial: OnDenial = "raise",
) -> None:
    """Run `guard.check(...)` for one tool call; raise if denied.

    Returns `None` on allow. Never returns on a denial — that is the whole point:
    the caller has no way to accidentally continue into the tool body.
    """
    if policy.scope is None:  # UNGUARDED
        return

    context = dict(policy.context(args)) if policy.context is not None else {}
    decision = guard.check(
        policy.scope, context=context, metered=policy.metered, tool=tool_name,
        disposition=policy.disposition,
    )
    if decision:
        return

    if on_denial == "tool_failed":
        raise ToolFailed(
            f"Denied by attenu-guard: {decision.explain()} "
            f"(tool={tool_name!r}, scope={policy.scope!r}). "
            f"This agent does not hold the authority for this action; do not retry it."
        )
    raise AuthorityDenied(decision)


def _authorize_v2(
    guard: Guard,
    policy: ToolPolicy,
    tool_name: str,
    args: Mapping[str, Any],
    *,
    on_denial: OnDenial,
) -> tuple[Decision, Any]:
    """Like `authorize_tool_call`, for a `schema_version=2` chain: passes `capture`/`adapter`/
    `authorized_params` and RETURNS `(decision, snapshot)` on allow instead of `None`, so the
    caller can bind an outcome to `decision.call_id`. Never called for `UNGUARDED`
    (`policy.scope is None`) -- callers check that first, exactly as `authorize_tool_call` does."""
    snapshot = _snapshot_params(args)
    context = dict(policy.context(args)) if policy.context is not None else {}
    decision = guard.check(
        policy.scope, context=context, metered=policy.metered, tool=tool_name,
        disposition=policy.disposition, capture=Capture.WRAPPER_ASYNC, adapter=_ADAPTER_INFO,
        authorized_params=snapshot,
    )
    if decision:
        return decision, snapshot

    if on_denial == "tool_failed":
        raise ToolFailed(
            f"Denied by attenu-guard: {decision.explain()} "
            f"(tool={tool_name!r}, scope={policy.scope!r}). "
            f"This agent does not hold the authority for this action; do not retry it."
        )
    raise AuthorityDenied(decision)


async def _run_wrapped_and_record_outcome(
    guard: Guard, call_id: str, snapshot: Any, handler: Callable[[], Any],
) -> Any:
    """Call `handler()` (the tool body), time it, and call `guard.record_outcome()` with what
    actually happened -- the shared tail of both hook points' wrapper capture."""
    started_at = time.monotonic()
    try:
        result = await handler()
    except asyncio.CancelledError:
        guard.record_outcome(call_id, BodyState.ABANDONED, invoked_params=snapshot,
                             duration_ms=_elapsed_ms(started_at))
        raise
    except Exception as exc:
        guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                             invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
        raise
    guard.record_outcome(call_id, _body_state_for(result), invoked_params=snapshot,
                         duration_ms=_elapsed_ms(started_at))
    return result


def _resolve(
    ctx: RunContext[Any],
    tool_name: str,
    policies: Mapping[str, ToolPolicy],
    get_guard: Callable[[RunContext[Any]], Guard | None],
    on_unmapped: Literal["deny", "allow"],
    label: str,
) -> tuple[Guard, ToolPolicy] | None:
    """Resolve (guard, policy) for a call, or `None` when the call is exempt."""
    policy = policies.get(tool_name)
    if policy is None:
        if on_unmapped == "allow":
            return None
        msg = (f"{label}: tool {tool_name!r} has no ToolPolicy, so the authority it "
               f"consumes is undeclared and the call cannot be authorized. Add it to "
               f"`policies`, mark it `UNGUARDED`, or pass `on_unmapped='allow'`.")
        # No authority is known for this tool: on the ledger as `unresolved` when a Guard exists.
        g = get_guard(ctx)
        if g is not None:
            g.record_denial(ReasonCode.NO_AUTHORITY, msg, tool=tool_name, disposition=Disposition.UNRESOLVED)
        raise UnmappedToolError(msg)

    guard = get_guard(ctx)
    if guard is None:
        raise MissingGuardError(
            f"{label}: no attenu-guard `Guard` on the run's deps, so tool "
            f"{tool_name!r} cannot be authorized. Run the agent with "
            f"`deps=GuardedDeps(guard=..., app=...)`, or pass a custom `get_guard`."
        )
    return guard, policy


def _find_execution_wrapper_nested_inside(
    capabilities: Any, mine: "DelegationGuard"
) -> Optional[AbstractCapability[Any]]:
    """The first capability ordered AFTER `mine` in the RESOLVED chain that overrides
    `wrap_tool_execute` -- i.e. anything that would sit between `mine` and the raw tool body.

    `capabilities` is a `CombinedCapability` (or, for a lone capability, something else, in which
    case there are no siblings and nothing can nest inside). `apply` is pydantic-ai's own public
    visitor and yields the leaves in chain order, outer first, so position in that list IS
    nesting depth -- this reads the settled chain rather than re-deriving it from an ordering
    tier, which is why it stays correct if pydantic-ai's ordering primitives change.

    With `get_ordering()` declaring `wrapped_by=[AbstractCapability]` nothing can be ordered
    after `mine`, so this is belt-and-braces on both call sites (`for_agent`, over
    `agent.root_capability`, and `wrap_tool_execute`, over `ctx.root_capability`) -- see the
    class docstring's "ORDERING". If `mine` is not in the chain at all its position cannot be
    established, so every execution wrapper in the chain is reported: fail closed."""
    if not isinstance(capabilities, CombinedCapability):
        return None
    leaves: list[AbstractCapability[Any]] = []
    capabilities.apply(leaves.append)
    position = next((i for i, leaf in enumerate(leaves) if leaf is mine), -1)
    for leaf in leaves[position + 1:]:
        if leaf is mine:
            continue
        if type(leaf).wrap_tool_execute is not AbstractCapability.wrap_tool_execute:
            return leaf
    return None


def _execution_wrapper_nested_inside_message(sibling: AbstractCapability[Any]) -> str:
    return (
        f"DelegationGuard is ordered OUTSIDE {type(sibling).__name__}, which also wraps tool "
        f"execution, so {type(sibling).__name__} sits between DelegationGuard and the raw tool "
        "body. DelegationGuard cannot then prove that the handler it calls IS the tool body: a "
        f"call it authorizes would execute inside {type(sibling).__name__}'s own "
        "wrap_tool_execute, and that capability's own failure before calling its handler would "
        "be misreported here as a RAISED outcome for a body DelegationGuard never reached. "
        "DelegationGuard asks pydantic-ai to sort it last in the chain (position='innermost', "
        "wrapped_by=[AbstractCapability]), which no capability list should be able to override, "
        f"so this is worth reporting. Until then, remove either {type(sibling).__name__} or "
        "DelegationGuard from this agent: they cannot both wrap the raw tool body."
    )


# ==========================================================================
# Hook point 2a — agent-wide capability (preferred)
# ==========================================================================

class DelegationGuard(AbstractCapability[Any]):
    """Authorize every tool call this agent makes, before the tool body runs.

    Registered via `Agent(capabilities=[DelegationGuard(policies)])`. Because the
    hook lives in `ToolManager`, one registration covers function tools, every
    `Toolset` on the agent, and MCP servers.

    Output tools are exempt by design — Pydantic AI does not fire tool hooks for
    them (`pydantic_ai/tool_manager.py:455`); they produce the run's result and
    reach no external system.

    ORDERING: `get_ordering()` declares `position="innermost", wrapped_by=[AbstractCapability]`.
    Authorization and outcome-recording are ONE operation, both inside `wrap_tool_execute`
    (there is no `before_tool_execute` override at all -- see "WHY ONE OPERATION, NOT TWO"
    below), so what `handler` actually is decides whether a recorded outcome is honest.

    `wrapped_by` is a RELATIVE constraint -- "these capabilities are outside me" -- and a TYPE
    ref is resolved with `issubclass` over every other capability's leaves, with the self-edge
    skipped (`pydantic_ai/capabilities/_ordering.py`, `_ref_matches` + `_add_relative_edges`).
    `AbstractCapability` is therefore the ref that names EVERY sibling without knowing any of
    them in advance: the sorter adds an edge from this capability to each of the others and
    settles it LAST, in every list order, including past the capabilities pydantic-ai injects
    itself. Last is innermost -- the chain runs outer to inner and the last capability wraps the
    raw tool invocation -- so `handler` IS the raw tool body, and an outcome recorded around it
    is an outcome of that body and nothing else. `position="innermost"` is kept alongside it:
    it is the tier pydantic-ai's own two-phase `for_agent` binding reads, and it is the
    declaration a reader looks for; the `wrapped_by` edge is what makes it exact rather than a
    tier shared with other members.

    VERSION FLOOR: `wrapped_by` is present since at least 2.29.0, below the `pydantic-ai-slim
    >=2.31` extra floor, and `capabilities/_ordering.py` is byte-identical from 2.31.0 to 2.37.0.

    THE TWO CHECKS ARE BELT-AND-BRACES, NOT THE GUARANTEE. `for_agent()` and
    `wrap_tool_execute` both ask `_find_execution_wrapper_nested_inside(...)` whether anything
    in the RESOLVED chain is ordered after this capability and overrides `wrap_tool_execute` --
    i.e. whether anything at all sits between it and the raw body. Under the ordering above
    nothing can, and both checks stay silent; they are kept for a future pydantic-ai ordering
    primitive that could out-rank `wrapped_by`, and they read the settled chain directly rather
    than inferring position from a tier, so they remain correct if that machinery changes.

    THE ONE CASE THE CHECKS CANNOT IMPROVE: two capabilities that BOTH demand the last slot.
    A sibling declaring `wrapped_by=[AbstractCapability]` (or `wrapped_by=[DelegationGuard]`,
    or an instance ref to this one) makes each depend on the other, and `sort_capabilities`
    raises `UserError("Circular ordering constraints among capabilities")`. Refusal is the
    correct outcome -- they cannot both be innermost -- but the diagnostic is pydantic-ai's and
    names neither capability, and this file cannot reword it: the sort runs inside
    `CombinedCapability.__post_init__`, which `Agent.__init__` calls BEFORE any capability's
    `for_agent`, so no adapter frame is on the stack to catch it. The same is true of a per-run
    `agent.run(..., capabilities=[...])` injection of such a sibling, which composes (and sorts)
    a second `CombinedCapability` the same way.

    HISTORY: this file previously declared `position="innermost"` alone. Codex review round 2
    (finding 5) established that `innermost` is a TIER, not a unique position -- the sorter puts
    every innermost capability after every non-innermost one but keeps LIST order among them --
    and round 3 (finding 3) live-probed the consequence against pinned 2.31.1: a sibling
    innermost execution wrapper's own pre-handler failure was recorded here as a `RAISED`
    outcome for a body this capability never reached, with the raw body's own side-effect sink
    left empty. Round 4 (finding 2) found two ways past the construction-time rejection added in
    round 3 (a sibling whose `for_agent()` REBINDS to an execution wrapper; the per-run
    `capabilities=[...]` injection) and added the per-call re-read. Those rounds also recorded,
    wrongly, that the ordering primitives "reference specific OTHER capability types/instances,
    which this file cannot know in advance" and that it therefore "cannot out-order its way to
    safety". A type ref matched by `issubclass` needs no such knowledge: rejecting a sibling
    innermost execution wrapper was never necessary, and both of round 4's escapes now simply
    sort OUTSIDE this capability instead of being refused.

    WHY ONE OPERATION, NOT TWO: an earlier version of this class authorized in `before_tool_
    execute` and stashed the allowed decision for a SEPARATE `wrap_tool_execute` to pick up and
    close out, correlated by `id(call)`. `CombinedCapability.before_tool_execute` composes ALL
    capabilities' `before_tool_execute` sequentially, in LISTED order (`innermost`ness does not
    change that: it is a tier over `wrap_tool_execute`'s nesting, not over `before_tool_execute`'s
    sequence) -- so if `[DelegationGuard, OtherInnermost]` were BOTH registered, and `Other
    Innermost` was listed second, its OWN `before_tool_execute` could still raise AFTER this
    class's own already ran and stashed a pending entry -- leaking it, and wedging `complete()`.
    Collapsing authorization and outcome into ONE call inside `wrap_tool_execute` removes the
    map entirely: if some OTHER capability's `before_tool_execute` (or an outer `wrap_tool_
    execute`) raises before this one's own `wrap_tool_execute` is ever reached, THIS capability's
    `guard.check()` simply never ran either -- no allow, no leak, nothing false.

    DO NOT also wrap the SAME tool with `GuardedToolset` (below): each is an independent,
    complete authorization path, and using both on one tool means `guard.check()` runs TWICE
    for the same call -- two `allow`/`outcome` pairs on the ledger for one body, and (with
    `metered=True`) the call counted twice against any `CallLimit`. Pick exactly one hook point
    per tool: `DelegationGuard` for "every tool on this agent", `GuardedToolset` for "just this
    one toolset, leave the rest alone". `for_agent()` rejects this combination at AGENT
    CONSTRUCTION time (not per-call) when it can be detected -- see its docstring.
    """

    def __init__(
        self,
        policies: Mapping[str, ToolPolicy],
        *,
        get_guard: Callable[[RunContext[Any]], Guard | None] = _default_get_guard,
        on_unmapped: Literal["deny", "allow"] = "deny",
        on_denial: OnDenial = "raise",
        id: str | None = None,
    ) -> None:
        self.policies = dict(policies)
        self.get_guard = get_guard
        self.on_unmapped = on_unmapped
        self.on_denial = on_denial
        self.id = id

    def get_ordering(self) -> CapabilityOrdering:
        """Sorted LAST in the capability chain, so `wrap_tool_execute`'s `handler` is the raw
        tool body -- see the class docstring's "ORDERING" for the mechanism and the version
        floor. `position="innermost"` is the tier; `wrapped_by=[AbstractCapability]` is the
        relative edge that makes it exact, since a type ref is matched with `issubclass` and so
        names every sibling, registered or per-run, without knowing any of them in advance."""
        return CapabilityOrdering(position="innermost", wrapped_by=[AbstractCapability])

    def for_agent(self, agent: Any) -> "DelegationGuard":
        """Rejects `DelegationGuard` + `GuardedToolset` dual instrumentation on the SAME agent
        at AGENT CONSTRUCTION time. Called after the agent's toolsets are fully assembled
        (`AbstractCapability.for_agent`'s own docstring: an `innermost` capability's `for_agent`
        runs in a second phase specifically so `agent.toolsets` is complete), so `agent.toolsets`
        is walked here, unwrapping `WrapperToolset` chains, for a `GuardedToolset` instance --
        direct membership in `toolsets=[...]` and nesting inside another wrapper are both
        detected -- see the class docstring's "DO NOT also wrap...". What this CANNOT detect: a
        `GuardedToolset` built and used entirely dynamically (e.g. constructed inside a tool
        call and never listed in `agent.toolsets` at all) -- there is no hook this file can use
        to see that ahead of time; the class docstring's warning is what covers it.

        It then asks `_find_execution_wrapper_nested_inside` whether anything in
        `agent.root_capability` is ordered AFTER this capability and overrides
        `wrap_tool_execute` (checked via `type(leaf).wrap_tool_execute is not
        AbstractCapability.wrap_tool_execute`, the same idiom pydantic-ai's own
        `_has_wrap_node_run` uses internally for the analogous check). `get_ordering()`'s
        `wrapped_by=[AbstractCapability]` edge means nothing can be, so this is belt-and-braces
        -- see the class docstring's "ORDERING", and `wrap_tool_execute` for the same check
        against the chain a run actually resolves. A sibling that ALSO demands the last slot
        never reaches this method at all: the sorter refuses it first, with its own cycle error.
        """
        for toolset in getattr(agent, "toolsets", None) or ():
            seen = toolset
            while seen is not None:
                if isinstance(seen, GuardedToolset):
                    raise UserError(
                        "DelegationGuard and GuardedToolset are both registered on this agent "
                        f"(GuardedToolset wraps {seen.wrapped!r}). Each is a complete, "
                        "independent authorization path; using both means guard.check() runs "
                        "TWICE for the same call. Use exactly one: DelegationGuard for the "
                        "whole agent, or GuardedToolset for just this toolset (not both)."
                    )
                seen = getattr(seen, "wrapped", None)

        root = getattr(agent, "root_capability", None)
        nested = _find_execution_wrapper_nested_inside(root, self)
        if nested is not None:
            raise UserError(_execution_wrapper_nested_inside_message(nested))
        return self

    async def wrap_tool_execute(
        self,
        ctx: RunContext[Any],
        *,
        call: ToolCallPart,
        tool_def: ToolDefinition,
        args: dict[str, Any],
        handler: Callable[[dict[str, Any]], Any],
    ) -> Any:
        """The same nesting check as `for_agent()`, against the chain the RUN actually resolved.
        `ctx.root_capability` is the agent's own documented mechanism for this ("the effective
        root capability for this run... capability implementations can use this to validate
        per-run additions" -- `pydantic_ai._run_context.RunContext.root_capability`'s own
        docstring), so it reflects what construction cannot see: a sibling whose `for_agent()`
        REBINDS to an execution wrapper, and a per-run `agent.run(..., capabilities=[...])`
        injection. Both now sort OUTSIDE this capability rather than inside it (class docstring,
        "ORDERING"), so like `for_agent()`'s copy this is belt-and-braces against a future
        ordering primitive. It still runs BEFORE `_resolve()` or `guard.check()`, so a rejection
        writes nothing to the ledger, exactly as an unresolved tool or a missing Guard does."""
        nested = _find_execution_wrapper_nested_inside(ctx.root_capability, self)
        if nested is not None:
            raise UserError(_execution_wrapper_nested_inside_message(nested))

        resolved = _resolve(
            ctx, call.tool_name, self.policies, self.get_guard, self.on_unmapped,
            "DelegationGuard",
        )
        if resolved is None:
            return await handler(args)
        guard, policy = resolved
        if policy.scope is not None and guard.schema_version == 2:
            decision, snapshot = _authorize_v2(
                guard, policy, call.tool_name, args, on_denial=self.on_denial
            )
            return await _run_wrapped_and_record_outcome(
                guard, decision.call_id, snapshot, lambda: handler(args)
            )
        authorize_tool_call(guard, policy, call.tool_name, args, on_denial=self.on_denial)
        return await handler(args)


# ==========================================================================
# Hook point 2b — per-toolset wrapper (for guarding one toolset)
# ==========================================================================

@dataclass
class GuardedToolset(WrapperToolset[Any]):
    """Wrap any toolset so `guard.check(...)` runs before its tools execute.

    `WrapperToolset.call_tool` is the only route to the wrapped toolset's own
    `call_tool`, so authorizing here provably precedes the tool body. Prefer
    `DelegationGuard` when you want the whole agent covered; use this when you
    want to guard exactly one toolset (e.g. a single MCP server) and leave the
    agent's other tools alone.
    """

    policies: Mapping[str, ToolPolicy] = field(default_factory=dict)
    get_guard: Callable[[RunContext[Any]], Guard | None] = _default_get_guard
    on_unmapped: Literal["deny", "allow"] = "deny"
    on_denial: OnDenial = "raise"

    async def call_tool(
        self,
        name: str,
        tool_args: dict[str, Any],
        ctx: RunContext[Any],
        tool: ToolsetTool[Any],
    ) -> Any:
        resolved = _resolve(
            ctx, name, self.policies, self.get_guard, self.on_unmapped, "GuardedToolset"
        )
        if resolved is None:
            return await self.wrapped.call_tool(name, tool_args, ctx, tool)
        guard, policy = resolved
        if policy.scope is not None and guard.schema_version == 2:
            decision, snapshot = _authorize_v2(guard, policy, name, tool_args, on_denial=self.on_denial)
            return await _run_wrapped_and_record_outcome(
                guard, decision.call_id, snapshot,
                lambda: self.wrapped.call_tool(name, tool_args, ctx, tool),
            )
        authorize_tool_call(guard, policy, name, tool_args, on_denial=self.on_denial)
        return await self.wrapped.call_tool(name, tool_args, ctx, tool)

    # NOTE: `WrapperToolset` rebuilds itself with `dataclasses.replace` in
    # `for_run` / `for_run_step` / `visit_and_replace`. The extra fields above ride
    # along automatically *because they are declared as dataclass fields* — declare
    # config on a wrapper toolset any other way and it is silently lost per run step.
