"""
attenu_guard.adapters.pydantic_ai — a thin attenu-guard integration for Pydantic AI.

Tested against pydantic-ai-slim 2.31.1 (Python >= 3.10).

HOOK POINTS USED
----------------
1. Child creation / delegation — `GuardedDeps.delegate(...)`.
   Pydantic AI's documented multi-agent pattern is "agent delegation": a tool on
   the parent agent calls `child_agent.run(..., usage=ctx.usage)`. There is no
   framework callback at that moment, so the integration sits at the construction
   site: the parent's deps carry its `Guard`, and the delegating tool mints the
   child's attenuated `Guard` and passes it down as the child run's `deps`.
   `RunContext.deps` (`pydantic_ai/_run_context.py:64`) is the carrier.

2. Tool invocation — `DelegationGuard.before_tool_execute(...)`, a subclass of
   `pydantic_ai.capabilities.AbstractCapability`
   (`pydantic_ai/capabilities/abstract.py:846`), registered with
   `Agent(capabilities=[...])`.
   `ToolManager._run_execute_hooks` awaits `before_tool_execute` at
   `pydantic_ai/tool_manager.py:459`, and only afterwards calls
   `wrap_tool_execute(..., handler=do_execute)` at
   `pydantic_ai/tool_manager.py:463`, where `do_execute` is the only path to
   `toolset.call_tool` (`pydantic_ai/tool_manager.py:1003`). Raising from
   `before_tool_execute` therefore provably prevents the tool body from running.
   This is agent-wide: it covers function tools, `Toolset`s, and MCP servers
   alike, with one registration.

   `GuardedToolset` is the alternative, narrower hook: a
   `pydantic_ai.toolsets.WrapperToolset` whose `call_tool` authorizes before
   delegating to `self.wrapped.call_tool` (`pydantic_ai/toolsets/wrapper.py:63`).
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

Execution binding (0.9.0, on a `schema_version=2` chain — see `Guard.issue`):
BOTH hook points here are genuine WRAPPER capture (`Capture.WRAPPER_ASYNC`) — unlike
most other framework adapters, this one calls the tool body itself and awaits it, the
same way `adapters.langgraph`'s reference wiring does:

  * `DelegationGuard`: `before_tool_execute` still does authorization (unchanged shape,
    unchanged on `schema_version=1`); on a v2 chain it ALSO passes `capture`/`adapter`/
    `authorized_params` and stashes the allowed `Decision` for `wrap_tool_execute` --
    `AbstractCapability`'s own wrap-the-body hook -- to close out, correlated by
    `id(call)` (the SAME `ToolCallPart` object flows through both hooks for one call
    within `ToolManager._run_execute_hooks`).
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
import copy
import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Literal, Mapping, TypeVar

from pydantic_ai.capabilities.abstract import AbstractCapability
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


def _snapshot_params(args: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    the tool body runs -- and reused for both `authorized_params` and `invoked_params`."""
    try:
        return copy.deepcopy(dict(args))
    except Exception:
        return dict(args)

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

`"raise"`      — re-raise `attenu_guard.AuthorityDenied`. Pydantic AI does not
                 catch it (`pydantic_ai/tool_manager.py:477-489` only catches
                 `ValidationError` / `ModelRetry` / `ToolFailed`), so it aborts the
                 whole agent run. Deterministic hard stop; the default, because a
                 denied action is a security event, not a conversational hiccup.
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


# ==========================================================================
# Hook point 2a — agent-wide capability (preferred)
# ==========================================================================

class DelegationGuard(AbstractCapability[Any]):
    """Authorize every tool call this agent makes, before the tool body runs.

    Registered via `Agent(capabilities=[DelegationGuard(policies)])`. Because the
    hook lives in `ToolManager`, one registration covers function tools, every
    `Toolset` on the agent, and MCP servers.

    Output tools are exempt by design — Pydantic AI does not fire tool hooks for
    them (`pydantic_ai/tool_manager.py:454`); they produce the run's result and
    reach no external system.
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
        # Execution binding (0.9.0): an allowed, v2 check() waiting on wrap_tool_execute to
        # close it out -- keyed by id(call), the SAME ToolCallPart before_tool_execute and
        # wrap_tool_execute both see for one call within ToolManager._run_execute_hooks.
        self._pending: dict[int, tuple[Guard, str, Any]] = {}

    async def before_tool_execute(
        self,
        ctx: RunContext[Any],
        *,
        call: ToolCallPart,
        tool_def: ToolDefinition,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        resolved = _resolve(
            ctx, call.tool_name, self.policies, self.get_guard, self.on_unmapped,
            "DelegationGuard",
        )
        if resolved is not None:
            guard, policy = resolved
            if policy.scope is not None and guard.schema_version == 2:
                decision, snapshot = _authorize_v2(
                    guard, policy, call.tool_name, args, on_denial=self.on_denial
                )
                self._pending[id(call)] = (guard, decision.call_id, snapshot)
            else:
                authorize_tool_call(
                    guard, policy, call.tool_name, args, on_denial=self.on_denial
                )
        return args

    async def wrap_tool_execute(
        self,
        ctx: RunContext[Any],
        *,
        call: ToolCallPart,
        tool_def: ToolDefinition,
        args: dict[str, Any],
        handler: Callable[[dict[str, Any]], Any],
    ) -> Any:
        pending = self._pending.pop(id(call), None)
        if pending is None:
            return await handler(args)  # v1, UNGUARDED, or the call was denied
        guard, call_id, snapshot = pending
        return await _run_wrapped_and_record_outcome(
            guard, call_id, snapshot, lambda: handler(args)
        )


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
