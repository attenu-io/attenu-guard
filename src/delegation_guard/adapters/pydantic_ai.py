"""
delegation_guard.adapters.pydantic_ai — a thin delegation-guard integration for Pydantic AI.

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
`delegation_guard`, and nothing else. Copy it into your project as-is.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Literal, Mapping, TypeVar

from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.exceptions import ToolFailed, UserError
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.tools import RunContext, ToolDefinition
from pydantic_ai.toolsets.abstract import ToolsetTool
from pydantic_ai.toolsets.wrapper import WrapperToolset

from delegation_guard import Authority, AuthorityDenied, Guard

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

`"raise"`      — re-raise `delegation_guard.AuthorityDenied`. Pydantic AI does not
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
# delegation-guard deliberately does not decide this for you — the integrator
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
        policy.scope, context=context, metered=policy.metered, tool=tool_name
    )
    if decision:
        return

    if on_denial == "tool_failed":
        raise ToolFailed(
            f"Denied by delegation-guard: {decision.explain()} "
            f"(tool={tool_name!r}, scope={policy.scope!r}). "
            f"This agent does not hold the authority for this action; do not retry it."
        )
    raise AuthorityDenied(decision)


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
        raise UnmappedToolError(
            f"{label}: tool {tool_name!r} has no ToolPolicy, so the authority it "
            f"consumes is undeclared and the call cannot be authorized. Add it to "
            f"`policies`, mark it `UNGUARDED`, or pass `on_unmapped='allow'`."
        )

    guard = get_guard(ctx)
    if guard is None:
        raise MissingGuardError(
            f"{label}: no delegation-guard `Guard` on the run's deps, so tool "
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
            authorize_tool_call(
                guard, policy, call.tool_name, args, on_denial=self.on_denial
            )
        return args


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
        if resolved is not None:
            guard, policy = resolved
            authorize_tool_call(guard, policy, name, tool_args, on_denial=self.on_denial)
        return await self.wrapped.call_tool(name, tool_args, ctx, tool)

    # NOTE: `WrapperToolset` rebuilds itself with `dataclasses.replace` in
    # `for_run` / `for_run_step` / `visit_and_replace`. The extra fields above ride
    # along automatically *because they are declared as dataclass fields* — declare
    # config on a wrapper toolset any other way and it is silently lost per run step.
