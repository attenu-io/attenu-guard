"""dg_openai_agents.py — delegation-guard x the OpenAI Agents SDK.

Copy this single file into your project. It needs `openai-agents` and
`delegation-guard`, and nothing else.

Hook points used (openai-agents 0.21.1)
---------------------------------------
1. DELEGATION — where the child's attenuated `Guard` is minted:
   * `RunHooks.on_handoff(context, from_agent, to_agent)`
     (`agents/lifecycle.py:59`; invoked at `agents/run_internal/turn_resolution.py:614`,
     after the destination agent is resolved and *before* the child's first model
     call). This is the only handoff hook that names BOTH sides of the delegation,
     so `DelegationGuardHooks` uses it and covers every handoff in the run at once
     — including plain `handoff()` objects and bare `handoffs=[agent]` entries.
   * `handoff(agent, on_handoff=...)` (`agents/handoffs/__init__.py:334`) — the
     earliest handoff callback, but it is not told which agent is handing off, so
     `guarded_handoff()` takes `parent=` explicitly. Use it when you would rather
     not pass `hooks=` to `Runner.run`.
   * For agents-as-tools there is no handoff at all: `Agent.as_tool()`
     (`agents/agent.py:576`) returns an ordinary `FunctionTool` whose body is a
     nested `Runner.run`. `guarded_agent_tool()` therefore mints the child from
     that tool's own input guardrail, which runs before the nested run starts.

2. TOOL INVOCATION — where `guard.check()` runs before the tool body:
   * `FunctionTool.tool_input_guardrails` (`agents/tool.py:480`), executed by
     `_execute_tool_input_guardrails` at `agents/run_internal/tool_execution.py:2012`
     — strictly BEFORE `hooks.on_tool_start` (line 2023) and before the tool body
     is invoked at all. `RunHooks.on_tool_start` cannot be used for enforcement:
     it returns `None`, so it can observe but not stop a call.

Usage
-----
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*", "mail.send"},
                       ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    registry = GuardRegistry(root_agent="orchestrator", root_guard=root)
    registry.grant("summarizer", Authority(scopes={"crm.read"},
                   ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
                   task="summarize Q3 pipeline")

    tools = [guarded_tool(crm_query, "crm.read",
                          context_fn=lambda a: {"rows": a.get("rows", 0)}),
             guarded_tool(crm_export, "crm.export",
                          context_fn=lambda a: {"egress": "any"})]
    summarizer   = Agent(name="summarizer",   tools=tools)
    orchestrator = Agent(name="orchestrator", tools=tools, handoffs=[summarizer])

    await Runner.run(orchestrator, "...", context=registry, hooks=DelegationGuardHooks())

`context=` is the registry itself here; if you already pass your own context
object, hang the registry off it as `.delegation_guard` (attribute) or
`["delegation_guard"]` (mapping key) instead — `_resolve_registry` finds all three.

Fail-closed by design: if the registry is missing, if the running agent has no
minted guard, or if the tool arguments cannot be parsed, the call is DENIED.
An agent nobody delegated to holds no authority — it does not fall back to its
parent's.

This adapter deliberately does not decide *what* authority a task needs. You
write the `Authority` for each sub-agent; delegation-guard only guarantees the
child can never exceed the parent, and proves it in the audit ledger.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from agents import (
    Agent,
    FunctionTool,
    Handoff,
    RunContextWrapper,
    RunHooks,
    ToolGuardrailFunctionOutput,
    ToolInputGuardrail,
    ToolInputGuardrailData,
    handoff,
)

from delegation_guard import Authority, AuthorityError, Decision, Guard, Reason

__all__ = [
    "GuardRegistry",
    "Grant",
    "Denial",
    "DelegationGuardHooks",
    "guarded_tool",
    "guarded_agent_tool",
    "guarded_handoff",
    "NO_AUTHORITY",
]

# Reason code for the adapter's own fail-closed paths — the running agent holds
# no Authority object at all, which is upstream of any scope/ceiling question.
# (delegation-guard's `ReasonCode` has no constant for this; see the PoC report.)
NO_AUTHORITY = "no_delegated_authority"

OnDenied = str  # "reject" (tell the model) | "raise" (halt the run)


@dataclass(frozen=True)
class Grant:
    """The authority a named sub-agent may be delegated, declared up front."""

    authority: Authority
    task: str


@dataclass(frozen=True)
class Denial:
    """One refused tool call, kept for assertions, dashboards and tests."""

    agent: str
    tool: str
    scope: str
    decision: Decision

    def explain(self) -> str:
        return f"{self.agent} -> {self.tool} ({self.scope}): {self.decision.explain()}"


class GuardRegistry:
    """Maps agent NAME -> the `Guard` minted for that agent in this run.

    Pass it as `Runner.run(..., context=registry)` (or hang it off your own
    context object as `.delegation_guard`). It holds the root guard, the
    declared grants, the minted child guards, and the denial record.
    """

    def __init__(self, *, root_agent: str, root_guard: Guard):
        self.root_agent = root_agent
        self.root_guard = root_guard
        self.grants: dict[str, Grant] = {}
        self.denials: list[Denial] = []
        self.errors: list[AuthorityError] = []
        self._guards: dict[str, Guard] = {root_agent: root_guard}
        self._revoked: set[str] = set()

    # ---- declaration ----------------------------------------------------
    def grant(self, agent_name: str, authority: Authority, task: str) -> "GuardRegistry":
        """Declare the authority `agent_name` may hold when delegated to.

        This is a REQUEST, not a grant: whatever is written here is met down
        against the delegating parent's authority, so it can never widen it.
        """
        self.grants[agent_name] = Grant(authority, task)
        return self

    # ---- minting --------------------------------------------------------
    def delegate(self, parent_agent: str, child_agent: str) -> Optional[Guard]:
        """Mint (or return the already-minted) child Guard. `None` means the
        delegation was refused — every caller treats that as fail-closed."""
        if child_agent in self._revoked:
            return None
        existing = self._guards.get(child_agent)
        if existing is not None and child_agent != self.root_agent:
            return existing            # idempotent: hooks + guarded_handoff may both fire
        grant = self.grants.get(child_agent)
        parent = self._guards.get(parent_agent)
        if grant is None or parent is None:
            return None
        try:
            child = parent.delegate(child_agent, grant.authority, grant.task)
        except AuthorityError as exc:  # revoked/expired parent, depth or fanout overflow
            self.errors.append(exc)
            return None
        self._guards[child_agent] = child
        return child

    def guard_for(self, agent_name: str) -> Optional[Guard]:
        """The agent's Guard, INCLUDING one that has been revoked.

        A revoked guard is deliberately still returned: `guard.check()` is the
        enforcement point, and it is the chain — not this registry — that knows
        the node and its whole subtree are revoked. Hiding the guard here would
        replace delegation-guard's authoritative `revoked` reason code with a
        vaguer adapter-level one and would skip the cascade entirely.
        """
        return self._guards.get(agent_name)

    # ---- revocation -----------------------------------------------------
    def revoke(self, agent_name: str) -> list:
        """Cascade-revoke an agent's subtree, and refuse to ever re-mint it in
        this run — otherwise a second handoff would quietly hand back a fresh,
        unrevoked guard."""
        self._revoked.add(agent_name)
        guard = self._guards.get(agent_name)
        if guard is None:
            return []
        return self.root_guard.revoke(guard.node_id)

    # ---- reporting ------------------------------------------------------
    def record_denial(self, agent: str, tool: str, scope: str, decision: Decision) -> Denial:
        denial = Denial(agent, tool, scope, decision)
        self.denials.append(denial)
        return denial


def _resolve_registry(context_obj: Any) -> Optional[GuardRegistry]:
    """Find the registry on whatever the developer passed as `context=`."""
    if isinstance(context_obj, GuardRegistry):
        return context_obj
    attached = getattr(context_obj, "delegation_guard", None)
    if isinstance(attached, GuardRegistry):
        return attached
    if isinstance(context_obj, Mapping):
        value = context_obj.get("delegation_guard")
        if isinstance(value, GuardRegistry):
            return value
    return None


def _deny(message: str, code: str = NO_AUTHORITY) -> Decision:
    return Decision.deny(Reason(code, message=message))


def _outcome(decision: Decision, on_denied: OnDenied) -> ToolGuardrailFunctionOutput:
    info = decision.to_dict()
    message = f"delegation-guard: {decision.explain()}"
    if on_denied == "raise":
        # Halts the run with ToolInputGuardrailTripwireTriggered.
        return ToolGuardrailFunctionOutput.raise_exception(output_info=info)
    # Default: the tool body is skipped and `message` is returned to the model as
    # the tool's output, so the agent can recover or explain instead of the whole
    # run dying on one over-reach. The SDK handles this natively
    # (agents/run_internal/tool_execution.py:2016) — no exception plumbing needed.
    return ToolGuardrailFunctionOutput.reject_content(message, output_info=info)


def _parse_arguments(raw: str) -> Optional[dict]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _with_guardrail(tool: FunctionTool, guardrail: ToolInputGuardrail) -> FunctionTool:
    """Return a copy of `tool` with our guardrail running first.

    A shallow copy, not `dataclasses.replace`: `Agent.as_tool()` sets private
    instance attributes (`_agent_instance`, `_is_agent_tool`) that `replace()`
    would silently drop. Copying leaves the caller's original tool untouched,
    so the same underlying function can be guarded with different scopes in
    different places.
    """
    guarded = copy.copy(tool)
    guarded.tool_input_guardrails = [guardrail, *(tool.tool_input_guardrails or [])]
    return guarded


def guarded_tool(
    tool: FunctionTool,
    scope: str,
    *,
    context_fn: Optional[Callable[[dict], Mapping]] = None,
    metered: bool = False,
    on_denied: OnDenied = "reject",
    tool_label: Optional[str] = None,
) -> FunctionTool:
    """Authorize every invocation of `tool` against the RUNNING agent's Guard.

    Parameters
    ----------
    scope : the scope this tool needs, e.g. ``"crm.read"``.
    context_fn : maps the tool's parsed arguments to a `guard.check()` context,
        e.g. ``lambda args: {"rows": args.get("rows", 0)}``. Omitted means an
        empty context — fine for a scope-only check, but note that a ceiling
        whose field is absent from the context is not asserted against, so pass
        the quantity whenever a ceiling should bind.
    metered : forwarded to `guard.check(metered=...)`; with a Guard issued
        `strict_metering=True`, a metered call arriving with no context at all
        is refused rather than treated as free.
    on_denied : ``"reject"`` returns the denial to the model as the tool result
        (default); ``"raise"`` halts the run with
        `ToolInputGuardrailTripwireTriggered`.

    The tool body NEVER runs on a denial, under either setting.
    """

    async def _authorize(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        tool_context = data.context
        tool_name = tool_label or tool_context.tool_name
        agent_name = getattr(data.agent, "name", "<unknown>")

        registry = _resolve_registry(tool_context.context)
        if registry is None:
            return _outcome(
                _deny("no delegation-guard registry on the run context; refusing "
                      f"{tool_name!r}"),
                on_denied,
            )

        guard = registry.guard_for(agent_name)
        if guard is None:
            decision = _deny(f"agent {agent_name!r} has no delegated authority in this "
                             f"chain; refusing {tool_name!r}")
            registry.record_denial(agent_name, tool_name, scope, decision)
            return _outcome(decision, on_denied)

        arguments = _parse_arguments(tool_context.tool_arguments)
        if arguments is None:
            decision = _deny(f"could not parse arguments for {tool_name!r}; refusing "
                             "rather than evaluating ceilings against an unknown quantity")
            registry.record_denial(agent_name, tool_name, scope, decision)
            return _outcome(decision, on_denied)

        check_context = dict(context_fn(arguments)) if context_fn else {}
        decision = guard.check(scope, context=check_context, metered=metered, tool=tool_name)
        if decision:
            return ToolGuardrailFunctionOutput.allow(output_info=decision.to_dict())

        registry.record_denial(agent_name, tool_name, scope, decision)
        return _outcome(decision, on_denied)

    return _with_guardrail(
        tool,
        ToolInputGuardrail(guardrail_function=_authorize, name=f"delegation_guard[{scope}]"),
    )


def guarded_agent_tool(
    agent_tool: FunctionTool,
    *,
    scope: Optional[str] = None,
    on_denied: OnDenied = "reject",
) -> FunctionTool:
    """Guard an `Agent.as_tool(...)` tool: mint the sub-agent's Guard before the
    nested run starts, and refuse to start it at all if the delegation is not
    permitted.

    `scope`, if given, is additionally checked against the CALLING agent's Guard
    — use it when invoking this sub-agent is itself a privileged act.
    """
    sub_agent = getattr(agent_tool, "_agent_instance", None)
    if sub_agent is None:
        raise ValueError(
            "guarded_agent_tool() expects the FunctionTool returned by Agent.as_tool(); "
            f"{agent_tool.name!r} has no bound agent."
        )
    child_name = sub_agent.name

    async def _delegate(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        tool_context = data.context
        tool_name = tool_context.tool_name
        caller = getattr(data.agent, "name", "<unknown>")

        registry = _resolve_registry(tool_context.context)
        if registry is None:
            return _outcome(
                _deny(f"no delegation-guard registry on the run context; refusing to "
                      f"start {child_name!r}"),
                on_denied,
            )

        if scope is not None:
            caller_guard = registry.guard_for(caller)
            if caller_guard is None:
                decision = _deny(f"agent {caller!r} has no delegated authority in this chain")
                registry.record_denial(caller, tool_name, scope, decision)
                return _outcome(decision, on_denied)
            decision = caller_guard.check(scope, tool=tool_name)
            if not decision:
                registry.record_denial(caller, tool_name, scope, decision)
                return _outcome(decision, on_denied)

        if registry.delegate(caller, child_name) is None:
            decision = _deny(f"{caller!r} may not delegate to {child_name!r}: no grant "
                             "declared, revoked, or the chain refused the delegation")
            registry.record_denial(caller, tool_name, scope or f"agent.{child_name}", decision)
            return _outcome(decision, on_denied)

        return ToolGuardrailFunctionOutput.allow(
            output_info={"delegated_to": child_name, "by": caller}
        )

    return _with_guardrail(
        agent_tool,
        ToolInputGuardrail(guardrail_function=_delegate,
                           name=f"delegation_guard[delegate:{child_name}]"),
    )


def guarded_handoff(agent: Agent, *, parent: str, **handoff_kwargs: Any) -> Handoff:
    """`handoff(agent, ...)` that mints the child's Guard when the handoff fires.

    Use this when you do not want to pass `hooks=` to `Runner.run`. `parent` must
    be named explicitly because the SDK's `on_handoff` callback is not told which
    agent is handing off — `DelegationGuardHooks` has no such limitation.

    A refused delegation cannot cancel the handoff (the SDK's handoff callback
    has no veto), but the child is then left with NO guard, so its very first
    guarded tool call is denied and no tool body runs.
    """

    async def _on_handoff(ctx: RunContextWrapper[Any]) -> None:
        registry = _resolve_registry(ctx.context)
        if registry is not None:
            registry.delegate(parent, agent.name)

    return handoff(agent, on_handoff=_on_handoff, **handoff_kwargs)


class DelegationGuardHooks(RunHooks):
    """Run-level hooks that mint an attenuated Guard at EVERY handoff.

    Pass as `Runner.run(..., hooks=DelegationGuardHooks())`. This covers bare
    `handoffs=[agent]` entries and hand-written `handoff()` objects alike, with
    no per-handoff wiring. Compose with your own hooks by subclassing and calling
    `await super().on_handoff(...)`.
    """

    async def on_handoff(self, context, from_agent, to_agent) -> None:  # type: ignore[override]
        registry = _resolve_registry(context.context)
        if registry is not None:
            registry.delegate(from_agent.name, to_agent.name)
