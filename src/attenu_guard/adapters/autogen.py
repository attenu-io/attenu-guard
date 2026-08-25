"""attenu-guard × AutoGen (`autogen-agentchat` 0.7.x) — thin integration adapter.

Hook points used
----------------
1. **Delegation / handoff — `GuardedHandoff`.**
   AutoGen's `Swarm` delegation primitive is `AssistantAgent(handoffs=[Handoff(...)])`.
   A `Handoff` exposes a `handoff_tool` property that AutoGen materialises once, at
   agent construction (`autogen_agentchat/agents/_assistant_agent.py:801`), and then
   executes **outside the workbench**, directly via `handoff_tool.run_json(...)`
   (`_assistant_agent.py:1561-1574`). So a guarded workbench never sees a handoff.
   `GuardedHandoff` is a `Handoff` subclass that overrides that property: when the
   model calls `transfer_to_<target>`, the adapter mints the child `Guard` with
   `parent_guard.delegate(...)` and registers it under the target agent's name.
   This is the framework's own extension point — no monkeypatching.

2. **Tool invocation — `GuardedWorkbench`.**
   Every non-handoff tool call an `AssistantAgent` makes is routed through its
   `Workbench` (`_assistant_agent.py:1576-1613`); when you pass `tools=[...]`
   AutoGen wraps them in a `StaticStreamWorkbench` (`_assistant_agent.py:835`).
   `GuardedWorkbench` subclasses `StaticStreamWorkbench` and overrides **both**
   `call_tool` and `call_tool_stream` — AutoGen picks the streaming path whenever
   `isinstance(wb, StaticStreamWorkbench)` (`_assistant_agent.py:1580`), so
   overriding only `call_tool` would silently leave the real path unguarded.
   `guard.check(...)` runs before `super()` is called, so a denied tool body
   never executes.

Usage
-----
Build one `GuardRegistry` per run, seeded with the root `Guard`. Give each agent a
`GuardedWorkbench` (via `guarded_agent`) carrying a `{tool_name: ToolPolicy}` map
that says which scope and context each tool consumes. Wire delegation with
`GuardedHandoff(target=..., source=..., registry=..., grant=Grant(authority, task))`
for `Swarm` handoffs, or with `ToolPolicy(delegates_to=..., grant=...)` for the
agents-as-tools pattern (`AgentTool` / `TeamTool`). Both fail closed: an agent with
no delegated `Guard`, and a tool with no `ToolPolicy`, are denied. attenu-guard
deliberately does not decide *what* authority a task needs — you write the `Grant`.

Denials are returned to the model as an error `ToolResult` by default
(`on_deny="error"`) rather than raised: AutoGen converts it into a
`FunctionExecutionResult(is_error=True)` the model can react to, whereas an
exception raised from `call_tool` propagates out of `_execute_tool_call`
uncaught and tears down the whole `team.run()`. Use `on_deny="raise"` when you
want that hard stop (it raises `attenu_guard.AuthorityDenied`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncGenerator, Callable, Dict, List, Mapping, Optional

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.base import Handoff
from autogen_core import CancellationToken
from autogen_core.tools import (
    BaseTool,
    FunctionTool,
    StaticStreamWorkbench,
    TextResultContent,
    ToolOverride,
    ToolResult,
)
from pydantic import BaseModel, ConfigDict

from attenu_guard import Authority, AuthorityDenied, AuthorityError, Guard
from attenu_guard.reasons import Disposition, ReasonCode

__all__ = [
    "Grant",
    "ToolPolicy",
    "GuardRegistry",
    "GuardedWorkbench",
    "GuardedHandoff",
    "guarded_agent",
]

ContextFn = Callable[[Mapping[str, Any]], Mapping[str, Any]]


# ---------------------------------------------------------------------------
# policy declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    """The authority a parent *requests* for a child at a delegation point.

    What the child actually receives is `parent.authority.meet(request)`, so a
    greedy Grant cannot widen the child beyond its parent.
    """

    authority: Authority
    task: str = ""


@dataclass(frozen=True)
class ToolPolicy:
    """Maps one AutoGen tool onto the authority it consumes.

    `context` turns the tool's JSON arguments into the context dict that
    attenu-guard's ceilings evaluate (e.g. ``{"rows": 4200}``). If the tool is
    itself a delegation point (an `AgentTool`/`TeamTool`), set `delegates_to` to
    the child agent's registry name and `grant` to the authority it should get —
    the child `Guard` is minted after the check passes, before the tool body runs.
    """

    scope: str
    context: Optional[ContextFn] = None
    metered: bool = False
    delegates_to: Optional[str] = None
    grant: Optional[Grant] = None
    disposition: Optional[str] = None     # see attenu_guard.Disposition


# ---------------------------------------------------------------------------
# registry — agent name -> Guard, for one run
# ---------------------------------------------------------------------------


class GuardRegistry:
    """Holds the live delegation chain for a single AutoGen run.

    AutoGen agents are long-lived objects addressed by name, so the adapter keys
    guards by agent name. Fail-closed: an agent nobody has delegated to has no
    entry, and every tool call it makes is denied.
    """

    def __init__(self, root: Guard, root_agent: str) -> None:
        self.root = root
        self._guards: Dict[str, Guard] = {root_agent: root}

    def get(self, agent: str) -> Optional[Guard]:
        return self._guards.get(agent)

    def require(self, agent: str) -> Guard:
        guard = self._guards.get(agent)
        if guard is None:
            raise KeyError(f"no Guard registered for agent {agent!r}")
        return guard

    def delegate(self, parent_agent: str, child_agent: str, grant: Grant) -> Guard:
        """Mint the child Guard. Raises `AuthorityError` on structural failure
        (revoked/expired parent, depth/fanout overflow)."""
        parent = self.require(parent_agent)
        child = parent.delegate(child_agent, grant.authority, grant.task or child_agent)
        self._guards[child_agent] = child
        return child

    def revoke(self, agent: str) -> list:
        """Cascade-revoke an agent's subtree. Its guard stays registered so
        later calls are denied with `revoked` rather than the fail-closed
        `no authority` reason."""
        return self.root.revoke(self.require(agent).node_id)

    def graph(self) -> dict:
        return self.root.graph()


# ---------------------------------------------------------------------------
# hook point 2 — tool invocation
# ---------------------------------------------------------------------------


def _deny_result(name: str, message: str) -> ToolResult:
    return ToolResult(
        name=name,
        result=[TextResultContent(content=message)],
        is_error=True,
    )


class GuardedWorkbench(StaticStreamWorkbench):
    """A `StaticStreamWorkbench` that runs `guard.check()` before every tool body.

    Drop-in for the workbench `AssistantAgent` builds for you: pass
    ``workbench=GuardedWorkbench(tools, ...)`` instead of ``tools=[...]``.
    """

    def __init__(
        self,
        tools: List[BaseTool[Any, Any]],
        *,
        agent_name: str,
        registry: GuardRegistry,
        policies: Mapping[str, ToolPolicy],
        on_deny: str = "error",
        tool_overrides: Optional[Dict[str, ToolOverride]] = None,
    ) -> None:
        super().__init__(tools, tool_overrides)
        if on_deny not in ("error", "raise"):
            raise ValueError("on_deny must be 'error' or 'raise'")
        self._agent_name = agent_name
        self._registry = registry
        self._policies = dict(policies)
        self._on_deny = on_deny

    # -- the gate ----------------------------------------------------------
    def _authorize(
        self, name: str, arguments: Mapping[str, Any]
    ) -> Optional[ToolResult]:
        """Return a denial `ToolResult`, or None when the call may proceed.

        Raises `AuthorityDenied` instead of returning when ``on_deny="raise"``.
        """
        original = self._override_name_to_original.get(name, name)
        policy = self._policies.get(original)
        if policy is None:
            # No authority is known for this tool: put it on the ledger as
            # `unresolved` when a Guard exists (the Decisions queue folds the ledger).
            g = self._registry.get(self._agent_name)
            msg = f"attenu-guard: no ToolPolicy declared for tool {original!r} (fail-closed)."
            decision = (g.record_denial(ReasonCode.NO_AUTHORITY, msg, tool=original,
                                        disposition=Disposition.UNRESOLVED) if g is not None else None)
            return self._deny(name, msg, decision=decision)

        guard = self._registry.get(self._agent_name)
        if guard is None:
            return self._deny(
                name,
                f"attenu-guard: agent {self._agent_name!r} holds no delegated "
                f"authority (fail-closed).",
                decision=None,
            )

        context = policy.context(arguments) if policy.context else {}
        decision = guard.check(
            policy.scope, context=context, tool=original, metered=policy.metered,
            disposition=policy.disposition,
        )
        if not decision:
            return self._deny(
                name,
                f"attenu-guard: {decision.explain()} "
                f"(agent={self._agent_name}, tool={original}, scope={policy.scope})",
                decision=decision,
            )

        # Allowed — and if this tool is itself a delegation point, mint the child
        # now, before the body runs.
        if policy.delegates_to and policy.grant:
            try:
                self._registry.delegate(
                    self._agent_name, policy.delegates_to, policy.grant
                )
            except AuthorityError as exc:
                return self._deny(
                    name,
                    f"attenu-guard: cannot delegate to "
                    f"{policy.delegates_to!r}: {exc}",
                    decision=None,
                )
        return None

    def _deny(self, name: str, message: str, *, decision) -> ToolResult:
        if self._on_deny == "raise":
            if decision is not None:
                raise AuthorityDenied(decision)
            raise PermissionError(message)
        return _deny_result(name, message)

    # -- overrides ---------------------------------------------------------
    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        cancellation_token: CancellationToken | None = None,
        call_id: str | None = None,
    ) -> ToolResult:
        denial = self._authorize(name, arguments or {})
        if denial is not None:
            return denial
        return await super().call_tool(name, arguments, cancellation_token, call_id)

    async def call_tool_stream(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        cancellation_token: CancellationToken | None = None,
        call_id: str | None = None,
    ) -> AsyncGenerator[Any | ToolResult, None]:
        # NOTE: AssistantAgent takes this path, not call_tool, whenever the
        # workbench is a StaticStreamWorkbench (_assistant_agent.py:1580).
        denial = self._authorize(name, arguments or {})
        if denial is not None:
            yield denial
            return
        async for event in super().call_tool_stream(
            name, arguments, cancellation_token, call_id
        ):
            yield event


# ---------------------------------------------------------------------------
# hook point 1 — handoff / child creation
# ---------------------------------------------------------------------------


class GuardedHandoff(Handoff):
    """A `Handoff` that mints the target's `Guard` when the transfer tool fires.

    Needed because AutoGen executes handoff tools outside the workbench
    (`_assistant_agent.py:1561-1574`), so `GuardedWorkbench` never sees them.
    Pass this anywhere a `Handoff` is accepted — `AssistantAgent` only checks
    `isinstance(handoff, Handoff)` (`_assistant_agent.py:800`).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source: str
    """Registry name of the delegating (parent) agent."""
    registry: GuardRegistry
    grant: Grant

    @property
    def handoff_tool(self) -> BaseTool[BaseModel, BaseModel]:
        def _handoff_tool() -> str:
            try:
                self.registry.delegate(self.source, self.target, self.grant)
            except AuthorityError as exc:
                # Do not raise: AutoGen does not wrap handoff-tool execution in a
                # try/except, so an exception here tears down team.run(). Refusing
                # in the tool result keeps the run alive, and the target agent is
                # left with no Guard — so every tool it tries is fail-closed.
                return (
                    f"attenu-guard: refused to delegate to {self.target!r}: {exc}"
                )
            return self.message

        return FunctionTool(
            _handoff_tool, name=self.name, description=self.description, strict=True
        )


# ---------------------------------------------------------------------------
# convenience
# ---------------------------------------------------------------------------


def guarded_agent(
    *,
    name: str,
    model_client,
    tools: List[BaseTool[Any, Any]],
    policies: Mapping[str, ToolPolicy],
    registry: GuardRegistry,
    on_deny: str = "error",
    **assistant_kwargs: Any,
) -> AssistantAgent:
    """Build an `AssistantAgent` whose tools are gated by attenu-guard.

    Note AutoGen rejects `tools=` and `workbench=` together
    (`_assistant_agent.py:829`), so the tools go into the workbench instead.
    """
    workbench = GuardedWorkbench(
        list(tools),
        agent_name=name,
        registry=registry,
        policies=policies,
        on_deny=on_deny,
    )
    return AssistantAgent(
        name=name, model_client=model_client, workbench=workbench, **assistant_kwargs
    )
