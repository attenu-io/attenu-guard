"""attenu-guard × AG2 (`ag2` 1.0.x, the AutoGen fork).

Tested against **ag2 1.0.2** on Python 3.12. Install the framework with
``pip install 'attenu-guard[ag2]'``.

AG2 1.0 is a rewrite: the package is `ag2` (not `autogen`), an agent is
`ag2.Agent`, and every hook is a `ag2.middleware.BaseMiddleware` subclass.

HOOK POINTS USED
----------------
1. **Tool invocation — `DelegationGuard(BaseMiddleware).on_tool_execution`.**
   `BaseMiddleware.on_tool_execution(call_next, event, context)`
   (`ag2/middleware/base.py:105-111`) is a genuine around-hook. `FunctionTool.register`
   folds the agent's middleware around the tool object
   (`ag2/tools/final/function_tool.py:120-124`, wrapper at `:212-216`), and the
   subscriber consumes the return value directly:

       result = await execution(event, context)   # function_tool.py:127
       await context.send(result)                 # function_tool.py:128

   The tool body is `FunctionTool.__call__` (`function_tool.py:132-145`), reachable
   only through `call_next`. Returning a `ToolResultEvent` without calling `call_next`
   therefore provably prevents the body from running, and that event *is* what the
   model sees. The agent instantiates one middleware object per turn and hands it to
   the executor at `ag2/agent.py:1351` / `:1415-1421`.

2. **Delegation — the same hook, on the delegating tool.**
   AG2 1.0 has no separate delegation callback because every in-process handover is
   itself a tool call:

   * `Agent.as_tool(...)` (`ag2/agent.py:1494`) builds a `@tool`-decorated
     `task_<agent-name>` function (`ag2/tools/subagents/subagent_tool.py:45-68`) whose
     body calls `run_task` → `agent.ask(...)`
     (`ag2/tools/subagents/run_task.py:138-148`).
   * `tasks=TaskConfig(...)` injects `run_subtask` / `run_subtasks`
     (`ag2/agent.py:1673-1706`), which construct the child `Agent` at
     `ag2/agent.py:1463-1469`.
   * `background_agent_tool` (`ag2/tools/subagents/background.py:21-72`) and the
     cross-process `delegate` tool (`ag2/network/client/tools/delegate.py:80-197`) are
     `@tool`s too.

   Set `ToolPolicy(delegates_to=..., grant=...)` on those names: the child `Guard` is
   minted with `parent.delegate(...)` after the check passes and before the sub-agent
   starts.

WHO IS THE PARENT
-----------------
`GuardRegistry` keys guards by agent name, and each `DelegationGuard` reports the agent
it is actually running on — AG2 stamps the live agent into the context at
`ag2/agent.py:1491` (`context.dependencies[AGENT_CONTEXT_DEPENDENCY_KEY] = self`), so
the parent of a delegation is the agent whose turn issued the delegating tool call, not
"the last agent to speak". `agent_name=` pins it explicitly when you prefer that.

**Agent middleware does not propagate into sub-agents.** `run_task` copies the parent's
dependencies and variables to the child (`run_task.py:141`, `:147`) but not its
middleware, and `_spawn_subtask` constructs the child `Agent` with no `middleware=`
argument (`ag2/agent.py:1463-1469`) — `TaskConfig` has no such field
(`ag2/agent.py:102-119`). Two consequences:

* For agents you construct (`as_tool` children): give each one its own
  `DelegationGuard`. `guarded_agent()` is the one-liner.
* For `tasks=TaskConfig(...)` children, whose constructor you cannot reach: use
  `guarded_tools(...)`, which attaches the same policy as *per-tool* middleware via
  `FunctionTool.with_middleware` (`function_tool.py:97-104`). Tool-level middleware
  travels with the deep-copied tool object into the child
  (`function_tool.py:110-111`), so the child's calls are still checked.

`GuardRegistry` is fail-closed either way: an agent nobody delegated to holds no
`Guard`, so every tool it tries is denied.

DENIAL SHAPE
------------
A denial is returned as `ToolResultEvent.from_call(event, result=<message>)`
(`ag2/events/tool_events.py:130-136`) — the framework's own shape for a tool result, so
the model can react. `on_deny="error"` returns a `ToolErrorEvent` instead; note that
`ToolErrorEvent.from_call` embeds the formatted traceback in the text sent to the model
(`ag2/events/tool_events.py:153-168`), so `"result"` is the default.

Raising is deliberately **not** offered: `_execute_call` catches every exception and
converts it into a `ToolErrorEvent` (`ag2/tools/executor.py:116-122`), so a raise cannot
stop the run — it would only look like a tool failure. The adapter's own bookkeeping is
wrapped so an unexpected error still denies rather than falling through.

USAGE
-----
Build one `GuardRegistry` per run, seeded with the root `Guard`. Give every agent a
`DelegationGuard` carrying a ``{tool_name: ToolPolicy}`` map that says which scope and
context each tool consumes, and mark the delegating tools with `delegates_to` /
`grant`. A tool with no `ToolPolicy` is denied. attenu-guard deliberately does not
decide *what* authority a task needs — you write the `Grant`.

    registry = GuardRegistry(root_guard, "orchestrator")
    worker = guarded_agent("worker", "…", config=…, tools=[…],
                           policies=WORKER_POLICIES, registry=registry)
    boss = guarded_agent("orchestrator", "…", config=…,
                         tools=[worker.as_tool(description="…")],
                         policies={"task_worker": ToolPolicy("crm.read",
                                                             delegates_to="worker",
                                                             grant=Grant(…))},
                         registry=registry)

KNOWN GAPS (things this seam cannot see)
----------------------------------------
* **Provider-side builtin tools** — `WebSearchTool`, `CodeExecutionTool`, `ShellTool`,
  `MCPServerTool`, `MemoryTool`, `SkillsTool` and friends register a no-op subscriber
  and ignore the `middleware` argument entirely (e.g.
  `ag2/tools/builtin/web_search.py:78-90`); they execute at the model provider. They
  cannot be gated here — do not attach them to a guarded agent.
* **`ToolResult(final=True)`** from any tool in a parallel batch makes the executor
  return early (`ag2/tools/executor.py:68-89`), discarding sibling results including a
  denial message. The denied body still never ran; only the message is lost.
* **Concurrency** — one middleware instance serves a whole turn while
  `asyncio.gather` runs the turn's tool calls concurrently
  (`ag2/tools/executor.py:60`). This adapter keeps no per-call state; `Guard` itself is
  the thread-safe/concurrency-safe surface.
* **Cross-process fan-out** over `ag2.network` is arbitrated at the hub
  (`ag2/network/hub/arbiter.py:245-324`), not here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional

from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent
from ag2.middleware import BaseMiddleware, Middleware
from ag2.tools import Toolkit
from ag2.tools.final.function_tool import FunctionTool
from ag2.utils import AGENT_CONTEXT_DEPENDENCY_KEY

from attenu_guard import Authority, AuthorityError, Guard
from attenu_guard.reasons import Disposition, ReasonCode

__all__ = [
    "Grant",
    "ToolPolicy",
    "GuardRegistry",
    "DelegationGuard",
    "guard_middleware",
    "guard_tool_hook",
    "guarded_tools",
    "guarded_agent",
]

ContextFn = Callable[[Mapping[str, Any]], Mapping[str, Any]]

_ON_DENY = ("result", "error")


def _check_on_deny(on_deny: str) -> str:
    if on_deny not in _ON_DENY:
        raise ValueError("on_deny must be 'result' or 'error'")
    return on_deny


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
    """Maps one AG2 tool onto the authority it consumes.

    `context` turns the tool's JSON arguments into the context dict that attenu-guard's
    ceilings evaluate (e.g. ``{"rows": 4200}``). If the tool is itself a delegation
    point — `task_<agent>` from `Agent.as_tool()`, `run_subtask`, a background or
    network `delegate` tool — set `delegates_to` to the child agent's registry name and
    `grant` to the authority it should get: the child `Guard` is minted after the check
    passes, before the sub-agent starts.
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
    """Holds the live delegation chain for a single AG2 run.

    AG2 agents are long-lived objects addressed by name, so the adapter keys guards by
    agent name. Fail-closed: an agent nobody has delegated to has no entry, and every
    tool call it makes is denied.
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
        """Cascade-revoke an agent's subtree. Its guard stays registered so later calls
        are denied with `revoked` rather than the fail-closed `no authority` reason."""
        return self.root.revoke(self.require(agent).node_id)

    def graph(self) -> dict:
        return self.root.graph()


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


class _Gate:
    """The policy decision, shared by the agent-level and tool-level hooks."""

    def __init__(
        self,
        registry: GuardRegistry,
        policies: Mapping[str, ToolPolicy],
        *,
        agent_name: Optional[str],
        on_deny: str,
    ) -> None:
        _check_on_deny(on_deny)
        self.registry = registry
        self.policies = dict(policies)
        self.agent_name = agent_name
        self.on_deny = on_deny

    def principal(self, context: Any) -> str:
        """The agent this call is running on.

        AG2 stamps the live `Agent` into the context dependencies at
        `ag2/agent.py:1491`, which is what makes a tool-level hook usable inside a
        `run_subtask` child whose constructor the caller never saw.
        """
        if self.agent_name is not None:
            return self.agent_name
        agent = None
        deps = getattr(context, "dependencies", None)
        if deps is not None:
            agent = deps.get(AGENT_CONTEXT_DEPENDENCY_KEY)
        return getattr(agent, "name", "<unknown>")

    def denial(self, event: ToolCallEvent, message: str):
        if self.on_deny == "error":
            return ToolErrorEvent.from_call(event, PermissionError(message))
        return ToolResultEvent.from_call(event, result=message)

    def authorize(self, event: ToolCallEvent, context: Any) -> Optional[Any]:
        """Return a denial event, or None when the call may proceed."""
        name = event.name
        principal = self.principal(context)
        policy = self.policies.get(name)

        if policy is None:
            # No authority is known for this tool: put it on the ledger as
            # `unresolved` when a Guard exists (the Decisions queue folds the ledger).
            g = self.registry.get(principal)
            msg = f"attenu-guard: no ToolPolicy declared for tool {name!r} (fail-closed)."
            if g is not None:
                g.record_denial(
                    ReasonCode.NO_AUTHORITY, msg, tool=name,
                    disposition=Disposition.UNRESOLVED,
                )
            return self.denial(event, msg)

        guard = self.registry.get(principal)
        if guard is None:
            return self.denial(
                event,
                f"attenu-guard: agent {principal!r} holds no delegated authority "
                f"(fail-closed).",
            )

        try:
            arguments = event.serialized_arguments
        except Exception:
            arguments = {}
        ctx = policy.context(arguments) if policy.context else {}
        decision = guard.check(
            policy.scope, context=ctx, tool=name, metered=policy.metered,
            disposition=policy.disposition,
        )
        if not decision:
            return self.denial(
                event,
                f"attenu-guard: {decision.explain()} "
                f"(agent={principal}, tool={name}, scope={policy.scope})",
            )

        # Allowed — and if this tool is itself a delegation point, mint the child now,
        # before the body starts the sub-agent.
        if policy.delegates_to and policy.grant:
            try:
                self.registry.delegate(principal, policy.delegates_to, policy.grant)
            except AuthorityError as exc:
                return self.denial(
                    event,
                    f"attenu-guard: cannot delegate to {policy.delegates_to!r}: {exc}",
                )
        return None

    async def run(self, call_next, event: ToolCallEvent, context: Any):
        try:
            denial = self.authorize(event, context)
        except Exception as exc:
            # Never fall through to the body because the check itself broke. AG2
            # converts a raise into a ToolErrorEvent anyway (`executor.py:116-122`),
            # so denying explicitly is the only fail-closed option.
            return self.denial(
                event, f"attenu-guard: authorization check failed: {exc!r}"
            )
        if denial is not None:
            # No `call_next` -> `FunctionTool.__call__` (`function_tool.py:132`) is
            # never reached, so the tool body provably does not run.
            return denial
        return await call_next(event, context)


class DelegationGuard(BaseMiddleware):
    """Agent middleware that runs `guard.check()` before every tool body.

    AG2 instantiates middleware per turn through a `MiddlewareFactory`
    (`ag2/middleware/base.py:29-75`), so build it with `guard_middleware(...)` rather
    than constructing it directly:

        agent = Agent(..., middleware=[guard_middleware(registry, POLICIES)])

    Install one per agent — agent middleware does not propagate into sub-agents (see
    the module docstring).
    """

    def __init__(
        self,
        event: Any,
        context: Any,
        *,
        registry: GuardRegistry,
        policies: Mapping[str, ToolPolicy],
        agent_name: Optional[str] = None,
        on_deny: str = "result",
    ) -> None:
        super().__init__(event, context)
        self._gate = _Gate(
            registry, policies, agent_name=agent_name, on_deny=on_deny
        )

    async def on_tool_execution(self, call_next, event, context):
        return await self._gate.run(call_next, event, context)


def guard_middleware(
    registry: GuardRegistry,
    policies: Mapping[str, ToolPolicy],
    *,
    agent_name: Optional[str] = None,
    on_deny: str = "result",
) -> Middleware:
    """The `Middleware` factory to pass to ``Agent(middleware=[...])``.

    AG2 instantiates the middleware once per turn, so `on_deny` is validated here —
    otherwise a typo would only surface on the first tool call of the first run.
    """
    _check_on_deny(on_deny)
    return Middleware(
        DelegationGuard,
        registry=registry,
        policies=policies,
        agent_name=agent_name,
        on_deny=on_deny,
    )


# ---------------------------------------------------------------------------
# tool-level hook — reaches children whose constructor you cannot touch
# ---------------------------------------------------------------------------


def guard_tool_hook(
    registry: GuardRegistry,
    policies: Mapping[str, ToolPolicy],
    *,
    agent_name: Optional[str] = None,
    on_deny: str = "result",
) -> Callable[..., Awaitable[Any]]:
    """The gate as a bare `ToolMiddleware` (`ag2/middleware/base.py:85`).

    Pass it wherever AG2 accepts per-tool middleware: ``@tool(middleware=[hook])``,
    ``Toolkit(*tools, middleware=[hook])``, ``FunctionTool.with_middleware(hook)`` or
    ``agent.as_tool(middleware=[hook])``.
    """
    gate = _Gate(
        registry, policies, agent_name=agent_name, on_deny=_check_on_deny(on_deny)
    )

    async def hook(call_next, event, context):
        return await gate.run(call_next, event, context)

    return hook


def guarded_tools(
    tools: Iterable[Any],
    registry: GuardRegistry,
    policies: Mapping[str, ToolPolicy],
    *,
    agent_name: Optional[str] = None,
    on_deny: str = "result",
) -> List[Any]:
    """Attach the same gate to each tool as *per-tool* middleware.

    Use this in addition to `guard_middleware` when an agent has
    ``tasks=TaskConfig(...)``: the auto-spawned child is constructed inside AG2
    (`ag2/agent.py:1463-1469`) with the parent's tool objects but none of its
    middleware, and `FunctionTool.ensure_tool` deep-copies each tool
    (`ag2/tools/final/function_tool.py:110-111`) — carrying its per-tool middleware
    into the child, where the agent-level hook cannot reach.

    Leave `agent_name` as None so the principal is read from the live context
    (`ag2/agent.py:1491`); the auto-spawned child's name is generated at runtime.

    `Toolkit` has no `with_middleware`; rebuild it as
    ``Toolkit(*members, middleware=[guard_tool_hook(...)])`` instead
    (`ag2/tools/final/toolkit.py:42-48` bakes toolkit middleware into every member).
    """
    hook = guard_tool_hook(
        registry, policies, agent_name=agent_name, on_deny=on_deny
    )

    out: List[Any] = []
    for t in tools:
        if isinstance(t, Toolkit):
            raise TypeError(
                "guarded_tools() cannot wrap a Toolkit in place; build it as "
                "Toolkit(*members, middleware=[guard_tool_hook(registry, policies)])"
            )
        tool_obj = t if isinstance(t, FunctionTool) else FunctionTool.ensure_tool(t)
        out.append(tool_obj.with_middleware(hook))
    return out


# ---------------------------------------------------------------------------
# convenience
# ---------------------------------------------------------------------------


def guarded_agent(
    name: str,
    prompt: str,
    *,
    tools: Iterable[Any],
    policies: Mapping[str, ToolPolicy],
    registry: GuardRegistry,
    on_deny: str = "result",
    also_guard_tools: bool = False,
    **agent_kwargs: Any,
):
    """Build an `ag2.Agent` whose every tool call is gated by attenu-guard.

    `also_guard_tools=True` additionally wraps each tool with `guarded_tools(...)`, so
    an agent configured with ``tasks=TaskConfig(...)`` still gates the calls its
    auto-spawned subtask makes.
    """
    from ag2 import Agent

    tool_list = list(tools)
    if also_guard_tools:
        tool_list = guarded_tools(
            tool_list, registry, policies, on_deny=on_deny
        )
    existing = list(agent_kwargs.pop("middleware", None) or [])
    mw = guard_middleware(
        registry, policies, agent_name=name, on_deny=on_deny
    )
    return Agent(
        name, prompt, tools=tool_list, middleware=[mw, *existing], **agent_kwargs
    )
