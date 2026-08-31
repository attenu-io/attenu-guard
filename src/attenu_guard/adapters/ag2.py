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

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`)
------------------------------------------------------------------------------
TWO MODES, gated by `strict_single_hook` (constructor/factory parameter, default `False`) --
see the "Round 2 correction" below for why this is no longer a bare, unconditional claim.

Pinned ag2 1.0.2's `FunctionTool.register()` (`function_tool.py`) folds an ORDERED LIST of
middleware into ONE composed chain around the tool body, at TWO INDEPENDENT points:

* Agent-level: `FunctionTool.register()`'s own `execution = _wrap_middleware(mw.
  on_tool_execution, execution)` loop iterates its `middleware` PARAMETER in that
  parameter's own order WITHOUT reversal -- but that parameter is NOT `Agent(middleware=
  [...])`'s list unchanged: `agent.py`'s own turn setup (`~agent.py:1362-1366`) builds it as
  `for m in reversed(tuple(chain(self._middleware, additional_middleware))):
  middleware_instances.append(mw)`, i.e. `Agent(middleware=[...])`'s user-facing list
  REVERSED, before ever reaching `register()`. The two reversals compose: at the
  USER-FACING `Agent(middleware=[...])` level, the FIRST-listed middleware ends up
  OUTERMOST (closest to the caller), the LAST-listed ends up innermost, closest to the
  tool-level chain below -- empirically confirmed end-to-end through a real `Agent`
  (`middleware=[A, B]` dispatches `A-enter, B-enter, body, B-exit, A-exit`), not inferred
  from either loop's shape in isolation -- a bare read of `register()`'s own loop alone
  (no `reversed()`) is NOT sufficient to conclude the user-facing ordering, since the
  caller upstream of it already reverses once.
* Tool-level: ``for hook in reversed(self._middleware): execution = _wrap_middleware(hook,
  execution)`` -- reversed, so the LAST-listed hook ends up INNERMOST, closest to the raw
  ``execution: ToolExecution = self``. This is what `FunctionTool.with_middleware(...)` /
  `Toolkit(middleware=[...])` -> `guard_tool_hook()` / `guarded_tools()` sits in.

Both are genuinely composable, not hypothetical: `ag2/middleware/builtin/` ships real
middleware meant to be stacked (`llm_retry.py`, `token_limiter.py`, `approval.py`,
`logging.py`, `metrics.py`, `telemetry.py`, `history_limiter.py`).

`_Gate.run` genuinely awaits whatever `call_next` it was handed, so `Capture.WRAPPER_ASYNC`
(when unlocked, see below) is never a fabricated pre-hook read -- but on either composition
point above, that `call_next` can be a SIBLING middleware's wrapper rather than the tool body,
if a sibling sits closer to `FunctionTool.__call__` at the SAME composition point:

* Sibling OUTER, short-circuits (returns its own event without calling its `call_next`): this
  gate is never reached -- nothing is recorded, nothing false.
* Sibling OUTER, reaches this gate, then RETRIES its own `call_next` (= this gate) more than
  once for what the model sees as one tool call: each invocation is independently authorized
  and independently recorded -- honest per-call, but the ledger cannot tell two such records
  apart from two genuinely separate tool calls.
* This gate OUTER, a sibling further in short-circuits the real body: this gate's own
  `call_next` still returns genuinely, so `BodyState` is recorded honestly for whatever it
  returned -- which is the sibling's fabricated event, not the real tool body's. `RETURNED` (or
  `RAISED`) is recorded for a body that never ran. Same shape as langchain's/agno's "guard
  outer, sibling short-circuits" residual.
* This gate OUTER, a sibling further in retries the real body: `call_next` returns once with
  the FINAL attempt's result -- one honest record, under-reporting that the body ran more than
  once.
* This gate INNER, closest to the body (or to a still-inner middleware): safe by construction
  at this composition point -- nothing between it and the body can fabricate what it observes.

`strict_single_hook=False` (the default): `capture`/`authorized_params` are never passed to
`guard.check()`. `Guard.check()` itself stamps `Capture.PRE_HOOK_ONLY` and `record_outcome()`
is never called -- authorization is enforced exactly as always, and nothing about the tool
body's actual completion is claimed, regardless of what any sibling middleware at either
composition point does.

`strict_single_hook=True`: an explicit caller attestation that this `DelegationGuard` /
`guard_tool_hook` instance is the ONLY middleware registered at ITS composition point
(agent-level or tool-level respectively) -- unlocks `Capture.WRAPPER_ASYNC` and
`record_outcome()`. `authorized_params`/`invoked_params` become one immutable snapshot
(`_freeze()`, never a copy protocol -- see its own docstring) of `event.serialized_arguments`,
taken at authorization time -- BEFORE `call_next` runs -- reused unchanged for both. This
package has no way to verify the attestation from inside `_Gate.run`: pinned ag2 exposes no
construction-time listing of a tool's or an agent's full middleware roster the way
`pydantic-ai`'s `for_agent()` does for batch 1's equivalent detect-and-refuse pattern -- so a
wrong attestation reproduces exactly the residuals enumerated above. Set it only when you
control every middleware registered at that composition point and can confirm, from your own
registration call, that this is the sole entry there.

`BodyState.RAISED`, genuinely (independent of `strict_single_hook`, once `record_outcome()`
actually runs under strict mode): pinned ag2 1.0.2's `FunctionTool.__call__` (`function_tool.py`)
catches every tool-body exception ITSELF and returns a `ToolErrorEvent` carrying the original
`.error: Exception` -- it never lets a generic exception propagate as a raised Python exception
through `call_next`'s own return (unlike CrewAI/AutoGen, which swallow the distinction into an
indistinguishable string; unlike Google ADK/pydantic-ai, which let a genuine exception
propagate). So `isinstance(result, ToolErrorEvent)` is the honest signal here, and
`error_code=type(result.error).__name__` is read straight off it, not inferred from a message.
`asyncio.CancelledError` (a `BaseException`, not caught by that `except Exception`) DOES
propagate through this wrapper's own `await`, and is `BodyState.ABANDONED`, still re-raised.

HONESTY NOTE: even under `strict_single_hook=True`, a `ToolErrorEvent` observed here could, in
principle, come from a DIFFERENT middleware positioned closer to the tool body at a DIFFERENT
composition point (e.g. this gate is the sole agent-level middleware, but a tool-level sibling
exists) returning its own error/denial rather than the tool body itself raising -- the
attestation is scoped to ONE composition point, not to "nothing else touches this tool
anywhere." A caller running this gate at one composition point while other middleware sits at
the other should treat `BodyState.RAISED` here as "this call did not complete cleanly through
MY composition point", not necessarily "the tool body itself threw".

ROUND 2 CORRECTION (Codex review, batch 2, finding 1): the previous revision of this section
claimed `Capture.WRAPPER_ASYNC` was unconditionally "a genuine observation with no cross-hook
correlation of any kind" for every `_Gate.run` call. That was wrong at BOTH of AG2's
composition points -- verified against pinned ag2 1.0.2 source as documented above -- because
`FunctionTool.register()` composes an ORDERED LIST of middleware, not a single fixed wrapper
around the body, at the agent level AND independently at the tool level. `strict_single_hook`
(default `False`) is the fix: genuine capture is now an explicit, scoped opt-in, not a default
claim this adapter could not actually back.

ROUND 3 CORRECTION (a parallel adversarial review, verified against pinned ag2 1.0.2 source):
the "Agent-level" bullet above previously claimed the LAST-listed `Agent(middleware=[...])`
entry ends up outermost -- backwards. That earlier claim was checked by testing
`FunctionTool.register()`'s own `_wrap_middleware` loop IN ISOLATION, against a hand-built
list, which never went through `agent.py`'s own turn setup at all -- and that setup reverses
`Agent(middleware=[...])`'s user list BEFORE it ever reaches `register()`
(`~agent.py:1362-1366`). Testing the internal primitive alone, with an arbitrarily-ordered
list I constructed myself, was not the same claim as testing what a caller actually observes
from `Agent(middleware=[...])` -- the fix above corrects that gap by tracing (and then
confirming end-to-end through a real `Agent`) the FULL path a caller's list travels, not just
the one function closest to the tool body.

On `schema_version=1` (the default), nothing in this whole section applies -- `capture`/
`adapter`/`authorized_params` are never passed to `check()`, and `record_outcome()` is never
called, regardless of `strict_single_hook`.

DELEGATION IS NOT A SEPARATE PATH HERE: unlike the other adapters in this package, AG2 has no
distinct delegation callback -- every hand-off IS itself a regular tool call (`Agent.as_tool()`,
`TaskConfig`, `background_agent_tool`, the network `delegate` tool), authorized through the SAME
`authorize()`/`run()` as any other tool via its own `ToolPolicy(scope=...)`. So a delegation
tool call gets exactly the same `capture`/`authorized_params`/`record_outcome()` treatment,
gated by the SAME `strict_single_hook`, as any other allowed call at that composition point: on
`strict_single_hook=True`, one `allow`/`outcome` pair, `Capture.WRAPPER_ASYNC`, observing the
delegating tool's OWN completion (which includes the sub-agent's whole run, since `call_next`
does not return until it does) -- subject to the same sibling-middleware residuals documented
above. On the `False` default, `Capture.PRE_HOOK_ONLY` and no `record_outcome()`, like any other
call. The ONLY thing execution binding does not touch, in either mode, is the internal
`self.registry.delegate(...)` -> `parent.delegate(...)` MINT step that runs after the scope
check passes, inside the SAME `authorize()` call -- that step never calls `guard.check()` a
second time, so it contributes no separate `Decision`/`call_id` of its own.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional

from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent
from ag2.middleware import BaseMiddleware, Middleware
from ag2.tools import Toolkit
from ag2.tools.final.function_tool import FunctionTool
from ag2.utils import AGENT_CONTEXT_DEPENDENCY_KEY

from attenu_guard import Authority, AuthorityError, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

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


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}._Gate.run",
}


def _is_deferred_result(result: Any) -> bool:
    if inspect.isgenerator(result) or inspect.isasyncgen(result):
        return True
    if isinstance(result, (asyncio.Future, concurrent.futures.Future)):
        return True
    return False


def _body_state_for(result: Any) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


from ._snapshot import freeze as _freeze


def _snapshot_params(arguments: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    `call_next` runs -- and reused as both `authorized_params` and `invoked_params`."""
    return _freeze(dict(arguments))


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
        strict_single_hook: bool = False,
    ) -> None:
        _check_on_deny(on_deny)
        self.registry = registry
        self.policies = dict(policies)
        self.agent_name = agent_name
        self.on_deny = on_deny
        self.strict_single_hook = strict_single_hook

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

    def authorize(
        self, event: ToolCallEvent, context: Any
    ) -> "tuple[Optional[Any], Optional[Guard], Any, Any]":
        """Return `(denial_event_or_None, guard, call_id_or_None, snapshot_or_None)`.

        The last two fields are set only for an ALLOWED, v2 `check()` -- what `run()` needs
        to close the outcome out afterward.
        """
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
            return self.denial(event, msg), None, None, None

        guard = self.registry.get(principal)
        if guard is None:
            return self.denial(
                event,
                f"attenu-guard: agent {principal!r} holds no delegated authority "
                f"(fail-closed).",
            ), None, None, None

        try:
            arguments = event.serialized_arguments
        except Exception:
            arguments = {}
        ctx = policy.context(arguments) if policy.context else {}
        v2 = self.strict_single_hook and guard.schema_version == 2
        snapshot = _snapshot_params(arguments) if v2 else None
        extra = (
            dict(capture=Capture.WRAPPER_ASYNC, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(
            policy.scope, context=ctx, tool=name, metered=policy.metered,
            disposition=policy.disposition, **extra,
        )
        if not decision:
            return self.denial(
                event,
                f"attenu-guard: {decision.explain()} "
                f"(agent={principal}, tool={name}, scope={policy.scope})",
            ), None, None, None

        # Allowed — and if this tool is itself a delegation point, mint the child now,
        # before the body starts the sub-agent.
        if policy.delegates_to and policy.grant:
            try:
                self.registry.delegate(principal, policy.delegates_to, policy.grant)
            except AuthorityError as exc:
                return self.denial(
                    event,
                    f"attenu-guard: cannot delegate to {policy.delegates_to!r}: {exc}",
                ), None, None, None
        return None, guard, (decision.call_id if v2 else None), snapshot

    async def run(self, call_next, event: ToolCallEvent, context: Any):
        try:
            denial, guard, call_id, snapshot = self.authorize(event, context)
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
        if call_id is None:
            return await call_next(event, context)

        start = time.monotonic()
        try:
            result = await call_next(event, context)
        except asyncio.CancelledError:
            # The wrapper stopped observing while the body may still run -- `abandoned`, not
            # `raised`; still re-raised so cancellation propagates normally.
            guard.record_outcome(call_id, BodyState.ABANDONED,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        if isinstance(result, ToolErrorEvent):
            # Genuinely observed: FunctionTool.__call__ catches every tool-body exception
            # itself and returns this typed event carrying the original .error -- see the
            # module docstring's "EXECUTION BINDING" for what this can and cannot tell apart.
            guard.record_outcome(call_id, BodyState.RAISED,
                                 error_code=type(result.error).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
        else:
            guard.record_outcome(call_id, _body_state_for(result),
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
        return result


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
        strict_single_hook: bool = False,
    ) -> None:
        super().__init__(event, context)
        self._gate = _Gate(
            registry, policies, agent_name=agent_name, on_deny=on_deny,
            strict_single_hook=strict_single_hook,
        )

    async def on_tool_execution(self, call_next, event, context):
        return await self._gate.run(call_next, event, context)


def guard_middleware(
    registry: GuardRegistry,
    policies: Mapping[str, ToolPolicy],
    *,
    agent_name: Optional[str] = None,
    on_deny: str = "result",
    strict_single_hook: bool = False,
) -> Middleware:
    """The `Middleware` factory to pass to ``Agent(middleware=[...])``.

    AG2 instantiates the middleware once per turn, so `on_deny` is validated here —
    otherwise a typo would only surface on the first tool call of the first run.

    strict_single_hook: execution-binding (0.9.0) mode switch -- see the module docstring's
                       "EXECUTION BINDING ... TWO MODES". `False` (default): every
                       `guard.check()` call is left to the Guard's own honest
                       `Capture.PRE_HOOK_ONLY` default; no outcome is ever recorded. `True`:
                       an explicit attestation that this middleware is the ONLY entry in
                       `Agent(middleware=[...])` for the tools it guards, AND that none of
                       those tools carry their own tool-level `with_middleware(...)` chain --
                       this file cannot verify either half itself.
    """
    _check_on_deny(on_deny)
    return Middleware(
        DelegationGuard,
        registry=registry,
        policies=policies,
        agent_name=agent_name,
        on_deny=on_deny,
        strict_single_hook=strict_single_hook,
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
    strict_single_hook: bool = False,
) -> Callable[..., Awaitable[Any]]:
    """The gate as a bare `ToolMiddleware` (`ag2/middleware/base.py:85`).

    Pass it wherever AG2 accepts per-tool middleware: ``@tool(middleware=[hook])``,
    ``Toolkit(*tools, middleware=[hook])``, ``FunctionTool.with_middleware(hook)`` or
    ``agent.as_tool(middleware=[hook])``.

    strict_single_hook: see `guard_middleware`'s own docstring -- the same attestation, scoped
                       to this tool's own middleware chain (`with_middleware(...)`) instead of
                       the agent-level one.
    """
    gate = _Gate(
        registry, policies, agent_name=agent_name, on_deny=_check_on_deny(on_deny),
        strict_single_hook=strict_single_hook,
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
    strict_single_hook: bool = False,
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

    strict_single_hook: forwarded to `guard_tool_hook` unchanged -- see the module
                       docstring's "EXECUTION BINDING ... TWO MODES". `False` (default) is
                       safe regardless of what other tool-level middleware these tools carry;
                       `True` attests this is the ONLY tool-level middleware on each tool.
    """
    hook = guard_tool_hook(
        registry, policies, agent_name=agent_name, on_deny=on_deny,
        strict_single_hook=strict_single_hook,
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
