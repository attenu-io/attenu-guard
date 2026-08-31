"""attenu-guard × Microsoft Agent Framework (`agent-framework` 1.15.x).

Tested against `agent-framework` / `agent-framework-core` **1.15.0** on Python 3.12.
Install the framework with ``pip install 'attenu-guard[agent-framework]'``.

HOOK POINTS USED
----------------
1. **Tool invocation — `DelegationGuard(FunctionMiddleware)`.**
   Agent Framework's function seam is `FunctionMiddleware.process(context, call_next)`
   (`agent_framework/_middleware.py:594`, abstract `process` at `:642`). The pipeline
   that drives it is `FunctionMiddlewarePipeline.execute`
   (`agent_framework/_middleware.py:1126-1163`): the tool body is reachable **only**
   through `final_wrapper` (`:1146-1149`), which is only ever reached by the innermost
   `call_next()`. Returning from `process` without awaiting `call_next()` therefore
   provably prevents the body from running, and `context.result` (`:1163`) is what the
   model sees instead. `final_wrapper` calls `final_function_handler`
   (`agent_framework/_tools.py:1596-1601`), the single path to `FunctionTool.invoke`.

   One registration covers both loops: the non-streaming
   (`_tools.py:3174`) and streaming (`_tools.py:3337`) function-calling loops share
   the same `execute_function_calls` partial, built once at `_tools.py:3628-3634`
   over the same pipeline.

2. **Delegation — the same middleware, on the delegating tool.**
   Agent Framework has no separate delegation callback. Every in-process handover is
   shaped as a tool call:

   * `Agent.as_tool(...)` (`agent_framework/_agents.py:608`) returns an ordinary
     `FunctionTool` (`:718-724`) whose body starts the sub-agent at
     `self.run(...)` (`:694`) — so the gate runs before the child ever starts.
   * Handoff orchestration mints one `handoff_to_<target_id>` `FunctionTool` per edge
     (`agent_framework_orchestrations/_handoff.py:124-126`, `:335-350`). Its own
     `_AutoHandoffMiddleware` is *appended* (`_handoff.py:269`), so a `DelegationGuard`
     registered on the agent runs first and can refuse the transfer.

   Set `ToolPolicy(delegates_to=..., grant=...)` on those tools: the child `Guard` is
   minted with `parent.delegate(...)` after the check passes and before the body runs.

WHO IS THE PARENT
-----------------
`GuardRegistry` keys guards by agent name, and each `DelegationGuard` is constructed
with the name of the agent it is installed on — so the parent of a delegation is the
agent whose middleware saw the delegating tool call, never "the last agent to speak".

**Middleware does not propagate into sub-agents.** `as_tool` calls `self.run(...)` on
the *child* object (`_agents.py:694`), which runs the child's own middleware list;
workflow participants (`agent_framework/_workflows/_agent_executor.py:425`, `:481`)
likewise run whatever middleware their own `Agent` carries. Install a `DelegationGuard`
on **every** agent in the graph. `guarded_agent()` is the one-liner for that, and
`GuardRegistry` is fail-closed: an agent nobody delegated to holds no `Guard`, so every
tool it tries is denied.

DENIAL SHAPE
------------
`on_deny="result"` (default) sets `context.result` to a denial string and returns
without `call_next()`; the framework wraps it as a `function_result`
(`_tools.py:1616`) the model can react to. `on_deny="failure"` raises
`MiddlewareFailure` (`_middleware.py:85`), the loop's documented fail-closed escape:
the batch is cancelled, no further tool call starts, and the error reaches the caller
of `Agent.run`.

A plain exception is **not** a denial here — `_tools.py:1642-1643` converts any
ordinary exception into a tool-error result and the loop keeps running (fail-open).
This adapter therefore never lets its own bookkeeping raise: an unexpected error inside
the check is re-raised as `MiddlewareFailure` (`_tools.py:1635-1641` propagates it).

USAGE
-----
Build one `GuardRegistry` per run, seeded with the root `Guard`. Give every agent a
`DelegationGuard` carrying a ``{tool_name: ToolPolicy}`` map that says which scope and
context each tool consumes, and mark the delegating tools with
`delegates_to` / `grant`. Both fail closed: an agent with no delegated `Guard`, and a
tool with no `ToolPolicy`, are denied. attenu-guard deliberately does not decide *what*
authority a task needs — you write the `Grant`.

    registry = GuardRegistry(root_guard, "orchestrator")
    worker = guarded_agent(client=..., name="worker", tools=[...],
                           policies=WORKER_POLICIES, registry=registry)
    boss = guarded_agent(client=..., name="orchestrator",
                         tools=[worker.as_tool(name="worker", description="...")],
                         policies={"worker": ToolPolicy("crm.read",
                                                        delegates_to="worker",
                                                        grant=Grant(...))},
                         registry=registry)

KNOWN GAPS (things this seam cannot see)
----------------------------------------
* **Hosted / service-side tools** (hosted web search, code interpreter, hosted MCP)
  arrive as `informational_only` function calls and are filtered out before the seam
  (`_tools.py:1654-1655`); they execute at the model provider. They cannot be gated
  here — do not attach them to a guarded agent.
* **`Agent.as_mcp_server()`** invokes the agent tool directly
  (`_agents.py:1745`: `await agent_tool.invoke(...)`), bypassing the function
  pipeline. Guard the exposed agent's own tools instead of relying on the delegation
  gate.
* **Middleware ordering is trust ordering**: client-level function middleware runs
  outside agent-level (`_tools.py:3165`), so anything registered ahead of this guard
  can substitute a result before the check runs -- and `FunctionMiddlewarePipeline.execute`
  (`_middleware.py:1126-1163`) is a genuinely composable chain (verified against pinned
  1.15.x: index 0 runs first/outermost), so a sibling registered AFTER this guard, at
  either the agent or the client level, can equally short-circuit or repeat the real tool
  body underneath this guard's own `call_next()` -- see "EXECUTION BINDING ... TWO MODES"
  below for what that means for `record_outcome()`.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`)
------------------------------------------------------------------------------
TWO MODES, gated by `strict_single_hook` (constructor/factory parameter, default `False`) --
see the "Round 2 correction" below for why this is no longer a bare, unconditional claim.

Pinned 1.15.x's `FunctionMiddlewarePipeline.execute` (`_middleware.py:1126-1163`) is a
genuinely composable chain: `self._middleware[index].process(context,
create_next_handler(index + 1))` -- index 0 runs FIRST, and is therefore OUTERMOST (its
`call_next()` invokes index 1's `process`, and so on down to `final_wrapper`). `Agent.middleware`
(`_agents.py:468`) is a plain mutable `list` attribute, not a fixed roster resolved once at
construction -- a caller can append or insert into it any time after `Agent(...)` returns, and
"client-level function middleware runs outside agent-level" (`_tools.py:3165`, the module
docstring's own "KNOWN GAPS") is a SEPARATE, even-less-visible composition point this class
cannot see at all, from either constructor.

`DelegationGuard.process` genuinely awaits whatever `call_next` it was handed, so
`Capture.WRAPPER_ASYNC` (when unlocked, see below) is never a fabricated pre-hook read -- but a
sibling positioned closer to `final_wrapper` in the SAME pipeline (agent-level or client-level)
can still stand between this guard's own `call_next()` and the real tool body:

* Sibling INNER (later in the pipeline), short-circuits (sets `context.result` without calling
  its own `call_next()`): this guard's `call_next()` still returns genuinely, so
  `_body_state_for(context.result)` is recorded honestly for whatever the sibling put there --
  `RETURNED` for a body that never ran.
* Sibling INNER, calls its own `call_next()` more than once (a retry) for what the model sees
  as one tool call: this guard's `call_next()` is awaited once and returns once with the final
  attempt's `context.result` -- one honest record, under-reporting that the body ran more than
  once.
* Sibling OUTER (earlier in the pipeline, ahead of this guard -- e.g. `guarded_agent()` was not
  used, or client-level middleware), short-circuits before this guard is ever reached: nothing
  is recorded, nothing false -- but note this is ALSO the pre-existing authorization-skip gap
  the module docstring's "KNOWN GAPS" already documents; `guarded_agent()` puts the guard first
  specifically to avoid it for the agent-level list.
* This guard INNER, closest to `final_wrapper` (no sibling after it anywhere in either
  composition point): safe by construction -- nothing between it and the real tool body can
  fabricate what it observes.

`strict_single_hook=False` (the default): `capture`/`authorized_params` are never passed to
`guard.check()`. `Guard.check()` itself stamps `Capture.PRE_HOOK_ONLY` and `record_outcome()`
is never called -- authorization is enforced exactly as always (this guard still runs first
when built via `guarded_agent()`, still denies before `call_next()`), and nothing about the
tool body's actual completion is claimed, regardless of what any sibling middleware at either
composition point does, now or later.

`strict_single_hook=True`: an explicit caller attestation that this `DelegationGuard` instance
is the ONLY function middleware that will ever run on this agent -- across `Agent.middleware`
AND the client's own middleware list, for the life of the agent, not merely at construction --
unlocks `Capture.WRAPPER_ASYNC` and `record_outcome()`. `authorized_params`/`invoked_params`
become one immutable snapshot (`_freeze()`, never a copy protocol -- see its own docstring) of
the tool call's arguments, taken at authorization time -- BEFORE `call_next()` runs -- reused
unchanged for both. This package has no way to verify the attestation from inside `process()`:
`Agent.middleware`'s mutability and the invisible client-level list mean there is no
construction-time roster to check the way `pydantic-ai`'s `for_agent()` offers for batch 1's
equivalent detect-and-refuse pattern, so a wrong attestation reproduces exactly the residuals
enumerated above. Set it only when you control every function middleware on this agent AND its
client, for the agent's entire lifetime.

`BodyState.RAISED`, genuinely (independent of `strict_single_hook`, once `record_outcome()`
actually runs under strict mode): verified directly against pinned 1.15.x source
(`_tools.py`/`_middleware.py`) that a tool-body exception propagates as a REAL raised Python
exception all the way through `FunctionMiddlewarePipeline.execute`'s `final_wrapper`
(`context.result = await context.result`) and every enclosing `middleware.process`'s own
`await call_next()`, including this one -- the `except Exception` that finally converts it into
a tool-error result (`_tools.py:1642-1643`, cited in the module docstring's "DENIAL SHAPE") sits
ABOVE the whole middleware pipeline, not inside `final_function_handler`, so this wrapper's own
`try`/`except` around `await call_next()` genuinely observes the raise before that outer catch
ever runs. `asyncio.CancelledError` (a `BaseException`) is `BodyState.ABANDONED`, still
re-raised. On a clean return, `context.result` holds the tool's own return value directly (no
wrapping), so `_body_state_for(context.result)` reads it honestly.

ROUND 2 CORRECTION (Codex review, batch 2, finding 1): the previous revision of this section
claimed `Capture.WRAPPER_ASYNC` was unconditionally "a genuine observation with no cross-hook
correlation of any kind" for every `process()` call. That was wrong -- verified against pinned
1.15.x source as documented above -- because `FunctionMiddlewarePipeline.execute` composes an
ORDERED, mutable LIST of middleware, not a single fixed wrapper around the body, and
`Agent.middleware` stays mutable for the agent's whole lifetime. `strict_single_hook` (default
`False`) is the fix: genuine capture is now an explicit, scoped opt-in, not a default claim
this adapter could not actually back.

On `schema_version=1` (the default), nothing in this whole section applies. Delegation is not a
separate path here, same as `adapters.ag2`: Agent Framework has no distinct delegation callback
-- every hand-off (`Agent.as_tool()`, a `handoff_to_<target>` tool) is a regular tool call
authorized through this SAME `process()`/`_authorize()` via its own `ToolPolicy(scope=...)`, so
a delegation tool call gets exactly the same `capture`/`authorized_params`/`record_outcome()`
treatment, gated by the SAME `strict_single_hook`, as any other allowed call. Only the internal
`self._registry.delegate(...)` mint step (inside `_authorize`, after the scope check passes)
adds no second, separate check/outcome of its own, in either mode.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from agent_framework import (
    Agent,
    FunctionInvocationContext,
    FunctionMiddleware,
    MiddlewareFailure,
)

from attenu_guard import Authority, AuthorityDenied, AuthorityError, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

__all__ = [
    "Grant",
    "ToolPolicy",
    "GuardRegistry",
    "DelegationGuard",
    "guarded_agent",
    "handoff_tool_name",
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
    """Maps one Agent Framework tool onto the authority it consumes.

    `context` turns the tool's validated arguments into the context dict that
    attenu-guard's ceilings evaluate (e.g. ``{"rows": 4200}``). If the tool is itself a
    delegation point — an `Agent.as_tool(...)` wrapper or a `handoff_to_<target>` tool
    — set `delegates_to` to the child agent's registry name and `grant` to the
    authority it should get: the child `Guard` is minted after the check passes and
    before the tool body starts the sub-agent (`_agents.py:694`).
    """

    scope: str
    context: Optional[ContextFn] = None
    metered: bool = False
    delegates_to: Optional[str] = None
    grant: Optional[Grant] = None
    disposition: Optional[str] = None     # see attenu_guard.Disposition


def handoff_tool_name(target_id: str) -> str:
    """The tool name handoff orchestration mints for an edge to `target_id`.

    Mirrors `agent_framework_orchestrations._handoff.get_handoff_tool_name`
    (`_handoff.py:124-126`) so a policy map can be written without importing the
    orchestrations package.
    """
    return f"handoff_to_{target_id}"


# ---------------------------------------------------------------------------
# registry — agent name -> Guard, for one run
# ---------------------------------------------------------------------------


class GuardRegistry:
    """Holds the live delegation chain for a single Agent Framework run.

    Agent Framework agents are long-lived objects addressed by name, so the adapter
    keys guards by agent name. Fail-closed: an agent nobody has delegated to has no
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
        """Cascade-revoke an agent's subtree. Its guard stays registered so later
        calls are denied with `revoked` rather than the fail-closed `no authority`
        reason."""
        return self.root.revoke(self.require(agent).node_id)

    def graph(self) -> dict:
        return self.root.graph()


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.DelegationGuard.process",
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
    `call_next()` runs -- and reused as both `authorized_params` and `invoked_params`."""
    return _freeze(dict(arguments))


def _as_mapping(arguments: Any) -> Mapping[str, Any]:
    """Normalise `FunctionInvocationContext.arguments`.

    It is typed `BaseModel | Mapping[str, Any]` (`_middleware.py:324`); the
    function-calling loop passes a dict, but a tool declared with an `input_model`
    can hand over the validated pydantic model.
    """
    if isinstance(arguments, Mapping):
        return arguments
    dump = getattr(arguments, "model_dump", None)
    if callable(dump):
        try:
            return dump()
        except Exception:                                    # pragma: no cover
            return {}
    return getattr(arguments, "__dict__", {}) or {}


class DelegationGuard(FunctionMiddleware):
    """Function middleware that runs `guard.check()` before every tool body.

    Install one per agent — middleware does not propagate into sub-agents (see the
    module docstring). Register it **first** in ``Agent(middleware=[...])``: middleware
    ahead of it can substitute a result and skip the check entirely
    (`_tools.py:3165`, `_middleware.py:1153-1155`).

    strict_single_hook: see the module docstring's "EXECUTION BINDING ... TWO MODES" --
                       `False` (default) never claims genuine execution capture, safe no
                       matter what else is on `Agent(middleware=[...])` or the client's own
                       middleware list, now OR later (`Agent.middleware` is a plain mutable
                       list -- nothing this class sees at construction time is a durable
                       guarantee). `True` attests this is the ONLY function middleware that
                       will ever run on this agent, for the life of the agent.
    """

    def __init__(
        self,
        *,
        agent_name: str,
        registry: GuardRegistry,
        policies: Mapping[str, ToolPolicy],
        on_deny: str = "result",
        strict_single_hook: bool = False,
    ) -> None:
        if on_deny not in ("result", "failure"):
            raise ValueError("on_deny must be 'result' or 'failure'")
        self._agent_name = agent_name
        self._registry = registry
        self._policies = dict(policies)
        self._on_deny = on_deny
        self._strict_single_hook = strict_single_hook

    # -- the gate ----------------------------------------------------------
    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        try:
            denial, guard, call_id, snapshot = self._authorize(
                context.function.name, _as_mapping(context.arguments)
            )
        except MiddlewareFailure:
            raise
        except Exception as exc:                             # pragma: no cover
            # The enforcement layer itself failed. A plain exception here would be
            # converted into a tool-error result and the loop would keep running
            # (`_tools.py:1642-1643`) — fail-open. Abort instead.
            raise MiddlewareFailure(
                f"attenu-guard: authorization check failed for "
                f"{context.function.name!r}"
            ) from exc

        if denial is not None:
            # No `call_next()` -> `final_wrapper` (`_middleware.py:1146`) is never
            # reached, so the tool body provably does not run.
            context.result = denial
            return
        if call_id is None:
            await call_next()
            return

        start = time.monotonic()
        try:
            await call_next()
        except asyncio.CancelledError:
            # The wrapper stopped observing while the body may still run -- `abandoned`, not
            # `raised`; still re-raised so cancellation propagates normally.
            guard.record_outcome(call_id, BodyState.ABANDONED,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        except Exception as exc:
            # Genuinely observed: verified against pinned 1.15.x source that a tool-body
            # exception propagates as a real raised exception all the way through
            # final_wrapper and every enclosing process()'s own call_next() -- see the
            # module docstring's "EXECUTION BINDING". The outer conversion into a tool-
            # error result happens ABOVE the whole middleware pipeline, not here.
            guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        guard.record_outcome(call_id, _body_state_for(context.result),
                             invoked_params=snapshot, duration_ms=_elapsed_ms(start))

    def _authorize(
        self, name: str, arguments: Mapping[str, Any]
    ) -> "tuple[Optional[str], Optional[Guard], Any, Any]":
        """Return `(denial_message_or_None, guard, call_id_or_None, snapshot_or_None)`.

        Raises `MiddlewareFailure` instead of returning when ``on_deny="failure"``. The
        last two fields are set only for an ALLOWED, v2 `check()` -- what `process()`
        needs to close the outcome out afterward.
        """
        policy = self._policies.get(name)
        if policy is None:
            # No authority is known for this tool: put it on the ledger as
            # `unresolved` when a Guard exists (the Decisions queue folds the ledger).
            g = self._registry.get(self._agent_name)
            msg = f"attenu-guard: no ToolPolicy declared for tool {name!r} (fail-closed)."
            decision = (
                g.record_denial(
                    ReasonCode.NO_AUTHORITY, msg, tool=name,
                    disposition=Disposition.UNRESOLVED,
                )
                if g is not None
                else None
            )
            return self._deny(msg, decision=decision), None, None, None

        guard = self._registry.get(self._agent_name)
        if guard is None:
            return self._deny(
                f"attenu-guard: agent {self._agent_name!r} holds no delegated "
                f"authority (fail-closed).",
                decision=None,
            ), None, None, None

        v2 = self._strict_single_hook and guard.schema_version == 2
        snapshot = _snapshot_params(arguments) if v2 else None
        extra = (
            dict(capture=Capture.WRAPPER_ASYNC, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        ctx = policy.context(arguments) if policy.context else {}
        decision = guard.check(
            policy.scope, context=ctx, tool=name, metered=policy.metered,
            disposition=policy.disposition, **extra,
        )
        if not decision:
            return self._deny(
                f"attenu-guard: {decision.explain()} "
                f"(agent={self._agent_name}, tool={name}, scope={policy.scope})",
                decision=decision,
            ), None, None, None

        # Allowed — and if this tool is itself a delegation point, mint the child now,
        # before the body starts the sub-agent (`_agents.py:694`).
        if policy.delegates_to and policy.grant:
            try:
                self._registry.delegate(
                    self._agent_name, policy.delegates_to, policy.grant
                )
            except AuthorityError as exc:
                return self._deny(
                    f"attenu-guard: cannot delegate to {policy.delegates_to!r}: {exc}",
                    decision=None,
                ), None, None, None
        return None, guard, (decision.call_id if v2 else None), snapshot

    def _deny(self, message: str, *, decision) -> str:
        if self._on_deny == "failure":
            if decision is not None:
                raise MiddlewareFailure(message) from AuthorityDenied(decision)
            raise MiddlewareFailure(message)
        return message


# ---------------------------------------------------------------------------
# convenience
# ---------------------------------------------------------------------------


def guarded_agent(
    *,
    client,
    name: str,
    tools,
    policies: Mapping[str, ToolPolicy],
    registry: GuardRegistry,
    on_deny: str = "result",
    strict_single_hook: bool = False,
    **agent_kwargs: Any,
) -> Agent:
    """Build an `Agent` whose every tool call is gated by attenu-guard.

    The guard is placed first in the middleware list so nothing can substitute a
    result ahead of the check (`_middleware.py:1153-1155`).

    strict_single_hook: forwarded to `DelegationGuard` unchanged -- see the module
                       docstring's "EXECUTION BINDING ... TWO MODES". Passing `True` here
                       attests to `existing` being empty for the life of this agent, not
                       merely at this call -- this function cannot enforce that after
                       `Agent.middleware` (a plain mutable list) is handed back to the
                       caller.
    """
    existing = list(agent_kwargs.pop("middleware", None) or [])
    guard = DelegationGuard(
        agent_name=name, registry=registry, policies=policies, on_deny=on_deny,
        strict_single_hook=strict_single_hook,
    )
    return Agent(
        client=client, name=name, tools=tools, middleware=[guard, *existing],
        **agent_kwargs,
    )
