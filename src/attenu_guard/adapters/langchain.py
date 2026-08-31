"""attenu_guard.adapters.langchain — attenu-guard × LangGraph 1.x / LangChain 1.x / deepagents.

A thin, paste-into-your-project adapter that enforces monotonic authority
attenuation across a LangGraph agent's tool calls and sub-agent delegations.

Hook points used (all official framework APIs — no monkeypatching)
------------------------------------------------------------------
* TOOL INVOCATION — `ToolNode(tools, wrap_tool_call=...)`
  (`langgraph/prebuilt/tool_node.py`, the `wrap_tool_call` parameter) and the
  identical `AgentMiddleware.wrap_tool_call` / `awrap_tool_call` hook used by
  `langchain.agents.create_agent`. Both receive a `ToolCallRequest` and an
  `execute`/`handler` callable; NOT calling that callable short-circuits the
  tool, so `Guard.check()` runs strictly *before* the tool body.

* CHILD CREATION / DELEGATION — the same hook, filtered on the framework's
  delegation tool. In `deepagents` an orchestrator spawns a sub-agent by
  calling the built-in `task(description, subagent_type)` tool, so
  intercepting that one tool call *is* intercepting the delegation. The
  adapter mints the child with `parent_guard.delegate(...)` and installs it
  as the active Guard (a `ContextVar`) for the duration of the sub-agent's
  run — LangGraph propagates context into node execution via
  `contextvars.copy_context()`, so the sub-agent's own tool calls see it.

Usage
-----
Declare, once, which scope each tool needs and which `Authority` each
sub-agent may hold; then install one middleware object everywhere::

    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

    guarded = GuardedDelegation(
        root,
        tools={
            "crm_query":  ToolPolicy("crm.read",   lambda a: {"rows": a["rows"]}),
            "crm_export": ToolPolicy("crm.export", lambda a: {"egress": "any"}),
        },
        subagents={"summarizer": Authority(
            scopes={"crm.read"},
            ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)},
    )

    # (a) plain LangGraph
    graph.add_node("tools", ToolNode(tools, wrap_tool_call=guarded.wrap_tool_call))
    # (b) LangChain create_agent / deepagents — install on the orchestrator
    #     AND on every sub-agent spec's `middleware` list
    agent = create_deep_agent(model=..., subagents=[...],
                              middleware=[guarded.middleware()])

The policy map is shared by every agent on purpose: the *map* says which
scope a tool needs, the *Guard* says whether this particular agent still
holds it. Same tools, attenuated authority.

Denial behaviour
----------------
`on_deny="tool_error"` (default) returns a `ToolMessage(status="error")`
carrying `Decision.explain()`. LangGraph/LangChain handle that gracefully:
the denial goes back to the model as a normal tool result, the agent loop
keeps running, and the model can pick a different action. That is the right
default for an agent that should recover.

`on_deny="raise"` raises `attenu_guard.AuthorityDenied`, which propagates
straight out of `graph.invoke()` and aborts the run. Use that where a denial
means "stop everything" rather than "try something else".

Either way the tool body never executes.

Execution binding (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`): this adapter
calls the tool body itself (`handler(request)`/`await handler(request)`), exactly like
`adapters.langgraph`'s reference wiring, so it genuinely observes completion --
`Capture.WRAPPER_SYNC` from `wrap_tool_call`, `Capture.WRAPPER_ASYNC` from `awrap_tool_call`.
`authorized_params`/`invoked_params` are both taken from ONE immutable snapshot of the tool
call's `args` (`_freeze()`, never a copy protocol -- see its own docstring), taken BEFORE the
handler runs and reused unchanged for both, so a handler that mutates its own inputs in place
cannot make this adapter claim it observed two different values for one call. `duration_ms`
covers the wrapper's own await/call of `handler`, not the tool's internal-only work outside
that boundary (there is none here -- `handler` IS the tool body). A delegation tool call
(`_gate_delegation`) mints the child via `guard.delegate()`, which never calls `guard.check()`
in the first place -- there is no `Decision`/`call_id` to bind an outcome to, so a delegation
call is unaffected by any of this and stays exactly as before. On `schema_version=1` (the
default), nothing here changes at all -- `capture`/`adapter`/`authorized_params` are never
passed to `check()`, and `record_outcome()` is never called.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import inspect
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping, Optional

from langchain_core.messages import ToolMessage

from attenu_guard import (
    Authority, AuthorityDenied, AuthorityError, Decision, Guard, Reason, __version__,
)
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

__all__ = [
    "ToolPolicy",
    "GuardedDelegation",
    "current_guard",
    "use_guard",
]


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


def _freeze(value: Any) -> Any:
    """A genuinely immutable, fully decoupled rebuild of `value` -- NEVER calls a copy protocol
    (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back itself (or
    another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is independent
    of the live object graph, so a "snapshot" built that way can silently change out from under
    the commitment when the tool body (or LangChain itself) later mutates the original in place.
    Containers are always rebuilt from scratch as fresh builtins (dict/list, recursively); only
    already-immutable leaf types (`str`/`int`/`float`/`bool`/`None`/`bytes`) are kept as-is --
    sharing an immutable value carries no aliasing risk regardless of what protocol it does or
    does not implement. Everything else becomes its `repr()` -- a brand-new, independent string
    -- rather than being handed through any copy protocol that could return a live reference."""
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if isinstance(value, Mapping):
        return {k: _freeze(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_freeze(v) for v in value]
    try:
        return repr(value)
    except Exception:
        return f"<unrepresentable {type(value).__name__}>"


def _snapshot_params(args: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    the handler runs -- and reused for both `authorized_params` and `invoked_params`."""
    return _freeze(dict(args))


def _adapter_info(hook: str) -> dict:
    return {"module": __name__, "version": __version__, "hook_path": f"{__name__}.{hook}"}


# ---------------------------------------------------------------------------
# The active Guard. LangGraph runs nodes through `contextvars.copy_context()`
# (langgraph/pregel/_executor.py:64, langgraph/_internal/_runnable.py:135), so
# a Guard installed here by the parent's delegation hook is visible to the
# sub-agent graph invoked inside it — and never leaks back out or sideways.
# ---------------------------------------------------------------------------
_ACTIVE_GUARD: contextvars.ContextVar[Optional[Guard]] = contextvars.ContextVar(
    "attenu_guard_active", default=None
)


def current_guard() -> Optional[Guard]:
    """The Guard currently in force, or None outside any delegation."""
    return _ACTIVE_GUARD.get()


@contextmanager
def use_guard(guard: Guard):
    """Make `guard` the active Guard for the duration of the block."""
    token = _ACTIVE_GUARD.set(guard)
    try:
        yield guard
    finally:
        _ACTIVE_GUARD.reset(token)


@dataclass(frozen=True)
class ToolPolicy:
    """What one tool needs in order to run.

    scope:   the attenu-guard scope, e.g. `"crm.read"`.
    context: optional callable mapping the tool call's `args` dict to the
             context bag ceilings are evaluated against, e.g.
             `lambda args: {"rows": args["rows"]}`. Omit for a scope-only check.
    metered: forwarded to `Guard.check(metered=...)` — set True for calls that
             consume a metered budget, so `strict_metering` guards can refuse
             an undeclared quantity instead of treating it as free.
    disposition: optional `Disposition` the authority source knows about this
             tool (`held_pending_grant` · `withheld_tier2` · `unresolved`);
             recorded on a `deny` so "held" never reads as "denied". Omit for a
             grantable tool (a deny is then `out_of_authority`).
    """

    scope: str
    context: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None
    metered: bool = False
    disposition: Optional[str] = None

    def context_for(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.context(args) if self.context else {}


class GuardedDelegation:
    """Binds a attenu-guard chain to a LangGraph/LangChain agent tree.

    Parameters
    ----------
    root : Guard
        The Guard this agent runs under. Sub-agents are delegated from the
        Guard that is active when their delegation tool is called, so a
        grandchild is attenuated from the child, not from the root.
    tools : Mapping[str, ToolPolicy]
        Tool name -> policy. **Fail-closed**: a tool call with no entry is
        denied (`allow_unlisted=True` inverts that, for incremental rollout).
    subagents : Mapping[str, Authority] | None
        Sub-agent name -> the `Authority` it may *request*. The granted
        authority is always `parent.meet(request)`, so listing a wide
        Authority here can never widen a narrow parent. A sub-agent with no
        entry cannot be spawned at all.
    delegation_tool : str
        The framework's spawn tool. `"task"` for deepagents.
    subagent_arg / task_arg : str
        Which of that tool's arguments name the sub-agent and describe the
        task. deepagents uses `subagent_type` / `description`.
    on_deny : {"tool_error", "raise"}
        See the module docstring.
    """

    def __init__(
        self,
        root: Guard,
        *,
        tools: Mapping[str, ToolPolicy],
        subagents: Optional[Mapping[str, Authority]] = None,
        delegation_tool: str = "task",
        subagent_arg: str = "subagent_type",
        task_arg: str = "description",
        on_deny: str = "tool_error",
        allow_unlisted: bool = False,
        default_policy: Optional[Callable[[str], ToolPolicy]] = None,
        default_subagent_authority: Optional[Callable[[str], Authority]] = None,
    ) -> None:
        """
        default_policy / default_subagent_authority — OBSERVE-MODE hooks for
        sampling (attenu-derive): called with the tool name / sub-agent name
        when no policy / Authority was declared, and their result is used as if
        it had been declared — so every call is authorized-and-RECORDED on the
        audit log with the generated scope/context, instead of denied
        (the fail-closed default) or silently passed through (`allow_unlisted`).
        `default_policy` takes precedence over `allow_unlisted`.
        """
        if on_deny not in ("tool_error", "raise"):
            raise ValueError("on_deny must be 'tool_error' or 'raise'")
        self.root = root
        self.tools = dict(tools)
        self.subagents = dict(subagents or {})
        self.delegation_tool = delegation_tool
        self.subagent_arg = subagent_arg
        self.task_arg = task_arg
        self.on_deny = on_deny
        self.allow_unlisted = allow_unlisted
        self.default_policy = default_policy
        self.default_subagent_authority = default_subagent_authority
        self.children: MutableMapping[str, Guard] = {}
        self._middleware = None

    # -- introspection ------------------------------------------------------
    def active_guard(self) -> Guard:
        """The Guard this tool call must be authorized against."""
        return current_guard() or self.root

    def child(self, name: str) -> Optional[Guard]:
        """The most recently minted Guard for sub-agent `name`, if any."""
        return self.children.get(name)

    def revoke(self, name: Optional[str] = None) -> list:
        """Revoke a sub-agent's subtree by name (or this whole chain)."""
        if name is None:
            return self.root.revoke()
        child = self.children.get(name)
        if child is None:
            return []
        return self.root.revoke(child.node_id)

    # -- the hook ------------------------------------------------------------
    def wrap_tool_call(self, request, handler):
        """`ToolNode(wrap_tool_call=...)` / `AgentMiddleware.wrap_tool_call`."""
        gate = self._gate(request, capture=Capture.WRAPPER_SYNC)
        if gate.denial is not None:
            return gate.denial
        if gate.child is None:
            return self._run_sync(gate, lambda: handler(request))
        try:
            with use_guard(gate.child):
                return self._run_sync(gate, lambda: handler(request))
        finally:
            gate.child.complete()               # the delegation returned: lifecycle end on the ledger (informational)

    async def awrap_tool_call(self, request, handler):
        """Async twin of `wrap_tool_call`."""
        gate = self._gate(request, capture=Capture.WRAPPER_ASYNC)
        if gate.denial is not None:
            return gate.denial
        if gate.child is None:
            return await self._run_async(gate, lambda: handler(request))
        try:
            with use_guard(gate.child):
                return await self._run_async(gate, lambda: handler(request))
        finally:
            gate.child.complete()

    # -- execution binding (0.9.0): runs the handler and closes out the outcome, on v2 only ----
    def _run_sync(self, gate: "GuardedDelegation._Gate", call: Callable[[], Any]) -> Any:
        if gate.decision is None:
            return call()
        start = time.monotonic()
        try:
            result = call()
        except Exception as exc:
            gate.guard.record_outcome(gate.decision.call_id, BodyState.RAISED,
                                      error_code=type(exc).__name__,
                                      invoked_params=gate.snapshot, duration_ms=_elapsed_ms(start))
            raise
        gate.guard.record_outcome(gate.decision.call_id, _body_state_for(result),
                                  invoked_params=gate.snapshot, duration_ms=_elapsed_ms(start))
        return result

    async def _run_async(self, gate: "GuardedDelegation._Gate", call: Callable[[], Any]) -> Any:
        if gate.decision is None:
            return await call()
        start = time.monotonic()
        try:
            result = await call()
        except asyncio.CancelledError:
            # The wrapper stopped observing while the body may still run -- `abandoned`, not
            # `raised`; still re-raised so cancellation propagates normally.
            gate.guard.record_outcome(gate.decision.call_id, BodyState.ABANDONED,
                                      invoked_params=gate.snapshot, duration_ms=_elapsed_ms(start))
            raise
        except Exception as exc:
            gate.guard.record_outcome(gate.decision.call_id, BodyState.RAISED,
                                      error_code=type(exc).__name__,
                                      invoked_params=gate.snapshot, duration_ms=_elapsed_ms(start))
            raise
        gate.guard.record_outcome(gate.decision.call_id, _body_state_for(result),
                                  invoked_params=gate.snapshot, duration_ms=_elapsed_ms(start))
        return result

    def middleware(self):
        """An `AgentMiddleware` wrapping this gate, for `create_agent` /
        `create_deep_agent`. Install the SAME object on the orchestrator and
        on every sub-agent spec. Imported lazily so this module stays usable
        with plain LangGraph, without the `langchain` package."""
        if self._middleware is None:
            from langchain.agents.middleware import AgentMiddleware

            outer = self

            class DelegationGuardMiddleware(AgentMiddleware):
                """Authorizes every tool call, and attenuates every spawn."""

                def wrap_tool_call(self, request, handler):
                    return outer.wrap_tool_call(request, handler)

                async def awrap_tool_call(self, request, handler):
                    return await outer.awrap_tool_call(request, handler)

            self._middleware = DelegationGuardMiddleware()
        return self._middleware

    # -- internals -----------------------------------------------------------
    @dataclass
    class _Gate:
        denial: Any = None
        child: Optional[Guard] = None
        # Execution binding (0.9.0): set only for an ALLOWED, v2, non-delegation check -- the
        # decision to close out via record_outcome() once the wrapper's own handler() call
        # returns/raises. `guard`/`snapshot` travel alongside since `_run_sync`/`_run_async`
        # don't otherwise have access to the Guard instance the decision came from.
        decision: Optional[Decision] = None
        guard: Optional[Guard] = None
        snapshot: Any = None

    def _gate(self, request, *, capture: str) -> "GuardedDelegation._Gate":
        """Decide, without running anything: deny / delegate / pass through."""
        call = request.tool_call
        name = call["name"]
        args = call.get("args") or {}
        guard = self.active_guard()

        if name == self.delegation_tool and (self.subagents or self.default_subagent_authority):
            return self._gate_delegation(request, guard, args)

        policy = self.tools.get(name)
        if policy is None and self.default_policy is not None:
            policy = self.default_policy(name)
        if policy is None:
            if self.allow_unlisted:
                return self._Gate()
            # No authority is known for this tool: the refusal goes on the
            # ledger (record_denial) as `unresolved` — an operator's Decisions
            # queue is a fold over the ledger, not over this adapter's memory.
            return self._Gate(denial=self._deny(request, guard.record_denial(
                Reason(ReasonCode.NO_AUTHORITY, requested=name,
                       message=f"no attenu-guard policy declared for tool {name!r}"),
                tool=name, disposition=Disposition.UNRESOLVED)))

        v2 = guard.schema_version == 2
        snapshot = _snapshot_params(args) if v2 else None
        hook = "GuardedDelegation.awrap_tool_call" if capture == Capture.WRAPPER_ASYNC else "GuardedDelegation.wrap_tool_call"
        extra = (
            dict(capture=capture, adapter=_adapter_info(hook), authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(
            policy.scope,
            context=policy.context_for(args),
            metered=policy.metered,
            tool=name,
            disposition=policy.disposition,
            **extra,
        )
        if not decision:
            return self._Gate(denial=self._deny(request, decision))
        return self._Gate(decision=decision if v2 else None, guard=guard, snapshot=snapshot)

    def _gate_delegation(self, request, guard: Guard, args: Mapping[str, Any]) -> "GuardedDelegation._Gate":
        subagent = args.get(self.subagent_arg)
        requested = self.subagents.get(subagent)
        if requested is None and self.default_subagent_authority is not None and subagent is not None:
            requested = self.default_subagent_authority(str(subagent))
        if requested is None:
            return self._Gate(denial=self._deny(request, Decision.deny(
                Reason("delegation_refused", constraint=self.subagent_arg,
                       requested=subagent,
                       message=f"sub-agent {subagent!r} has no declared Authority"),
                node=guard.node_id)))
        try:
            child = guard.delegate(
                str(subagent), requested, task=str(args.get(self.task_arg, "")))
        except AuthorityError as exc:
            # A structural failure (revoked/expired parent, depth/fanout
            # overflow). attenu-guard already wrote a `spawn_denied`
            # audit entry; surface the same reason to the caller.
            return self._Gate(denial=self._deny(request, Decision.deny(
                Reason(exc.reason, requested=subagent, message=str(exc)),
                node=guard.node_id)))
        self.children[str(subagent)] = child
        return self._Gate(child=child)

    def _deny(self, request, decision):
        if self.on_deny == "raise":
            raise AuthorityDenied(decision)
        return ToolMessage(
            content=f"AuthorityDenied: {decision.explain()}",
            tool_call_id=request.tool_call.get("id") or "",
            name=request.tool_call["name"],
            status="error",
        )
