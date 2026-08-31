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

Execution binding (0.9.0, on a `schema_version=2` chain — see `Guard.issue`): both
`GuardedWorkbench.call_tool` and `call_tool_stream` are genuine WRAPPER capture
(`Capture.WRAPPER_ASYNC`) — like `adapters.langgraph`'s reference wiring, both call
`super().call_tool(...)`/`super().call_tool_stream(...)` themselves and observe
completion directly. Unlike every other adapter in this package, a delegation-marked
tool here (`policy.delegates_to` set — the agents-as-tools pattern, `AgentTool`/
`TeamTool`) STILL gets execution binding: its body (the nested run) genuinely
executes through THIS same `super().call_tool(...)` call, so there is something real
to bind an outcome to — unlike a `Swarm` handoff (`GuardedHandoff`), which AutoGen
executes entirely outside the workbench and so never calls `guard.check()` at all,
and so never binds one either.

HONESTY NOTE on `BodyState.RAISED`: AutoGen's own `StaticWorkbench.call_tool` /
`StaticStreamWorkbench.call_tool_stream` (`autogen_core/tools/_static_workbench.py`) --
the base class `super()` calls into -- catch every `Exception` the tool body raises,
internally, and return/yield a `ToolResult(is_error=True, ...)` instead of letting it
propagate. By the time this wrapper's `try` block resumes, a raised exception and an
ordinary return are the same shape (a `ToolResult`, `is_error` set either way), so
`BodyState.RAISED` is never reported by this adapter on that path -- every completed
call is `BodyState.RETURNED`, whatever `is_error` says. `asyncio.CancelledError` is
NOT caught by AutoGen's own `except Exception` (it is a `BaseException`), so it DOES
propagate past both layers -- `BodyState.ABANDONED` is genuinely reachable, and is
still re-raised so cancellation propagates normally.
`call_tool_stream` records the outcome once the underlying stream is exhausted
(`RETURNED`, every event forwarded via `yield` first) or raises (`RAISED`/`ABANDONED`).
An early `aclose()` (or garbage collection) before exhaustion raises `GeneratorExit`
INSIDE this generator at the `yield` -- also a `BaseException`, so it too propagates
past `except Exception` -- and is recorded `BodyState.ABANDONED`, then re-raised
(required: an async generator that does not re-raise `GeneratorExit`, or return without
yielding again, is a `RuntimeError` per Python's own generator protocol).
"""
from __future__ import annotations

import asyncio
import time
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

from attenu_guard import Authority, AuthorityDenied, AuthorityError, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.GuardedWorkbench.call_tool",
}


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


def _freeze(value: Any) -> Any:
    """A genuinely immutable, fully decoupled rebuild of `value` -- NEVER calls a copy protocol
    (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back itself (or
    another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is independent
    of the live object graph, so a "snapshot" built that way can silently change out from under
    the commitment when the tool body (or AutoGen itself) later mutates the original in place.
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


def _snapshot_params(arguments: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    the tool body runs -- and reused for both `authorized_params` and `invoked_params`."""
    return _freeze(dict(arguments))

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
    ) -> tuple[Optional[ToolResult], Optional[tuple]]:
        """Return `(denial, pending)`. `denial` is a `ToolResult` (or None when the call may
        proceed); `pending` is `(guard, call_id, snapshot)` -- execution binding (0.9.0) -- on a
        `schema_version=2` chain, `None` otherwise (v1, or a denial already returned).

        Raises `AuthorityDenied` instead of returning `denial` when ``on_deny="raise"``.
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
            return self._deny(name, msg, decision=decision), None

        guard = self._registry.get(self._agent_name)
        if guard is None:
            return self._deny(
                name,
                f"attenu-guard: agent {self._agent_name!r} holds no delegated "
                f"authority (fail-closed).",
                decision=None,
            ), None

        context = policy.context(arguments) if policy.context else {}
        v2 = guard.schema_version == 2
        snapshot = _snapshot_params(arguments) if v2 else None
        extra = (
            dict(capture=Capture.WRAPPER_ASYNC, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(
            policy.scope, context=context, tool=original, metered=policy.metered,
            disposition=policy.disposition, **extra,
        )
        if not decision:
            return self._deny(
                name,
                f"attenu-guard: {decision.explain()} "
                f"(agent={self._agent_name}, tool={original}, scope={policy.scope})",
                decision=decision,
            ), None

        # Allowed — and if this tool is itself a delegation point, mint the child
        # now, before the body runs. Unlike every other adapter, the delegation tool's own
        # check() STILL gets execution binding below: its body (the nested run) genuinely
        # executes through THIS same call_tool()/call_tool_stream(), not a separate mechanism.
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
                ), None
        pending = (guard, decision.call_id, snapshot) if v2 else None
        return None, pending

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
        denial, pending = self._authorize(name, arguments or {})
        if denial is not None:
            return denial
        if pending is None:
            return await super().call_tool(name, arguments, cancellation_token, call_id)
        # Execution binding (0.9.0): this wrapper calls the tool body itself, so it genuinely
        # observes completion -- see the module docstring's "Execution binding".
        guard, oc_call_id, snapshot = pending
        started_at = time.monotonic()
        try:
            result = await super().call_tool(name, arguments, cancellation_token, call_id)
        except asyncio.CancelledError:
            # NOT caught by AutoGen's own StaticWorkbench.call_tool (it only catches
            # `Exception`), so this genuinely propagates -- `abandoned`, not `raised`. Still
            # re-raised: cancellation must propagate normally.
            guard.record_outcome(oc_call_id, BodyState.ABANDONED, invoked_params=snapshot,
                                 duration_ms=_elapsed_ms(started_at))
            raise
        except Exception as exc:
            # Rarely reached in practice: AutoGen's own StaticWorkbench.call_tool already
            # catches every Exception the tool body raises and returns a ToolResult(is_error=
            # True) instead -- see the module docstring's honesty note. Kept as a defensive,
            # honest fallback in case that ever changes or a future BaseTool bypasses it.
            guard.record_outcome(oc_call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
            raise
        guard.record_outcome(oc_call_id, BodyState.RETURNED, invoked_params=snapshot,
                             duration_ms=_elapsed_ms(started_at))
        return result

    async def call_tool_stream(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        cancellation_token: CancellationToken | None = None,
        call_id: str | None = None,
    ) -> AsyncGenerator[Any | ToolResult, None]:
        # NOTE: AssistantAgent takes this path, not call_tool, whenever the
        # workbench is a StaticStreamWorkbench (_assistant_agent.py:1580).
        denial, pending = self._authorize(name, arguments or {})
        if denial is not None:
            yield denial
            return
        if pending is None:
            async for event in super().call_tool_stream(
                name, arguments, cancellation_token, call_id
            ):
                yield event
            return
        # Execution binding (0.9.0): every event is forwarded as it arrives; the outcome is
        # recorded once the underlying stream is exhausted (RETURNED) or raises (RAISED -- see
        # the module docstring's honesty note: rarely reached, AutoGen's own
        # StaticStreamWorkbench.call_tool_stream already catches every Exception the tool body
        # raises and yields a ToolResult(is_error=True) instead). An early `aclose()`/GC before
        # exhaustion raises `GeneratorExit` INSIDE this generator at the `yield` -- a
        # `BaseException`, not caught by `except Exception` below -- recorded `ABANDONED`
        # (Codex review finding 6: a prior version left it unrecorded here despite `allow`
        # advertising `wrapper_async`, an observation this adapter can actually make and must
        # not skip). `GeneratorExit` MUST be re-raised (or the generator must return without
        # yielding again) -- Python itself enforces this on every async generator.
        guard, oc_call_id, snapshot = pending
        started_at = time.monotonic()
        try:
            async for event in super().call_tool_stream(name, arguments, cancellation_token, call_id):
                yield event
        except asyncio.CancelledError:
            guard.record_outcome(oc_call_id, BodyState.ABANDONED, invoked_params=snapshot,
                                 duration_ms=_elapsed_ms(started_at))
            raise
        except GeneratorExit:
            guard.record_outcome(oc_call_id, BodyState.ABANDONED, invoked_params=snapshot,
                                 duration_ms=_elapsed_ms(started_at))
            raise
        except Exception as exc:
            guard.record_outcome(oc_call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
            raise
        else:
            guard.record_outcome(oc_call_id, BodyState.RETURNED, invoked_params=snapshot,
                                 duration_ms=_elapsed_ms(started_at))


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
