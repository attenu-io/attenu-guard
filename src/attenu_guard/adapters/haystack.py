"""attenu-guard x Haystack (deepset `haystack-ai` 3.1.0) — thin integration adapter.

Tested against **haystack-ai 3.1.0** (Apache-2.0, requires Python >= 3.10).

HOOK POINTS USED
----------------
1. **Delegation — the `AgentTool` call.**
   Haystack's multi-agent primitive is `haystack.tools.AgentTool`
   (`haystack/tools/agent_tool.py:46`), a `ComponentTool` wrapping a whole `Agent`
   (`agent_tool.py:192-200`): the parent's model calls it like any other tool, and the
   sub-agent runs inside that call. There is no separate delegation callback, so the
   delegation moment *is* a tool invocation — which is exactly where this adapter sits.
   A `ToolPolicy` carrying `delegates_to=` + `grant=` mints the child with
   `parent.delegate(...)` after the check passes and **before** the sub-agent starts,
   and publishes it for the duration of the sub-run (see "WHO IS THE PARENT" below).

2. **Tool invocation — `Tool.invoke` / `Tool.invoke_async` (`guard_tools`).**
   `haystack/components/agents/tool_calling.py:219` (`result = tool.invoke(**args)`) and
   `:256` (`result = await tool.invoke_async(**args)`) are the *only* paths from the
   Agent's run loop to a tool body; `Tool.invoke` (`haystack/tools/tool.py:283`) is what
   finally calls `self.function(**kwargs)` (`tool.py:298`). `guard_tools()` returns
   copies of your tools whose `invoke` / `invoke_async` run `guard.check(...)` first and
   raise on a denial, so the body provably cannot run.

   Because the guarded object is a **subclass of the tool's own class** (built once per
   class, `__class__` swapped onto a `copy.copy` of your tool), everything Haystack keys
   off the concrete type keeps working: `isinstance(tool, ComponentTool)` in
   `_get_func_params` (`tool_calling.py:277`), `_component`, `inputs_from_state`,
   `outputs_to_state`, `outputs_to_string`. One wrapper therefore covers plain `Tool`s,
   `ComponentTool`, `PipelineTool`, `AgentTool`, and MCP tools alike.

3. **Tool invocation, the framework-native alternative — `ConfirmationStrategy`.**
   Haystack 3.x ships a `before_tool` Agent hook whose whole job is vetoing pending tool
   calls: `ConfirmationHook` (`haystack/hooks/human_in_the_loop/hooks.py:19`) runs at
   `agent.py:1003` (async `:1068`), *before* `_run_tool` at `agent.py:1014` (`:1079`), and
   a `ToolExecutionDecision(execute=False)` makes Haystack drop the call from the
   conversation and answer the model with an error tool-result
   (`hooks/human_in_the_loop/strategies.py:_apply_tool_execution_decisions`).
   `AttenuationStrategy` is that `ConfirmationStrategy`
   (`hooks/human_in_the_loop/types/protocol.py:57`); `attenuation_hook(policies)` wires it
   under the wildcard key so one registration covers every tool of that Agent.

   Use hook 2 **or** hook 3 for a given tool, not both — each is a full `guard.check()`,
   and metered checks would be counted twice. Hook 2 is the default recommendation: it is
   the only one that also covers tools invoked outside an `Agent` (a `Pipeline`, or a
   direct `tool.invoke(...)`), and the only one that can mint a child `Guard`.

   Not used: the bare `before_tool` `Hook` protocol (`haystack/hooks/protocol.py:21`).
   A hook influences the run only by mutating `State` in place and has no return value,
   so on its own it cannot stop a call; `ConfirmationHook` is Haystack's supported way to
   turn that hook point into a veto, and hook 3 goes through it rather than around it.

WHO IS THE PARENT
-----------------
A `contextvars.ContextVar` holds the `Guard` in force for the current agent, and the
guarded `AgentTool` rebinds it to the child for the duration of the sub-run. This is
correct under Haystack's own concurrency: parallel tool calls are submitted with
`contextvars.copy_context()` per call (`tool_calling.py:213`, `_make_context_bound_invoke`)
and async ones run as separate tasks (`tool_calling.py:251`), so each call sees a private
copy — a fan-out of three `AgentTool` calls in one turn produces three *siblings* of the
same parent, never a chain. Nothing is keyed by agent name, so re-entrant and recursive
delegation are correct too.

Enter the scope once, around the root agent's run:

    with authority(root_guard):
        result = agent.run(messages=[ChatMessage.from_user("...")])

Outside it there is no Guard, and every guarded tool denies (fail-closed).

DENIAL SHAPE
------------
A denial raises `AuthorityDeniedTool`, a subclass of Haystack's own
`haystack.tools.errors.ToolInvocationError`. That is deliberate: `ToolInvocationError` is
the one exception the Agent's tool runner catches (`tool_calling.py:221`, `:257`), and the
Agent's existing `raise_on_tool_invocation_failure` switch then decides the outcome —

  * `False` (Haystack's default, `agent.py:369`): the run continues and the model is shown
    an error tool-result saying it lacks the authority (`_finalize_tool_result`,
    `tool_calling.py:505-509`);
  * `True`: the run aborts with the denial.

Either way the tool body never ran, and `outputs_to_string` handlers are bypassed rather
than fed a denial string. `AuthorityDeniedTool.decision` carries the attenu-guard
`Decision`, and `__cause__` the `AuthorityDenied`. Pass `on_deny="raise"` to raise
`attenu_guard.AuthorityDenied` instead — an unconditional hard stop that Haystack does not
catch, whatever the Agent is configured to do.

Fail-closed by default: a tool with no `ToolPolicy`, and any call made with no `Guard` in
scope, are denied and recorded (`ReasonCode.NO_AUTHORITY`, disposition `unresolved`).

USAGE
-----
    from attenu_guard import Authority, Guard, RowLimit, EgressRank
    from attenu_guard.adapters.haystack import (
        Grant, ToolPolicy, UNGUARDED, authority, guard_tools,
    )

    RESEARCHER = Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900)

    researcher = Agent(chat_generator=..., tools=guard_tools(
        [crm_query, crm_export],
        {"crm_query": ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]}),
         "crm_export": ToolPolicy("crm.export", context=lambda a: {"egress": "any"})},
    ))
    coordinator = Agent(chat_generator=..., tools=guard_tools(
        [AgentTool(agent=researcher, name="research", description="...")],
        {"research": ToolPolicy(None, delegates_to="researcher",
                                grant=Grant(RESEARCHER, task="summarise Q3"))},
    ))

    root = Guard.issue("coordinator", COORDINATOR_AUTHORITY, task="quarterly report")
    with authority(root):
        coordinator.run(messages=[ChatMessage.from_user("Summarise Q3")])

attenu-guard deliberately does not decide *what* authority a task needs — you write the
`Authority` and the `Grant`.

This module imports `haystack` and `attenu_guard`, and nothing else. Install its extra
with `pip install 'attenu-guard[haystack]'`.

NOTE ON SERIALIZATION
---------------------
A guarded tool is a runtime object bound to a live `Guard`, so it deliberately refuses
`to_dict()`. Serialize your pipeline or agent with the *unguarded* tools and apply
`guard_tools(...)` after `from_dict()`.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain — see `Guard.issue`)
-----------------------------------------------------------------------------
Hook 2 (`guard_tool`/`guard_tools`, `Tool.invoke`/`invoke_async`) is genuine WRAPPER capture
(`Capture.WRAPPER_SYNC`/`Capture.WRAPPER_ASYNC`) — like `adapters.langgraph`'s reference wiring,
`_Guarded.invoke`/`invoke_async` call `super().invoke`/`invoke_async` themselves and await/observe
completion directly, so `BodyState.RAISED` (with `error_code`) is genuinely reachable: unlike CrewAI
and the OpenAI Agents SDK, Haystack never swallows a tool's exception into a returned string before
this wrapper sees it -- it re-raises (`Tool.invoke`/`invoke_async` wrap the body's own exception in a
`ToolInvocationError` with the original as `__cause__`, which this adapter unwraps for `error_code`
via `_underlying_error_code` -- see there). A delegation tool (`policy.delegates_to`
set) never calls `guard.check()` for itself — it mints the child via `guard.delegate()` — so there is
nothing to bind an outcome to; only a non-delegation, non-`UNGUARDED` policy gets execution binding.

Hook 3 (`AttenuationStrategy`/`attenuation_hook`) is NOT wrapped: it sees a pending tool call and can
veto it, but — as the module docstring above already says — "it cannot mint the child Guard" because
it never touches the tool body either way; the framework itself calls the tool afterward, entirely
outside this hook. Its `guard.check()` calls stay the library's own default `pre_hook_only`
observation; no `capture`/`authorized_params` are passed here.
"""
from __future__ import annotations

import asyncio
import copy
import inspect
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Literal

from haystack.hooks.human_in_the_loop import ConfirmationHook, ToolExecutionDecision
from haystack.tools import Tool, Toolset, flatten_tools_or_toolsets
from haystack.tools.errors import ToolInvocationError

from attenu_guard import Authority, AuthorityDenied, AuthorityError, Decision, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}._Guarded.invoke",
}


def _is_deferred_result(result: Any) -> bool:
    return inspect.isgenerator(result) or inspect.isasyncgen(result)


def _body_state_for(result: Any) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


def _freeze(value: Any) -> Any:
    """A genuinely immutable, fully decoupled rebuild of `value` -- NEVER calls a copy protocol
    (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back itself (or
    another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is independent
    of the live object graph, so a "snapshot" built that way can silently change out from under
    the commitment when the tool body (or Haystack itself) later mutates the original in place.
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
    the tool body runs -- and reused for both `authorized_params` and `invoked_params`."""
    return _freeze(dict(args))

__all__ = [
    "Grant",
    "ToolPolicy",
    "UNGUARDED",
    "AuthorityDeniedTool",
    "authority",
    "current_guard",
    "guard_tool",
    "guard_tools",
    "AttenuationStrategy",
    "attenuation_hook",
]

ContextFn = Callable[[Mapping[str, Any]], Mapping[str, Any]]

OnDeny = Literal["tool_error", "raise"]
"""What a denial raises.

`"tool_error"` — `AuthorityDeniedTool`, a `ToolInvocationError`. The Agent's own
                 `raise_on_tool_invocation_failure` then decides whether the model is told
                 and carries on, or the run aborts. The default.
`"raise"`      — `attenu_guard.AuthorityDenied`. Haystack does not catch it, so the run
                 stops whatever the Agent is configured to do.
"""


# ==========================================================================
# Policy declarations — the security decision, written once, in code
# ==========================================================================


@dataclass(frozen=True)
class Grant:
    """The authority a parent *requests* for a child at a delegation point.

    What the child actually receives is `parent.authority.meet(request)`, so a greedy
    `Grant` cannot widen the child beyond its parent.
    """

    authority: Authority
    task: str = ""


@dataclass(frozen=True)
class ToolPolicy:
    """Maps one Haystack tool onto the authority it consumes.

    scope:        the scope checked against the agent's `Authority`, e.g. `"crm.read"`.
                  `None` marks the tool as not authority-bearing (see `UNGUARDED`) — the
                  usual case for a pure delegation tool.
    context:      maps the tool's arguments to the context the ceilings are evaluated
                  against, e.g. `lambda a: {"rows": a["rows"], "egress": "none"}`.
    metered:      forwarded to `Guard.check(metered=...)`.
    disposition:  see `attenu_guard.Disposition`; recorded on a deny.
    delegates_to: the child agent's id, when this tool is a delegation point (an
                  `AgentTool`). The child `Guard` is minted after the check passes and is
                  in force for the whole sub-run.
    grant:        the `Grant` the child is minted with. Required with `delegates_to`.
    """

    scope: str | None
    context: ContextFn | None = None
    metered: bool = False
    disposition: str | None = None
    delegates_to: str | None = None
    grant: Grant | None = None

    def __post_init__(self) -> None:
        if bool(self.delegates_to) != bool(self.grant):
            raise ValueError(
                "ToolPolicy: `delegates_to` and `grant` must be given together — a "
                "delegation point needs both the child's id and the authority it asks for."
            )


UNGUARDED = ToolPolicy(scope=None)
"""Explicit opt-out for a tool that consumes no authority of its own.

The canonical case is a delegation tool: `Guard.delegate` already records the handoff as a
`spawn` entry, and the child's authority is bounded by construction, so re-checking a scope
here would be ceremony. Being explicit keeps the default (deny) fail-closed.
"""


# ==========================================================================
# Hook point 1 — who is the parent
# ==========================================================================

_CURRENT: ContextVar[Guard | None] = ContextVar("attenu_guard_haystack_current", default=None)


@contextmanager
def authority(guard: Guard) -> Iterator[Guard]:
    """Put `guard` in force for everything that runs inside the block.

    Enter it once around the root agent's run. The guarded `AgentTool` rebinds it to the
    child `Guard` for the duration of a sub-run, so a tool always resolves the authority of
    the agent that is actually calling it.
    """
    token = _CURRENT.set(guard)
    try:
        yield guard
    finally:
        _CURRENT.reset(token)


def current_guard() -> Guard | None:
    """The `Guard` in force for the calling agent, or `None` outside any `authority(...)`."""
    return _CURRENT.get()


# ==========================================================================
# The shared authorization core (used by BOTH tool hook points)
# ==========================================================================


def _denial_message(tool_name: str, detail: str) -> str:
    return (
        f"attenu-guard denied `{tool_name}`: {detail} This agent does not hold the "
        f"authority for this action; do not retry it."
    )


def _no_guard_message(tool_name: str) -> str:
    return (
        f"attenu-guard: no Guard is in force, so `{tool_name}` cannot be authorized "
        f"(fail-closed). Run the agent inside `with authority(guard): ...`."
    )


def _unmapped_message(tool_name: str) -> str:
    return (
        f"attenu-guard: tool `{tool_name}` has no ToolPolicy, so the authority it consumes "
        f"is undeclared and the call cannot be authorized (fail-closed). Add it to "
        f"`policies`, or mark it `UNGUARDED`."
    )


def authorize_tool_call(
    tool_name: str,
    policy: ToolPolicy | None,
    args: Mapping[str, Any],
) -> tuple[Guard, Decision | None]:
    """Authorize one tool call. Returns `(guard, decision)` on allow — `decision` is `None`
    for an `UNGUARDED` tool, which consumes no authority. Raises `_Refusal` on a denial.

    This is the single decision point both hook 2 and hook 3 go through, so the two paths
    can never disagree about what is allowed.
    """
    guard = _CURRENT.get()

    if policy is None:
        message = _unmapped_message(tool_name)
        # No authority is known for this tool: put it on the ledger as `unresolved` when a
        # Guard exists (the Decisions queue folds the ledger).
        decision = (
            guard.record_denial(
                ReasonCode.NO_AUTHORITY,
                message,
                tool=tool_name,
                disposition=Disposition.UNRESOLVED,
            )
            if guard is not None
            else None
        )
        raise _Refusal(message, tool_name, decision)

    if guard is None:
        raise _Refusal(_no_guard_message(tool_name), tool_name, None)

    if policy.scope is None:  # UNGUARDED
        return guard, None

    context = dict(policy.context(args)) if policy.context is not None else {}
    decision = guard.check(
        policy.scope,
        context=context,
        metered=policy.metered,
        tool=tool_name,
        disposition=policy.disposition,
    )
    if not decision:
        raise _Refusal(_denial_message(tool_name, decision.explain()), tool_name, decision)
    return guard, decision


def _authorize_v2(
    guard: Guard, policy: ToolPolicy, tool_name: str, args: Mapping[str, Any], *, is_async: bool,
) -> tuple[Decision, Any]:
    """Like `authorize_tool_call`, for a `schema_version=2` chain and a non-`UNGUARDED` policy:
    passes `capture`/`adapter`/`authorized_params` and returns `(decision, snapshot)` on allow
    (never `None` -- the caller only calls this when `policy.scope is not None`), so the caller
    can bind an outcome to `decision.call_id`. Raises `_Refusal` on a denial, exactly like
    `authorize_tool_call`, so both go through `_ToolGuard._refuse`'s shaping."""
    snapshot = _snapshot_params(args)
    context = dict(policy.context(args)) if policy.context is not None else {}
    capture = Capture.WRAPPER_ASYNC if is_async else Capture.WRAPPER_SYNC
    decision = guard.check(
        policy.scope, context=context, metered=policy.metered, tool=tool_name,
        disposition=policy.disposition, capture=capture, adapter=_ADAPTER_INFO,
        authorized_params=snapshot,
    )
    if not decision:
        raise _Refusal(_denial_message(tool_name, decision.explain()), tool_name, decision)
    return decision, snapshot


class _Refusal(Exception):
    """Internal: a refusal, before either hook has shaped it for the framework."""

    def __init__(self, message: str, tool_name: str, decision: Decision | None) -> None:
        super().__init__(message)
        self.message = message
        self.tool_name = tool_name
        self.decision = decision


# ==========================================================================
# Hook point 2 — Tool.invoke / Tool.invoke_async
# ==========================================================================


class AuthorityDeniedTool(ToolInvocationError):
    """A denial, in Haystack's own tool-failure shape.

    Subclasses `haystack.tools.errors.ToolInvocationError`, the one exception the Agent's
    tool runner catches (`tool_calling.py:221`, `:257`), so the Agent's existing
    `raise_on_tool_invocation_failure` switch decides whether the model is told and the run
    continues, or the run aborts. `decision` is the attenu-guard `Decision`; `__cause__` is
    the `AuthorityDenied` it came from, when there was one.
    """

    def __init__(self, message: str, tool_name: str, decision: Decision | None = None) -> None:
        super().__init__(message, tool_name)
        self.decision = decision


class _NullScope:
    """A no-op `with` scope, for a call that is not a delegation point."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> Literal[False]:
        return False


class _ToolGuard:
    """The per-tool state a guarded tool carries: its policy and how to refuse."""

    __slots__ = ("policy", "on_deny", "tool_name")

    def __init__(self, tool_name: str, policy: ToolPolicy | None, on_deny: OnDeny) -> None:
        self.tool_name = tool_name
        self.policy = policy
        self.on_deny = on_deny

    def scope(self, args: Mapping[str, Any], *, is_async: bool = False) -> tuple[Any, Any]:
        """Authorize the call, and return `(with_scope, pending)`.

        `with_scope` is the child's `Guard` scope for a delegation point, `_NullScope()`
        otherwise. `pending` is `(guard, call_id, snapshot)` -- execution binding (0.9.0) --
        when this is a `schema_version=2` chain and a non-`UNGUARDED`, non-delegation policy;
        `None` otherwise (v1, `UNGUARDED`, or a delegation tool, which never calls
        `guard.check()` for itself -- see the module docstring's "EXECUTION BINDING"). Never
        returns on a denial.
        """
        guard = _CURRENT.get()
        policy = self.policy
        v2 = (
            guard is not None and guard.schema_version == 2
            and policy is not None and policy.scope is not None
        )
        pending = None
        if v2:
            try:
                decision, snapshot = _authorize_v2(guard, policy, self.tool_name, args, is_async=is_async)
            except _Refusal as refusal:
                self._refuse(refusal)
                raise  # unreachable: _refuse never returns
            pending = (guard, decision.call_id, snapshot)
        else:
            try:
                guard, _ = authorize_tool_call(self.tool_name, self.policy, args)
            except _Refusal as refusal:
                self._refuse(refusal)
                raise  # unreachable: _refuse never returns

        if policy is not None and policy.delegates_to and policy.grant is not None:
            # Mint the child now: after the check passed, before the sub-agent starts. A
            # delegation tool with an UNGUARDED policy (scope=None -- the usual case; see
            # `UNGUARDED`'s docstring) never called guard.check() above, so `pending` is already
            # None here and there is nothing to bind. A delegation tool that ALSO declares a real
            # `scope` (unusual, but the dataclass allows it) DID call guard.check() above and
            # allocate a real call_id on the ledger -- `pending` must be carried through, not
            # dropped, or that call_id is left pending forever (Codex review finding 4: a
            # dropped, already-registered outcome wedges complete()).
            try:
                child = guard.delegate(
                    policy.delegates_to,
                    policy.grant.authority,
                    policy.grant.task or policy.delegates_to,
                )
            except AuthorityError as exc:
                # Structural failure: revoked/expired parent, or a depth/fanout ceiling.
                message = _denial_message(self.tool_name, f"cannot delegate to {policy.delegates_to!r}: {exc}")
                decision = guard.record_denial(
                    ReasonCode.NO_AUTHORITY, message, tool=self.tool_name, disposition=Disposition.UNRESOLVED
                )
                self._refuse(_Refusal(message, self.tool_name, decision))
            return authority(child), pending
        return _NullScope(), pending

    def _refuse(self, refusal: _Refusal) -> None:
        """Raise the denial in the shape the caller asked for. Never returns.

        `on_deny="raise"` needs a `Decision` to raise `AuthorityDenied` around. The two
        refusals that have none — no Guard in scope at all, and an unmapped tool with no
        Guard to record against — fall through to `AuthorityDeniedTool`; both are wiring
        mistakes rather than authority decisions, and both still stop the call.
        """
        if self.on_deny == "raise" and refusal.decision is not None:
            raise AuthorityDenied(refusal.decision)
        cause = AuthorityDenied(refusal.decision) if refusal.decision is not None else None
        error = AuthorityDeniedTool(refusal.message, self.tool_name, refusal.decision)
        raise error from cause


class _GuardedMarker:
    """Marks a class built by `_guarded_class`, so a tool is never guarded twice."""


def _nested_denial(exc: ToolInvocationError) -> BaseException | None:
    """The denial this tool failure is really about, if it is one.

    An `AgentTool` runs the sub-agent inside its own `function`, and `Tool.invoke`
    (`haystack/tools/tool.py:299-302`) wraps whatever that raises in a plain
    `ToolInvocationError`. Without unwrapping, a denial two levels down would reach the
    caller as a generic tool failure. Ordinary tool failures return `None` and are
    re-raised exactly as Haystack raised them, cause chain intact.
    """
    cause = exc.__cause__
    if isinstance(cause, (AuthorityDeniedTool, AuthorityDenied)):
        return cause
    return None


def _underlying_error_code(exc: ToolInvocationError) -> str:
    """The tool BODY's own exception class name for `record_outcome(error_code=...)` --
    unwrapped one level when `Tool.invoke`/`invoke_async` (`tool.py:296-302`,`:320-323`) has
    already re-raised the body's exception as a `ToolInvocationError` with the original set as
    `__cause__` (this is NOT `_nested_denial`'s case -- that is a denial from a nested
    delegation; this is any ordinary tool failure). Reporting `ToolInvocationError` itself would
    describe Haystack's own re-wrapping, not what the tool body actually raised."""
    cause = exc.__cause__
    return type(cause).__name__ if cause is not None else type(exc).__name__


_GUARDED_CLASSES: dict[type, type] = {}


def _guarded_class(base: type) -> type:
    """Build (once per tool class) the subclass that authorizes before invoking.

    Subclassing the tool's *own* class is what keeps `isinstance(tool, ComponentTool)` —
    and so `_get_func_params` (`tool_calling.py:277`), `inputs_from_state` and State
    injection — working exactly as before.
    """
    cached = _GUARDED_CLASSES.get(base)
    if cached is not None:
        return cached

    class _Guarded(_GuardedMarker, base):  # type: ignore[misc,valid-type]
        """`{base}` + an attenu-guard check before the tool body."""

        _attenu: _ToolGuard

        def invoke(self, **kwargs: Any) -> Any:
            ctx_scope, pending = self._attenu.scope(kwargs, is_async=False)
            with ctx_scope:
                if pending is None:
                    try:
                        return super().invoke(**kwargs)
                    except ToolInvocationError as exc:
                        denial = _nested_denial(exc)
                        if denial is None:
                            raise
                        raise denial from None
                # Execution binding (0.9.0): this wrapper calls the tool body itself, so it
                # genuinely observes completion -- see the module docstring's "EXECUTION BINDING".
                guard, call_id, snapshot = pending
                started_at = time.monotonic()
                try:
                    result = super().invoke(**kwargs)
                except ToolInvocationError as exc:
                    denial = _nested_denial(exc)
                    error_code = type(denial).__name__ if denial is not None else _underlying_error_code(exc)
                    guard.record_outcome(call_id, BodyState.RAISED, error_code=error_code,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
                    if denial is None:
                        raise
                    raise denial from None
                except Exception as exc:
                    guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
                    raise
                guard.record_outcome(call_id, _body_state_for(result), invoked_params=snapshot,
                                     duration_ms=_elapsed_ms(started_at))
                return result

        async def invoke_async(self, **kwargs: Any) -> Any:
            ctx_scope, pending = self._attenu.scope(kwargs, is_async=True)
            with ctx_scope:
                if pending is None:
                    try:
                        return await super().invoke_async(**kwargs)
                    except ToolInvocationError as exc:
                        denial = _nested_denial(exc)
                        if denial is None:
                            raise
                        raise denial from None
                guard, call_id, snapshot = pending
                started_at = time.monotonic()
                try:
                    result = await super().invoke_async(**kwargs)
                except asyncio.CancelledError:
                    # The wrapper stopped observing while the body may still run -- `abandoned`,
                    # not `raised`. Still re-raised: cancellation must propagate normally.
                    guard.record_outcome(call_id, BodyState.ABANDONED, invoked_params=snapshot,
                                         duration_ms=_elapsed_ms(started_at))
                    raise
                except ToolInvocationError as exc:
                    denial = _nested_denial(exc)
                    error_code = type(denial).__name__ if denial is not None else _underlying_error_code(exc)
                    guard.record_outcome(call_id, BodyState.RAISED, error_code=error_code,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
                    if denial is None:
                        raise
                    raise denial from None
                except Exception as exc:
                    guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                         invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
                    raise
                guard.record_outcome(call_id, _body_state_for(result), invoked_params=snapshot,
                                     duration_ms=_elapsed_ms(started_at))
                return result

        def to_dict(self) -> dict[str, Any]:
            raise NotImplementedError(
                f"attenu-guard: a guarded tool ({self.name!r}) is bound to a live Guard and "
                f"cannot be serialized. Serialize the unguarded tools, then apply "
                f"`guard_tools(...)` after `from_dict()`."
            )

    _Guarded.__name__ = f"Guarded{base.__name__}"
    _Guarded.__qualname__ = _Guarded.__name__
    _Guarded.__doc__ = f"{base.__name__} + an attenu-guard check before the tool body."
    _GUARDED_CLASSES[base] = _Guarded
    return _Guarded


def guard_tool(tool: Tool, policy: ToolPolicy | None, *, on_deny: OnDeny = "tool_error") -> Tool:
    """Return a copy of `tool` that runs `guard.check(...)` before its body.

    The original is left untouched. `policy=None` means "no policy declared", which is
    denied and recorded as `unresolved` — the fail-closed default.
    """
    if not isinstance(tool, Tool):
        raise TypeError(f"guard_tool expects a haystack Tool, got {type(tool).__name__}")
    if on_deny not in ("tool_error", "raise"):
        raise ValueError("on_deny must be 'tool_error' or 'raise'")

    guarded = copy.copy(tool)
    if not isinstance(tool, _GuardedMarker):
        # Guarding an already-guarded tool re-binds its policy rather than nesting a second
        # check, which would double-charge every metered call.
        guarded.__class__ = _guarded_class(type(tool))
    guarded._attenu = _ToolGuard(tool.name, policy, on_deny)  # type: ignore[attr-defined]
    return guarded


def guard_tools(
    tools: Sequence[Tool | Toolset] | Toolset,
    policies: Mapping[str, ToolPolicy],
    *,
    on_deny: OnDeny = "tool_error",
) -> list[Tool]:
    """Guard every tool an agent can reach, and return the list to pass as `tools=`.

    Accepts anything Haystack's `tools=` accepts (a list of `Tool`s and/or `Toolset`s, or a
    single `Toolset`) and flattens it with the framework's own
    `flatten_tools_or_toolsets` — the same call the Agent makes
    (`tool_calling.py:_validate_and_prepare_tools`), so what you guard is exactly what the
    Agent will run. A tool with no entry in `policies` is kept, and denied at call time.
    """
    return [guard_tool(t, policies.get(t.name), on_deny=on_deny) for t in flatten_tools_or_toolsets(tools)]


# ==========================================================================
# Hook point 3 — the `before_tool` ConfirmationStrategy (framework-native denial)
# ==========================================================================


class AttenuationStrategy:
    """A Haystack `ConfirmationStrategy` that answers from the `Guard` instead of a human.

    Registered through `ConfirmationHook` at the `before_tool` hook point, which runs at
    `agent.py:1003` — before `_run_tool` at `agent.py:1014` — so a rejected call never
    reaches a tool. Haystack drops it from the conversation and answers the model with an
    error tool-result carrying `feedback`.

    Scope-only: this hook point sees pending tool calls, not the sub-agent that an
    `AgentTool` is about to start, so it cannot mint a child `Guard`. Guard `AgentTool`s
    with `guard_tools(...)` (hook 2) even when leaf tools go through this strategy.
    """

    # ConfirmationHook is validated to this hook point (`agent.py:_validate_hooks`).
    def __init__(self, policies: Mapping[str, ToolPolicy]) -> None:
        self.policies = dict(policies)

    def _decide(self, tool_name: str, tool_params: dict[str, Any], tool_call_id: str | None) -> ToolExecutionDecision:
        policy = self.policies.get(tool_name)
        if policy is not None and policy.delegates_to:
            raise ValueError(
                f"attenu-guard: tool {tool_name!r} is a delegation point, which this hook "
                f"point cannot carry — it cannot mint the child Guard. Guard it with "
                f"`guard_tools(...)` instead."
            )
        try:
            authorize_tool_call(tool_name, policy, tool_params)
        except _Refusal as refusal:
            return ToolExecutionDecision(
                tool_name=tool_name, execute=False, tool_call_id=tool_call_id, feedback=refusal.message
            )
        return ToolExecutionDecision(
            tool_name=tool_name, execute=True, tool_call_id=tool_call_id, final_tool_params=tool_params
        )

    def run(
        self,
        *,
        tool_name: str,
        tool_description: str = "",  # noqa: ARG002 — part of the protocol, unused
        tool_params: dict[str, Any],
        tool_call_id: str | None = None,
        confirmation_strategy_context: dict[str, Any] | None = None,  # noqa: ARG002
    ) -> ToolExecutionDecision:
        """Decide one pending tool call. `execute=False` makes Haystack drop it."""
        return self._decide(tool_name, tool_params, tool_call_id)

    async def run_async(
        self,
        *,
        tool_name: str,
        tool_description: str = "",  # noqa: ARG002
        tool_params: dict[str, Any],
        tool_call_id: str | None = None,
        confirmation_strategy_context: dict[str, Any] | None = None,  # noqa: ARG002
    ) -> ToolExecutionDecision:
        """Async twin of `run`. The check itself is synchronous and does no I/O."""
        return self._decide(tool_name, tool_params, tool_call_id)

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError(
            "attenu-guard: AttenuationStrategy holds live policies and cannot be "
            "serialized. Register it after deserializing the Agent."
        )


def attenuation_hook(policies: Mapping[str, ToolPolicy]) -> ConfirmationHook:
    """A `before_tool` hook that authorizes every tool call of one Agent.

    Registered under the wildcard key `"*"`, so one registration covers every tool that
    Agent can reach (`strategies.py:_get_confirmation_strategy`):

        agent = Agent(chat_generator=..., tools=[...],
                      hooks={"before_tool": [attenuation_hook(POLICIES)]})
    """
    return ConfirmationHook(confirmation_strategies={"*": AttenuationStrategy(policies)})
