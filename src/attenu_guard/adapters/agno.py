"""attenu-guard × Agno (`agno` 2.9.x) — thin integration adapter.

Hook points used
----------------
Both are Agno's own `tool_hooks` extension point — no monkeypatching. A tool
hook wraps the call: `FunctionCall._build_nested_execution_chain`
(agno/tools/function.py:2020) nests the hooks around the entrypoint and hands
each one a `next_func` as its `function_call` argument, so **a hook that never
calls `function_call(**arguments)` prevents the tool body from running at
all**. Agno itself relies on this — `FunctionCall.execute` sanitises injected
arguments *before* the hooks run specifically "so a hook used as an
authorization gate cannot read an identity the call will not actually execute
with" (agno/tools/function.py:2160-2162).

1. **Delegation — `delegation_tool_hook`, passed as `Team(tool_hooks=[...])`.**
   Agno's delegation primitive is `Team(members=[...])`; the leader delegates by
   calling an injected `delegate_task_to_member(member_id, task)` tool (built in
   `agno/team/_default_tools.py:441`, registered at `agno/team/_tools.py:324`).
   That Function passes through the same tool-hook plumbing as any other team
   tool (`agno/team/_tools.py:437`), so a hook on the Team intercepts the exact
   moment of delegation. There the adapter mints the child's Guard with
   `parent_guard.delegate(...)` and registers it under the member's id, then
   lets the delegation proceed. A member with no `Grant` is refused outright.

2. **Tool invocation — `guarded_tool_hook`, passed as `Agent(tool_hooks=[...])`.**
   `agent.tool_hooks` are attached to every one of that agent's Functions
   (`agno/agent/_tools.py:434,468,518`). The hook resolves the caller's Guard,
   runs `guard.check(scope, context=..., tool=...)`, and only then calls
   `function_call(**arguments)`.

Note that these are *different objects*: `team.tool_hooks` are attached to the
team's own Functions and are **never** propagated to members
(`_initialize_member`, agno/team/_init.py:487, copies only model/debug/team_id).
Every agent must therefore carry its own guarded hook. This is also why Agno
gives a leader no code-level authority over a member — see the README.

Hooks are keyed automatically: Agno injects the calling `agent` and `team`
objects into any hook that declares them (`_build_hook_args`,
agno/tools/function.py:1990), so one hook factory serves every agent and the
registry is keyed by `agent.id` (falling back to `team.id` for the leader).

Do not confuse `tool_hooks` with `Agent(pre_hooks=/post_hooks=)`: the latter are
Agno's *guardrails*, which run once over the run **input**
(`BaseGuardrail.check(run_input)`, agno/guardrails/base.py:11) and never see a
tool call. Only `tool_hooks` can gate a tool.

Usage
-----
Build one `GuardRegistry` per run, seeded with the root `Guard`. Put
`delegation_tool_hook(registry, {member_id: Grant(authority, task)})` on the
`Team`, and `guarded_tool_hook(registry, {tool_name: ToolPolicy(scope, ...)})`
on every `Agent`. Both fail closed: a member with no `Grant`, an agent with no
delegated `Guard`, and a tool with no `ToolPolicy` are all denied.
attenu-guard deliberately does not decide *what* authority a task needs —
you write the `Grant`.

Denials raise `AuthorityDenied` by default (`on_deny="error"`), which
`FunctionCall.execute` catches (agno/tools/function.py:2244) and turns into a
tool message with `tool_call_error=True` (agno/models/base.py:2109) that the
model can read and react to; the run continues. Use `on_deny="stop"` to raise
Agno's `StopAgentRun` instead and tear the whole run down. Returning a denial
*string* is deliberately not offered: Agno would record that as a successful
tool result.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`) -- TWO MODES
-----------------------------------------------------------------------------------------
`guarded_tool_hook`/`aguarded_tool_hook` call `function_call(**arguments)`/`await
function_call(**arguments)` themselves -- but whether that genuinely IS the raw tool body
depends on what else is wired up, verified directly against pinned agno 2.9's
`agno/tools/function.py`, `FunctionCall._build_nested_execution_chain`:

  * `Agent(tool_hooks=[...])` is a LIST. Every hook in it is folded into ONE nested chain
    (`reduce(create_hook_wrapper, reversed(final_hooks), execute_entrypoint)`); the `function_
    call`/`next_func` THIS hook receives is whichever accumulator sits just inside it in that
    fold -- another hook's own wrapper, unless this hook is the innermost (last) one listed.
  * EVEN when this hook is the innermost (or the only) one, `execute_entrypoint` itself --
    Agno's OWN dispatch, not a sibling's -- returns a CACHED result (`_detached(cached_result)`)
    without ever calling `self.function.entrypoint(**arguments)` when the tool declares
    `cache_results=True` and the cache key still matches. This is not a sibling hook this file
    could detect or refuse; it is baked into the same function this hook's `function_call`
    argument resolves into.

Per this whole effort's governing principle -- an honest unobserved beats a promised outcome
that can be lost -- this adapter therefore ships with TWO modes, controlled by
`guarded_tool_hook(..., strict_single_hook=...)` (and `aguarded_tool_hook`'s identical kwarg):

  * DEFAULT (`strict_single_hook=False`): every `guard.check()` call passes NO `capture`/
    `authorized_params` at all. On a v2 chain the Guard itself stamps its own default, honest
    `Capture.PRE_HOOK_ONLY`; this adapter never calls `record_outcome()`.
  * STRICT (`strict_single_hook=True`): an explicit attestation that (a) this hook is the ONLY
    entry in the tool's `tool_hooks=[...]` list, and (b) none of the tools it guards declare
    `cache_results=True` -- this file cannot verify either half itself, there is no hook
    exposing the full `tool_hooks` list or each tool's cache configuration to an individual
    hook the way `AbstractCapability.for_agent()` does in `adapters.pydantic_ai`.
    `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` accordingly. `authorized_params`/`invoked_params`
    are one immutable snapshot (`_freeze()`, never a copy protocol -- see its own docstring) of
    the model-supplied `arguments`, taken BEFORE `function_call` runs and reused unchanged for
    both. `BodyState.RAISED` (with `error_code`) is genuinely observed on both paths when the
    attestation holds -- Agno does not swallow a tool's exception before this hook's own call
    returns/raises. `asyncio.CancelledError` on the async path is `BodyState.ABANDONED`, still
    re-raised.

`delegation_tool_hook`/`adelegation_tool_hook` mint the child via `parent.delegate(...)`, which
never calls `guard.check()` at all -- there is no `Decision`/`call_id` to bind an outcome to,
so delegation is unaffected by any of this, on any mode or schema version. On `schema_version=1`
(the default), nothing here changes at all.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from attenu_guard import Authority, AuthorityDenied, Decision, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

__all__ = [
    "DELEGATION_TOOLS",
    "Grant",
    "GuardRegistry",
    "ToolPolicy",
    "adelegation_tool_hook",
    "aguarded_tool_hook",
    "delegation_tool_hook",
    "guarded_tool_hook",
    "principal_key",
]

#: The tools Agno injects into a Team leader for delegation.
#: `delegate_task_to_member` is the coordinate/route primitive;
#: `delegate_task_to_members` is the broadcast one (`TeamMode.broadcast`).
#: Both are registered by name in agno/team/_default_tools.py:1420,1427.
DELEGATION_TOOLS = ("delegate_task_to_member", "delegate_task_to_members")

# Spelled with `Union` rather than `X | Y`: this is a runtime-evaluated module-level
# assignment, and PEP 604 unions on typing generics only work from Python 3.10 —
# attenu-guard supports 3.9, as does Agno (Requires-Python >=3.9).
ContextSpec = Optional[
    Union[Mapping[str, Any], Callable[[Mapping[str, Any]], Mapping[str, Any]]]
]


@dataclass(frozen=True)
class ToolPolicy:
    """Says what authority one tool consumes.

    `scope` is the attenu-guard scope the tool needs. `context` supplies the
    ceiling dimensions (`{"rows": n}`, `{"egress": "any"}`, ...) — either a
    fixed mapping or a callable taking the model-supplied arguments, so a
    ceiling can depend on what the model actually asked for.
    """

    scope: str
    context: ContextSpec = None
    metered: bool = False
    disposition: Optional[str] = None     # see attenu_guard.Disposition

    def context_for(self, arguments: Mapping[str, Any]) -> Dict[str, Any]:
        if self.context is None:
            return {}
        if callable(self.context):
            return dict(self.context(arguments))
        return dict(self.context)


@dataclass(frozen=True)
class Grant:
    """The authority a parent requests for one child, plus the task that
    justifies it. `Guard.delegate` takes the meet with the parent's own
    authority, so a Grant can only ever narrow — never widen."""

    authority: Authority
    task: str


class GuardRegistry:
    """Per-run map from Agno principal id to its `Guard`.

    Seeded with the root Guard under `root_key` (the Team's id); the delegation
    hook fills in the children as the leader delegates.
    """

    def __init__(self, root: Guard, *, root_key: str) -> None:
        self._root = root
        self._guards: Dict[str, Guard] = {root_key: root}

    @property
    def root(self) -> Guard:
        return self._root

    def register(self, key: str, guard: Guard) -> None:
        self._guards[key] = guard

    def guard_for(self, key: Optional[str]) -> Optional[Guard]:
        if key is None:
            return None
        return self._guards.get(key)


def principal_key(agent: Any, team: Any) -> Optional[str]:
    """The registry key for whoever is making this tool call.

    Agno injects both objects; `agent` is None for a Team leader's own tools and
    set for a member's tools (even when that member is running inside a team),
    so agent-then-team is the right precedence.
    """
    principal = agent if agent is not None else team
    if principal is None:
        return None
    return getattr(principal, "id", None) or getattr(principal, "name", None)


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.guarded_tool_hook",
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
    `function_call` runs -- and reused as both `authorized_params` and `invoked_params`."""
    return _freeze(dict(arguments))


def _deny(decision: Decision, on_deny: str) -> None:
    """Turn a denied Decision into the exception the caller asked for."""
    error = AuthorityDenied(decision)
    if on_deny == "stop":
        from agno.exceptions import StopAgentRun

        raise StopAgentRun(str(error)) from error
    raise error


def _denied(reason: str) -> Decision:
    """A synthetic Decision for fail-closed cases the library was never asked
    about (no Guard, no ToolPolicy) — nothing to log against, so it is built
    here rather than by `Guard.check`."""
    from attenu_guard import Reason

    return Decision(allowed=False, reasons=(Reason(code="scope_not_granted", message=reason),))


def guarded_tool_hook(
    registry: GuardRegistry,
    policies: Mapping[str, ToolPolicy],
    *,
    on_deny: str = "error",
    key: Optional[str] = None,
    strict_single_hook: bool = False,
) -> Callable[..., Any]:
    """An Agno `tool_hook` that authorizes every tool call against the caller's
    Guard before the tool body runs.

    Pass as `Agent(tool_hooks=[guarded_tool_hook(registry, policies)])`. `key`
    overrides the automatic `agent.id` lookup for agents whose id you cannot
    control.

    strict_single_hook: execution-binding (0.9.0) mode switch -- see the module docstring's
                       "EXECUTION BINDING ... TWO MODES". `False` (default): every
                       `guard.check()` call is left to the Guard's own honest
                       `Capture.PRE_HOOK_ONLY` default; no outcome is ever recorded. `True`:
                       an explicit attestation that this hook is the ONLY entry in
                       `Agent(tool_hooks=[...])` for the tools it guards, AND that none of
                       them declare `cache_results=True` -- this file cannot verify either
                       half of that attestation itself; see the HONESTY NOTES.
    """

    def authorize(function_name, arguments, agent, team, *,
                  capture: str) -> "tuple[Guard, Optional[str], Any]":
        """Raise unless this call is authorized; else return `(guard, call_id_or_None,
        snapshot_or_None)` -- the last two set only for an ALLOWED, v2 check(), what the
        caller needs to close the outcome out afterward. Shared by both hook flavours."""
        lookup = key or principal_key(agent, team)
        guard = registry.guard_for(lookup)
        if guard is None:
            _deny(_denied(f"no delegated authority for principal {lookup!r}"), on_deny)

        policy = policies.get(function_name)
        if policy is None:
            # No authority is known for this tool: on the ledger as `unresolved`
            # (record_denial), not only raised — the Decisions queue folds the ledger.
            _deny(guard.record_denial(ReasonCode.NO_AUTHORITY,
                                      f"no ToolPolicy declared for tool {function_name!r}",
                                      tool=function_name, disposition=Disposition.UNRESOLVED), on_deny)

        v2 = strict_single_hook and guard.schema_version == 2
        snapshot = _snapshot_params(arguments) if v2 else None
        extra = (
            dict(capture=capture, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(
            policy.scope,
            context=policy.context_for(arguments),
            metered=policy.metered,
            tool=function_name,
            disposition=policy.disposition,
            **extra,
        )
        if not decision:
            _deny(decision, on_deny)
        return guard, (decision.call_id if v2 else None), snapshot

    def hook(function_name, function_call, arguments, agent=None, team=None):
        # Agno's own delegation tools are the delegation hook's business.
        if function_name in DELEGATION_TOOLS:
            return function_call(**(arguments or {}))
        arguments = arguments or {}
        guard, call_id, snapshot = authorize(function_name, arguments, agent, team,
                                             capture=Capture.WRAPPER_SYNC)
        if call_id is None:
            return function_call(**arguments)
        start = time.monotonic()
        try:
            result = function_call(**arguments)
        except Exception as exc:
            guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        guard.record_outcome(call_id, _body_state_for(result),
                             invoked_params=snapshot, duration_ms=_elapsed_ms(start))
        return result

    hook._dg_authorize = authorize  # type: ignore[attr-defined]
    return hook


def aguarded_tool_hook(
    registry: GuardRegistry,
    policies: Mapping[str, ToolPolicy],
    *,
    on_deny: str = "error",
    key: Optional[str] = None,
    strict_single_hook: bool = False,
) -> Callable[..., Any]:
    """Async twin of `guarded_tool_hook`, for agents whose tools are `async def`.

    Required — not optional — for async tools: Agno only reaches
    `aexecute` when the *entrypoint* is a coroutine function
    (`agno/tools/function.py:2396`), and there `next_func` is itself async
    (`:2378`). A sync hook would return that coroutine un-awaited, so the tool
    would never run and the model would receive the repr of a coroutine object
    as a *successful* result. Conversely a sync tool never reaches this hook:
    async hooks are dropped from the sync chain with only a warning
    (`agno/tools/function.py:2081`). Match the flavour to the tool.

    strict_single_hook: see `guarded_tool_hook`'s own docstring.
    """
    sync = guarded_tool_hook(registry, policies, on_deny=on_deny, key=key,
                             strict_single_hook=strict_single_hook)
    authorize = sync._dg_authorize  # type: ignore[attr-defined]

    async def hook(function_name, function_call, arguments, agent=None, team=None):
        if function_name in DELEGATION_TOOLS:
            return await function_call(**(arguments or {}))
        arguments = arguments or {}
        guard, call_id, snapshot = authorize(function_name, arguments, agent, team,
                                             capture=Capture.WRAPPER_ASYNC)
        if call_id is None:
            return await function_call(**arguments)
        start = time.monotonic()
        try:
            result = await function_call(**arguments)
        except asyncio.CancelledError:
            # The wrapper stopped observing while the body may still run -- `abandoned`, not
            # `raised`; still re-raised so cancellation propagates normally.
            guard.record_outcome(call_id, BodyState.ABANDONED,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        except Exception as exc:
            guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        guard.record_outcome(call_id, _body_state_for(result),
                             invoked_params=snapshot, duration_ms=_elapsed_ms(start))
        return result

    return hook


def delegation_tool_hook(
    registry: GuardRegistry,
    grants: Mapping[str, Grant],
    *,
    on_deny: str = "error",
    key: Optional[str] = None,
    members: Optional[Sequence[str]] = None,
) -> Callable[..., Any]:
    """An Agno `tool_hook` that mints a child Guard at the moment the leader
    delegates.

    Pass as `Team(tool_hooks=[delegation_tool_hook(registry, grants)])`.
    `grants` maps member id -> `Grant`. A member with no Grant is refused: you
    cannot delegate to an agent whose authority you have not written down.

    Each delegation mints a *fresh* child Guard, so two tasks handed to the same
    member are two separate, separately-revocable grants in the audit trail.
    For `delegate_task_to_members` (broadcast) the tool carries no member id, so
    every member of the team is minted; pass `members` to override the list.
    """

    def mint(function_name, arguments, agent, team) -> None:
        """Mint the child Guard(s) for this delegation, or raise."""
        parent = registry.guard_for(key or principal_key(agent, team))
        if parent is None:
            _deny(_denied("delegating agent holds no authority"), on_deny)

        if function_name == "delegate_task_to_member":
            targets = [arguments.get("member_id")]
        else:  # broadcast: no member id in the call, so mint for every member
            targets = list(members) if members is not None else _team_member_keys(team)

        for target in targets:
            grant = grants.get(target) if target is not None else None
            if grant is None:
                _deny(_denied(f"no Grant declared for member {target!r}"), on_deny)
            child = parent.delegate(
                target,
                grant.authority,
                task=arguments.get("task") or grant.task,
            )
            registry.register(target, child)

    def hook(function_name, function_call, arguments, agent=None, team=None):
        if function_name not in DELEGATION_TOOLS:
            return function_call(**(arguments or {}))
        arguments = arguments or {}
        mint(function_name, arguments, agent, team)
        return function_call(**arguments)

    hook._dg_mint = mint  # type: ignore[attr-defined]
    return hook


def adelegation_tool_hook(
    registry: GuardRegistry,
    grants: Mapping[str, Grant],
    *,
    on_deny: str = "error",
    key: Optional[str] = None,
    members: Optional[Sequence[str]] = None,
) -> Callable[..., Any]:
    """Async twin of `delegation_tool_hook`. Agno builds an async
    `delegate_task_to_member` for async runs (`agno/team/_default_tools.py:1423`),
    so a Team driven with `arun`/`aprint_response` needs this flavour. See
    `aguarded_tool_hook` for why the flavour must match."""
    sync = delegation_tool_hook(registry, grants, on_deny=on_deny, key=key, members=members)
    mint = sync._dg_mint  # type: ignore[attr-defined]

    async def hook(function_name, function_call, arguments, agent=None, team=None):
        if function_name not in DELEGATION_TOOLS:
            return await function_call(**(arguments or {}))
        arguments = arguments or {}
        mint(function_name, arguments, agent, team)
        return await function_call(**arguments)

    return hook


def _team_member_keys(team: Any) -> list:
    members = getattr(team, "members", None) or []
    keys = []
    for member in members:
        member_key = getattr(member, "id", None) or getattr(member, "name", None)
        if member_key is not None:
            keys.append(member_key)
    return keys
