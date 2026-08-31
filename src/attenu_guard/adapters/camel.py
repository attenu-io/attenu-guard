"""attenu_guard.adapters.camel — a thin attenu-guard integration for CAMEL-AI.

Tested against camel-ai 0.2.90 (Apache-2.0), Python 3.14.

WHY THIS EXISTS
---------------
CAMEL's sub-agent delegation gives the child everything the parent has.
`AgentToolkit.agent_run_subagent` (camel/toolkits/agent_toolkit.py:286) is the
documented way for one agent to hand a task to another; the child is built by
`_create_subagent` (agent_toolkit.py:161), whose tool list comes from
`_resolve_child_tools` (agent_toolkit.py:149) -> `ChatAgent._clone_tools`
(camel/agents/chat_agent.py:6183). That clone is a copy of the parent's WHOLE
toolset. The sub-agent's task is narrow; its authority is not. Nothing in CAMEL
relates what the child may do to what the delegated task needs, and nothing
narrows the child a second time when it delegates onward.

The same gap exists on the Workforce path: `Workforce._post_task`
(camel/societies/workforce/workforce.py:4071) hands a task to a worker over the
task channel, and the worker runs it with whatever tools its author gave the
`ChatAgent` (`SingleAgentWorker.__init__`, single_agent_worker.py:234). The task
is per-assignment; the authority is fixed at construction.

This module supplies the missing narrowing, at the two points where it can be
enforced rather than requested.

THE TWO HOOK POINTS
-------------------
1. **Tool invocation** -> `GuardedFunctionTool`, a `camel.toolkits.FunctionTool`
   subclass that runs `guard.check(scope, ...)` before the wrapped tool's body.
   `FunctionTool` is the single object every CAMEL tool call goes through:

     - sync:      `ChatAgent._execute_tool` calls `tool(**args)`
                  (chat_agent.py:4048) -> `FunctionTool.__call__`
                  (camel/toolkits/function_tool.py:613);
     - async:     `ChatAgent._aexecute_tool` tries `tool.func.async_call`,
                  then `tool.async_call` (chat_agent.py:4093-4099) ->
                  `FunctionTool.async_call` (function_tool.py:700);
     - streaming: `_execute_tool_from_stream_data` calls `tool(**args)`
                  (chat_agent.py:5031) and its async twin repeats the
                  `tool.func.async_call` / `tool.async_call` ladder
                  (chat_agent.py:5165-5172).

   Both `__call__` and `async_call` are overridden here, so every one of those
   paths authorizes first. The `tool.func.async_call` branch is the one that
   would otherwise reach around an `async_call` override; `__init__` closes it
   by making sure `self.func` never carries an `async_call` attribute (see
   `_normalize_func`). Subclassing `FunctionTool` is CAMEL's own extension
   mechanism, so no monkeypatching is involved, and the model-facing schema is
   copied verbatim from the inner tool -- the wrapper is invisible upstream.

2. **Delegation / handoff** -> `GuardedAgentToolkit`, an `AgentToolkit`
   subclass. CAMEL fires no callback at handoff time, so the hook is the
   delegation call itself: `agent_run_subagent` is overridden to mint a fresh
   child Guard with `parent_guard.delegate(...)` -- provably narrower than the
   parent, whatever authority is asked for -- and `_create_subagent` is
   overridden to build the sub-agent from tools bound to THAT Guard instead of
   cloning the parent's toolset. Every handoff, including a resumed session,
   gets its own node id, its own task string, and its own `spawn` entry in the
   hash-chained audit log.

USAGE
-----
    def child_tools(ref):                       # built fresh per delegation
        return guard_tools(ref, {crm_query: "crm.read"},
                           context_fns={"crm_query": lambda rows: {"rows": rows}})

    root = Guard.issue("orchestrator", Authority(scopes={"crm.*", "mail.send"},
                       ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    ref = GuardRef(root)
    toolkit = GuardedAgentToolkit(
        parent_guard=root,
        authority=Authority(scopes={"crm.read"},
                            ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        child_tools=child_tools)
    parent = ChatAgent(system_message=..., model=model,
                       tools=[*guard_tools(ref, {crm_query: "crm.read",
                                                 crm_export: "crm.export"}),
                              *toolkit.get_tools()],
                       toolkits_to_register_agent=[toolkit])
    parent.step("Summarise the Q3 pipeline.")

A denial raises `AuthorityDenied` from inside the wrapper, before the tool body.
`ChatAgent._execute_tool` catches it (chat_agent.py:4059) and records it as the
tool's result, so the model sees "you are not authorized to do that" and can
adapt instead of the run dying. Pass `on_denied="return"` to hand the model the
explanation as ordinary tool output instead of an error.

This module imports `camel` (it subclasses `FunctionTool` and `AgentToolkit`)
and nothing from `attenu_guard` beyond the public API -- no library changes are
needed on either side.

Execution binding (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`): `GuardedFunction
Tool.__call__`/`async_call` call the inner tool themselves (`super().__call__(...)` /
`self._inner_async_call(...)`/`super().async_call(...)`), exactly like `adapters.langgraph`'s
reference wiring, so `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` is a genuine observation. `authorized
_params`/`invoked_params` are one immutable snapshot (`_freeze()`, never a copy protocol -- see
its own docstring) of `{"args": [...], "kwargs": {...}}`, taken BEFORE the inner tool runs and
reused unchanged for both. `BodyState.RAISED` (with `error_code`) is genuinely observed on both
paths -- CAMEL does not swallow a tool's exception before this wrapper's own call returns/raises
(`ChatAgent._execute_tool`'s own `except` runs OUTSIDE this wrapper, around the whole call).
`asyncio.CancelledError` on the async path is `BodyState.ABANDONED`, still re-raised. Minting a
child Guard (`GuardedAgentToolkit.mint`) goes through `parent_guard.enforce(...)`, which never
returns a `Decision`/`call_id` (it raises on deny, returns `None` on allow) -- there is nothing
to bind an outcome to, so delegation is unaffected by any of this, on any schema version. On
`schema_version=1` (the default), nothing here changes at all.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import functools
import inspect
import time
from typing import Any, Callable, Iterable, List, Mapping, Optional, Union

from camel.toolkits import FunctionTool
from camel.toolkits.agent_toolkit import AgentToolkit

from attenu_guard import Authority, AuthorityDenied, Guard, __version__
from attenu_guard.reasons import BodyState, Capture

__all__ = [
    "GuardRef",
    "UnboundGuard",
    "GuardedFunctionTool",
    "guard_tools",
    "guard_toolkit",
    "GuardedAgentToolkit",
]


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.GuardedFunctionTool._authorize",
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


def _freeze(value: Any) -> Any:
    """A genuinely immutable, fully decoupled rebuild of `value` -- NEVER calls a copy protocol
    (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back itself (or
    another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is independent
    of the live object graph, so a "snapshot" built that way can silently change out from under
    the commitment when the tool body (or CAMEL itself) later mutates the original in place.
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


def _snapshot_params(args, kwargs) -> Any:
    """An immutable snapshot of the call's arguments, taken BEFORE the inner tool runs and
    reused for both `authorized_params` and `invoked_params`."""
    return _freeze({"args": list(args), "kwargs": dict(kwargs)})


class UnboundGuard(RuntimeError):
    """Raised when a guarded tool runs while its `GuardRef` holds no Guard.

    A wiring error, not a policy outcome: there is no authority to evaluate
    against, so there is nothing meaningful to audit. It is still fail-closed —
    it is raised before the wrapped tool's body, and CAMEL surfaces it as a tool
    error like any other.
    """


GuardLike = Union[Guard, "GuardRef", Callable[[], Guard], None]


class GuardRef:
    """A late-bound handle on "the Guard currently in force for this agent".

    A sub-agent's tools are wired up once, when the agent is constructed, but
    its authority is minted per handoff — `GuardedAgentToolkit` calls
    `parent.delegate(...)` on every `agent_run_subagent`, so each delegation
    gets its own node id and its own audit entry. `GuardRef` is the indirection
    that lets already-constructed tools see that fresh Guard.

    It is never widened after a call: the last (narrowest) delegated Guard stays
    in force, so a stray tool invocation between handoffs is evaluated against
    attenuated authority rather than the orchestrator's. Before the first
    delegation it holds `None` and every guarded call fails closed with
    `UnboundGuard`.
    """

    __slots__ = ("guard",)

    def __init__(self, guard: Optional[Guard] = None):
        self.guard = guard

    def resolve(self) -> Guard:
        if self.guard is None:
            raise UnboundGuard(
                "no Guard is bound to this GuardRef: the tool was invoked "
                "outside any delegation. Mint one with parent.delegate(...) "
                "(GuardedAgentToolkit does this for you) before running the agent."
            )
        return self.guard

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"GuardRef(node_id={getattr(self.guard, 'node_id', None)!r})"


def _resolve(guard_like: GuardLike) -> Guard:
    """Accept a `Guard`, a `GuardRef`, or a zero-arg callable returning one."""
    if guard_like is None:
        raise UnboundGuard("no Guard supplied")
    if isinstance(guard_like, GuardRef):
        return guard_like.resolve()
    if isinstance(guard_like, Guard):
        return guard_like
    if callable(guard_like):
        got = guard_like()
        if got is None:
            raise UnboundGuard("guard provider returned None")
        return got
    raise TypeError(f"cannot resolve a Guard from {guard_like!r}")


def _normalize_func(func: Callable) -> tuple[Callable, Optional[Callable]]:
    """Return `(func_for_FunctionTool, inner_async_call)`.

    `ChatAgent._aexecute_tool` checks `hasattr(tool.func, 'async_call')` FIRST
    (chat_agent.py:4093) and, when it is there, awaits `tool.func.async_call`
    directly — reaching around any `async_call` override on the tool itself.
    That branch exists for a `FunctionTool` wrapping an MCP tool. So when the
    inner callable carries an `async_call`, it is replaced with a plain function
    that does not, and the original is handed back for `GuardedFunctionTool`'s
    own (authorizing) `async_call` to await.
    """
    inner_async_call = getattr(func, "async_call", None)
    if inner_async_call is None or not callable(inner_async_call):
        return func, None

    target = func

    def _sync_shim(*args: Any, **kwargs: Any) -> Any:
        return target(*args, **kwargs)

    try:  # best effort: an MCP tool object may have no __name__/__doc__
        functools.update_wrapper(_sync_shim, target)
    except (AttributeError, TypeError):  # pragma: no cover - exotic callables
        _sync_shim.__name__ = getattr(target, "name", "tool")
    return _sync_shim, inner_async_call


class GuardedFunctionTool(FunctionTool):
    """Wraps a CAMEL tool so every invocation is authorized first.

    Parameters
    ----------
    inner : FunctionTool | Callable
        The real tool. A plain callable is promoted to a `FunctionTool` first,
        so the schema CAMEL derives is the one it would have derived anyway.
        The inner tool's `openai_tool_schema` is then copied verbatim onto the
        wrapper: the model sees an identical tool and cannot tell it is there.
    guard : Guard | GuardRef | callable
        The authority to check against — the Guard belonging to THIS agent
        (typically a `GuardRef` filled in by `GuardedAgentToolkit`), never the
        orchestrator's broader one.
    scope : str
        The scope this tool needs, e.g. `"crm.read"`.
    context_fn : callable, optional
        Receives the exact `*args, **kwargs` the tool was called with and
        returns the context mapping `guard.check()` evaluates typed ceilings
        against, e.g. `{"rows": rows}`. Omit for a scope-only check. If it
        raises, the tool body still does not run — fail-closed.
    metered : bool
        Passed to `guard.check(metered=...)`; set True for tools that consume a
        metered ceiling, so a Guard issued with `strict_metering=True` refuses a
        call that declares no quantity.
    on_denied : {"raise", "return"}
        `"raise"` (default) raises `AuthorityDenied`; `ChatAgent._execute_tool`
        catches it (chat_agent.py:4059) and records it as the tool result, which
        the model reads and can react to. `"return"` returns
        `decision.explain()` as the tool's output instead.
    disposition : str, optional
        A `attenu_guard.Disposition` value recorded on the deny entry.
    """

    def __init__(self, inner: Union[FunctionTool, Callable], guard: GuardLike,
                 scope: str, *,
                 context_fn: Optional[Callable[..., Mapping]] = None,
                 metered: bool = False,
                 on_denied: str = "raise",
                 disposition: Optional[str] = None) -> None:
        if on_denied not in ("raise", "return"):
            raise ValueError('on_denied must be "raise" or "return"')
        inner_tool = inner if isinstance(inner, FunctionTool) else FunctionTool(inner)
        func, inner_async_call = _normalize_func(inner_tool.func)
        # Copy the schema rather than re-deriving it: identical model-facing
        # tool, and no schema-synthesis model is ever constructed.
        super().__init__(
            func=func,
            openai_tool_schema=copy.deepcopy(inner_tool.openai_tool_schema),
        )
        self.inner = inner_tool
        self._inner_async_call = inner_async_call
        self.guard = guard
        self.scope = scope
        self.context_fn = context_fn
        self.metered = metered
        self.on_denied = on_denied
        self.disposition = disposition

    # -- the authorization core --------------------------------------------
    def _authorize(self, args: tuple, kwargs: dict, *,
                   capture: str) -> "tuple[Optional[str], Optional[Guard], Any, Any]":
        """Return `(denial_text_or_None, guard, call_id_or_None, snapshot_or_None)`.

        Never returns a denial normally unless `on_denied="return"`: the
        caller has no way to accidentally continue into the tool body. The
        last two fields are set only for an ALLOWED, v2 check() -- what the
        caller needs to close the outcome out afterward. `capture` is
        `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` depending on which of `__call__`/
        `async_call` is authorizing.
        """
        guard = _resolve(self.guard)
        context: Mapping = self.context_fn(*args, **kwargs) if self.context_fn else {}
        v2 = guard.schema_version == 2
        snapshot = _snapshot_params(args, kwargs) if v2 else None
        extra = (
            dict(capture=capture, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(self.scope, context=context, metered=self.metered,
                               tool=self.get_function_name(),
                               disposition=self.disposition, **extra)
        if decision:
            return None, guard, (decision.call_id if v2 else None), snapshot
        if self.on_denied == "return":
            return f"AUTHORITY DENIED: {decision.explain()}", None, None, None
        raise AuthorityDenied(decision)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        denied, guard, call_id, snapshot = self._authorize(args, kwargs, capture=Capture.WRAPPER_SYNC)
        if denied is not None:
            return denied
        if call_id is None:
            return super().__call__(*args, **kwargs)
        start = time.monotonic()
        try:
            result = super().__call__(*args, **kwargs)
        except Exception as exc:
            guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        guard.record_outcome(call_id, _body_state_for(result),
                             invoked_params=snapshot, duration_ms=_elapsed_ms(start))
        return result

    async def async_call(self, *args: Any, **kwargs: Any) -> Any:
        denied, guard, call_id, snapshot = self._authorize(args, kwargs, capture=Capture.WRAPPER_ASYNC)
        if denied is not None:
            return denied

        async def _invoke():
            if self._inner_async_call is not None:
                return await self._inner_async_call(*args, **kwargs)
            return await super(GuardedFunctionTool, self).async_call(*args, **kwargs)

        if call_id is None:
            return await _invoke()
        start = time.monotonic()
        try:
            result = await _invoke()
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

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"GuardedFunctionTool(name={self.get_function_name()!r}, "
                f"scope={self.scope!r})")


def guard_tools(guard: GuardLike,
                scopes: Mapping[Union[FunctionTool, Callable], str],
                *,
                context_fns: Optional[Mapping[str, Callable[..., Mapping]]] = None,
                metered: Optional[Iterable[str]] = None,
                on_denied: str = "raise") -> List[GuardedFunctionTool]:
    """Wrap a whole tool list in one call — the usual entry point.

        tools = guard_tools(ref, {crm_query: "crm.read", crm_export: "crm.export"},
                            context_fns={"crm_query": lambda rows: {"rows": rows}})

    `scopes` maps each tool (a `FunctionTool` or a plain callable) to the scope
    it requires. `context_fns` and `metered` are keyed by TOOL NAME. Returns
    `GuardedFunctionTool`s in the same order, ready to pass to `tools=[...]`.
    """
    context_fns = context_fns or {}
    metered_names = set(metered or ())
    out: List[GuardedFunctionTool] = []
    for tool, scope in scopes.items():
        inner = tool if isinstance(tool, FunctionTool) else FunctionTool(tool)
        name = inner.get_function_name()
        out.append(GuardedFunctionTool(
            inner, guard, scope,
            context_fn=context_fns.get(name),
            metered=name in metered_names,
            on_denied=on_denied))
    return out


def guard_toolkit(guard: GuardLike,
                  toolkit: Any,
                  scopes: Mapping[str, str],
                  *,
                  context_fns: Optional[Mapping[str, Callable[..., Mapping]]] = None,
                  metered: Optional[Iterable[str]] = None,
                  on_denied: str = "raise",
                  on_unmapped: str = "deny") -> List[GuardedFunctionTool]:
    """Guard every tool a `BaseToolkit` exposes, keyed by tool name.

        tools = guard_toolkit(ref, SearchToolkit(),
                              {"search_wiki": "web.search", "search_exa": "web.search"})

    `scopes` maps the toolkit's tool names — CAMEL requires them to carry the
    toolkit's own prefix, e.g. `search_wiki`, `github_create_issue` — to the
    scope each consumes. `on_unmapped="deny"` (the default) refuses to build the
    list when the toolkit exposes a tool the caller did not price, so a toolkit
    that grows a tool in a later release cannot silently arrive unguarded; pass
    `"allow"` to let unmapped tools through unwrapped.
    """
    if on_unmapped not in ("deny", "allow"):
        raise ValueError('on_unmapped must be "deny" or "allow"')
    tools = list(toolkit.get_tools())
    names = [t.get_function_name() for t in tools]
    unmapped = [n for n in names if n not in scopes]
    if unmapped and on_unmapped == "deny":
        raise ValueError(
            f"{type(toolkit).__name__} exposes {unmapped!r}, whose authority cost "
            f"is undeclared, so those calls cannot be authorized. Add them to "
            f"`scopes` or pass on_unmapped='allow'.")
    return guard_tools(
        guard,
        {t: scopes[t.get_function_name()] for t in tools
         if t.get_function_name() in scopes},
        context_fns=context_fns, metered=metered, on_denied=on_denied)


# ==========================================================================
# Hook point 2 — delegation
# ==========================================================================

class GuardedAgentToolkit(AgentToolkit):
    """`AgentToolkit` that attenuates the sub-agent instead of cloning the parent.

    Stock `AgentToolkit` builds the child from `ChatAgent._clone_tools()`
    (chat_agent.py:6183, reached via `_resolve_child_tools`,
    agent_toolkit.py:149), so the sub-agent holds the parent's entire toolset
    for a task that needs a slice of it. This subclass replaces both ends of
    that: `agent_run_subagent` mints the child's Guard, and `_create_subagent`
    builds the child from tools bound to that Guard.

    Parameters
    ----------
    parent_guard : Guard
        The delegating agent's own Guard.
    authority : Authority
        What each sub-agent REQUESTS. What it gets is `meet(parent, request)` —
        it can only shrink, whatever this asks for.
    child_tools : callable
        `child_tools(ref: GuardRef) -> list` — builds the sub-agent's tools
        bound to the fresh child Guard. Called once per new session; use
        `guard_tools(ref, ...)` inside it.
    agent_id_prefix : str
        Label recorded as the child's agent id in the audit log.
    delegate_scope : str, optional
        When set, `parent_guard.enforce(delegate_scope)` runs first: may this
        parent hand off at all? A denial raises `AuthorityDenied` before any
        sub-agent exists.

    Every minted child Guard is kept in `.child_guards`, which is what you
    revoke: `root.revoke(toolkit.child_guards[-1].node_id)` cascades to the whole
    subtree, and because the session's `GuardRef` still points at that Guard,
    every subsequent tool call by that sub-agent is denied with `REVOKED`.

    NOTE: the sub-agent is deliberately NOT given this toolkit, so it cannot
    delegate onward under a Guard that was never minted for it. To allow a
    grandchild, hand the child its own `GuardedAgentToolkit` from inside
    `child_tools`, rooted at the Guard in the `GuardRef` it is passed.
    """

    def __init__(self, *,
                 parent_guard: Guard,
                 authority: Authority,
                 child_tools: Callable[[GuardRef], Iterable[Any]],
                 agent_id_prefix: str = "subagent",
                 delegate_scope: Optional[str] = None,
                 delegate_context: Optional[Mapping] = None,
                 timeout: Optional[float] = None) -> None:
        super().__init__(timeout=timeout)
        self.parent_guard = parent_guard
        self.authority = authority
        self.child_tools = child_tools
        self.agent_id_prefix = agent_id_prefix
        self.delegate_scope = delegate_scope
        self.delegate_context = dict(delegate_context or {})
        self.child_guards: List[Guard] = []
        self._guard_refs: dict = {}       # sub-agent agent_id -> GuardRef
        self._pending_ref: Optional[GuardRef] = None

    # -- the delegation hook ------------------------------------------------
    def mint(self, label: str, task: str) -> Guard:
        """Mint a fresh child Guard for `task`.

        Raises `AuthorityDenied` when `delegate_scope` is set and this parent
        may not delegate, and `AuthorityError` for structural failures (parent
        revoked or expired, chain depth/fanout exceeded).
        """
        if self.delegate_scope:
            self.parent_guard.enforce(self.delegate_scope,
                                      context=self.delegate_context,
                                      tool="agent_run_subagent")
        child = self.parent_guard.delegate(label, self.authority, task=task)
        self.child_guards.append(child)
        return child

    def _create_subagent(self, subagent_type: str, description: str):
        from camel.agents import ChatAgent

        parent = self._require_parent_agent()
        if parent is None:
            return None
        ref = self._pending_ref
        if ref is None:
            # Fail closed: reached only if a caller drove `_create_subagent`
            # outside `agent_run_subagent`, i.e. with no Guard minted.
            raise UnboundGuard(
                "GuardedAgentToolkit._create_subagent was called with no child "
                "Guard minted; sub-agents are only created through "
                "agent_run_subagent().")
        agent = ChatAgent(
            system_message=self._build_system_message(
                subagent_type=subagent_type, description=description),
            model=parent.model_backend.models,
            output_language=getattr(parent, "_output_language", None),
            tools=list(self.child_tools(ref)),
            max_iteration=parent.max_iteration,
        )
        self._guard_refs[agent.agent_id] = ref
        return agent

    def agent_run_subagent(self, prompt: str,
                           description: str = "Specialized sub-agent task",
                           subagent_type: str = "general-purpose",
                           agent_id: Optional[str] = None,
                           wait: bool = True,
                           timeout: Optional[float] = None):
        # Mint BEFORE super() runs, because super() calls `_create_subagent`,
        # which needs the child Guard to build the child's tools against.
        if prompt and prompt.strip() and self._require_parent_agent() is not None:
            ref = None
            if agent_id is not None:
                # Resolve the session BEFORE minting: an id this toolkit never
                # minted must not leave a stray delegation on the chain (it
                # would consume the parent's fanout budget and land in the
                # ledger as a handoff that never happened).
                ref = self._guard_refs.get(agent_id)
                if ref is None:
                    return self._error_result(
                        f"sub-agent {agent_id!r} has no delegated authority on "
                        f"this chain; it cannot be resumed.",
                        agent_id=agent_id, task_id=None, created=False,
                        subagent_type=subagent_type, description=description)
            child = self.mint(f"{self.agent_id_prefix}:{subagent_type}", prompt)
            if ref is None:
                self._pending_ref = GuardRef(child)
            else:
                ref.guard = child
        try:
            return super().agent_run_subagent(
                prompt=prompt, description=description,
                subagent_type=subagent_type, agent_id=agent_id,
                wait=wait, timeout=timeout)
        finally:
            self._pending_ref = None

    def guard_for(self, agent_id: str) -> Optional[Guard]:
        """The Guard currently in force for one sub-agent session."""
        ref = self._guard_refs.get(agent_id)
        return None if ref is None else ref.guard

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"GuardedAgentToolkit(parent={self.parent_guard.node_id!r}, "
                f"delegations={len(self.child_guards)})")


# The model-facing schema must stay byte-identical to stock CAMEL's, and
# `FunctionTool` derives it from the signature and docstring. Reuse the
# original docstring rather than restating it.
GuardedAgentToolkit.agent_run_subagent.__doc__ = (
    AgentToolkit.agent_run_subagent.__doc__)
