"""attenu_guard.adapters.astrbot — attenu-guard × AstrBot.

A thin, paste-into-your-project adapter that enforces monotonic authority
attenuation across an AstrBot agent's tool calls and its sub-agent (handoff)
delegations.

Hook points used
----------------
* TOOL INVOCATION — the tool object itself, via AstrBot's own guarded-tool
  contract. `FunctionToolExecutor._execute_local`
  (`astrbot/core/astr_agent_tool_exec.py`) picks what to invoke in this order:
  `tool.handler` first, then an overriding `call()`, then `run()`. AstrBot's own
  permission wrapper (`_PermissionGuardedTool` in
  `astrbot/core/provider/func_tool_manager.py`) exploits exactly that: it keeps
  `handler = None` so the executor is forced through its `call()`. This adapter's
  `GuardedTool` is the same shape — a `FunctionTool` subclass with `handler=None`
  and an overriding `call()` — so the Guard runs before the wrapped tool's body,
  on EVERY invocation path, and the body never runs on a denial.

* INSTALLATION ON EVERY AGENT, INCLUDING SUB-AGENTS — the tool manager's
  registry (`FunctionToolManager.func_list`, the list plugins register into via
  `add_func` / the `llm_tools` singleton). `install(tool_manager)` replaces each
  registered tool in place with a `GuardedTool` around it. That matters here,
  because a sub-agent's toolset is built by
  `FunctionToolExecutor._build_handoff_toolset`, which resolves tools from that
  same registry along TWO different branches:

      - `Agent.tools is None`  -> `tool_mgr.get_full_tool_set()`
      - `Agent.tools = [name]` -> `tool_mgr.get_func(name)`

  On AstrBot bd4b198a those two branches do NOT agree: `get_full_tool_set()`
  wraps each tool in `_PermissionGuardedTool`, while the named-tools branch
  returns the raw tool, so a tool marked `admin` in `tool_permissions` runs for a
  non-admin when it is assigned to a sub-agent by name. Guarding the REGISTRY
  rather than a toolset sidesteps that split by construction: both branches hand
  out the same already-guarded objects, and `get_full_tool_set()`'s extra
  `_PermissionGuardedTool` simply delegates into this adapter's `call()` (it
  routes through `type(self._wrapped).call` when the wrapped tool overrides it).

* CHILD CREATION / DELEGATION — `BaseFunctionToolExecutor`, the tool executor
  the agent runner is given (`astrbot.api.BaseFunctionToolExecutor`;
  `ToolLoopAgentRunner.reset(tool_executor=...)`). `executor_class()` returns a
  `FunctionToolExecutor` subclass whose `_execute_handoff` mints the child with
  `parent_guard.delegate(...)` and installs it as the active Guard (a
  `ContextVar`) for the duration of the sub-agent's run. AstrBot runs that
  sub-agent synchronously inside the same task (`await ctx.tool_loop_agent(...)`),
  so the ContextVar is in force for the child's own tool calls and is reset when
  the handoff returns.

  LIMIT, stated plainly: AstrBot's two production call sites construct the
  executor themselves — `astrbot/core/astr_main_agent.py` (`tool_executor=
  FunctionToolExecutor()`) and `Context.tool_loop_agent` in
  `astrbot/core/star/context.py`. Neither takes an executor from the caller, so
  in stock AstrBot the delegation hook applies only where YOUR code drives
  `ToolLoopAgentRunner` and passes `executor_class()`; reaching it on AstrBot's
  own path needs a one-line change there. The tool-invocation hook above needs no
  such change: it is installed into the registry and covers the parent and every
  sub-agent, both toolset branches included.

Usage
-----
::

    from astrbot.core.provider.register import llm_tools

    root = Guard.issue("astrbot-main", Authority(
        scopes={"chat.*", "admin.*"},
        ceilings=[Allow("admin_tool_role", {"admin"})], ttl=3600))

    guarded = GuardedDelegation(
        root,
        tools={"secret_delete_all": ToolPolicy(
            "admin.delete", context=lambda args: {})},
        subagents={"assistant": Authority(scopes={"chat.*"}, ttl=900)},
    )
    guarded.install(llm_tools)

The policy map is shared by every agent on purpose: the *map* says which scope a
tool needs, the *Guard* says whether this particular agent still holds it. A
ceiling declared once on the root Authority is carried onto every delegated node
by `Authority.meet`, so it binds the sub-agent without anyone wiring it into the
sub-agent's definition — which is the point when the sub-agent's own toolset is
what dropped the check.

Every `check()` is given a caller context bag as well as the tool's own
arguments. By default that bag is `{"role", "is_admin", "sender_id", "session"}`
read off `run_context.context.event` (`AstrMessageEvent.role` / `.is_admin()` /
`.get_sender_id()` / `.unified_msg_origin`), so WHO made the call is on the
ledger and available to ceilings without every policy restating it. Pass
`caller_context=` to change what is collected.

Denial behaviour
----------------
`on_deny="tool_error"` (default) returns an error string as the tool's result —
the same shape AstrBot's own `_check_tool_permission` returns ("error:
Permission denied. …"), so the denial goes back to the model as a normal tool
result and the agent loop keeps running. `on_deny="raise"` raises
`attenu_guard.AuthorityDenied` out of the tool call. Either way the wrapped
tool's body never executes.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain — see `Guard.issue`)
---------------------------------------------------------------------------
`inner()` — what `GuardedTool.call` invokes — is the wrapped tool's own handler /
`call()` / `run()`, resolved with the same precedence `_execute_local` uses. So
"my `inner` call is the real body" holds whenever the tool this adapter wrapped
is itself the real tool, which is what `install()` on a freshly registered
registry gives you; a tool the application had already wrapped with something
that substitutes a result would be indistinguishable from the body, exactly as
in `adapters.langchain`.

  * DEFAULT (`strict_single_hook=False`): no `capture`/`authorized_params` is
    passed; the Guard stamps its own honest `Capture.PRE_HOOK_ONLY` and no
    outcome is ever recorded.
  * STRICT (`strict_single_hook=True`): an explicit attestation that the wrapped
    tool is the real body. `Capture.WRAPPER_ASYNC` is passed (AstrBot's tool
    invocation is async throughout), and the outcome is closed out from `inner`'s
    own return/raise. `authorized_params`/`invoked_params` are one immutable
    snapshot (`_freeze()`) of the tool-call arguments, taken before the body runs
    and reused unchanged for both. This file cannot verify the attestation.
"""
from __future__ import annotations

import contextvars
import inspect
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping, Optional, Sequence

from attenu_guard import (
    Authority, AuthorityDenied, AuthorityError, Decision, Guard, Reason, __version__,
)
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

from ._snapshot import freeze as _freeze

__all__ = [
    "ToolPolicy",
    "GuardedDelegation",
    "GuardedTool",
    "caller_facts",
    "current_guard",
    "use_guard",
]


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


def _adapter_info(hook: str) -> dict:
    return {"module": __name__, "version": __version__, "hook_path": f"{__name__}.{hook}"}


# ---------------------------------------------------------------------------
# The active Guard. AstrBot awaits a sub-agent run inside the parent's handoff
# tool call, in the same task, so a Guard installed by the delegation hook is
# visible to the child's tool calls and is reset when the handoff returns.
# ---------------------------------------------------------------------------
_ACTIVE_GUARD: contextvars.ContextVar[Optional[Guard]] = contextvars.ContextVar(
    "attenu_guard_active_astrbot", default=None
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


def caller_facts(run_context: Any) -> dict:
    """WHO is making this call, read off the AstrBot event.

    `AstrMessageEvent.is_admin()` is literally `self.role == "admin"`, and the
    role is set by the platform adapter from the message's own sender, so this is
    the framework's own notion of the caller — not something the model can state
    about itself.
    """
    event = getattr(getattr(run_context, "context", None), "event", None)
    if event is None:
        return {}
    facts: dict = {}
    role = getattr(event, "role", None)
    if role is not None:
        facts["role"] = role
    is_admin = getattr(event, "is_admin", None)
    if callable(is_admin):
        try:
            facts["is_admin"] = bool(is_admin())
        except Exception:
            pass
    sender = getattr(event, "get_sender_id", None)
    if callable(sender):
        try:
            facts["sender_id"] = sender()
        except Exception:
            pass
    umo = getattr(event, "unified_msg_origin", None)
    if umo is not None:
        facts["session"] = umo
    return facts


@dataclass(frozen=True)
class ToolPolicy:
    """What one tool needs in order to run.

    scope:   the attenu-guard scope, e.g. `"admin.delete"`.
    context: optional callable mapping the tool-call arguments to the context bag
             ceilings are evaluated against. It is merged OVER the caller facts
             (`caller_facts`), so a policy can name a caller fact under the key a
             ceiling watches — e.g. `lambda args, caller: {"admin_tool_role":
             caller.get("role")}` marks this tool as admin-only under a single
             `Allow("admin_tool_role", {"admin"})` ceiling. A one-argument
             callable is accepted too, and is given the arguments alone.
    metered: forwarded to `Guard.check(metered=...)`.
    disposition: optional `Disposition` the authority source knows about this
             tool (`held_pending_grant` · `withheld_tier2` · `unresolved`);
             recorded on a `deny` so "held" never reads as "denied".
    """

    scope: str
    context: Optional[Callable[..., Mapping[str, Any]]] = None
    metered: bool = False
    disposition: Optional[str] = None

    def context_for(self, args: Mapping[str, Any], caller: Mapping[str, Any]) -> Mapping[str, Any]:
        bag = dict(caller)
        if self.context is None:
            return bag
        try:
            extra = self.context(args, caller)          # type: ignore[call-arg]
        except TypeError:
            extra = self.context(args)                  # type: ignore[call-arg]
        bag.update(extra or {})
        return bag


class GuardedDelegation:
    """Binds a attenu-guard chain to an AstrBot agent tree.

    Parameters
    ----------
    root : Guard
        The Guard this conversation runs under. Sub-agents are delegated from the
        Guard active when the handoff runs, so a grandchild is attenuated from
        the child, not from the root.
    tools : Mapping[str, ToolPolicy]
        Tool name -> policy. **Fail-closed**: a call to a tool with no entry is
        denied and recorded as `unresolved` (`allow_unlisted=True` inverts that,
        for incremental rollout).
    subagents : Mapping[str, Authority] | None
        Sub-agent name -> the `Authority` it may *request*. The granted authority
        is always `parent.meet(request)`, so a wide entry here can never widen a
        narrow parent. A sub-agent with no entry cannot be handed off to.
    caller_context : callable | None
        `run_context -> Mapping` — the caller facts added to every check.
        Defaults to `caller_facts`.
    on_deny : {"tool_error", "raise"}
        See the module docstring.
    """

    def __init__(
        self,
        root: Guard,
        *,
        tools: Mapping[str, ToolPolicy],
        subagents: Optional[Mapping[str, Authority]] = None,
        caller_context: Optional[Callable[[Any], Mapping[str, Any]]] = None,
        on_deny: str = "tool_error",
        allow_unlisted: bool = False,
        default_policy: Optional[Callable[[str], ToolPolicy]] = None,
        default_subagent_authority: Optional[Callable[[str], Authority]] = None,
        strict_single_hook: bool = False,
    ) -> None:
        """
        default_policy / default_subagent_authority — OBSERVE-MODE hooks for
        sampling (attenu-derive): called with the tool name / sub-agent name when
        nothing was declared, and their result is used as if it had been declared
        — so every call is authorized-and-RECORDED with the generated
        scope/context instead of denied (the fail-closed default) or silently
        passed through (`allow_unlisted`). `default_policy` takes precedence over
        `allow_unlisted`.
        strict_single_hook: execution-binding (0.9.0) mode switch — see the module
                          docstring. `False` (default) leaves every check on the
                          Guard's own honest `Capture.PRE_HOOK_ONLY` and records
                          no outcome; `True` is an attestation this file cannot
                          verify.
        """
        if on_deny not in ("tool_error", "raise"):
            raise ValueError("on_deny must be 'tool_error' or 'raise'")
        self.root = root
        self.tools = dict(tools)
        self.subagents = dict(subagents or {})
        self.caller_context = caller_context or caller_facts
        self.on_deny = on_deny
        self.allow_unlisted = allow_unlisted
        self.default_policy = default_policy
        self.default_subagent_authority = default_subagent_authority
        self.strict_single_hook = strict_single_hook
        self.children: MutableMapping[str, Guard] = {}
        self._lock = threading.Lock()
        self._installed: list[tuple[Any, int, Any]] = []   # (manager, index, original tool)

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

    # -- installation --------------------------------------------------------
    def install(self, tool_manager: Any) -> list[str]:
        """Guard every tool registered on `tool_manager`, in place.

        `tool_manager` is a `FunctionToolManager` — AstrBot's `llm_tools`
        singleton, or the manager an embedding application built. Each entry of
        its `func_list` is replaced by a `GuardedTool` around it, so the parent
        agent and every sub-agent toolset — `get_full_tool_set()` and
        `get_func(name)` alike — hand out guarded tools.

        Handoff tools are left alone: `FunctionToolExecutor.execute` dispatches
        on `isinstance(tool, HandoffTool)` before any local invocation, so a
        handoff never reaches a tool's `call()` and wrapping one would only break
        the dispatch. Delegation is hooked at the executor instead — see
        `executor_class()`.

        Returns the tool names now guarded. Idempotent.
        """
        names: list[str] = []
        with self._lock:
            for index, tool in enumerate(list(getattr(tool_manager, "func_list", []))):
                if isinstance(tool, GuardedTool) or _is_handoff(tool):
                    continue
                tool_manager.func_list[index] = GuardedTool(tool, self)
                self._installed.append((tool_manager, index, tool))
                names.append(tool.name)
        return names

    def uninstall(self) -> list[str]:
        """Put the original tools back. Returns the names restored."""
        with self._lock:
            names = []
            for manager, index, tool in reversed(self._installed):
                try:
                    if isinstance(manager.func_list[index], GuardedTool):
                        manager.func_list[index] = tool
                        names.append(tool.name)
                except IndexError:
                    continue
            self._installed.clear()
        return sorted(names)

    def guard_tools(self, tools: Sequence[Any]) -> list[Any]:
        """Wrap already-built tool objects. Returns new objects; idempotent."""
        return [t if (isinstance(t, GuardedTool) or _is_handoff(t)) else GuardedTool(t, self)
                for t in tools]

    def executor_class(self) -> Any:
        """A `FunctionToolExecutor` subclass that mints a child Guard per handoff.

        Pass it where your code constructs the agent runner::

            await runner.reset(..., tool_executor=guarded.executor_class()())

        See the module docstring for where this does and does not apply in stock
        AstrBot.
        """
        from astrbot.core.astr_agent_tool_exec import FunctionToolExecutor

        outer = self

        class _GuardedFunctionToolExecutor(FunctionToolExecutor):
            attenu_guard_owner = outer

            @classmethod
            async def _execute_handoff(cls, tool, run_context, **tool_args):
                guard = outer.active_guard()
                name = getattr(getattr(tool, "agent", None), "name", None) or tool.name
                gate = outer._gate_delegation(guard, str(name), str(tool_args.get("input", "")))
                if gate.denial is not None:
                    yield _denial_result(outer._deny_text(gate.denial))
                    return
                try:
                    with use_guard(gate.child):
                        async for item in super()._execute_handoff(tool, run_context, **tool_args):
                            yield item
                finally:
                    gate.child.complete()   # the handoff returned: lifecycle end on the ledger

        _GuardedFunctionToolExecutor.__name__ = "AttenuGuardedFunctionToolExecutor"
        _GuardedFunctionToolExecutor.__qualname__ = _GuardedFunctionToolExecutor.__name__
        return _GuardedFunctionToolExecutor

    # -- the hook ------------------------------------------------------------
    async def call(self, tool_name: str, args: Mapping[str, Any], run_context: Any,
                   inner: Callable[[], Any]) -> Any:
        """Authorize one tool call, then run `inner` (or refuse, and never run it).

        Public so a project that wires its own tool wrapper can reuse the gate
        without going through `install()`.
        """
        gate = self._gate(tool_name, args, run_context)
        if gate.denial is not None:
            return self._deny(gate.denial)
        return await self._run(gate, inner)

    # -- execution binding (0.9.0): runs the body and closes out the outcome, v2 only ----
    async def _run(self, gate: "GuardedDelegation._Gate", call: Callable[[], Any]) -> Any:
        if gate.decision is None:
            return await _await_maybe(call())
        start = time.monotonic()
        try:
            result = await _await_maybe(call())
        except Exception as exc:
            gate.guard.record_outcome(gate.decision.call_id, BodyState.RAISED,
                                      error_code=type(exc).__name__,
                                      invoked_params=gate.snapshot,
                                      duration_ms=_elapsed_ms(start))
            raise
        gate.guard.record_outcome(gate.decision.call_id, BodyState.RETURNED,
                                  invoked_params=gate.snapshot,
                                  duration_ms=_elapsed_ms(start))
        return result

    # -- internals -----------------------------------------------------------
    @dataclass
    class _Gate:
        denial: Any = None
        child: Optional[Guard] = None
        decision: Optional[Decision] = None
        guard: Optional[Guard] = None
        snapshot: Any = None

    def _gate(self, name: str, args: Mapping[str, Any], run_context: Any) -> "GuardedDelegation._Gate":
        """Decide, without running anything: deny or pass through."""
        guard = self.active_guard()
        policy = self.tools.get(name)
        if policy is None and self.default_policy is not None:
            policy = self.default_policy(name)
        if policy is None:
            if self.allow_unlisted:
                return self._Gate()
            # No authority is known for this tool: the refusal goes on the ledger
            # (record_denial) as `unresolved` — an operator's Decisions queue is a
            # fold over the ledger, not over this adapter's memory.
            return self._Gate(denial=guard.record_denial(
                Reason(ReasonCode.NO_AUTHORITY, requested=name,
                       message=f"no attenu-guard policy declared for tool {name!r}"),
                tool=name, disposition=Disposition.UNRESOLVED))

        caller = dict(self.caller_context(run_context) or {})
        v2 = self.strict_single_hook and guard.schema_version == 2
        snapshot = _freeze(dict(args)) if v2 else None
        extra = (
            dict(capture=Capture.WRAPPER_ASYNC,
                 adapter=_adapter_info("GuardedDelegation.call"),
                 authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(
            policy.scope,
            context=policy.context_for(args, caller),
            metered=policy.metered,
            tool=name,
            disposition=policy.disposition,
            **extra,
        )
        if not decision:
            return self._Gate(denial=decision)
        return self._Gate(decision=decision if v2 else None, guard=guard, snapshot=snapshot)

    def _gate_delegation(self, guard: Guard, subagent: str, task: str) -> "GuardedDelegation._Gate":
        requested = self.subagents.get(subagent)
        if requested is None and self.default_subagent_authority is not None:
            requested = self.default_subagent_authority(subagent)
        if requested is None:
            return self._Gate(denial=Decision.deny(
                Reason("delegation_refused", constraint="subagent", requested=subagent,
                       message=f"sub-agent {subagent!r} has no declared Authority"),
                node=guard.node_id))
        try:
            child = guard.delegate(subagent, requested, task=task)
        except AuthorityError as exc:
            # A structural failure (revoked/expired parent, depth/fanout overflow).
            # attenu-guard already wrote a `spawn_denied` audit entry; surface the
            # same reason to the caller.
            return self._Gate(denial=Decision.deny(
                Reason(exc.reason, requested=subagent, message=str(exc)),
                node=guard.node_id))
        self.children[subagent] = child
        return self._Gate(child=child)

    def _deny_text(self, decision: Decision) -> str:
        return f"error: AuthorityDenied. {decision.explain()}"

    def _deny(self, decision: Decision):
        if self.on_deny == "raise":
            raise AuthorityDenied(decision)
        # AstrBot's own permission check returns an error STRING as the tool
        # result, which the executor turns into a normal tool message, so the
        # model sees the denial and can choose another action.
        return self._deny_text(decision)


def _is_handoff(tool: Any) -> bool:
    try:
        from astrbot.core.agent.handoff import HandoffTool
    except Exception:
        return False
    return isinstance(tool, HandoffTool)


def _denial_result(text: str):
    import mcp

    return mcp.types.CallToolResult(content=[mcp.types.TextContent(type="text", text=text)])


async def _await_maybe(result: Any) -> Any:
    """Resolve whatever a tool body returned: value, awaitable, or async generator.

    Mirrors what `_PermissionGuardedTool.call` does for the tools it proxies —
    an `@filter.llm_tool` handler may be any of the three.
    """
    if inspect.isasyncgen(result):
        last: Any = None
        async for item in result:
            last = item
        return last
    if inspect.isawaitable(result):
        return await result
    return result


class GuardedTool:
    """A transparent proxy that authorizes before it runs the wrapped tool.

    Shaped like AstrBot's own `_PermissionGuardedTool`: `handler` stays `None` so
    `FunctionToolExecutor._execute_local` is forced through `call()` on every
    invocation path, and the wrapped tool's real body is resolved with the same
    precedence the executor uses (`handler` → an overriding `call` → `run`).

    Not declared as a `FunctionTool` subclass at import time so this module stays
    importable with no AstrBot installed; `__new__` builds a subclass bound to the
    installed `FunctionTool` on first use, which is what the executor's `isinstance`
    and the toolset's schema conversion need.
    """

    _impl: Any = None

    def __new__(cls, tool: Any, owner: GuardedDelegation):
        return cls._implementation()(tool, owner)

    @classmethod
    def _implementation(cls) -> Any:
        if cls._impl is not None:
            return cls._impl
        from astrbot.core.agent.tool import FunctionTool

        class _GuardedTool(FunctionTool, GuardedTool):
            def __init__(self, tool: Any, owner: GuardedDelegation) -> None:
                # Do NOT pass handler: keeping self.handler = None routes the
                # executor through call() for every invocation of this tool.
                FunctionTool.__init__(
                    self,
                    name=tool.name,
                    description=tool.description,
                    parameters=getattr(tool, "parameters", {}) or {},
                )
                self._wrapped = tool
                self._owner = owner
                self.active = getattr(tool, "active", True)
                self.handler_module_path = getattr(tool, "handler_module_path", None)
                self.is_background_task = getattr(tool, "is_background_task", False)

            def __new__(cls, *args, **kwargs):        # bypass GuardedTool.__new__
                return object.__new__(cls)

            @property
            def wrapped(self) -> Any:
                """The tool this one guards."""
                return self._wrapped

            async def call(self, context: Any, **kwargs: Any) -> Any:
                return await self._owner.call(
                    self.name, kwargs, context, lambda: self._invoke(context, **kwargs))

            def _invoke(self, context: Any, **kwargs: Any) -> Any:
                """The wrapped tool's real body, chosen exactly as `_execute_local` would."""
                tool = self._wrapped
                if getattr(tool, "handler", None) is not None:
                    return tool.handler(getattr(getattr(context, "context", None), "event", None),
                                        **kwargs)
                call_override = getattr(type(tool), "call", None)
                if call_override is not None and call_override is not FunctionTool.call:
                    return tool.call(context, **kwargs)
                run = getattr(tool, "run", None)
                if run is not None:
                    return run(getattr(getattr(context, "context", None), "event", None), **kwargs)
                return "error: tool has no callable handler"

            def __getattr__(self, item: str) -> Any:
                # Tools carrying extra public state (an MCP client, a session)
                # keep working through the wrapper.
                return getattr(self.__dict__["_wrapped"], item)

        _GuardedTool.__name__ = "AttenuGuardedTool"
        _GuardedTool.__qualname__ = _GuardedTool.__name__
        cls._impl = _GuardedTool
        return _GuardedTool
