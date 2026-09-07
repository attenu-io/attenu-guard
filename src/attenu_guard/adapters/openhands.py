"""attenu_guard.adapters.openhands — attenu-guard × the OpenHands software-agent-sdk.

A thin, paste-into-your-project adapter that enforces monotonic authority
attenuation across an OpenHands conversation's tool calls and its sub-agent
delegations.

Hook points used (all official framework APIs — no monkeypatching)
------------------------------------------------------------------
* TOOL INVOCATION — `ToolDefinition.set_executor(executor)`
  (`openhands/sdk/tool/tool.py`). `ToolDefinition.__call__` runs
  `self.executor(action, conversation)` and nothing else in front of it, so a
  `ToolExecutor` that wraps the tool's own executor sees every call to that
  tool and can refuse it *before* the body runs. `set_executor` returns a
  `model_copy`, so the guarded tool is a new instance of the SAME tool class —
  its `kind`, schema and observation type are untouched.

* INSTALLATION ON EVERY AGENT, INCLUDING SUB-AGENTS — `register_tool(name, cls)`
  (`openhands/sdk/tool/registry.py`). `AgentBase._initialize()` resolves every
  declared tool spec through `resolve_tool()` → this registry, for the parent
  conversation AND for every sub-agent conversation `TaskManager._create_task()`
  builds. So ONE `install(...)` call reaches the child layer. That matters here:
  a sub-agent's tools come from its own agent definition (`.agents/agents/*.md`),
  never from the parent's tool list, so anything wired only onto the parent's
  agent is not in force inside the delegation.

* CHILD CREATION / DELEGATION — the same executor hook, filtered on the
  framework's delegation tool. In OpenHands an orchestrator spawns a sub-agent
  by calling the `task` tool (`TaskToolSet` → `TaskTool` → `TaskExecutor` →
  `TaskManager.start_task`), so intercepting that one tool's executor *is*
  intercepting the delegation. The adapter mints the child with
  `parent_guard.delegate(...)` and installs it as the active Guard (a
  `ContextVar`) for the duration of the sub-agent's run.

  The sub-agent runs synchronously inside that executor call
  (`TaskManager._run_task` → `conversation.run()`), and OpenHands dispatches
  every tool call through `ParallelToolExecutor`, which submits work as
  `contextvars.copy_context().run(...)` — `openhands/sdk/agent/parallel_executor.py`,
  whose own comment reads "submit() itself propagates no contextvars; a fresh
  copy per task". So the Guard installed here by the parent's delegation hook is
  visible inside the sub-agent's own tool threads, and never leaks back out or
  sideways.

Usage
-----
Declare, once, which scope each tool needs and which `Authority` each sub-agent
may hold; then install the guarded resolvers before the conversation starts::

    from openhands.tools.file_editor import FileEditorTool
    from openhands.tools.task import TaskToolSet
    from openhands.tools.terminal import TerminalTool

    root = Guard.issue("orchestrator", Authority(
        scopes={"shell.*", "fs.*"},
        ceilings=[Deny("writes_protected_path", {"yes"})], ttl=3600))

    guarded = GuardedDelegation(
        root,
        tools={
            "terminal":    ToolPolicy("shell.execute", lambda a: {...}),
            "file_editor": ToolPolicy("fs.write"),
        },
        subagents={"shell": Authority(scopes={"shell.execute"}, ttl=900)},
    )
    guarded.install(TerminalTool, FileEditorTool, TaskToolSet)

    agent = Agent(llm=llm, tools=[Tool(name="terminal"),
                                  Tool(name="file_editor"),
                                  Tool(name=TaskToolSet.name)])

The policy map is shared by every agent on purpose: the *map* says which scope a
tool needs, the *Guard* says whether this particular agent still holds it. Same
tools, attenuated authority. A ceiling declared once on the root Authority is
carried onto every delegated node by `Authority.meet`, so it binds the sub-agent
without anyone wiring it into the sub-agent's definition.

`install()` mutates the SDK's process-wide tool registry — the same registry
`register_default_tools()` writes to. Call it before any conversation is
constructed; `uninstall()` puts the original registrations back.

Denial behaviour
----------------
`on_deny="tool_error"` (default) raises `ValueError` carrying
`Decision.explain()`. `Agent._execute_action_event` catches `ValueError` from a
tool and turns it into an `AgentErrorEvent` — "Error executing tool '<name>': …"
— so the denial goes back to the model as a normal tool result, the agent loop
keeps running, and the model can pick a different action. That is the right
default for an agent that should recover.

`on_deny="raise"` raises `attenu_guard.AuthorityDenied`, which is NOT a
`ValueError`, so it is not caught there and propagates out of
`conversation.run()`, aborting the run. Use that where a denial means "stop
everything" rather than "try something else". Inside a sub-agent it aborts the
sub-agent's own run; `TaskManager._run_task` catches it and returns an error
`TaskObservation` to the parent.

Either way the tool body never executes.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain — see `Guard.issue`) — TWO MODES
----------------------------------------------------------------------------------------
`inner(action, conversation)` — what this adapter's `_GuardedExecutor` calls — is the
executor this adapter wrapped at `install()`/`guard_tools()` time, i.e. the executor the
tool carried when the adapter first saw it. Unlike LangChain's
`create_agent(middleware=[...])` path, OpenHands composes NOTHING between
`ToolDefinition.__call__` and `self.executor(...)`: there is exactly one executor slot per
tool, and `set_executor` replaces it. So "my `inner` call is the real body" is true by
construction WHENEVER the executor this adapter wrapped is itself the tool's real body — the
residual is entirely the caller's own doing: an application that had already wrapped a tool's
executor with something that substitutes a result, retries the body, or returns without ever
reaching it would be indistinguishable from the body itself, exactly as in `adapters.langchain`.

  * DEFAULT (`strict_single_hook=False`): every `guard.check()` call passes NO `capture`/
    `authorized_params` at all. On a v2 chain the Guard stamps its own honest
    `Capture.PRE_HOOK_ONLY`; this adapter never calls `record_outcome()`. This is the only
    mode that requires no attestation about what else wrapped the executor.
  * STRICT (`strict_single_hook=True`): an explicit attestation that the executor this
    adapter wrapped IS the tool's real body — true for a tool taken straight from
    `TerminalTool.create(...)` / `register_default_tools()` and not otherwise wrapped. `_gate`
    then passes `Capture.WRAPPER_SYNC` to `guard.check()`, and `_run` closes the outcome out
    from `inner`'s own return/raise, a genuine observation under that attestation.
    `authorized_params`/`invoked_params` are one immutable snapshot (`_freeze()`, never a copy
    protocol — see its own docstring) of the VALIDATED action's fields, taken BEFORE `inner`
    runs and reused unchanged for both. Note this is stronger than the raw tool-call arguments
    an LLM emitted: by the time an executor runs, OpenHands has already validated them into
    the tool's `action_type`, and that object is what the body receives. `duration_ms` covers
    this adapter's own call of `inner`. This file cannot verify the attestation itself.

There is no async twin: OpenHands' internal dispatch never awaits `ToolDefinition.acall`
("The SDK's internal async dispatch path does not call this hook; it dispatches through
`__call__` directly from its own executor" — `tool.py`), and `ToolExecutor.__call__` is
synchronous. `Capture.WRAPPER_ASYNC` therefore never appears from this adapter.

A delegation tool call (`_gate_delegation`) mints the child via `guard.delegate()`, which never
calls `guard.check()` in the first place — there is no `Decision`/`call_id` to bind an outcome
to, so a delegation call is unaffected by any of this. On `schema_version=1` (the default),
nothing here changes at all.
"""
from __future__ import annotations

import contextvars
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
    "current_guard",
    "use_guard",
]

# Fields pydantic puts on every OpenHands `Action` that are framework plumbing, not
# tool-call arguments. They are dropped from the context bag and from the params
# commitment so a policy sees the same keys the model actually sent.
_ACTION_PLUMBING = ("kind", "security_risk", "summary")


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


def _adapter_info(hook: str) -> dict:
    return {"module": __name__, "version": __version__, "hook_path": f"{__name__}.{hook}"}


def _action_args(action: Any) -> dict:
    """The validated action's own fields, as a plain dict."""
    dump = getattr(action, "model_dump", None)
    if callable(dump):
        try:
            args = dict(dump())
        except Exception:
            args = {}
    elif isinstance(action, Mapping):
        args = dict(action)
    else:
        args = {}
    for key in _ACTION_PLUMBING:
        args.pop(key, None)
    return args


# ---------------------------------------------------------------------------
# The active Guard. OpenHands runs every tool call through
# `contextvars.copy_context().run(...)` (openhands/sdk/agent/parallel_executor.py),
# so a Guard installed here by the parent's delegation hook is visible to the
# sub-agent conversation invoked inside it — and never leaks back out or sideways.
# ---------------------------------------------------------------------------
_ACTIVE_GUARD: contextvars.ContextVar[Optional[Guard]] = contextvars.ContextVar(
    "attenu_guard_active_openhands", default=None
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

    scope:   the attenu-guard scope, e.g. `"shell.execute"`.
    context: optional callable mapping the validated action's fields to the
             context bag ceilings are evaluated against, e.g.
             `lambda args: {"command": args["command"]}`. Omit for a
             scope-only check.
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
    """Binds a attenu-guard chain to an OpenHands agent tree.

    Parameters
    ----------
    root : Guard
        The Guard this conversation runs under. Sub-agents are delegated from
        the Guard that is active when the delegation tool is called, so a
        grandchild is attenuated from the child, not from the root.
    tools : Mapping[str, ToolPolicy]
        Tool name -> policy, keyed by the tool's OpenHands name (`"terminal"`,
        `"file_editor"`, …). **Fail-closed**: a tool call with no entry is
        denied (`allow_unlisted=True` inverts that, for incremental rollout).
    subagents : Mapping[str, Authority] | None
        Sub-agent type -> the `Authority` it may *request*. The granted
        authority is always `parent.meet(request)`, so listing a wide Authority
        here can never widen a narrow parent. A sub-agent with no entry cannot
        be spawned at all.
    delegation_tool : str
        The framework's spawn tool. `"task"` for the OpenHands `TaskToolSet`.
    subagent_arg / task_arg : str
        Which of that tool's action fields name the sub-agent and describe the
        task. OpenHands' `TaskAction` uses `subagent_type` / `prompt`.
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
        task_arg: str = "prompt",
        on_deny: str = "tool_error",
        allow_unlisted: bool = False,
        default_policy: Optional[Callable[[str], ToolPolicy]] = None,
        default_subagent_authority: Optional[Callable[[str], Authority]] = None,
        strict_single_hook: bool = False,
    ) -> None:
        """
        default_policy / default_subagent_authority — OBSERVE-MODE hooks for
        sampling (attenu-derive): called with the tool name / sub-agent type
        when no policy / Authority was declared, and their result is used as if
        it had been declared — so every call is authorized-and-RECORDED on the
        audit log with the generated scope/context, instead of denied (the
        fail-closed default) or silently passed through (`allow_unlisted`).
        `default_policy` takes precedence over `allow_unlisted`.
        strict_single_hook: execution-binding (0.9.0) mode switch — see the module
                          docstring's "EXECUTION BINDING … TWO MODES". `False`
                          (default): every `guard.check()` call is left to the Guard's
                          own honest `Capture.PRE_HOOK_ONLY` default; no outcome is
                          ever recorded. `True`: an explicit attestation that the
                          executor this adapter wrapped is the tool's real body. This
                          file cannot verify that attestation itself.
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
        self.strict_single_hook = strict_single_hook
        self.children: MutableMapping[str, Guard] = {}
        self._lock = threading.Lock()
        self._installed: dict[str, Any] = {}          # tool name -> the class we displaced
        self._resolver_classes: dict[Any, Any] = {}   # original class -> guarded resolver class
        self._conversation_guards: dict[int, Guard] = {}   # id(conversation) -> its child Guard
        self._registry_module: Any = None             # the SDK registry module, while armed
        self._registry_original: Any = None           # its original `_REG` mapping

    # -- introspection ------------------------------------------------------
    def active_guard(self, conversation: Any = None) -> Guard:
        """The Guard this tool call must be authorized against.

        A conversation wins over the ContextVar when one is bound to it. The SDK's
        `DelegateExecutor` runs each sub-agent in a plain `threading.Thread`, and a thread does
        not inherit context, so a ContextVar-carried Guard never reaches a delegated child —
        its tool calls would land on the PARENT's node. The conversation object, unlike the
        context, IS handed to the executor on every call, so that is what the child Guard is
        bound to. `task`-style delegation, which runs inline, keeps using the ContextVar."""
        if conversation is not None:
            bound = self._conversation_guards.get(id(conversation))
            if bound is not None:
                return bound
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
    def install(self, *tool_classes: Any) -> list[str]:
        """Re-register each tool class under its own name, guarded.

        Pass the classes your agents declare by name — `TerminalTool`,
        `FileEditorTool`, `TaskToolSet`, … The registry entry is replaced by a
        resolver that calls the ORIGINAL class's `create()` and hands back the
        very same tool objects with a guarded executor installed
        (`set_executor` → `model_copy`, same class, same schema).

        Because `AgentBase._initialize()` resolves through this registry for the
        parent conversation and for every sub-agent conversation the
        `TaskManager` builds, one call covers both layers.

        Returns the tool names that were (re-)registered.
        """
        from openhands.sdk.tool.registry import register_tool

        names: list[str] = []
        with self._lock:
            for cls in tool_classes:
                name = getattr(cls, "name", None)
                if not name:
                    raise ValueError(f"{cls!r} has no OpenHands tool name")
                resolver = self._resolver_classes.get(cls)
                if resolver is None:
                    resolver = self._make_resolver(cls, name)
                    self._resolver_classes[cls] = resolver
                self._installed.setdefault(name, cls)
                register_tool(name, resolver)
                names.append(name)
            self._arm_registry()
        return names

    def _arm_registry(self) -> None:
        """Cover tools registered AFTER this call, too. Caller holds `self._lock`.

        `install(*classes)` guards the classes it is handed, at the moment it is handed them.
        That is every tool a project names up front — and none of the tools it registers later.
        `register_tool()` is a runtime API: a sub-agent's own definition can name a tool nobody
        registered when the parent conversation was built, and such a tool ran, un-gated and
        un-ledgered, on the child's node (found by the OpenHands battery, H12).

        The SDK exposes no hook on registration, so the adapter installs one: the registry's
        `_REG` mapping is replaced by a `dict` subclass whose `__setitem__` wraps the incoming
        resolver. `register_tool()` writes through that mapping under its own lock, inside its
        own module, whatever the caller imported or when — so this covers every registration,
        including one made by SDK code the project never calls itself. `uninstall()` restores
        the original mapping and every original resolver.

        `_REG` is private to the SDK. There is no public equivalent, and the alternatives are
        worse: guarding on the read side means patching the `resolve_tool` name already bound
        into `openhands.sdk.agent.base`, and guarding nothing means a whole class of tool runs
        unrecorded. Narrow, reversible, and one seam.
        """
        from openhands.sdk.tool import registry as _registry

        if isinstance(getattr(_registry, "_REG", None), _GuardingRegistry):
            return                                             # already armed (idempotent)
        current = _registry._REG
        armed = _GuardingRegistry(self)
        self._registry_module = _registry
        self._registry_original = current
        # Existing entries are wrapped on the way in, so a tool registered BEFORE install()
        # but never passed to it is covered from here on as well.
        for name, resolver in current.items():
            armed[name] = resolver
        _registry._REG = armed

    def _guard_resolver(self, resolver: Any) -> Any:
        """Wrap one registry resolver so the tools it produces come back guarded."""
        if getattr(resolver, "_attenu_guarded_by", None) is self:
            return resolver

        def guarded(params, conv_state):
            return [self._guard_tool(t) for t in resolver(params, conv_state)]

        guarded._attenu_guarded_by = self          # idempotence, and what uninstall() unwraps
        guarded._attenu_original = resolver
        return guarded

    def uninstall(self) -> list[str]:
        """Put the original registrations back. Returns the names restored."""
        with self._lock:
            names = sorted(self._installed)
            if self._installed:
                from openhands.sdk.tool.registry import register_tool

                for name, cls in self._installed.items():
                    register_tool(name, cls)
                self._installed.clear()
            module, original = self._registry_module, self._registry_original
            if module is not None:
                # Restore the plain mapping, carrying across every entry made while armed —
                # unwrapped, so nothing keeps a reference to this Guard after uninstall().
                live = module._REG
                restored = original if isinstance(original, dict) else {}
                restored.clear()
                for name, resolver in live.items():
                    restored[name] = getattr(resolver, "_attenu_original", resolver)
                module._REG = restored
                self._registry_module = self._registry_original = None
        return names

    def guard_tools(self, tools: Sequence[Any]) -> list[Any]:
        """Wrap already-built `ToolDefinition` instances. Returns new instances
        (the originals are frozen and unchanged). Idempotent."""
        return [self._guard_tool(t) for t in tools]

    def _make_resolver(self, original: Any, name: str) -> Any:
        from openhands.sdk.tool.tool import ToolDefinition

        outer = self

        class _GuardedResolver(ToolDefinition):
            """Registry-only shim: never instantiated, only its `create` is called."""

            @classmethod
            def create(cls, conv_state=None, **params):
                made = original.create(conv_state=conv_state, **params)
                return [outer._guard_tool(t) for t in made]

            @classmethod
            def is_usable(cls) -> bool:
                return original.is_usable()

        _GuardedResolver.__name__ = f"AttenuGuarded{original.__name__}"
        _GuardedResolver.__qualname__ = _GuardedResolver.__name__
        # Keep the registry name coherent. `ToolDefinition.__init_subclass__` derives a
        # name from the class name; this shim stands in for `original`, so it carries
        # `original`'s name. It is never instantiated -- only its `create` is called.
        _GuardedResolver.name = name
        return _GuardedResolver

    def _guard_tool(self, tool: Any) -> Any:
        if getattr(tool, "executor", None) is None:
            return tool
        if isinstance(tool.executor, _GuardedExecutor):
            return tool
        return tool.set_executor(_GuardedExecutor(tool.executor, tool.name, self))

    # -- the hook ------------------------------------------------------------
    def call(self, tool_name: str, action: Any, inner: Callable[[], Any],
             conversation: Any = None) -> Any:
        """Authorize one tool call, then run `inner` (or refuse, and never run it).

        Public so a project that wires its own `ToolExecutor` can reuse the gate
        without going through `install()`. `conversation`, when the caller has it, is how a
        delegated sub-agent's calls find their own node across a thread boundary — see
        `active_guard`.
        """
        args = _action_args(action)
        gate = self._gate(tool_name, args, conversation)
        if gate.denial is not None:
            return self._deny(tool_name, gate.denial)
        if gate.child is None:
            return self._run(gate, inner)
        try:
            with use_guard(gate.child):
                return self._run(gate, inner)
        finally:
            gate.child.complete()   # the delegation returned: lifecycle end on the ledger

    # -- execution binding (0.9.0): runs the body and closes out the outcome, on v2 only ----
    def _run(self, gate: "GuardedDelegation._Gate", call: Callable[[], Any]) -> Any:
        if gate.decision is None:
            return call()
        start = time.monotonic()
        try:
            result = call()
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

    def _gate(self, name: str, args: Mapping[str, Any],
              conversation: Any = None) -> "GuardedDelegation._Gate":
        """Decide, without running anything: deny / delegate / pass through."""
        guard = self.active_guard(conversation)

        if name == self.delegation_tool and (self.subagents or self.default_subagent_authority):
            return self._gate_delegation(guard, args)

        policy = self.tools.get(name)
        if policy is None and self.default_policy is not None:
            policy = self.default_policy(name)
        if policy is None:
            if self.allow_unlisted:
                # Un-gated, but never invisible: the call happened, so it goes on the ledger as
                # an `allow` marked `policy="unlisted"` — which says the chain did NOT authorize
                # it. A verifier counts those as ungated instead of checking containment.
                guard.record_passthrough(name)
                return self._Gate()
            # No authority is known for this tool: the refusal goes on the ledger
            # (record_denial) as `unresolved` — an operator's Decisions queue is a
            # fold over the ledger, not over this adapter's memory.
            return self._Gate(denial=guard.record_denial(
                Reason(ReasonCode.NO_AUTHORITY, requested=name,
                       message=f"no attenu-guard policy declared for tool {name!r}"),
                tool=name, disposition=Disposition.UNRESOLVED))

        v2 = self.strict_single_hook and guard.schema_version == 2
        snapshot = _freeze(dict(args)) if v2 else None
        extra = (
            dict(capture=Capture.WRAPPER_SYNC,
                 adapter=_adapter_info("GuardedDelegation.call"),
                 authorized_params=snapshot)
            if v2 else {}
        )
        try:
            context = policy.context_for(args)
        except Exception as exc:
            # The operator's own context function raised, so no context can be derived and no
            # ceiling can be evaluated. The body must not run (it does not) — and the refusal
            # goes on the ledger, because a refusal nobody can see is the defect this adapter
            # was fixed for twice already. `NO_AUTHORITY` is the existing vocabulary for an
            # adapter-level refusal upstream of scope/ceiling evaluation (its own docstring
            # names unparseable arguments); `unresolved` says no authority could be determined.
            return self._Gate(denial=guard.record_denial(
                Reason(ReasonCode.NO_AUTHORITY, constraint="context", requested=name,
                       message=f"context function for tool {name!r} raised "
                               f"{type(exc).__name__}: {exc}"),
                scope=policy.scope, tool=name, disposition=Disposition.UNRESOLVED))

        decision = guard.check(
            policy.scope,
            context=context,
            metered=policy.metered,
            tool=name,
            disposition=policy.disposition,
            **extra,
        )
        if not decision:
            return self._Gate(denial=decision)
        return self._Gate(decision=decision if v2 else None, guard=guard, snapshot=snapshot)

    def _canonical_subagent(self, subagent: Any) -> Any:
        """The name the SDK will actually run, for a name the model actually asked for.

        `default` is an SDK alias for `general-purpose` (`subagent/registry.py`
        `_DEPRECATED_NAMES`), and there are three more. A gate keyed on the raw string missed
        every one of them: observe minted a child under `default` while `general-purpose` ran,
        and enforce refused a sub-agent the operator HAD declared (safe direction, wrong
        reason). Resolution is the SDK's own — `get_agent_factory()` returns the factory whose
        `definition.name` is the canonical name — so the declared name covers its aliases
        without this adapter keeping a copy of a table that is not ours.

        An absent or empty selector is NOT resolved. The SDK maps it to the default agent;
        doing that here would silently mint a child for a call that named no sub-agent at all,
        turning a refusal (`delegation_refused`) into a spawn. Unknown names are returned
        unchanged, to be refused by the caller as before."""
        if not subagent or not isinstance(subagent, str):
            return subagent
        try:
            from openhands.sdk.subagent.registry import get_agent_factory
        except Exception:
            return subagent                                   # older SDK: no registry to ask
        try:
            import warnings
            with warnings.catch_warnings():
                # Resolving an alias is not the caller deprecating anything; the SDK's own
                # warning fires when the model uses one, and it fires again where the SDK runs it.
                warnings.simplefilter("ignore")
                factory = get_agent_factory(subagent)
        except Exception:
            return subagent                                   # unknown name: refuse it, as before
        canonical = getattr(getattr(factory, "definition", None), "name", None)
        return canonical or subagent

    def _gate_delegation(self, guard: Guard, args: Mapping[str, Any]) -> "GuardedDelegation._Gate":
        asked = args.get(self.subagent_arg)
        subagent = self._canonical_subagent(asked)
        requested = self.subagents.get(subagent)
        if requested is None and self.default_subagent_authority is not None and subagent is not None:
            requested = self.default_subagent_authority(str(subagent))
        # A refused delegation is a DENY on the audit trail, not just a message back to the model:
        # the sub-agent asked for authority and did not get it. Routed through record_denial so the
        # refusal lands in the same tamper-evident log — and in the `denials()` fold an operator's
        # Decisions queue is built from — as every other refusal.
        if requested is None:
            return self._Gate(denial=guard.record_denial(
                Reason(ReasonCode.DELEGATION_REFUSED, constraint=self.subagent_arg,
                       requested=subagent,
                       message=f"sub-agent {subagent!r} has no declared Authority"),
                tool=self.delegation_tool, disposition=Disposition.UNRESOLVED))
        task = str(args.get(self.task_arg, ""))
        if asked != subagent:
            # The ledger names the agent that ran; the task text keeps what was asked for, so a
            # reader can see the alias without a second field in the published audit schema.
            task = f"{task} [requested as {asked!r}]" if task else f"[requested as {asked!r}]"
        try:
            child = guard.delegate(str(subagent), requested, task=task)
        except AuthorityError as exc:
            # A structural failure (revoked/expired parent, depth/fanout overflow).
            # attenu-guard already wrote a `spawn_denied` audit entry — one refusal, one entry, so
            # nothing is recorded twice here; `denials()` folds `spawn_denied` alongside `deny`.
            # Surface the same reason to the caller.
            return self._Gate(denial=Decision.deny(
                Reason(exc.reason, requested=subagent, message=str(exc)),
                node=guard.node_id))
        self.children[str(subagent)] = child
        return self._Gate(child=child)

    def delegate_executor(self, inner: Any) -> Any:
        """Wrap the SDK's `DelegateExecutor` so `delegate` is a delegation seam too.

        `openhands.tools.delegate` is the SDK's SECOND way to hand work to a sub-agent, and it
        ships without a tool class — an app wires its own around `DelegateExecutor`. This
        adapter only ever treated the configured `delegation_tool` (`task`) as a spawn, so an
        app that delegates this way minted NO child node and the sub-agent's own tool calls were
        recorded on the parent's node (OpenHands battery, `h18-omitted-delegate`: `terminal`
        landed on n0). The ceiling still denied the write, because the rule was on the root — but
        the attenuation was not real and the delegation graph was wrong, which is the whole
        claim.

        Wire it where the app builds the executor::

            executor = guarded.delegate_executor(DelegateExecutor())

        `spawn` mints one child per sub-agent id, from the Authority declared for its agent TYPE
        (resolved through the SDK's registry, so `default` finds `general-purpose` — the same
        alias table as `_canonical_subagent`, reached from the other side: `_resolve_agent_type`
        returns the literal `"default"` when `agent_types` is omitted). A type with no declared
        Authority is refused before the SDK creates anything, and the refusal is a `deny` on the
        trail. Each child is then bound to ITS conversation, which is how its calls find their
        own node once `_delegate_tasks` runs them in threads — see `active_guard`.
        """
        outer = self

        class _GuardedDelegateExecutor:
            """Structural wrapper: the SDK types executors, it does not isinstance-check them."""

            def __init__(self) -> None:
                self._inner = inner
                self._bound: dict[str, Guard] = {}

            @property
            def inner(self) -> Any:
                return self._inner

            def __call__(self, action: Any, conversation: Any = None) -> Any:
                command = getattr(action, "command", None)
                if command == "spawn":
                    return self._spawn(action, conversation)
                return self._inner(action, conversation)

            def _spawn(self, action: Any, conversation: Any) -> Any:
                guard = outer.active_guard(conversation)
                ids = list(getattr(action, "ids", None) or [])
                types = list(getattr(action, "agent_types", None) or [])
                # `_resolve_agent_type`'s own rule: a missing or blank entry is "default", which
                # is an ALIAS, not an agent. Resolve it the same way a `task` delegation is.
                wanted = [outer._canonical_subagent(
                    (types[i].strip() if i < len(types) and types[i] else "") or "default")
                    for i in range(len(ids))]

                missing = [(i, t) for i, t in zip(ids, wanted) if outer._authority_for(t) is None]
                if missing:
                    agent_id, agent_type = missing[0]
                    denial = guard.record_denial(
                        Reason(ReasonCode.DELEGATION_REFUSED, constraint="agent_type",
                               requested=agent_type,
                               message=f"sub-agent type {agent_type!r} (id {agent_id!r}) has no "
                                       f"declared Authority"),
                        tool="delegate", disposition=Disposition.UNRESOLVED)
                    return _delegate_error(f"AuthorityDenied: {denial.explain()}",
                                           getattr(action, "command", "spawn"))

                result = self._inner(action, conversation)
                if getattr(result, "is_error", False):
                    return result                      # the SDK refused; nothing was created
                # Bind AFTER the SDK created the conversations: `_sub_agents[agent_id]` is the
                # object its tool calls will be handed, in whatever thread they run in.
                sub_agents = getattr(self._inner, "_sub_agents", {}) or {}
                for agent_id, agent_type in zip(ids, wanted):
                    sub = sub_agents.get(agent_id)
                    if sub is None or agent_id in self._bound:
                        continue
                    child = guard.delegate(agent_type, outer._authority_for(agent_type),
                                           task=f"delegate: {agent_id}")
                    outer.children[agent_id] = child
                    self._bound[agent_id] = child
                    outer._conversation_guards[id(sub)] = child
                return result

            def close(self) -> None:
                for agent_id, child in list(self._bound.items()):
                    child.complete()               # the sub-agent is done: lifecycle end
                    self._bound.pop(agent_id, None)
                sub_agents = getattr(self._inner, "_sub_agents", {}) or {}
                for sub in sub_agents.values():
                    outer._conversation_guards.pop(id(sub), None)
                close = getattr(self._inner, "close", None)
                if callable(close):
                    close()

            def __getattr__(self, item: str) -> Any:
                return getattr(self._inner, item)

        return _GuardedDelegateExecutor()

    def _authority_for(self, subagent: Any) -> Optional[Authority]:
        """The Authority declared for this sub-agent name, or the observe-mode default."""
        requested = self.subagents.get(subagent)
        if requested is None and self.default_subagent_authority is not None and subagent:
            requested = self.default_subagent_authority(str(subagent))
        return requested

    def _deny(self, tool_name: str, decision: Decision):
        if self.on_deny == "raise":
            raise AuthorityDenied(decision)
        # `Agent._execute_action_event` catches ValueError from a tool and emits an
        # AgentErrorEvent, so the model sees the denial and can choose another action.
        raise ValueError(f"AuthorityDenied: {decision.explain()}")


def _delegate_error(text: str, command: str) -> Any:
    """A `DelegateObservation` carrying a refusal, or the plain text if the SDK is absent."""
    try:
        from openhands.tools.delegate import DelegateObservation

        return DelegateObservation.from_text(text=text, command=command, is_error=True)
    except Exception:
        return text


class _GuardingRegistry(dict):
    """The SDK tool registry's `_REG` mapping, with a gate on the way in.

    Installed by `GuardedDelegation._arm_registry()` and removed by `uninstall()`. Every
    `register_tool()` call — whenever it happens, whatever imported it — writes here, so a tool
    registered long after `install()` is guarded on the node that runs it, exactly like one the
    project named up front. Reads are a plain dict lookup; nothing else about the registry
    changes."""

    def __init__(self, owner: "GuardedDelegation") -> None:
        super().__init__()
        self._owner = owner

    def __setitem__(self, name, resolver):
        super().__setitem__(name, self._owner._guard_resolver(resolver))


class _GuardedExecutor:
    """A `ToolExecutor` that authorizes before it delegates to the tool's real executor.

    Not declared as a `ToolExecutor` subclass so this module stays importable with no
    OpenHands installed; `ToolExecutor` is an ABC used structurally by the SDK
    (`ToolDefinition.executor` is typed, not isinstance-checked, at call time).
    """

    def __init__(self, inner: Any, tool_name: str, owner: GuardedDelegation) -> None:
        self._inner = inner
        self._tool_name = tool_name
        self._owner = owner

    @property
    def inner(self) -> Any:
        """The executor this one wraps."""
        return self._inner

    def __call__(self, action: Any, conversation: Any = None) -> Any:
        return self._owner.call(
            self._tool_name, action, lambda: self._inner(action, conversation),
            conversation=conversation,
        )

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()

    def interrupt(self) -> None:
        interrupt = getattr(self._inner, "interrupt", None)
        if callable(interrupt):
            interrupt()

    def __getattr__(self, item: str) -> Any:
        # Tools whose executors carry extra public state (a manager, a session)
        # keep working through the wrapper.
        return getattr(self._inner, item)
