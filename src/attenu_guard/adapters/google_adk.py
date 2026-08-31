"""
attenu_guard.adapters.google_adk — a thin attenu-guard integration for Google ADK.

Ships as `attenu_guard.adapters.google_adk` (`pip install 'attenu-guard[google-adk]'`). It is one `BasePlugin` subclass; you register
it once on your `App` and every agent in the tree is covered.

HOOK POINTS USED (verified against google-adk 2.7.1 in site-packages)
---------------------------------------------------------------------
1. CHILD CREATION — `BasePlugin.before_agent_callback(agent, callback_context)`
   (declared `google/adk/plugins/base_plugin.py:198`; invoked for plugins at
   `google/adk/agents/base_agent.py:483-487`, ahead of the per-agent
   `before_agent_callback`s at 495-501).

   This is the ONLY hook that fires for all three of ADK's delegation
   primitives — LLM-driven `transfer_to_agent`, `AgentTool` (agent-as-tool),
   and 2.x `mode='task'` sub-agents. (`before_tool_callback` misses the third:
   a task-mode delegation FC is dispatched at
   `google/adk/workflow/_llm_agent_wrapper.py:483-485` via `_dispatch_task_fc`,
   entirely outside `handle_function_calls_async`, so no tool callback runs for
   it.) The child's `Guard` is minted here, once per agent, via
   `parent_guard.delegate(...)`.

2. TOOL INVOCATION — `BasePlugin.before_tool_callback(tool, tool_args,
   tool_context)` (declared `base_plugin.py:297`; invoked at
   `google/adk/flows/llm_flows/functions.py:603-607`, which is Step 1 of
   `_execute_single_function_call_async` and runs BEFORE the tool body at
   `functions.py:627` — returning a non-`None` dict makes Step 3 skip the call
   entirely). `guard.check(...)` runs here; on a denial the tool body never
   executes.

WHO IS THE PARENT?
------------------
The guard chain mirrors the *runtime* flow of control, not the static
`sub_agents` tree: the parent of a newly-seen agent is whichever agent was last
active when control reached it. That is strictly stricter than using
`agent.parent_agent`, and it is what neutralises ADK's unenforced
`disallow_transfer_to_peers` (see README): an agent reached by a peer transfer
inherits from the *peer*, so a narrow sibling can never hand off into a wider
one.

DENIAL SHAPE
------------
By default a denial is returned to the model as the tool's result — a dict with
`error="authority_denied"` and machine-readable `reasons`. That is what ADK's
`before_tool_callback` contract is built for, it keeps the run alive so the
agent can recover or explain, and the denial lands in session history where it
is auditable. Pass `raise_on_deny=True` for a hard stop instead: the plugin
raises `AuthorityDenied`, which ADK's `PluginManager` re-raises as a
`RuntimeError` with the original exception as `__cause__`, aborting the run.

USAGE
-----
    from google.adk.apps.app import App
    from google.adk.runners import Runner
    from attenu_guard import Authority, Guard, RowLimit, EgressRank
    from attenu_guard.adapters.google_adk import DelegationGuardPlugin, ToolAuthority

    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

    plugin = DelegationGuardPlugin(
        root,
        root_agent_name="orchestrator",
        delegations={"summarizer": Authority(
            scopes={"crm.read"},
            ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)},
        tools={
            "crm_query":  ToolAuthority("crm.read",   lambda a: {"rows": a.get("rows", 0)}),
            "crm_export": ToolAuthority("crm.export", lambda a: {"egress": "any"}),
        },
    )
    runner = Runner(app=App(name="app", root_agent=orchestrator, plugins=[plugin]),
                    session_service=InMemorySessionService())
    ...
    root.revoke(plugin.guard_for("summarizer").node_id)   # cascade kill-switch

attenu-guard deliberately does not decide what authority a task needs — you
write the `Authority` for each delegation and the `ToolAuthority` for each tool.
An agent with no entry in `delegations`, and a tool with no entry in `tools`,
both fail CLOSED.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain — see `Guard.issue`) — TWO MODES
-----------------------------------------------------------------------------------------
The plugin never calls the tool body itself — ADK does, via `__call_tool_async` in
`flows/llm_flows/functions.py` — so the only way it can observe completion at all is ADK's
own post-invocation callbacks, `after_tool_callback`/`on_tool_error_callback` — and those
are NOT guaranteed terminal observers for every call (see HONESTY NOTES below). Per the
execution-binding spec's own governing principle — an honest unobserved beats a promised
outcome that can be lost — this plugin therefore ships with TWO modes, controlled by
`DelegationGuardPlugin(..., strict_single_hook=...)`:

  * DEFAULT (`strict_single_hook=False`): every `guard.check()` call passes NO `capture`/
    `authorized_params` at all. On a v2 chain the Guard itself stamps its own default,
    honest `Capture.PRE_HOOK_ONLY` (`Guard.check()`'s documented behavior for a bare call);
    this plugin never stashes a pending outcome and `after_tool_callback`/
    `on_tool_error_callback` never call `record_outcome()`. None of the HONESTY NOTES below
    apply to this mode — there is nothing pending for a substituted response, a cancelled
    call or a shadowing plugin to corrupt. This is the only mode that requires no
    attestation about what else is registered on the `App`/`Runner`.
  * STRICT (`strict_single_hook=True`): an explicit attestation — this plugin's caller is
    telling it that `DelegationGuardPlugin` is registered first (or alone) among the
    `App`/`Runner`'s plugins for tool callbacks, and that no agent in the tree uses a
    canonical `before_tool_callback=` that substitutes a tool's response (see the first two
    HONESTY NOTES below). `_authorize` (the single choke point both the tool check and the
    delegation-scope check go through) then passes `capture=Capture.FRAMEWORK_POST_HOOK` to
    `guard.check()`, and the outcome is closed out from TWO of ADK's own post-invocation
    hooks, whichever one actually fires for a given call:

      * `after_tool_callback(tool, tool_args, tool_context, result)` on success —
        `BodyState.RETURNED`;
      * `on_tool_error_callback(tool, tool_args, tool_context, error)` on a raised
        exception — `BodyState.RAISED`, `error_code=type(error).__name__`. Returning
        `None` from it (as this plugin always does) means the original exception still
        propagates exactly as it would without this plugin installed — the plugin only
        observes, it never swallows the error.

    `duration_ms` is therefore an OBSERVATION window (`_authorize`'s `check()` call to
    whichever callback fires), not a body-execution timer — matching `Guard.record_outcome`'s
    own documented contract ("observation start to observation end") — and it can include
    time spent in OTHER before-callbacks/plugins, cache lookups, and ADK's own dispatch
    overhead, not solely the tool body's own runtime.

    The two are mutually exclusive per call (`functions.py`'s `try: ... except Exception
    as tool_error: error_response = await _run_on_tool_error_callbacks(...)` — the error
    callback runs, then EITHER its return value stands in for the result and
    `after_tool_callback` runs too with THAT synthesized result, OR (this plugin's case:
    `on_tool_error_callback` always returns `None`) the original exception re-raises and
    `after_tool_callback` never runs at all for this call). The two hooks correlate their
    pending state with `_authorize`'s `check()` by `id(tool_context)`: ADK constructs one
    `ToolContext` per function call and threads the SAME object through before/after/error
    for it, so the id is a safe, call-scoped key — and (strict mode) the `_PendingOutcome`
    itself holds a strong reference to that SAME `tool_context` object (not merely a key
    derived from its id), so its `id()` genuinely cannot be reused by a different,
    concurrently-live object while the entry exists; insertion is `.setdefault`-style, so a
    colliding, still-unconsumed key is left alone rather than overwritten. Unlike CrewAI and
    the OpenAI Agents SDK, ADK does not swallow a tool's exception into a returned/formatted
    result before this plugin's error hook runs, so `BodyState.RAISED` is genuinely reachable
    here for calls whose error hook DOES fire — see the honesty notes below for when it does
    not.

    `BodyState.DEFERRED`: `after_tool_callback` checks `tool.is_long_running` /
    `tool._defers_response` (the SAME flags ADK's own `functions.py` checks, later, to
    decide whether `function_response` is the tool's real, final output or a placeholder
    whose true result arrives later via session injection) BEFORE deciding `RETURNED` vs
    `DEFERRED` — reporting a long-running/deferred tool's `after_tool_callback` firing as
    `RETURNED` would misrepresent it as a completed call.

HONESTY NOTES (strict mode) — ADK's `before`/`after`/error callbacks are NOT guaranteed to
be this plugin's terminal observer for every call even when `strict_single_hook=True`; each
of the following is a genuine, structural gap in the documented plugin/callback surface, not
a bug this file can code around without going outside that surface. This is exactly why
`strict_single_hook` defaults to `False`: it is a caller attestation this file cannot itself
verify, not a guarantee this file can make on its own.

  * A CANONICAL `before_tool_callback` (an AGENT-level callback the caller registers,
    e.g. `LlmAgent(before_tool_callback=...)` — a *different* mechanism from THIS
    plugin, which is registered at the `App`/`Runner` level) can itself supply a
    response and make ADK skip the tool body entirely (`functions.py`, Step 2 before
    Step 3) — yet `after_tool_callback` (Step 4) STILL runs, with that substituted
    response, and this plugin has no signal in `after_tool_callback` to tell "the tool
    genuinely ran" apart from "a canonical before-callback supplied this instead". If a
    caller's own agents use `before_tool_callback=`, a call this plugin authorized may
    be recorded `RETURNED` for a body that never executed. `strict_single_hook=True` is
    the caller's attestation that no agent in the tree does this; this file cannot detect
    or reject the violation itself.
  * `asyncio.CancelledError` is a `BaseException`; ADK's own `except Exception` around
    the tool call (`functions.py`) does not catch it, so NEITHER `on_tool_error_callback`
    NOR `after_tool_callback` ever fires for a cancelled call — this plugin cannot
    record `BodyState.ABANDONED` for it (there is no hook to record it FROM). The
    call's outcome is simply left unrecorded, which is the honest reflection of "this
    plugin was never told what happened", not a fabricated result.
  * Plugin dispatch (`PluginManager._run_callbacks`) stops at the FIRST plugin whose
    callback returns non-`None`. This plugin's own `after_tool_callback`/
    `on_tool_error_callback` always return `None` (they only observe, never override),
    so they never block ANOTHER plugin's callback from running — but the reverse is not
    true: if a DIFFERENT plugin is registered BEFORE this one and its
    `after_tool_callback`/`on_tool_error_callback` returns non-`None`, THIS plugin's own
    callback never runs for that call, and its pending outcome is never closed out.
    `strict_single_hook=True` is the caller's attestation that `DelegationGuardPlugin` is
    registered first (or alone) so this cannot happen; this file cannot verify plugin
    registration order itself.

The second and third gaps only ever leave a call's outcome unrecorded -- the honest
"unobserved" the execution-binding spec calls for when a path cannot guarantee
observation. The first (a canonical before-callback substituting the response) is the
one gap this plugin cannot even detect, let alone avoid recording wrongly: ADK gives
`after_tool_callback` no signal distinguishing a substituted response from a genuine
one. A caller whose agents ALSO use `before_tool_callback=` must NOT set
`strict_single_hook=True` for those agents' tools, or must treat this plugin's execution
binding as informative, not load-bearing, for those specific tools.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext

from attenu_guard import Authority, AuthorityDenied, Decision, Guard, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition, ReasonCode

_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.DelegationGuardPlugin._authorize",
}


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


from ._snapshot import freeze as _freeze


def _snapshot_params(tool_args: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    ADK invokes the tool body -- and reused as both `authorized_params` and `invoked_params`."""
    return _freeze(dict(tool_args))


def _body_state_for(tool: BaseTool, result: Any) -> str:
    """`DEFERRED` when `tool` is declared long-running or self-deferring (the SAME flags ADK's
    own `functions.py` checks to decide whether `result` is the tool's real, final output --
    see the module docstring's "BodyState.DEFERRED"), `RETURNED` otherwise."""
    if getattr(tool, "is_long_running", False) or getattr(tool, "_defers_response", False):
        return BodyState.DEFERRED
    return BodyState.RETURNED


@dataclass
class _PendingOutcome:
    """An allowed, v2 `check()` waiting on `after_tool_callback`/`on_tool_error_callback` to
    close it out -- keyed by `id(tool_context)` in `DelegationGuardPlugin._pending_outcomes`.

    Holds `tool_context` itself (not just its id) as a STRONG reference for the whole span
    this entry is pending -- that is what actually makes `id(tool_context)` safe to use as a
    dict key here: as long as this entry exists, this field keeps the object alive, so its id
    cannot be reassigned to a different, concurrently-live object. A dict keyed by an object's
    id without holding the object itself would not have this property (only the caller's own
    reference would keep the id valid, which is not this plugin's to assume)."""

    guard: Guard
    call_id: str
    snapshot: Any
    started_at: float
    tool_context: ToolContext

__all__ = ["DelegationGuardPlugin", "ToolAuthority", "TRANSFER_TOOL_NAME"]

TRANSFER_TOOL_NAME = "transfer_to_agent"


@dataclass(frozen=True)
class ToolAuthority:
    """How one ADK tool maps onto a attenu-guard authorization check.

    scope:    the scope string this tool needs, e.g. "crm.read".
    context:  optional callable taking the tool's raw `args` dict and returning
              the context mapping for `guard.check()` (e.g.
              `lambda a: {"rows": a["rows"]}`). Omit for a scope-only check.
    metered:  passed through as `guard.check(metered=...)`; with a Guard issued
              `strict_metering=True`, a metered call carrying no context is
              refused rather than treated as free.
    disposition: optional `Disposition` value the authority source knows
              about this tool — `held_pending_grant` (curated, waiting on an
              operator), `withheld_tier2`, `unresolved`. Recorded on a `deny`
              (ledger + the denial dict) so "held" never reads as "denied";
              omit for a grantable tool (a deny is then `out_of_authority`).
    """

    scope: str
    context: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None
    metered: bool = False
    disposition: Optional[str] = None


class DelegationGuardPlugin(BasePlugin):
    """Enforces monotonic authority attenuation across an ADK agent tree."""

    def __init__(
        self,
        root_guard: Guard,
        *,
        delegations: Mapping[str, Authority],
        tools: Mapping[str, ToolAuthority],
        root_agent_name: Optional[str] = None,
        exempt_tools: Iterable[str] = (),
        delegation_scope: Optional[str] = None,
        raise_on_deny: bool = False,
        name: str = "attenu_guard",
        default_tool_authority: Optional[Callable[[str], ToolAuthority]] = None,
        default_delegation: Optional[Callable[[str], Authority]] = None,
        strict_single_hook: bool = False,
    ):
        """
        root_guard:       the Guard you issued for the root agent. You keep it —
                          it owns the audit log, the delegation graph and
                          `revoke()`.
        delegations:      {agent_name: requested Authority}. The child actually
                          receives `meet(parent, requested)`, which can only
                          shrink. An agent missing from this map is delegated
                          `Authority()` — no scopes, i.e. it can do nothing.
        tools:            {tool_name: ToolAuthority}. A tool missing from this
                          map is checked against a scope equal to its own name,
                          which no sane Authority grants — so undeclared tools
                          fail closed *and* land in the audit log with a
                          `scope_not_granted` reason rather than vanishing.
        root_agent_name:  the agent that holds `root_guard`. Defaults to the
                          first agent ADK runs.
        exempt_tools:     extra tool names to skip entirely. ADK's own
                          `transfer_to_agent` and every `AgentTool` are already
                          skipped, because they are delegation, not action —
                          they are governed by `delegations` (and optionally by
                          `delegation_scope`).
        delegation_scope: if set, a transfer / AgentTool call is itself checked
                          as `f"{delegation_scope}.{target_agent}"` against the
                          *delegating* agent's authority. This is the
                          code-enforced hand-off gate ADK does not have (its
                          `disallow_transfer_to_peers` is prompt-only on the
                          2.7.1 default path). Leave `None` to allow any
                          hand-off and rely on attenuation alone.
        raise_on_deny:    raise `AuthorityDenied` instead of returning a denial
                          dict to the model.
        default_tool_authority / default_delegation — OBSERVE-MODE hooks for
                          sampling (attenu-derive): called with the tool name /
                          agent name when no ToolAuthority / Authority was
                          declared, and their result is used as if it had been
                          declared — so every call is authorized-and-RECORDED
                          on the audit log with the generated scope/context,
                          instead of denied (the fail-closed default, which
                          stays the default without the hooks).
        strict_single_hook: execution-binding (0.9.0) mode switch -- see the module
                          docstring's "EXECUTION BINDING ... TWO MODES". `False`
                          (default): every `guard.check()` call is left to the Guard's own
                          honest `Capture.PRE_HOOK_ONLY` default; no outcome is ever
                          recorded, and no attestation is required. `True`: an explicit
                          attestation that `DelegationGuardPlugin` is registered first (or
                          alone) for tool callbacks on this `App`/`Runner`, and that no
                          agent in the tree substitutes a tool's response via a canonical
                          `before_tool_callback=` -- restores `Capture.FRAMEWORK_POST_HOOK`
                          and real outcome recording via `after_tool_callback`/
                          `on_tool_error_callback`. This file cannot verify either half of
                          that attestation itself; see the HONESTY NOTES.
        """
        super().__init__(name=name)
        self._root = root_guard
        self._delegations = dict(delegations)
        self._tools = dict(tools)
        self._exempt = set(exempt_tools) | {TRANSFER_TOOL_NAME}
        self._delegation_scope = delegation_scope
        self._raise = raise_on_deny
        self._default_tool_authority = default_tool_authority
        self._default_delegation = default_delegation
        self._strict_single_hook = strict_single_hook
        # The task text a pending hand-off carries (the AgentTool `request`),
        # consumed by `_ensure_guard` when the child agent starts — so the
        # spawn record says what the child was asked, not just its name.
        self._pending_tasks: dict[str, str] = {}
        # Who issued the pending hand-off. "Parent = the last active agent"
        # is right for sequential control flow but wrong when one model turn
        # issues several AgentTool calls and ADK runs them concurrently: the
        # second child would be minted from the first (a chain, not a
        # fan-out). The delegating agent is known at the tool call, so it is
        # recorded here and consumed by `_ensure_guard`.
        self._pending_parent: dict[str, str] = {}

        self._guards: dict[str, Guard] = {}
        self._current: Optional[str] = None
        # Execution binding (0.9.0): an allowed, v2 check() waiting on after_tool_callback /
        # on_tool_error_callback to close it out -- keyed by id(tool_context), see the module
        # docstring's "EXECUTION BINDING" section.
        self._pending_outcomes: dict[int, _PendingOutcome] = {}
        if root_agent_name:
            self._guards[root_agent_name] = root_guard
            self._current = root_agent_name

    # ---- public introspection -------------------------------------------
    def guard_for(self, agent_name: str) -> Guard:
        """The Guard minted for `agent_name` (KeyError if it never ran)."""
        return self._guards[agent_name]

    @property
    def guards(self) -> Mapping[str, Guard]:
        return dict(self._guards)

    # ---- hook 1: control transfers to an agent --------------------------
    async def before_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> None:
        self._ensure_guard(agent.name)
        self._current = agent.name
        return None  # never short-circuit the agent itself

    async def after_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> None:
        """The agent's run returned to its caller: lifecycle end on the ledger (informational)."""
        g = self._guards.get(agent.name)
        if g is not None and g is not self._root:
            g.complete()
        return None

    # ---- hook 2: an agent is about to invoke a tool ---------------------
    async def before_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext
    ) -> Optional[dict[str, Any]]:
        agent_name = tool_context.agent_name
        guard = self._ensure_guard(agent_name)
        self._current = agent_name

        target = self._delegation_target(tool, tool_args)
        if target is not None:
            # A transfer BACK to an ancestor (ADK's `transfer_to_agent` to the parent/root) is control flow
            # returning up, not a new delegation: no `agent.delegate.<ancestor>` check, no new Guard; the
            # returning child is marked done on the ledger and control moves to the ancestor.
            ancestor = self._guards.get(target)
            if ancestor is not None and guard.is_descendant_of(ancestor):
                try:
                    guard.complete()
                except Exception:  # noqa: BLE001 - informational lifecycle event must never block control flow
                    pass
                self._current = target
                return None
            self._pending_parent[target] = agent_name
            request = tool_args.get("request")
            if isinstance(request, str) and request:
                self._pending_tasks[target] = request
            if self._delegation_scope is None:
                return None
            return self._authorize(
                guard, agent_name, tool.name or "<unnamed>",
                f"{self._delegation_scope}.{target}", {}, metered=False,
                tool_args=tool_args, tool_context=tool_context,
            )

        if tool.name in self._exempt:
            return None

        declared = self._tools.get(tool.name or "")
        if declared is None and self._default_tool_authority is not None:
            declared = self._default_tool_authority(tool.name or "<unnamed>")
        scope = declared.scope if declared else (tool.name or "<unnamed>")
        context: Mapping[str, Any] = {}
        if declared is not None and declared.context is not None:
            context = declared.context(tool_args)
        metered = declared.metered if declared else False
        # undeclared tool: no authority is known for it at all -> "unresolved"
        disposition = declared.disposition if declared is not None else Disposition.UNRESOLVED
        return self._authorize(
            guard, agent_name, tool.name or "<unnamed>", scope, context, metered=metered,
            disposition=disposition, tool_args=tool_args, tool_context=tool_context,
        )

    # ---- hook 2b/2c: the tool body has finished (0.9.0 execution binding) -----
    async def after_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext,
        result: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        self._close_outcome(tool_context, _body_state_for(tool, result))
        return None  # never override the result -- purely observational

    async def on_tool_error_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext,
        error: Exception,
    ) -> Optional[dict[str, Any]]:
        self._close_outcome(tool_context, BodyState.RAISED, error_code=type(error).__name__)
        return None  # never swallow the error -- it must propagate exactly as it would without us

    def _close_outcome(
        self, tool_context: ToolContext, body_state: str, *, error_code: Optional[str] = None,
    ) -> None:
        pending = self._pending_outcomes.pop(id(tool_context), None)
        if pending is None:
            return  # v1 chain, or nothing was pending for this call (e.g. it was denied)
        kwargs: dict[str, Any] = dict(
            invoked_params=pending.snapshot, duration_ms=_elapsed_ms(pending.started_at),
        )
        if error_code is not None:
            kwargs["error_code"] = error_code
        pending.guard.record_outcome(pending.call_id, body_state, **kwargs)

    # ---- internals -------------------------------------------------------
    @staticmethod
    def _delegation_target(tool: BaseTool, tool_args: Mapping[str, Any]) -> Optional[str]:
        """The agent this call hands work to, or None if it is a real action."""
        if tool.name == TRANSFER_TOOL_NAME:
            return tool_args.get("agent_name")
        if isinstance(tool, AgentTool):
            # AgentTool (and its `mode='single_turn'` / `mode='task'` subclasses)
            # take the wrapped agent's name as the tool name.
            return tool.agent.name
        return None

    def _ensure_guard(self, agent_name: str) -> Guard:
        """Mint (once) the Guard for `agent_name`, attenuated from whichever
        agent was last active — i.e. the one that actually handed over."""
        existing = self._guards.get(agent_name)
        if existing is not None:
            return existing

        if not self._guards:
            # First agent ADK runs and no explicit root_agent_name: it is root.
            self._guards[agent_name] = self._root
            return self._root

        issuer = self._pending_parent.pop(agent_name, None)
        parent = self._guards.get(issuer or self._current or "", self._root)
        request = self._delegations.get(agent_name)
        if request is None and self._default_delegation is not None:
            request = self._default_delegation(agent_name)
        if request is None:
            request = Authority()
        task = self._pending_tasks.pop(agent_name, None) or f"delegated to {agent_name}"
        child = parent.delegate(agent_name, request, task=task)
        self._guards[agent_name] = child
        return child

    def _authorize(
        self,
        guard: Guard,
        agent_name: str,
        tool_name: str,
        scope: str,
        context: Mapping[str, Any],
        *,
        metered: bool,
        tool_args: Mapping[str, Any],
        tool_context: ToolContext,
        disposition: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        v2 = self._strict_single_hook and guard.schema_version == 2
        snapshot = _snapshot_params(tool_args) if v2 else None
        extra = (
            dict(capture=Capture.FRAMEWORK_POST_HOOK, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(scope, context=context, metered=metered, tool=tool_name,
                               disposition=disposition, **extra)
        if decision:
            if v2:
                # Nothing here calls the tool body -- ADK does, elsewhere -- so the outcome is
                # closed out later by after_tool_callback/on_tool_error_callback, whichever ADK
                # actually runs for this call. See the module docstring's "EXECUTION BINDING".
                # .setdefault, not assignment: a colliding, still-unconsumed key (should not
                # happen -- the entry we are about to insert holds a strong reference to
                # tool_context itself, which is what pins id(tool_context) alive -- but is not
                # this plugin's to assume) is left alone rather than silently overwritten.
                self._pending_outcomes.setdefault(id(tool_context), _PendingOutcome(
                    guard=guard, call_id=decision.call_id, snapshot=snapshot,
                    started_at=time.monotonic(), tool_context=tool_context,
                ))
            return None
        if self._raise:
            raise AuthorityDenied(decision)
        return self._denial_response(decision, guard, agent_name, tool_name, scope, disposition)

    @staticmethod
    def _denial_response(
        decision: Decision, guard: Guard, agent_name: str, tool_name: str, scope: str,
        disposition: Optional[str] = None,
    ) -> dict[str, Any]:
        """The dict ADK hands back to the model in place of the tool result.

        `functions.py:603-625` treats any non-None return as the tool's response
        and skips the call, so this both blocks the body and tells the model,
        deterministically, what it is not allowed to do. `disposition` mirrors
        the ledger: held_pending_grant ("waiting on a human") is not
        out_of_authority ("stopped") — the model and the operator see the same word.
        """
        if disposition is None and any(r.code == ReasonCode.SCOPE_NOT_GRANTED for r in decision.reasons):
            disposition = Disposition.OUT_OF_AUTHORITY
        return {
            "error": "authority_denied",
            "agent": agent_name,
            "tool": tool_name,
            "scope": scope,
            "node": guard.node_id,
            "reasons": [r.code for r in decision.reasons],
            "disposition": disposition,
            "detail": decision.explain(),
        }
