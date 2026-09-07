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
from google.adk.tools.base_tool import BaseTool

# The plugin surface is ADK 1.x and later. On an older build (evo-ai pins google-adk 0.3.0)
# `google.adk.plugins` and `google.adk.apps.App` do not exist, and importing them made this whole
# module unimportable — so the shipped adapter could not attach to such a project AT ALL, which
# is worse than attaching a different way. The two hook points it needs are older than the plugin
# API: every agent has carried `before_agent_callback` and `before_tool_callback` since 0.x. When
# the plugin base is missing, this module still imports and `attach()` uses those instead. Same
# hooks, same semantics, same ledger; see `attach`.
try:                                    # ADK >= 1.x
    from google.adk.plugins.base_plugin import BasePlugin

    HAS_PLUGIN_API = True
except ImportError:                     # ADK 0.x — no plugin surface
    HAS_PLUGIN_API = False

    class BasePlugin:                   # type: ignore[no-redef]
        """Stand-in for ADK's plugin base on builds that have none.

        Only what ADK itself relies on: a `name`. This class is never registered anywhere on
        such a build (there is nothing to register it with) — it exists so the module imports
        and `attach()` can bind the very same methods to per-agent callbacks."""

        def __init__(self, name: str = "attenu_guard") -> None:
            self.name = name

try:
    from google.adk.agents.callback_context import CallbackContext
except ImportError:                     # pragma: no cover - older layouts
    CallbackContext = Any               # type: ignore[assignment,misc]
try:
    from google.adk.tools.agent_tool import AgentTool
except ImportError:                     # pragma: no cover - older layouts
    AgentTool = ()                      # type: ignore[assignment,misc]
try:
    from google.adk.tools.tool_context import ToolContext
except ImportError:                     # pragma: no cover - older layouts
    ToolContext = Any                   # type: ignore[assignment,misc]

from attenu_guard import Authority, AuthorityDenied, Decision, Guard, __version__
from ._context import evaluate as _safe_context
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
        exempt_tools:     extra tool names to skip AUTHORIZATION for. They are still
                          recorded — an exempt call lands on the ledger as an `allow`
                          marked `policy="unlisted"`, saying the chain did not authorize
                          it, so an exemption is visible to a reader instead of being a
                          hole in the trail. ADK's own
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
        # agent -> (parent agent name, the Authority it requested), so a later turn can
        # re-spawn the agent in the same place in the tree with the same ceiling.
        self._lineage: dict[str, tuple[str, Optional[Authority]]] = {}
        self._turns: dict[str, int] = {}
        # Delegation, not action: recorded as spawns, so never also as a passthrough.
        self._delegation_exempt = {TRANSFER_TOOL_NAME}
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
    # ---- attaching without the plugin API (ADK 0.x) --------------------------
    def attach(self, agent: Any, *, recursive: bool = True) -> list[str]:
        """Bind these same hooks to an agent's own callbacks. Returns the agent names covered.

        The plugin path stays the default and is what you want on ADK 1.x and later::

            App(name="app", root_agent=root, plugins=[guarded])

        On a build with no plugin surface — ADK 0.x, where `google.adk.plugins` and
        `google.adk.apps.App` do not exist — there is nothing to register a plugin with, and
        before this the adapter could not attach at all. Every agent has carried
        `before_agent_callback` / `before_tool_callback` (and their `after_` twins) since 0.x,
        and ADK calls them at the same points in the same order, so::

            guarded.attach(root_agent)      # walks sub_agents and AgentTool-wrapped agents

        gives the same two hook points, the same authorization, and the same ledger. The
        per-agent signatures are positional and carry no `agent` argument, so each binding is a
        closure over the agent it was attached to, and every binding is a PLAIN FUNCTION: ADK
        0.3.0 never awaits a callback result — it uses the return value directly, and treats a
        truthy one as "skip the tool body" — so an async callback there would skip every body and
        record nothing. See `_on_before_agent` for the detail. Sync returns are correct on 1.x and
        2.x as well, so the same functions are bound on every version.

        Existing callbacks are NOT displaced: an attribute already holding a callable becomes a
        list with this adapter's first, so a project's own hook still runs. This adapter's own
        hooks never short-circuit an allowed call, so running first is safe and running before a
        project's hook is the point — authorization has to happen before anything else decides.

        Idempotent per agent. `recursive` walks `sub_agents` and into every `AgentTool`'s wrapped
        agent, which is ADK's second delegation site.
        """
        covered: list[str] = []
        seen: set = set()
        stack = [agent]
        while stack:
            a = stack.pop()
            if a is None or id(a) in seen:
                continue
            seen.add(id(a))
            if getattr(a, "_attenu_guard_attached", None) is self:
                continue
            for attr, hook in (("before_agent_callback", self._on_before_agent(a)),
                               ("after_agent_callback", self._on_after_agent(a)),
                               ("before_tool_callback", self._on_before_tool),
                               ("after_tool_callback", self._on_after_tool)):
                if not hasattr(a, attr):
                    continue
                existing = getattr(a, attr, None)
                if existing is None:
                    setattr(a, attr, hook)
                elif isinstance(existing, list):
                    setattr(a, attr, [hook, *existing])
                else:
                    setattr(a, attr, [hook, existing])
            try:
                a._attenu_guard_attached = self
            except Exception:  # noqa: BLE001 - a frozen agent model still gets its callbacks
                pass
            covered.append(getattr(a, "name", "<unnamed>"))
            if recursive:
                stack.extend(getattr(a, "sub_agents", None) or [])
                for t in getattr(a, "tools", None) or []:
                    inner = getattr(t, "agent", None)
                    if inner is not None:
                        stack.append(inner)
        return covered

    # The per-agent adapters. PLAIN FUNCTIONS, not coroutines, and that is the whole point:
    # ADK 0.3.0 never awaits a callback result. `base_agent.py:261` calls
    # `before_agent_callback(...)` and puts the return straight into an `Event`, and
    # `functions.py:156-160` does `function_response = agent.before_tool_callback(...)` then
    # `if not function_response:` before calling the tool. A coroutine is truthy, so an async
    # callback there would skip EVERY tool body, hand the coroutine back as the tool result, and
    # authorize nothing while recording nothing — failing open on the audit trail while looking
    # like it worked. (An earlier revision of this file bound async callbacks and asserted ADK
    # awaits them; that is true on 1.x/2.x and false on 0.x, which is precisely the range
    # `attach()` exists for. Verified against a real google-adk 0.3.0, not reasoned about.)
    #
    # Sync is also correct on 1.x/2.x, where a non-awaitable return is used as-is, so `attach()`
    # binds the same plain functions on every version.
    def _on_before_agent(self, agent: Any) -> Callable:
        def before_agent(callback_context: Any = None, **_kw: Any):
            return self._before_agent_sync(agent, callback_context)

        return before_agent

    def _on_after_agent(self, agent: Any) -> Callable:
        def after_agent(callback_context: Any = None, **_kw: Any):
            return self._after_agent_sync(agent, callback_context)

        return after_agent

    def _on_before_tool(self, tool: Any = None, args: Any = None, tool_context: Any = None,
                        **_kw: Any):
        return self._before_tool_sync(tool, dict(args or {}), tool_context)

    def _on_after_tool(self, tool: Any = None, args: Any = None, tool_context: Any = None,
                       tool_response: Any = None, **_kw: Any):
        return self._after_tool_sync(tool, dict(args or {}), tool_context, tool_response)

    def _before_agent_sync(self, agent: Any, callback_context: Any) -> None:
        self._ensure_guard(agent.name)
        self._current = agent.name
        return None  # never short-circuit the agent itself

    def _after_agent_sync(self, agent: Any, callback_context: Any) -> None:
        """The agent's run returned to its caller: lifecycle end on the ledger (informational)."""
        g = self._guards.get(agent.name)
        if g is not None and g is not self._root:
            g.complete()
        return None

    # ---- hook 2: an agent is about to invoke a tool ---------------------
    def _before_tool_sync(self, tool: Any, tool_args: Mapping[str, Any],
                          tool_context: Any) -> Optional[dict[str, Any]]:
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
            # Un-gated by the operator's own instruction, but never invisible: the call happened,
            # so it goes on the ledger as an `allow` marked `policy="unlisted"`, which says the
            # chain did not authorize it (`Guard.record_passthrough`; a verifier counts those as
            # ungated rather than checking containment). This was the one path in this adapter
            # that ran a tool and wrote nothing — the B1 shape. ADK's own `transfer_to_agent` and
            # every `AgentTool` are exempt because they are DELEGATION, recorded as spawns
            # elsewhere on this same ledger, so they are not recorded again here.
            if tool.name not in self._delegation_exempt:
                try:
                    guard.record_passthrough(tool.name or "<unnamed>")
                except Exception:  # noqa: BLE001 - a gap in the record must not break the call
                    pass
            return None

        declared = self._tools.get(tool.name or "")
        if declared is None and self._default_tool_authority is not None:
            declared = self._default_tool_authority(tool.name or "<unnamed>")
        scope = declared.scope if declared else (tool.name or "<unnamed>")
        try:
            context: Mapping[str, Any] = _safe_context(
                guard, declared.context if declared is not None else None, tool_args,
                tool=tool.name or "<unnamed>", scope=scope)
        except AuthorityDenied as exc:
            # The refusal is already on the ledger (`deny`, `no_authority`, `unresolved`); this
            # adapter's contract is to hand ADK a denial dict rather than raise, unless the
            # caller asked for raising.
            if self._raise:
                raise
            return self._denial_response(exc.decision, guard, agent_name,
                                         tool.name or "<unnamed>", scope, Disposition.UNRESOLVED)
        metered = declared.metered if declared else False
        # undeclared tool: no authority is known for it at all -> "unresolved"
        disposition = declared.disposition if declared is not None else Disposition.UNRESOLVED
        return self._authorize(
            guard, agent_name, tool.name or "<unnamed>", scope, context, metered=metered,
            disposition=disposition, tool_args=tool_args, tool_context=tool_context,
        )

    # ---- hook 2b/2c: the tool body has finished (0.9.0 execution binding) -----
    def _after_tool_sync(self, tool: Any, tool_args: Mapping[str, Any], tool_context: Any,
                         result: Any) -> Optional[dict[str, Any]]:
        self._close_outcome(tool_context, _body_state_for(tool, result))
        return None  # never override the result -- purely observational

    def _on_tool_error_sync(self, tool: Any, tool_args: Mapping[str, Any], tool_context: Any,
                            error: BaseException) -> Optional[dict[str, Any]]:
        self._close_outcome(tool_context, BodyState.RAISED, error_code=type(error).__name__)
        return None  # never swallow the error -- it must propagate exactly as it would without us

    # ---- the plugin API's async surface -------------------------------------
    # Every hook's real work is SYNCHRONOUS (the guard core is), and lives in the `_*_sync`
    # methods above. These five exist because ADK's plugin API declares its callbacks async;
    # they add nothing but the coroutine. One implementation, two call shapes -- and it is what
    # lets `attach()` bind PLAIN FUNCTIONS on a build whose callbacks are never awaited.
    async def before_agent_callback(self, *, agent: BaseAgent,
                                    callback_context: CallbackContext) -> None:
        return self._before_agent_sync(agent, callback_context)

    async def after_agent_callback(self, *, agent: BaseAgent,
                                   callback_context: CallbackContext) -> None:
        return self._after_agent_sync(agent, callback_context)

    async def before_tool_callback(self, *, tool: BaseTool, tool_args: dict[str, Any],
                                   tool_context: ToolContext) -> Optional[dict[str, Any]]:
        return self._before_tool_sync(tool, tool_args, tool_context)

    async def after_tool_callback(self, *, tool: BaseTool, tool_args: dict[str, Any],
                                  tool_context: ToolContext,
                                  result: dict[str, Any]) -> Optional[dict[str, Any]]:
        return self._after_tool_sync(tool, tool_args, tool_context, result)

    async def on_tool_error_callback(self, *, tool: BaseTool, tool_args: dict[str, Any],
                                     tool_context: ToolContext,
                                     error: Exception) -> Optional[dict[str, Any]]:
        return self._on_tool_error_sync(tool, tool_args, tool_context, error)

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
        """The Guard for `agent_name`, minting one if this is the first time it has run.

        A node whose work was marked finished (`complete()`, which `after_agent_callback` does
        when an agent's run returns) is NOT reused: a second user turn in the same ADK session
        gets a FRESH node for that agent, under the same parent and with the same requested
        authority. See `_respawn` for why."""
        existing = self._guards.get(agent_name)
        if existing is not None and not existing.is_complete:
            return existing
        if existing is not None:
            # REVOKED is not FINISHED. A revoked node must keep answering as revoked: re-spawning
            # it would hand the agent a fresh, live node and undo the revocation — the one thing
            # this library must never do. It is reachable because `after_agent_callback` marks a
            # node complete when the agent's run returns, so an agent revoked after a turn is
            # BOTH; without this check it came back live on its next turn.
            if existing.is_revoked:
                return existing
            return self._respawn(agent_name, existing)

        if not self._guards:
            # First agent ADK runs and no explicit root_agent_name: it is root.
            self._guards[agent_name] = self._root
            return self._root

        issuer = self._pending_parent.pop(agent_name, None)
        parent_name = issuer or self._current or ""
        parent = self._guards.get(parent_name, self._root)
        request = self._delegations.get(agent_name)
        if request is None and self._default_delegation is not None:
            request = self._default_delegation(agent_name)
        if request is None:
            request = Authority()
        task = self._pending_tasks.pop(agent_name, None) or f"delegated to {agent_name}"
        child = parent.delegate(agent_name, request, task=task)
        self._guards[agent_name] = child
        # Remembered so a later turn can re-spawn this agent in the same place in the tree.
        self._lineage[agent_name] = (parent_name, request)
        return child

    def _respawn(self, agent_name: str, finalized: Guard) -> Guard:
        """A new turn reaching a finalized node gets a NEW node, not a refusal.

        ADK keeps one session across user turns, and `after_agent_callback` marks each agent
        done when its run returns — correctly: that run did finish. On the next turn the app
        rebuilds the tree and the same agent runs again, and every call on it was refused with
        `node_finalized`, so the whole turn produced no work. Two things were wrong with that.
        In observe mode the instrument must never change the run it is watching, and a recorder
        that starts refusing calls has changed it. In enforce mode a second turn is a new
        delegation under the same parent, not a call on a dead node — refusing it protects
        nothing, because the authority is unchanged and the parent could delegate again anyway.

        So the agent is re-spawned: same parent, same requested Authority, therefore the same
        `meet` and the same ceiling, recorded as a normal `spawn` on the ledger. The turn runs,
        the attenuation still holds, and the trail shows one node per turn — which is what
        actually happened. The parent is resolved through `_ensure_guard`, so a parent that was
        finalized too is re-spawned first and the new child hangs under the new parent.

        This is NOT the resume seam: nothing here re-binds a turn to its ORIGINAL node, which
        needs a core API (`Guard.resume`) and stays a product item. A per-turn node is the
        honest adapter-level answer — it neither loses the ceiling nor claims continuity it
        cannot prove.
        """
        parent_name, request = self._lineage.get(agent_name, ("", None))
        parent = self._root
        if parent_name and parent_name != agent_name:
            parent = self._ensure_guard(parent_name)
        if request is None:
            request = self._delegations.get(agent_name)
            if request is None and self._default_delegation is not None:
                request = self._default_delegation(agent_name)
            if request is None:
                request = Authority()
        # Nothing to hang a new node under: the root itself, an unrecorded lineage, or a parent
        # that is revoked (whose subtree must stay dead).
        if parent.is_complete or parent.is_revoked:
            return finalized
        turn = self._turns.get(agent_name, 1) + 1
        task = self._pending_tasks.pop(agent_name, None) or f"{agent_name}: turn {turn}"
        child = parent.delegate(agent_name, request, task=task)
        self._guards[agent_name] = child
        self._lineage[agent_name] = (parent_name, request)
        self._turns[agent_name] = turn
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
