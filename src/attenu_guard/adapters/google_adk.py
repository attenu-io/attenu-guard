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
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext

from attenu_guard import Authority, AuthorityDenied, Decision, Guard
from attenu_guard.reasons import Disposition, ReasonCode

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
            disposition=disposition,
        )

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
        disposition: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        decision = guard.check(scope, context=context, metered=metered, tool=tool_name,
                               disposition=disposition)
        if decision:
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
