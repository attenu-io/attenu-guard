"""
dg_claude_sdk.py — a thin delegation-guard integration for the Claude Agent SDK
(``claude-agent-sdk``, PyPI, tested against 0.2.139).

WHAT IT HOOKS
-------------
The Claude Agent SDK delegates through **subagents**: the parent calls the
built-in ``Agent`` tool (named ``Task`` before Claude Code v2.1.63) with a
``subagent_type``, and the CLI runs that subagent in a fresh context. The SDK
exposes both of the hook points delegation-guard needs, as plain ``async``
Python callbacks the CLI invokes over its JSON control channel
(``claude_agent_sdk/_internal/query.py:427-500``):

1. **Child creation** — ``hooks={"SubagentStart": [HookMatcher(hooks=[...])]}``.
   ``SubagentStartHookInput`` (``types.py:381``) carries ``agent_id`` and
   ``agent_type``. This is where the child's ``Guard`` is minted with
   ``parent_guard.delegate(...)``.
   The *decision to delegate at all* is authorized one step earlier, in
   ``PreToolUse`` on the ``Agent``/``Task`` tool, where ``tool_input`` carries
   ``subagent_type`` — so "who may delegate to what" is itself a scope.

2. **Tool invocation** — ``hooks={"PreToolUse": [HookMatcher(hooks=[...])]}``.
   ``PreToolUseHookInput`` (``types.py:311``) carries ``tool_name``,
   ``tool_input`` and — critically — the optional ``agent_id``/``agent_type``
   of the subagent making the call (``types.py:290-306``). That ``agent_id`` is
   the correlation key: it is what lets one process-wide hook route each tool
   call to the *right* child ``Guard``. It is absent on the main thread, which
   is how the orchestrator's own calls are distinguished.
   Returning ``{"hookSpecificOutput": {"hookEventName": "PreToolUse",
   "permissionDecision": "deny", ...}}`` blocks the call **before the tool body
   runs**; ``deny`` beats every other hook's verdict.

``can_use_tool`` (``ClaudeAgentOptions.can_use_tool``) is wired too, as a
second, independent gate — see ``ClaudeAgentOptions.can_use_tool``'s own
docstring (``types.py:2046``): it fires only for calls the CLI's permission
rules would otherwise *prompt* on, so it is not sufficient by itself. The
``PreToolUse`` hook is the primary enforcement point; ``can_use_tool`` catches
the same policy again if a call reaches the prompt path.

USAGE
-----
Build one registry per session, hand its hooks to ``ClaudeAgentOptions``, and
let it do the rest::

    reg = DelegationGuardRegistry(
        root=Guard.issue("orchestrator", Authority(
            scopes={"crm.*", "mail.send", "agent.delegate.*"},
            ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600)),
        agent_grants={"summarizer": AgentGrant(Authority(
            scopes={"crm.read"},
            ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900))},
        tool_policies={
            "mcp__crm__crm_query":  ToolPolicy("crm.read",   lambda i: {"rows": i.get("rows", 0)}),
            "mcp__crm__crm_export": ToolPolicy("crm.export", lambda i: {"egress": "any"}),
        })

    options = ClaudeAgentOptions(
        agents={"summarizer": AgentDefinition(...)},
        hooks=reg.hooks(),
        can_use_tool=reg.can_use_tool,
    )

Every allow and deny lands in ``reg.root.audit_log()``; ``reg.revoke_agent(id)``
cascade-revokes a subagent and every descendant it spawned.

DESIGN NOTES (both are security-relevant)
-----------------------------------------
* **Fail-closed everywhere.** A tool with no ``ToolPolicy``, an ``agent_type``
  with no ``AgentGrant``, or a ``PreToolUse`` that arrives for an ``agent_id``
  before its ``SubagentStart`` — each is denied or minted from the narrow
  grant, never allowed by default and never silently attributed to the root's
  broad authority. Hook dispatch is concurrent by the SDK's own documentation
  (``types.py:2064``: "multiple matchers registered on the same event are
  dispatched concurrently"), so ordering between ``SubagentStart`` and the
  subagent's first ``PreToolUse`` must not be assumed.
* **Allow is silence.** On an allow this hook returns ``{}`` rather than
  ``permissionDecision: "allow"``. Returning an explicit allow would *skip*
  the CLI's remaining permission machinery, including ``can_use_tool`` — so
  delegation-guard would end up widening the session's effective permissions.
  Returning ``{}`` means "delegation-guard has no objection"; the framework's
  own rules still apply on top.

This module imports ``claude_agent_sdk`` only lazily, from inside the two
methods that genuinely need its dataclasses (``hooks()`` and ``can_use_tool``),
so the file imports and unit-tests with zero third-party dependencies.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping, Optional

from delegation_guard import Authority, Guard

__all__ = ["ToolPolicy", "AgentGrant", "DelegationGuardRegistry", "DELEGATION_TOOLS"]

# The parent invokes a subagent through this built-in tool. Renamed from
# "Task" to "Agent" in Claude Code v2.1.63; the old name still appears in
# `system:init` tool lists and `result.permission_denials[].tool_name`, so
# both are recognised.
DELEGATION_TOOLS = ("Agent", "Task")


@dataclass(frozen=True)
class ToolPolicy:
    """Maps one tool name (or fnmatch pattern) onto the authority question.

    ``scope``       the permission string ``Guard.check`` is asked about.
    ``context_fn``  turns the tool's own ``tool_input`` dict into the context
                    bag the typed ceilings read (``{"rows": n}``,
                    ``{"egress": "any"}``, ``{"spend": 12.5}``, ...).
    ``metered``     forwarded to ``Guard.check(metered=...)``: marks this call
                    as consuming a metered resource, so a guard issued with
                    ``strict_metering=True`` refuses it if no context is
                    supplied at all.
    """
    scope: str
    context_fn: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None
    metered: bool = False

    def context(self, tool_input: Mapping[str, Any]) -> Mapping[str, Any]:
        return dict(self.context_fn(tool_input)) if self.context_fn else {}


@dataclass(frozen=True)
class AgentGrant:
    """What a subagent of a given ``agent_type`` is *asked* for at delegation
    time. What it actually receives is ``parent.authority.meet(requested)`` —
    never more than the parent held, whatever this says.

    ``tools`` is optional and purely belt-and-braces: the tool names to put in
    the SDK's own ``AgentDefinition.tools`` allowlist for this agent type, so
    the framework-level restriction and the authority-level one are derived
    from a single declaration and cannot drift apart.
    """
    authority: Authority
    task: str = ""
    tools: tuple[str, ...] = ()


@dataclass
class _Pending:
    """A delegation the parent has asked for but whose subagent has not started
    yet."""
    parent_agent_id: Optional[str]
    subagent_type: str
    tool_use_id: Optional[str]


class DelegationGuardRegistry:
    """Routes Claude Agent SDK tool calls to the right attenuated ``Guard``.

    One registry per session. Thread-safety note: the SDK dispatches hook
    callbacks concurrently, but they all run on the single asyncio/trio event
    loop that owns the transport, and none of the methods here ``await``
    between reading and mutating state — so the mutations below are atomic with
    respect to each other without a lock.
    """

    def __init__(
        self,
        root: Guard,
        *,
        agent_grants: Mapping[str, AgentGrant],
        tool_policies: Mapping[str, ToolPolicy],
        delegate_scope: Callable[[str], str] = lambda t: f"agent.delegate.{t}",
        delegation_tools: tuple[str, ...] = DELEGATION_TOOLS,
        revoke_on_stop: bool = True,
    ) -> None:
        self.root = root
        self.agent_grants = dict(agent_grants)
        self.tool_policies = dict(tool_policies)
        self.delegate_scope = delegate_scope
        self.delegation_tools = tuple(delegation_tools)
        # Revoking on SubagentStop is the security-correct default: a finished
        # agent should hold no authority. Set False if you use the SDK's
        # subagent *resume* (docs: "Resume subagents"), which brings the same
        # agent_id back to life — its Guard would otherwise stay revoked and
        # deny everything on the second run.
        self.revoke_on_stop = revoke_on_stop
        self._guards: MutableMapping[str, Guard] = {}
        self._pending: list[_Pending] = []
        self.denials: list[dict] = []   # everything this registry blocked, for reporting

    # ---- lookup ---------------------------------------------------------
    def guard_for(self, agent_id: Optional[str]) -> Optional[Guard]:
        """The Guard that governs ``agent_id``; the root when ``agent_id`` is
        None (the main thread). Returns None only when the agent is unknown and
        cannot be minted — the caller must treat that as a denial."""
        if agent_id is None:
            return self.root
        return self._guards.get(agent_id)

    def policy_for(self, tool_name: str) -> Optional[ToolPolicy]:
        exact = self.tool_policies.get(tool_name)
        if exact is not None:
            return exact
        # Longest pattern wins, so "mcp__crm__crm_export" beats "mcp__crm__*".
        for pattern in sorted(self.tool_policies, key=len, reverse=True):
            if fnmatch.fnmatchcase(tool_name, pattern):
                return self.tool_policies[pattern]
        return None

    # ---- hook point 1: child creation -----------------------------------
    def mint(self, agent_id: str, agent_type: str,
             parent: Optional[Guard] = None) -> Optional[Guard]:
        """Mint (or return the existing) Guard for a subagent instance.

        Returns None — fail closed — when ``agent_type`` has no ``AgentGrant``:
        an agent type nobody declared authority for gets no authority at all.
        """
        existing = self._guards.get(agent_id)
        if existing is not None:
            return existing
        grant = self.agent_grants.get(agent_type)
        if grant is None:
            return None
        if parent is None:
            parent = self._claim_pending_parent(agent_type)
        child = parent.delegate(agent_type, grant.authority,
                                task=grant.task or f"subagent:{agent_type}")
        self._guards[agent_id] = child
        return child

    def _claim_pending_parent(self, agent_type: str) -> Guard:
        """Pop the delegation request this subagent most likely came from.

        The SDK's ``SubagentStartHookInput`` carries the child's own
        ``agent_id``/``agent_type`` but NOT the spawning parent's ``agent_id``
        or the ``tool_use_id`` of the ``Agent`` call that created it, so the
        parent must be inferred from the ``PreToolUse`` we saw on that ``Agent``
        call. FIFO per ``agent_type`` is exact for the common case and
        approximate only when two *different* parents spawn the same
        ``agent_type`` concurrently — in which case the granted authority is
        still correct (it comes from the grant, met with a parent that holds
        the delegate scope) but the audit tree's parent edge may name the wrong
        sibling. See the findings report; this is an SDK payload gap, not a
        delegation-guard one.
        """
        for i, p in enumerate(self._pending):
            if p.subagent_type == agent_type:
                self._pending.pop(i)
                parent = self.guard_for(p.parent_agent_id)
                if parent is not None:
                    return parent
                break
        return self.root

    async def subagent_start(self, input_data: Mapping[str, Any],
                             tool_use_id: Optional[str],
                             context: Mapping[str, Any]) -> dict:
        """``SubagentStart`` hook: mint the child's attenuated Guard."""
        agent_id = input_data.get("agent_id")
        agent_type = input_data.get("agent_type")
        if not agent_id or not agent_type:
            return {}
        if self.mint(agent_id, agent_type) is None:
            # Nothing to enforce with. SubagentStart cannot deny (its only
            # hook-specific output is `additionalContext`), so the subagent
            # still starts — but with no Guard registered, every tool call it
            # makes is denied by `pre_tool_use` below.
            return {"systemMessage":
                    f"delegation-guard: no authority grant declared for agent_type "
                    f"{agent_type!r}; all of its tool calls will be denied."}
        return {}

    async def subagent_stop(self, input_data: Mapping[str, Any],
                            tool_use_id: Optional[str],
                            context: Mapping[str, Any]) -> dict:
        """``SubagentStop`` hook: cascade-revoke the finished subagent so a
        late or replayed tool call from it cannot still be authorized."""
        agent_id = input_data.get("agent_id")
        if self.revoke_on_stop and agent_id and agent_id in self._guards:
            self._guards[agent_id].revoke()
        return {}

    def revoke_agent(self, agent_id: str) -> list:
        """Cascade-revoke a subagent and every descendant it delegated to."""
        guard = self._guards.get(agent_id)
        if guard is None:
            return []
        return guard.revoke()

    # ---- hook point 2: tool invocation -----------------------------------
    def authorize(self, tool_name: str, tool_input: Mapping[str, Any],
                  agent_id: Optional[str], agent_type: Optional[str]):
        """The whole policy decision, framework-free.

        Returns ``(allowed: bool, reason: str)``. Every denial is also appended
        to ``self.denials`` and — when a Guard was found — to the hash-chained
        audit log.
        """
        guard = self.guard_for(agent_id)
        if guard is None:
            if agent_type:
                guard = self.mint(agent_id, agent_type)   # type: ignore[arg-type]
            if guard is None:
                return self._deny(
                    tool_name, agent_id,
                    f"unknown sub-agent {agent_id!r} of type {agent_type!r}: "
                    f"no delegation-guard authority grant is declared for it")

        if tool_name in self.delegation_tools:
            subagent_type = str(tool_input.get("subagent_type") or "")
            if subagent_type not in self.agent_grants:
                return self._deny(
                    tool_name, agent_id,
                    f"no authority grant declared for subagent_type "
                    f"{subagent_type!r}; refusing to delegate")
            scope = self.delegate_scope(subagent_type)
            decision = guard.check(scope, context={"subagent_type": subagent_type},
                                   tool=tool_name)
            if not decision:
                return self._deny(tool_name, agent_id, decision.explain())
            self._pending.append(_Pending(agent_id, subagent_type,
                                          str(tool_input.get("_tool_use_id") or "") or None))
            return True, f"delegation to {subagent_type!r} authorized"

        policy = self.policy_for(tool_name)
        if policy is None:
            return self._deny(
                tool_name, agent_id,
                f"tool {tool_name!r} has no delegation-guard ToolPolicy; "
                f"refusing to authorize an unmapped capability")

        decision = guard.check(policy.scope, context=policy.context(tool_input),
                               metered=policy.metered, tool=tool_name)
        if not decision:
            return self._deny(tool_name, agent_id, decision.explain())
        return True, f"{policy.scope} authorized"

    def _deny(self, tool_name: str, agent_id: Optional[str], reason: str):
        self.denials.append({"tool": tool_name, "agent_id": agent_id, "reason": reason})
        return False, reason

    async def pre_tool_use(self, input_data: Mapping[str, Any],
                           tool_use_id: Optional[str],
                           context: Mapping[str, Any]) -> dict:
        """``PreToolUse`` hook — the primary enforcement point.

        Denies before the tool body runs. On an allow it returns ``{}`` (no
        opinion) rather than an explicit ``"allow"``, which would bypass the
        CLI's own permission rules and ``can_use_tool``.
        """
        if input_data.get("hook_event_name") != "PreToolUse":
            return {}
        tool_name = str(input_data.get("tool_name") or "")
        tool_input = dict(input_data.get("tool_input") or {})
        if tool_use_id and tool_name in self.delegation_tools:
            tool_input.setdefault("_tool_use_id", tool_use_id)

        allowed, reason = self.authorize(
            tool_name, tool_input,
            input_data.get("agent_id"), input_data.get("agent_type"))
        if allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"delegation-guard: {reason}",
            },
            "systemMessage": f"delegation-guard denied {tool_name}: {reason}",
        }

    # ---- the second gate: ClaudeAgentOptions.can_use_tool ----------------
    async def can_use_tool(self, tool_name: str, tool_input: Mapping[str, Any],
                           context: Any):
        """``CanUseTool`` callback. Same policy, expressed as the SDK's
        ``PermissionResult``. ``context.agent_id`` (``types.py:214``) is the
        same correlation key the hook uses.

        Asymmetry worth knowing: ``ToolPermissionContext`` carries ``agent_id``
        but NOT ``agent_type`` (``PreToolUseHookInput`` carries both), so this
        path cannot lazily mint a Guard for a subagent it has never seen — it
        denies instead. Harmless in practice because ``PreToolUse`` fires
        first for the same call and does the minting; it is one more reason the
        hook, not this callback, is the enforcement point.
        """
        from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny

        agent_id = getattr(context, "agent_id", None)
        allowed, reason = self.authorize(tool_name, dict(tool_input), agent_id, None)
        if allowed:
            return PermissionResultAllow()
        return PermissionResultDeny(message=f"delegation-guard: {reason}")

    # ---- wiring ---------------------------------------------------------
    def hooks(self) -> dict:
        """The ``hooks=`` value for ``ClaudeAgentOptions``.

        No ``matcher`` is set on ``PreToolUse`` deliberately: an unmatched hook
        runs for *every* tool call, which is what fail-closed requires — a
        per-tool matcher would silently exempt any tool nobody remembered to
        list.
        """
        from claude_agent_sdk import HookMatcher

        return {
            "PreToolUse": [HookMatcher(hooks=[self.pre_tool_use])],
            "SubagentStart": [HookMatcher(hooks=[self.subagent_start])],
            "SubagentStop": [HookMatcher(hooks=[self.subagent_stop])],
        }

    def agent_definitions(self, **common: Any) -> dict:
        """Derive ``ClaudeAgentOptions.agents`` from the same ``AgentGrant``
        declarations, so the SDK's own per-agent ``tools`` allowlist and
        delegation-guard's authority grants cannot drift apart.

        ``common`` supplies the per-agent fields delegation-guard has no
        opinion about (``description``, ``prompt``, ``model``, ...) as
        ``{agent_type: {field: value}}``.
        """
        from claude_agent_sdk import AgentDefinition

        out = {}
        for name, grant in self.agent_grants.items():
            fields = dict(common.get(name) or {})
            fields.setdefault("description", grant.task or f"{name} subagent")
            fields.setdefault("prompt", grant.task or f"You are the {name} subagent.")
            if grant.tools:
                fields.setdefault("tools", list(grant.tools))
            out[name] = AgentDefinition(**fields)
        return out
