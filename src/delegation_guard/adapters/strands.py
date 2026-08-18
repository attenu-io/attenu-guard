"""
delegation-guard x AWS Strands Agents — a thin enforcement adapter.

Paste this file into your project. It uses `delegation_guard` unmodified and
only Strands' *public* hook API — no monkeypatching, no subclassing of Agent,
Swarm or Graph.

HOOK POINTS USED
----------------
1. Child creation / delegation
   a. `strands.hooks.BeforeToolCallEvent` where `event.selected_tool.tool_type
      == "agent"` — i.e. the "agents as tools" pattern (`Agent.as_tool()` ->
      `strands/agent/_agent_as_tool.py:28 _AgentAsTool`). The parent agent
      calling the sub-agent IS the delegation, so the child's `Guard` is minted
      there via `parent_guard.delegate(...)`.
   b. `strands.hooks.BeforeNodeCallEvent` (`strands/hooks/events.py:406`,
      raised at `strands/multiagent/swarm.py:810` and `graph.py:993`) — fires
      immediately before a swarm/graph node executes. The node that handed off
      is `swarm.state.node_history[-1]`, so the child Guard is minted from that
      node's Guard with the handoff message as the task.

2. Tool invocation
   `strands.hooks.BeforeToolCallEvent` (`strands/hooks/events.py:208`). Setting
   `event.cancel_tool = <str>` makes the executor skip the tool body entirely
   and hand the model an error ToolResult carrying that string
   (`strands/tools/executors/_executor.py:176-198`). That is a code-enforced
   gate, not a prompt: the function never runs.

USAGE
-----
Build a root `Guard`, describe (a) which scope+context each tool call needs and
(b) what authority each child may REQUEST, then register one
`DelegationGuard` on the parent agent, on every sub-agent, and — if you use one
— on the Swarm/Graph::

    dg = DelegationGuard(
        root_guard=Guard.issue("orchestrator", ORCH_AUTHORITY, task="root"),
        root_agent_name="orchestrator",
        scope_for=scope_map({
            "crm_query":  lambda i: ScopeRequest("crm.read",   {"rows": i["rows"]}),
            "crm_export": lambda i: ScopeRequest("crm.export", {"egress": "any"}),
            "summarizer": "agent.delegate",
        }),
        authority_for=lambda name, task: SUB_AGENT_AUTHORITY[name],
    )
    for agent in (orchestrator, summarizer):
        agent.hooks.add_hook(dg)      # or Agent(hooks=[dg], ...)
    swarm = Swarm([orchestrator, summarizer], hooks=[dg])   # if you use one

Prefer Strands' own authorization seam? `Agent(interventions=[dg.as_intervention()])`
gives the identical guarantee — `Deny` is applied as the same `cancel_tool` —
but interventions have no multi-agent lifecycle method, so a Swarm/Graph still
needs the hook registration above.

delegation-guard deliberately does NOT decide what authority a task needs — you
write `authority_for`. Whatever it returns is only ever an *input* to
`Authority.meet`, so a child can never come out wider than its parent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from strands.hooks import (
    BeforeNodeCallEvent,
    BeforeToolCallEvent,
    HookProvider,
    HookRegistry,
)
from strands.interventions import Deny, InterventionHandler, Proceed

from delegation_guard import Authority, AuthorityError, Guard

__all__ = [
    "ScopeRequest",
    "ScopeResolver",
    "AuthorityResolver",
    "DelegationGuard",
    "scope_map",
]


# ---------------------------------------------------------------------------
# What a single tool call is asking for
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScopeRequest:
    """The authority one tool call needs: a scope plus the quantities the
    ceilings are measured against (e.g. `{"rows": 4200}`, `{"egress": "any"}`).
    """

    scope: str
    context: Mapping[str, Any] = field(default_factory=dict)
    metered: bool = False


# (tool_use) -> ScopeRequest, or None meaning "this tool needs no authority"
ScopeResolver = Callable[[Mapping[str, Any]], "ScopeRequest | None"]

# (child_agent_name, task) -> the Authority the child may REQUEST, or None to
# refuse the delegation outright.
AuthorityResolver = Callable[[str, str], "Authority | None"]


def scope_map(
    mapping: Mapping[str, "str | ScopeRequest | Callable[[Mapping[str, Any]], ScopeRequest | None]"],
    *,
    unmapped: str = "deny",
) -> ScopeResolver:
    """Build a `ScopeResolver` from a `{tool_name: ...}` table.

    A value may be a bare scope string, a ready-made `ScopeRequest`, or a
    callable taking the tool's parsed arguments and returning one.

    `unmapped="deny"` (the default) is what makes this fail CLOSED: a tool
    nobody wrote a rule for resolves to the synthetic scope `tool.<name>`,
    which no `Authority` grants — so delegation-guard denies it through its
    normal path and the refusal lands in the audit log with the reason code
    `scope_not_granted`, rather than being special-cased in adapter code.
    `unmapped="allow"` opts a deployment out of that.
    """
    if unmapped not in ("deny", "allow"):
        raise ValueError("unmapped must be 'deny' or 'allow'")

    def resolve(tool_use: Mapping[str, Any]) -> ScopeRequest | None:
        name = tool_use["name"]
        if name not in mapping:
            return None if unmapped == "allow" else ScopeRequest(f"tool.{name}")

        rule = mapping[name]
        if isinstance(rule, str):
            return ScopeRequest(rule)
        if isinstance(rule, ScopeRequest):
            return rule
        return rule(_tool_input(tool_use))

    return resolve


def _tool_input(tool_use: Mapping[str, Any]) -> Mapping[str, Any]:
    """Strands parses the model's tool arguments into `tool_use["input"]`; a
    provider that streams a bare string leaves it as one."""
    raw = tool_use.get("input")
    if isinstance(raw, Mapping):
        return raw
    return {"input": raw}


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------

class DelegationGuard(HookProvider):
    """One object, registered on every Agent (and on the Swarm/Graph if you
    use one), that mints attenuated child Guards at delegation time and
    authorizes every tool call before its body runs.

    It is deliberately fail-closed: an agent with no Guard bound to it cannot
    call any tool, and a delegation whose `authority_for` returns None is
    refused.
    """

    def __init__(
        self,
        root_guard: Guard,
        root_agent: "Any | None" = None,
        *,
        root_agent_name: "str | None" = None,
        scope_for: ScopeResolver,
        authority_for: AuthorityResolver,
        on_decision: "Callable[[str, str, Any], None] | None" = None,
    ) -> None:
        if root_agent is None and root_agent_name is None:
            raise ValueError("pass root_agent, or root_agent_name if it does not exist yet")

        self.root_guard = root_guard
        self.root_agent = root_agent
        self._scope_for = scope_for
        self._authority_for = authority_for
        self._on_decision = on_decision

        root_name = root_agent_name or self._agent_name(root_agent)
        self._by_obj: dict[int, Guard] = {} if root_agent is None else {id(root_agent): root_guard}
        self._by_name: dict[str, Guard] = {root_name: root_guard}
        self._revoked_names: set[str] = set()

    # -- introspection ------------------------------------------------------

    def guard_for(self, agent: Any) -> "Guard | None":
        """The Guard bound to `agent` — by object identity, falling back to
        `agent.name`. The name fallback exists because Strands' `interventions=`
        is constructor-only: with agents-as-tools the parent does not exist yet
        when its sub-agent is built, so the guard can only be bound by name."""
        guard = self._by_obj.get(id(agent))
        if guard is None:
            guard = self._by_name.get(self._agent_name(agent))
            if guard is not None:
                self._by_obj[id(agent)] = guard
        return guard

    def guard_for_name(self, name: str) -> "Guard | None":
        return self._by_name.get(name)

    def revoke(self, name: str) -> list:
        """Cascade-revoke an agent's current Guard and refuse to re-mint one
        for that name.

        The second half is adapter policy, not library behaviour:
        `Guard.revoke()` revokes a chain NODE, but a framework that hands off
        to the same agent twice would simply mint a fresh node. Remembering
        the name is what makes revocation stick to the *principal*.
        """
        guard = self._by_name.get(name)
        if guard is None:
            raise KeyError(f"no Guard bound to agent {name!r}")
        self._revoked_names.add(name)
        return guard.revoke()

    # -- HookProvider -------------------------------------------------------

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self.before_tool_call)
        registry.add_callback(BeforeNodeCallEvent, self.before_node_call)

    # -- hook 2: every tool call, and hook 1a: agents-as-tools --------------

    def before_tool_call(self, event: BeforeToolCallEvent) -> None:
        denial = self.evaluate_tool_call(event)
        if denial is not None:
            event.cancel_tool = denial

    def evaluate_tool_call(self, event: BeforeToolCallEvent) -> "str | None":
        """Authorize the call and, if it is a delegation, mint the child Guard.
        Returns None to allow, or the denial message. Shared by the hook path
        and the `InterventionHandler` path — they differ only in how the
        refusal is delivered."""
        agent = event.agent
        tool_use = event.tool_use
        tool_name = tool_use["name"]

        guard = self.guard_for(agent)
        if guard is None:
            return (
                f"denied: agent {self._agent_name(agent)!r} holds no delegated "
                f"authority (no Guard bound), so it may not call {tool_name!r}"
            )

        # Authorize the call itself. For a sub-agent tool this gates the
        # *right to delegate*; for a normal tool it gates the action.
        request = self._scope_for(tool_use)
        if request is not None:
            decision = guard.check(
                request.scope,
                context=dict(request.context),
                metered=request.metered,
                tool=tool_name,
            )
            if self._on_decision is not None:
                self._on_decision(self._agent_name(agent), tool_name, decision)
            if not decision:
                return f"authority denied for {tool_name!r}: {decision.explain()}"

        # Agents-as-tools: this call IS a delegation — mint the child's Guard.
        selected = event.selected_tool
        if selected is not None and getattr(selected, "tool_type", None) == "agent":
            child_agent = getattr(selected, "agent", None)
            if child_agent is None:  # pragma: no cover - defensive
                return None
            child_name = getattr(selected, "tool_name", None) or self._agent_name(child_agent)
            task = str(_tool_input(tool_use).get("input", ""))
            return self._mint(guard, child_agent, child_name, task)

        return None

    # -- the same enforcement, as a Strands InterventionHandler -------------

    def as_intervention(self, name: str = "delegation-guard") -> InterventionHandler:
        """Expose this guard through Strands' own authorization seam, for
        `Agent(interventions=[...])`.

        `Deny` is applied by `strands/interventions/registry.py:127-129` as
        exactly the `event.cancel_tool` this adapter sets directly, so the
        guarantee is identical; the difference is idiom and ordering
        (interventions run at `HookOrder.INTERVENTION_INPUT`, i.e. after
        default-order hooks). Interventions have no multi-agent lifecycle
        method, so a Swarm/Graph still needs `register_hooks` for
        `BeforeNodeCallEvent`.
        """
        outer = self

        class _DelegationGuardIntervention(InterventionHandler):
            @property
            def name(self) -> str:
                return name

            @property
            def on_error(self) -> str:
                return "deny"  # a crashing policy check must fail closed

            def before_tool_call(self, event: BeforeToolCallEvent, **kwargs: Any):
                denial = outer.evaluate_tool_call(event)
                return Proceed() if denial is None else Deny(reason=denial)

        return _DelegationGuardIntervention()

    # -- hook 1b: swarm / graph handoff -------------------------------------

    def before_node_call(self, event: BeforeNodeCallEvent) -> None:
        orchestrator = event.source
        node = orchestrator.nodes[event.node_id]
        agent = node.executor

        # The entry node starts the chain; it must be the agent the root Guard
        # was issued to, otherwise we do not know what authority it holds.
        history = getattr(getattr(orchestrator, "state", None), "node_history", None) or []
        if not history:
            if self.guard_for(agent) is None:
                event.cancel_node = (
                    f"denied: entry node {event.node_id!r} holds no delegated authority"
                )
            return

        parent_guard = self.guard_for(history[-1].executor)
        if parent_guard is None:
            event.cancel_node = (
                f"denied: {history[-1].node_id!r} holds no delegated authority, "
                f"so it may not hand off to {event.node_id!r}"
            )
            return

        task = str(
            getattr(orchestrator.state, "handoff_message", None)
            or getattr(orchestrator.state, "task", "")
        )
        error = self._mint(parent_guard, agent, event.node_id, task)
        if error is not None:
            event.cancel_node = error

    # -- shared minting -----------------------------------------------------

    def _mint(self, parent_guard: Guard, child_agent: Any, child_name: str, task: str) -> "str | None":
        """Delegate `parent_guard` -> a child Guard bound to `child_agent`.
        Returns None on success, or a denial message to cancel with."""
        if child_name in self._revoked_names:
            return f"denied: authority for {child_name!r} has been revoked"

        request = self._authority_for(child_name, task)
        if request is None:
            return (
                f"denied: no Authority defined for delegation to {child_name!r} "
                f"(authority_for returned None)"
            )

        try:
            child = parent_guard.delegate(child_name, request, task=task)
        except AuthorityError as exc:
            return f"denied: cannot delegate to {child_name!r}: {exc.reason} ({exc})"

        self._by_obj[id(child_agent)] = child
        self._by_name[child_name] = child
        return None

    # -- misc ---------------------------------------------------------------

    @staticmethod
    def _agent_name(agent: Any) -> str:
        return str(getattr(agent, "name", None) or f"agent-{id(agent):x}")
