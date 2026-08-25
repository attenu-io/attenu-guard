# SPDX-License-Identifier: Apache-2.0
"""An Omnigent policy handler that gives each sub-agent an authority, not a counter.

Registered the way every Omnigent policy is registered — ``type: function`` with a
``handler:`` dotted path and ``factory_params:`` (docs/POLICIES.md "Factory form") — this
factory returns an evaluator ``fn(event) -> {"result": ...} | None`` that abstains on
everything except tool calls, and on tool calls answers three questions Omnigent's own
open issues leave to the operator:

  1. **Depth.** ``spawn_bounds`` counts dispatches *within one orchestrator turn* and
     resets on the runner's ``reset_turn`` hook, so each child starts a fresh count
     (issue #5169). Here the bound is a property of the delegation chain, not of a turn:
     a dispatch at depth > ``max_depth`` is DENIED whichever turn or session it happens in.
  2. **Per-sub-agent scope.** Each dispatched sub-agent's authority is derived from the
     tools its own spec declares and is the *meet* with its parent's — so a child can never
     hold more than the agent that dispatched it. (Issue #2390 asks for sub-agent access
     control keyed on the human *user*; this is keyed on the dispatching *agent*, which is
     a different question with a similar shape.)
  3. **Evidence.** Every ALLOW and DENY is appended to a hash-chained ledger that verifies
     with no service and no network, and can be exported as a signed bundle.

The chain lives in a process-local registry keyed by ``chain_id``, so the orchestrator's
policy instance and each sub-agent's policy instance share one chain: install the handler
server-wide (or in every agent spec) and give each instance its own ``agent:`` name.

This module imports nothing from ``omnigent`` at import time — the event and response
shapes are plain dicts — so it loads whether or not Omnigent is installed.
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from attenu_guard import (
    Authority,
    AuthorityError,
    CallLimit,
    EgressRank,
    Guard,
    ReasonCode,
)

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime
    from omnigent.policies.schema import PolicyEvent, PolicyResponse

__all__ = [
    "DelegationChain",
    "POLICY_REGISTRY",
    "attenu_delegation_guard",
    "chain_for",
]

#: Omnigent's sub-agent dispatch tool — the interception point named in issue #2390 and
#: the tool ``spawn_bounds`` counts by default.
DEFAULT_DISPATCH_TOOLS: tuple[str, ...] = ("sys_session_send",)

_ALLOW: dict[str, Any] = {"result": "ALLOW"}


def _deny(reason: str) -> dict[str, Any]:
    """Build an Omnigent DENY response.

    :param reason: Human-readable explanation surfaced in the transcript.
    :returns: A policy response dict.
    """
    return {"result": "DENY", "reason": reason}


# ---------------------------------------------------------------------------------------
# The roster: what the operator declares, and what the guard derives from it
# ---------------------------------------------------------------------------------------

def _ceilings_from_spec(specs: Sequence[Mapping[str, Any]] | None) -> list[Any]:
    """Turn the roster's declarative ceiling entries into guard ceilings.

    Two forms are understood, both YAML-friendly::

        {"max_calls": 1, "applies_to": "deploy.release"}
        {"egress": "none"}

    :param specs: The ``ceilings`` list from one roster entry, or ``None``.
    :returns: A list of ceiling objects for :class:`~attenu_guard.Authority`.
    """
    out: list[Any] = []
    for spec in specs or ():
        if "max_calls" in spec:
            out.append(CallLimit(int(spec["max_calls"]), spec.get("applies_to")))
        elif "egress" in spec:
            out.append(EgressRank(str(spec["egress"])))
        else:
            raise ValueError(f"unknown ceiling entry {dict(spec)!r}; expected 'max_calls' or 'egress'")
    return out


class DelegationChain:
    """One delegation chain shared by every policy instance in a process.

    The chain is the state that a per-turn counter cannot be: it is not reset at a turn
    boundary and it is not scoped to one session, so a depth or fan-out bound expressed on
    it holds across both.

    :param root: Roster name of the orchestrator — the chain's root node.
    :param roster: ``{agent_name: {"tools": [...], "subagents": [...], "ceilings": [...]}}``.
    :param scopes: Tool name to scope string, e.g. ``{"repo_write": "repo.write"}``.
    :param max_depth: Deepest delegation level allowed (root is depth 0).
    :param max_fanout: Most sub-agents one node may dispatch.
    :param ttl: Seconds the root authority stays valid.
    :param audit_path: Optional path for the append-only ledger file.
    :param chain_id: Registry key; instances sharing it share one chain.
    """

    _registry: dict[str, "DelegationChain"] = {}
    _registry_lock = threading.Lock()

    def __init__(
        self,
        *,
        root: str,
        roster: Mapping[str, Mapping[str, Any]],
        scopes: Mapping[str, str],
        max_depth: int = 2,
        max_fanout: int = 4,
        ttl: int | None = 3600,
        audit_path: str | None = None,
        chain_id: str = "omnigent",
    ) -> None:
        if root not in roster:
            raise ValueError(f"root agent {root!r} is not in the roster")
        self.root = root
        self.roster = {name: dict(entry) for name, entry in roster.items()}
        self.scopes = dict(scopes)
        self.chain_id = chain_id
        self.max_depth = max_depth
        self.max_fanout = max_fanout
        self._lock = threading.RLock()
        self._guards: dict[str, Guard] = {}
        self._root_guard = Guard.issue(
            root,
            self.authority_for(root, ttl=ttl),
            task=f"orchestrate ({root})",
            chain_id=chain_id,
            max_depth=max_depth,
            max_fanout=max_fanout,
            audit_path=audit_path,
        )
        self._guards[root] = self._root_guard

    # ---- derivation ---------------------------------------------------------------
    def subtree(self, name: str, _seen: frozenset[str] = frozenset()) -> set[str]:
        """Roster names reachable from *name*, inclusive.

        :param name: Roster entry to walk from.
        :param _seen: Names already visited (cycle guard).
        :returns: The set of names in this agent's declared delegation subtree.
        """
        if name in _seen or name not in self.roster:
            return set()
        seen = _seen | {name}
        out = {name}
        for child in self.roster[name].get("subagents", ()):
            out |= self.subtree(child, seen)
        return out

    def authority_for(self, name: str, *, ttl: int | None = None) -> Authority:
        """The authority a roster entry holds: its own tools plus its subtree's.

        A parent cannot delegate what it does not hold — the meet would strip it — so a
        node holds the union of the scopes declared across its delegation subtree. The
        narrowing that matters is still enforced: a child's authority is the meet with its
        parent's, and a sub-agent in a different branch never receives this branch's scopes.

        :param name: Roster entry.
        :param ttl: Seconds this authority stays valid; ``None`` inherits from the parent.
        :returns: The requested :class:`~attenu_guard.Authority`.
        """
        held: set[str] = set()
        for member in self.subtree(name):
            for tool in self.roster[member].get("tools", ()):
                scope = self.scopes.get(tool)
                if scope is None:
                    raise ValueError(f"tool {tool!r} declared by {member!r} has no scope in `scopes`")
                held.add(scope)
        ceilings = _ceilings_from_spec(self.roster[name].get("ceilings"))
        return Authority(scopes=frozenset(held), ceilings=ceilings, ttl=ttl)

    def scope_for(self, tool: str) -> str | None:
        """The scope a tool maps to, or ``None`` when the operator declared none.

        :param tool: Tool name from the event.
        :returns: The scope string, or ``None``.
        """
        return self.scopes.get(tool)

    # ---- chain --------------------------------------------------------------------
    @property
    def root_guard(self) -> Guard:
        """The chain's root guard.

        :returns: The orchestrator's :class:`~attenu_guard.Guard`.
        """
        return self._root_guard

    def guard_for(self, name: str) -> Guard | None:
        """The guard of an agent already on the chain.

        :param name: Roster name.
        :returns: Its guard, or ``None`` when nothing has delegated to it yet.
        """
        with self._lock:
            return self._guards.get(name)

    def delegate(self, parent: str, child: str, task: str) -> Guard:
        """Attenuate a new sub-agent onto the chain.

        :param parent: The dispatching agent's roster name.
        :param child: The dispatched sub-agent's roster name.
        :param task: Free-text task label recorded on the ledger.
        :returns: The child's guard — the existing one when this sub-agent is already on
            the chain, mirroring Omnigent's "reusing the same (agent, title) pair
            continues the existing session".
        :raises AuthorityError: On a structural refusal — depth, fan-out, revocation, TTL.
        """
        with self._lock:
            existing = self._guards.get(child)
            if existing is not None:
                return existing
            parent_guard = self._guards[parent]
            child_guard = parent_guard.delegate(child, self.authority_for(child), task)
            self._guards[child] = child_guard
            return child_guard

    def graph(self) -> dict:
        """The chain as a plain dict, for a reviewer or a test.

        :returns: ``Chain.graph()`` output.
        """
        return self._root_guard.graph()

    # ---- registry -----------------------------------------------------------------
    @classmethod
    def get_or_create(cls, chain_id: str, factory: Callable[[], "DelegationChain"]) -> "DelegationChain":
        """Fetch the chain registered under *chain_id*, building it on first use.

        :param chain_id: Registry key.
        :param factory: Zero-argument builder used when the key is absent.
        :returns: The shared chain.
        """
        with cls._registry_lock:
            chain = cls._registry.get(chain_id)
            if chain is None:
                chain = factory()
                cls._registry[chain_id] = chain
            return chain

    @classmethod
    def reset(cls, chain_id: str | None = None) -> None:
        """Drop registered chains — for tests and for a fresh demo run.

        :param chain_id: One key to drop, or ``None`` for all of them.
        :returns: ``None``.
        """
        with cls._registry_lock:
            if chain_id is None:
                cls._registry.clear()
            else:
                cls._registry.pop(chain_id, None)


def chain_for(chain_id: str = "omnigent") -> DelegationChain | None:
    """The registered chain, for evidence export after a run.

    :param chain_id: Registry key.
    :returns: The chain, or ``None`` when no policy instance has built it yet.
    """
    return DelegationChain._registry.get(chain_id)


# ---------------------------------------------------------------------------------------
# The policy factory
# ---------------------------------------------------------------------------------------

def attenu_delegation_guard(
    *,
    agent: str,
    roster: Mapping[str, Mapping[str, Any]],
    scopes: Mapping[str, str],
    root: str | None = None,
    max_depth: int = 2,
    max_fanout: int = 4,
    ttl: int | None = 3600,
    audit_path: str | None = None,
    chain_id: str = "omnigent",
    dispatch_tools: Sequence[str] = DEFAULT_DISPATCH_TOOLS,
) -> Callable[["PolicyEvent"], "PolicyResponse | None"]:
    """Factory: bound the delegation tree by authority rather than by a per-turn count.

    The returned evaluator abstains (``None``) on every phase but ``tool_call``. On a
    dispatch tool it attenuates the named sub-agent onto the chain and DENIES when the
    chain refuses — depth, fan-out, an undeclared sub-agent. On any other tool call it
    asks the acting agent's authority and DENIES when the scope is not held.

    :param agent: Roster name of the agent whose session this policy instance runs in.
    :param roster: ``{name: {"tools": [...], "subagents": [...], "ceilings": [...]}}``.
    :param scopes: Tool name to scope string, e.g. ``{"repo_write": "repo.write"}``.
    :param root: Roster name of the orchestrator; defaults to *agent*.
    :param max_depth: Deepest delegation level allowed (root is depth 0), e.g. ``2``.
    :param max_fanout: Most sub-agents one node may dispatch, e.g. ``4``.
    :param ttl: Seconds the root authority stays valid.
    :param audit_path: Optional ledger file path.
    :param chain_id: Registry key shared by every policy instance in this process.
    :param dispatch_tools: Tool names that dispatch a sub-agent, e.g. ``("sys_session_send",)``.
    :returns: An evaluator ``fn(event)`` returning an Omnigent decision dict, or ``None``.
    """
    if agent not in roster:
        raise ValueError(f"agent {agent!r} is not in the roster {sorted(roster)}")
    dispatch = frozenset(dispatch_tools)
    chain = DelegationChain.get_or_create(
        chain_id,
        lambda: DelegationChain(
            root=root or agent,
            roster=roster,
            scopes=scopes,
            max_depth=max_depth,
            max_fanout=max_fanout,
            ttl=ttl,
            audit_path=audit_path,
            chain_id=chain_id,
        ),
    )
    # Every instance sharing a chain_id must describe the same chain, or the second
    # instance would silently run against the first one's topology.
    if dict(chain.roster) != {n: dict(e) for n, e in roster.items()} or dict(chain.scopes) != dict(scopes):
        raise ValueError(
            f"chain_id {chain_id!r} is already registered with a different roster or scope map; "
            "every policy instance on one chain must declare the same topology",
        )

    def _evaluate(event: "PolicyEvent") -> "PolicyResponse | None":
        """Decide one Omnigent event.

        :param event: The V0 policy event dict.
        :returns: ALLOW / DENY, or ``None`` to abstain on non-tool phases.
        """
        if event.get("type") != "tool_call":
            return None
        data = event.get("data")
        if not isinstance(data, dict):
            return None
        tool = data.get("name") or event.get("target")
        if not isinstance(tool, str):
            return None
        args = data.get("arguments")
        args = args if isinstance(args, dict) else {}

        acting = chain.guard_for(agent)
        if acting is None:
            # This agent is not on the chain: nothing delegated to it, so it holds nothing.
            # Fail closed, and put the refusal on the same ledger as every other decision.
            chain.root_guard.record_denial(
                ReasonCode.NO_AUTHORITY,
                f"{agent!r} holds no authority in this chain",
                scope=chain.scope_for(tool) or tool,
                tool=tool,
            )
            return _deny(f"{agent!r} holds no authority in this delegation chain; {tool} denied.")

        if tool in dispatch:
            return _dispatch_decision(chain, acting, agent, tool, args)
        return _tool_decision(chain, acting, agent, tool, args)

    return _evaluate


def _dispatch_decision(
    chain: DelegationChain,
    acting: Guard,
    agent: str,
    tool: str,
    args: Mapping[str, Any],
) -> "PolicyResponse":
    """Attenuate a dispatched sub-agent, or explain why the chain refused.

    :param chain: The shared delegation chain.
    :param acting: The dispatching agent's guard.
    :param agent: The dispatching agent's roster name.
    :param tool: The dispatch tool name.
    :param args: The dispatch tool's arguments.
    :returns: An Omnigent decision dict.
    """
    child = args.get("agent")
    if not isinstance(child, str) or not child:
        # session_id mode addresses an existing child rather than a declared sub-agent
        # name; this policy gates named dispatch only, and says so rather than guessing.
        acting.record_denial(
            ReasonCode.NO_AUTHORITY,
            "dispatch carried no declared sub-agent name",
            scope="delegation",
            tool=tool,
        )
        return _deny(
            f"{tool} carried no declared sub-agent name (args.agent). Named dispatch only: "
            "this policy derives the child's authority from the sub-agent its spec declares.",
        )
    if child not in chain.roster:
        acting.record_denial(
            ReasonCode.NO_AUTHORITY,
            f"sub-agent {child!r} is not in the declared roster",
            scope="delegation",
            tool=tool,
        )
        return _deny(f"Sub-agent {child!r} is not in the declared roster, so no authority can be derived for it.")
    declared = tuple(chain.roster[agent].get("subagents", ()))
    if child not in declared:
        acting.record_denial(
            ReasonCode.NO_AUTHORITY,
            f"{agent!r} does not declare {child!r} as a sub-agent",
            scope="delegation",
            tool=tool,
        )
        return _deny(f"{agent!r} declares sub-agents {list(declared)}; {child!r} is not one of them.")

    child_args = args.get("args")
    task = ""
    if isinstance(child_args, dict):
        task = str(child_args.get("purpose") or "")
    try:
        child_guard = chain.delegate(agent, child, task or f"{agent} -> {child}")
    except AuthorityError as exc:
        if exc.reason == ReasonCode.MAX_DEPTH:
            return _deny(
                f"Delegation depth {exc.detail.get('max_depth', chain.max_depth) + 1} would exceed the chain "
                f"ceiling of {chain.max_depth}. The bound is on the chain, so it holds in every turn and every "
                f"session, not only in the one that dispatched.",
            )
        if exc.reason == ReasonCode.MAX_FANOUT:
            return _deny(
                f"{agent!r} has already dispatched {chain.max_fanout} sub-agents on this chain "
                f"(the chain ceiling, counted for the life of the chain rather than per turn).",
            )
        return _deny(f"Delegation to {child!r} refused: {exc.reason}.")

    held = sorted(child_guard.authority.scopes)
    return {
        "result": "ALLOW",
        "reason": f"{child} holds {held} (subset of {agent}); depth {chain.max_depth} ceiling not reached.",
    }


def _tool_decision(
    chain: DelegationChain,
    acting: Guard,
    agent: str,
    tool: str,
    args: Mapping[str, Any],
) -> "PolicyResponse":
    """Check one ordinary tool call against the acting agent's authority.

    :param chain: The shared delegation chain.
    :param acting: The acting agent's guard.
    :param agent: The acting agent's roster name.
    :param tool: The tool being called.
    :param args: The tool's arguments.
    :returns: An Omnigent decision dict.
    """
    scope = chain.scope_for(tool)
    if scope is None:
        # No declared scope: the operator never granted this tool to anyone, so no agent
        # can hold it. Denied by default rather than allowed by omission.
        acting.record_denial(
            ReasonCode.NO_AUTHORITY,
            f"tool {tool!r} has no declared scope",
            scope=tool,
            tool=tool,
        )
        return _deny(
            f"{tool} has no declared scope in this policy's `scopes` map, so no agent holds it. "
            "Declare it and grant it to the agents that need it.",
        )

    context = {k: v for k, v in args.items() if k in ("rows", "spend", "egress")}
    decision = acting.check(scope, context=context, tool=tool)
    if decision:
        return _ALLOW
    codes = ", ".join(r.code for r in decision.reasons) or "denied"
    return _deny(
        f"{agent!r} does not hold {scope} ({codes}). Its authority is "
        f"{sorted(acting.authority.scopes)} — the meet with the agent that dispatched it.",
    )


#: Makes the handler discoverable in Omnigent's policy registry
#: (``docs/POLICIES.md`` — "Making policies discoverable").
POLICY_REGISTRY = [
    {
        "handler": "attenu_omnigent.attenu_delegation_guard",
        "kind": "factory",
        "name": "Attenu delegation guard",
        "description": (
            "Derive each sub-agent's authority from its declared tools, keep it a subset of the "
            "agent that dispatched it, bound the chain's depth and fan-out, and record every "
            "ALLOW and DENY on a hash-chained ledger that verifies offline."
        ),
        "params_schema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "description": "Roster name of the agent this instance runs for"},
                "roster": {"type": "object", "description": "agent -> {tools, subagents, ceilings}"},
                "scopes": {"type": "object", "description": "tool name -> scope string"},
                "root": {"type": "string", "description": "Roster name of the orchestrator"},
                "max_depth": {"type": "integer", "description": "Deepest delegation level", "default": 2},
                "max_fanout": {"type": "integer", "description": "Most sub-agents per node", "default": 4},
                "audit_path": {"type": "string", "description": "Ledger file path"},
                "chain_id": {"type": "string", "description": "Registry key", "default": "omnigent"},
            },
            "required": ["agent", "roster", "scopes"],
        },
    },
]
