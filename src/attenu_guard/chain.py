"""
Chain state — the live delegation graph, TTL, integrity, and cascade revocation.

A Chain tracks the tree of delegations rooted at one top-level task and enforces
the structural invariants that no single-agent policy engine can express:

  * monotonic attenuation: every child authority <= its parent's (via meet);
  * time bounds: an authority stops authorizing once its TTL elapses;
  * depth / fanout ceilings on the tree;
  * aggregate ceilings summed across the whole chain;
  * cascade revocation: killing any node revokes its whole subtree;
  * in-process integrity: each node's authority is sealed with a per-chain
    secret so accidental (or unsophisticated) mutation of node state is caught
    at check() time. NOTE: this raises the bar against bugs and casual tampering
    only — a same-process adversary can read the secret. Real tamper-resistance
    comes from the production data-plane's signed, offline-verifiable grants;
    the in-process library tier explicitly trusts its own process.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import os
import threading
import time
from dataclasses import dataclass, field

from .authority import Authority, AuthorityError
from . import canonical


class MonotonicClock:
    """Default wall clock (seconds). Injectable so tests are deterministic."""
    def now(self) -> float:
        return time.monotonic()


@dataclass
class Node:
    node_id: str
    parent_id: str | None
    agent_id: str
    authority: Authority
    task: str
    depth: int
    issued_at: float
    revoked: bool = False
    complete: bool = False       # lifecycle end marker (Guard.complete()): informational, never widens or narrows authority
    children: list[str] = field(default_factory=list)
    seal: str = ""  # HMAC of the authority under the chain secret


class Chain:
    def __init__(self, chain_id: str, *, max_depth: int = 6, max_fanout: int = 16,
                 clock=None):
        self.chain_id = chain_id
        self.max_depth = max_depth
        self.max_fanout = max_fanout
        self.clock = clock or MonotonicClock()
        self.nodes: dict[str, Node] = {}
        self._revoked: set[str] = set()          # grow-only
        self._banned_agents: set[str] = set()    # grow-only: agent_ids no node may delegate to
        self._ids = itertools.count()
        self._consumed: dict[str, float] = {}     # aggregate counters
        self._calls: dict[tuple, int] = {}        # (node_id, scope) -> calls so far (auto-metering for CallLimit)
        self._strikes: dict[tuple, int] = {}      # (node_id, scope|*) -> denials so far (strike policy)
        self._secret = os.urandom(32)             # per-chain integrity key
        self._lock = threading.RLock()            # mutations from parallel tool calls
        # 0.9.0 execution binding (schema_version=2 chains only; see guard.py):
        self.params_salt: bytes | None = None     # 16 raw bytes, set once by Guard.issue(); shared
                                                    # by every node in the chain (see params.py)
        self._pending: dict[str, set[str]] = {}    # node_id -> call_ids awaiting an outcome
        self._outcomed: set[str] = set()           # call_ids that already received an outcome, chain-wide

    # ---- integrity -----------------------------------------------------
    def _seal(self, authority: Authority) -> str:
        blob = canonical.dumps(authority.to_dict())
        return hmac.new(self._secret, blob, hashlib.sha256).hexdigest()

    def verify_integrity(self, node: Node) -> bool:
        return hmac.compare_digest(node.seal, self._seal(node.authority))

    def new_node_id(self) -> str:
        return f"{self.chain_id}:n{next(self._ids)}"

    def add_root(self, agent_id: str, authority: Authority, task: str) -> Node:
        nid = self.new_node_id()
        node = Node(nid, None, agent_id, authority, task, depth=0,
                    issued_at=self.clock.now())
        node.seal = self._seal(authority)
        self.nodes[nid] = node
        return node

    # ---- ttl -----------------------------------------------------------
    def is_expired(self, node: Node) -> bool:
        ttl = node.authority.ttl
        if ttl is None:
            return False
        return (self.clock.now() - node.issued_at) > ttl

    def delegation_error(self, parent_id: str, agent_id: str) -> AuthorityError | None:
        """The structural preconditions for `add_child`, WITHOUT mutating
        anything: returns the AuthorityError that `add_child` would raise, or
        None if the delegation is currently permitted. `add_child` calls this;
        `Guard.would_delegate` exposes it as a pure dry-run."""
        parent = self.nodes[parent_id]
        if self.is_revoked(parent_id):
            return AuthorityError("cannot delegate from a revoked node",
                                  reason="chain_revoked", detail={"parent": parent_id})
        if agent_id in self._banned_agents:
            return AuthorityError(f"agent {agent_id!r} has been revoked in this chain",
                                  reason="agent_banned", detail={"agent": agent_id})
        if not self.verify_integrity(parent):
            return AuthorityError("parent authority failed integrity check",
                                  reason="integrity", detail={"parent": parent_id})
        if self.is_expired(parent):
            return AuthorityError("cannot delegate from an expired authority",
                                  reason="ttl_expired", detail={"parent": parent_id})
        if parent.depth + 1 > self.max_depth:
            return AuthorityError(
                f"delegation depth {parent.depth + 1} exceeds max_depth {self.max_depth}",
                reason="max_depth", detail={"max_depth": self.max_depth})
        if len(parent.children) + 1 > self.max_fanout:
            return AuthorityError(f"fanout exceeds max_fanout {self.max_fanout}",
                                  reason="max_fanout", detail={"max_fanout": self.max_fanout})
        return None

    def add_child(self, parent_id: str, agent_id: str,
                  requested: Authority, task: str) -> Node:
        with self._lock:
            return self._add_child_locked(parent_id, agent_id, requested, task)

    def _add_child_locked(self, parent_id: str, agent_id: str,
                          requested: Authority, task: str) -> Node:
        parent = self.nodes[parent_id]
        err = self.delegation_error(parent_id, agent_id)
        if err is not None:
            raise err

        # THE attenuation step: child authority is the meet, never a copy.
        child_auth = parent.authority.meet(requested)
        # Defensive re-assertion of the core invariant (must always hold).
        assert child_auth.is_narrower_than(parent.authority), "attenuation invariant violated"

        nid = self.new_node_id()
        node = Node(nid, parent_id, agent_id, child_auth, task, parent.depth + 1,
                    issued_at=self.clock.now())
        node.seal = self._seal(child_auth)
        self.nodes[nid] = node
        parent.children.append(nid)
        return node

    # ---- revocation ----------------------------------------------------
    def revoke(self, node_id: str) -> list[str]:
        with self._lock:
            revoked_now: list[str] = []
            stack = [node_id]
            while stack:
                nid = stack.pop()
                if nid in self._revoked:
                    continue
                self._revoked.add(nid)
                self.nodes[nid].revoked = True
                revoked_now.append(nid)
                stack.extend(self.nodes[nid].children)
            return revoked_now

    def is_revoked(self, node_id: str) -> bool:
        return node_id in self._revoked

    def revoke_agent(self, agent_id: str) -> list[str]:
        """PRINCIPAL-scoped revocation: cascade-revoke every node held by
        `agent_id` and ban the agent so no node in this chain can delegate to
        it again (grow-only, like `_revoked`). Closes the re-delegation
        bypass where a framework re-hands-off to a revoked agent and would
        otherwise mint it a fresh, clean child from a still-valid parent."""
        with self._lock:
            self._banned_agents.add(agent_id)
            revoked_now: list[str] = []
            for nid, node in list(self.nodes.items()):
                if node.agent_id == agent_id and nid not in self._revoked:
                    revoked_now.extend(self.revoke(nid))
            return revoked_now

    def is_banned(self, agent_id: str) -> bool:
        return agent_id in self._banned_agents

    # ---- aggregate budgets --------------------------------------------
    def consume(self, key: str, amount: float, chain_ceiling: float | None):
        with self._lock:
            total = self._consumed.get(key, 0.0) + amount
            if chain_ceiling is not None and total > chain_ceiling:
                raise AuthorityError(
                    f"chain aggregate {key}={total} exceeds chain ceiling {chain_ceiling}",
                    reason="chain_ceiling",
                    detail={"key": key, "total": total, "ceiling": chain_ceiling})
            self._consumed[key] = total

    def calls_so_far(self, node_id: str, scope: str) -> int:
        return self._calls.get((node_id, scope), 0)

    def count_call(self, node_id: str, scope: str) -> int:
        with self._lock:
            n = self._calls.get((node_id, scope), 0) + 1
            self._calls[(node_id, scope)] = n
            return n

    def uncount_call(self, node_id: str, scope: str) -> int:
        """Undo one count_call — used when a call's metering was applied but the transition then
        failed BEFORE the commit point (0.9.0: call_id allocation; spec section 1, 'meters are
        restored'), so the meter reads as if the call had never been evaluated."""
        with self._lock:
            n = max(0, self._calls.get((node_id, scope), 0) - 1)
            self._calls[(node_id, scope)] = n
            return n

    def record_strike(self, key: tuple) -> int:
        """Count a denial for the strike policy; returns the running total for `key`."""
        with self._lock:
            n = self._strikes.get(key, 0) + 1
            self._strikes[key] = n
            return n

    # ---- execution binding: pending calls + exactly-one-outcome (0.9.0, v2 chains) ------------
    def register_pending(self, node_id: str, call_id: str) -> None:
        """An `allow`ed call now awaits an outcome. Not locked here — callers already hold
        `self._lock` for the whole check() transition (see guard.py); this method itself takes
        the lock too so it stays correct if ever called standalone."""
        with self._lock:
            self._pending.setdefault(node_id, set()).add(call_id)

    def resolve_pending(self, call_id: str) -> str | None:
        """Remove `call_id` from whichever node's pending set holds it (record_outcome's job);
        returns that node_id, or None if it was not pending anywhere in this chain. A call_id
        that never was pending (e.g. bound to a deny, or foreign) is left for the offline
        verifier to flag — this is a best-effort runtime cleanup, not a gate."""
        with self._lock:
            for nid, calls in self._pending.items():
                if call_id in calls:
                    calls.discard(call_id)
                    return nid
            return None

    def pending_for(self, node_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._pending.get(node_id, ())))

    def mark_outcomed(self, call_id: str) -> bool:
        """True the FIRST time `call_id` is marked (and it is now recorded as outcomed); False if
        it was already outcomed — the runtime half of "exactly one outcome per call_id" (the
        restart rule is what makes this enforceable within one chain's continuous lifetime)."""
        with self._lock:
            if call_id in self._outcomed:
                return False
            self._outcomed.add(call_id)
            return True

    def graph(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "nodes": [
                {"id": n.node_id, "parent": n.parent_id, "agent": n.agent_id,
                 "task": n.task, "depth": n.depth, "revoked": n.revoked,
                 "authority": n.authority.to_dict()}
                for n in self.nodes.values()
            ],
        }
