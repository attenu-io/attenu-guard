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
import json
import os
import time
from dataclasses import dataclass, field

from .authority import Authority, AuthorityError


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
        self._ids = itertools.count()
        self._consumed: dict[str, float] = {}     # aggregate counters
        self._secret = os.urandom(32)             # per-chain integrity key

    # ---- integrity -----------------------------------------------------
    def _seal(self, authority: Authority) -> str:
        blob = json.dumps(authority.to_dict(), sort_keys=True,
                          separators=(",", ":")).encode()
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

    def add_child(self, parent_id: str, agent_id: str,
                  requested: Authority, task: str) -> Node:
        parent = self.nodes[parent_id]
        if self.is_revoked(parent_id):
            raise AuthorityError("cannot delegate from a revoked node",
                                 reason="chain_revoked", detail={"parent": parent_id})
        if not self.verify_integrity(parent):
            raise AuthorityError("parent authority failed integrity check",
                                 reason="integrity", detail={"parent": parent_id})
        if self.is_expired(parent):
            raise AuthorityError("cannot delegate from an expired authority",
                                 reason="ttl_expired", detail={"parent": parent_id})
        if parent.depth + 1 > self.max_depth:
            raise AuthorityError(
                f"delegation depth {parent.depth + 1} exceeds max_depth {self.max_depth}",
                reason="max_depth", detail={"max_depth": self.max_depth})
        if len(parent.children) + 1 > self.max_fanout:
            raise AuthorityError(f"fanout exceeds max_fanout {self.max_fanout}",
                                 reason="max_fanout", detail={"max_fanout": self.max_fanout})

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

    # ---- aggregate budgets --------------------------------------------
    def consume(self, key: str, amount: float, chain_ceiling: float | None):
        total = self._consumed.get(key, 0.0) + amount
        if chain_ceiling is not None and total > chain_ceiling:
            raise AuthorityError(
                f"chain aggregate {key}={total} exceeds chain ceiling {chain_ceiling}",
                reason="chain_ceiling",
                detail={"key": key, "total": total, "ceiling": chain_ceiling})
        self._consumed[key] = total

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
