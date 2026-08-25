"""
Strike policy — revoke a node after repeated denials (attenu-derive T26; default policy: 3 same-scope denials, configurable,
on/off). A denied agent that keeps probing the same wall is either broken or hostile; after N strikes the node is
cascade-revoked and the parent can see why on the ledger. Off by default (opt-in per installation).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StrikePolicy:
    enabled: bool = True                 # a StrikePolicy is only attached when wanted; `enabled=False` disarms without detaching
    n: int = 3                           # strikes before revocation
    mode: str = "same_scope"             # "same_scope": N denials of ONE scope | "total": N denials across any scope

    def __post_init__(self):
        if self.mode not in ("same_scope", "total"):
            raise ValueError("mode must be 'same_scope' or 'total'")
        if self.n < 1:
            raise ValueError("n must be >= 1")

    def key(self, node_id: str, scope: str) -> tuple:
        return (node_id, scope) if self.mode == "same_scope" else (node_id, "*")
