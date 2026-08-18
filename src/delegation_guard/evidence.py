"""
Offline evidence bundle + verifier (attenu-derive T33a). The delegation ledger is only worth as much as an
auditor's ability to check it WITHOUT the engine that produced it. This module exports a self-contained bundle
(the hash-chained ledger + a signed anchor) and verifies three invariants from that bundle ALONE:

  integrity     the hash chain reproduces AND matches the out-of-band signed anchor (a consistent full rewrite,
                which `AuditLog.verify` alone cannot catch, fails here — the anchor's head is the fixed point);
  monotonicity  every delegation is child ⊆ parent (the granted authority on each `spawn` is narrower than the
                parent node's authority) — Attenu's core claim, re-checked offline;
  containment   every `allow` action's scope was within the acting node's authority — the ledger is internally
                consistent, no action was authorised outside what the node held.

    from delegation_guard import evidence
    bundle = evidence.export_bundle(guard.audit_log(), signer)     # publish this + verify the anchor out-of-band
    rep = evidence.verify_bundle(bundle, signer)                   # {"ok", "checks": {...}, "failures": [...]}

Stdlib-only; `signer` is any `wire` signer (Ed25519 in production). No engine state is consulted — the bundle
is the whole input, which is the point.
"""
from __future__ import annotations

import json
from typing import Any

from delegation_guard.audit import SCHEMA_VERSION, AuditLog
from delegation_guard.authority import Authority

__all__ = ["export_bundle", "verify_bundle", "delegation_graph"]


def _chain_id(entries: list[dict]) -> str:
    for e in entries:
        if e.get("chain_id"):
            return e["chain_id"]
    return "chain"


def _anchor_for(entries: list[dict], signer, ts: int = 0) -> dict:
    """A signed commitment to the head of `entries` (mirrors AuditLog.anchor, but over a plain list — used by
    export and by tests that re-anchor a rewritten bundle)."""
    if not entries:
        seq, head = -1, "GENESIS"
    else:
        seq, head = entries[-1].get("seq", len(entries) - 1), entries[-1]["hash"]
    body = {"v": SCHEMA_VERSION, "chain_id": _chain_id(entries), "seq": seq, "head": head, "ts": ts}
    signing_input = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "kid": getattr(signer, "kid", None), "sig": signer.sign(signing_input).hex()}


def export_bundle(audit_log: AuditLog, signer, ts: int = 0) -> dict:
    """A self-contained evidence bundle: the full ledger + a signed anchor over its head."""
    entries = audit_log.entries
    anchor = _anchor_for(entries, signer, ts)
    from delegation_guard import AuditLog as _AL
    anchor["verified"] = _AL.verify_anchor(entries, anchor, signer)[0]
    return {"v": SCHEMA_VERSION, "chain_id": _chain_id(entries), "entries": entries, "anchor": anchor,
            "note": "offline-verifiable: delegation_guard.evidence.verify_bundle(bundle, signer)"}


def _node_authorities(entries: list[dict]) -> tuple[dict, dict, list]:
    """(node -> Authority, node -> parent, failures) reconstructed from root/spawn events, no engine state."""
    auth: dict[str, Authority] = {}; parent: dict[str, str] = {}; fail = []
    for e in entries:
        ev = e.get("event")
        if ev == "root":
            try: auth[e["node"]] = Authority.from_wire(e["authority"])
            except Exception as exc: fail.append(f"root {e.get('node')}: unreadable authority ({exc})")  # noqa: BLE001
        elif ev == "spawn":
            parent[e["node"]] = e.get("parent")
            try: auth[e["node"]] = Authority.from_wire(e["granted"])
            except Exception as exc: fail.append(f"spawn {e.get('node')}: unreadable granted ({exc})")  # noqa: BLE001
    return auth, parent, fail


def delegation_graph(bundle: dict) -> dict:
    """A view of the chain from the bundle: each node with its agent, task, authority, parent, and per-node action
    counts (allow/deny) — what a reviewer or a UI renders. Derived from the ledger alone."""
    entries = bundle.get("entries") or []
    auth, parent, _ = _node_authorities(entries)
    meta: dict[str, dict] = {}
    for e in entries:
        ev = e.get("event"); n = e.get("node")
        if ev in ("root", "spawn"):
            meta[n] = {"agent": e.get("agent"), "task": e.get("task"), "parent": e.get("parent"),
                       "scopes": sorted(auth[n].scopes) if n in auth else [], "allows": 0, "denies": 0, "revoked": False, "complete": False}
        elif ev == "allow" and n in meta: meta[n]["allows"] += 1
        elif ev == "deny" and n in meta: meta[n]["denies"] += 1
        elif ev == "done" and n in meta: meta[n]["complete"] = True
        elif ev == "kill":
            for r in (e.get("revoked") or []):
                if r in meta: meta[r]["revoked"] = True
    return {"chain_id": bundle.get("chain_id"), "nodes": meta,
            "edges": [{"parent": p, "child": c} for c, p in parent.items() if p]}


def verify_bundle(bundle: dict, signer) -> dict:
    """Verify integrity, monotonicity and containment from the bundle alone. Returns {ok, checks, failures, ...}."""
    entries = bundle.get("entries") or []
    anchor = bundle.get("anchor") or {}
    checks = {"integrity": False, "monotonicity": False, "containment": False}
    failures: list[str] = []

    # (1) integrity: hash chain + signed anchor
    ok_chain, err = AuditLog.verify(entries)
    ok_anchor, aerr = AuditLog.verify_anchor(entries, anchor, signer)
    checks["integrity"] = bool(ok_chain and ok_anchor)
    if not ok_chain: failures.append(f"integrity: {err}")
    if not ok_anchor: failures.append(f"integrity(anchor): {aerr}")

    auth, parent, afail = _node_authorities(entries)
    failures += afail

    # (2) monotonicity: every child ⊆ its parent
    mono = True
    for node, pid in parent.items():
        if pid is None or pid not in auth or node not in auth:
            continue
        if not auth[node].is_narrower_than(auth[pid]) and set(auth[node].scopes) - set(auth[pid].scopes):
            mono = False; failures.append(f"monotonicity: {node} not ⊆ parent {pid} (child scopes {sorted(set(auth[node].scopes) - set(auth[pid].scopes))} not held by parent)")
    checks["monotonicity"] = mono and not afail

    # (3) containment: every allow action's scope within the acting node's authority
    contained = True; actions = 0
    for e in entries:
        if e.get("event") != "allow":
            continue
        actions += 1
        node = e.get("node"); scope = e.get("scope"); ctx = e.get("context") or {}
        a = auth.get(node)
        if a is None:
            contained = False; failures.append(f"containment: allow on unknown node {node}"); continue
        if not a.permits(scope, ctx):
            contained = False; failures.append(f"containment: allow of {scope!r} on {node} outside its authority {sorted(a.scopes)}")
    checks["containment"] = contained

    return {"ok": all(checks.values()) and not failures, "checks": checks, "failures": failures,
            "nodes": len(auth), "actions_checked": actions, "chain_id": bundle.get("chain_id")}
