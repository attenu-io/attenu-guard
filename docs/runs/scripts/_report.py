"""Shared printing for the audit-continuity runners.

Every runner in this directory imports its scenario from ``examples/integrations/``
and adds printing only. This module is that printing: the sections are identical
across the five frameworks so the blocks can be read side by side, and everything
below the parent's own view is read out of an **exported bundle**, never out of
the live Guard — that is the point the write-up makes about the audit log
belonging to the chain rather than to an agent.
"""
from __future__ import annotations

from typing import Any, Iterable

from attenu_guard import evidence
from attenu_guard.wire import HS256TestSigner

SIGNER = HS256TestSigner(b"demo-key", kid="demo")


def head(fw: str, what: str) -> None:
    print(f"\n--- {fw}: {what} ---")


def bundle_of(guard) -> dict:
    return evidence.export_bundle(guard.audit_log(), SIGNER)


def node_agents(bundle: dict) -> dict[str, dict[str, Any]]:
    """node id -> {agent, parent, allows, denies}, from the bundle alone."""
    out: dict[str, dict[str, Any]] = {}
    for e in bundle["entries"]:
        node = e.get("node")
        if e["event"] in ("root", "spawn") and node:
            out[node] = {"agent": e.get("agent"), "parent": e.get("parent"),
                         "allows": 0, "denies": 0}
    for e in bundle["entries"]:
        node = e.get("node")
        if node in out and e["event"] in ("allow", "deny"):
            out[node]["allows" if e["event"] == "allow" else "denies"] += 1
    return out


def print_node_map(fw: str, bundle: dict) -> None:
    head(fw, "node -> agent, reconstructed from the bundle alone")
    for node, d in node_agents(bundle).items():
        print(f"  node={node}  agent={d['agent']}  parent={d['parent']}  "
              f"allows={d['allows']}  denies={d['denies']}")


def print_entries(fw: str, bundle: dict) -> None:
    head(fw, "bundle entries (seq node event scope; tool added, it is what names "
             "the call)")
    width = max(16, max(len(e.get("node") or "-") for e in bundle["entries"]) + 2)
    for e in bundle["entries"]:
        line = (f"{e['seq']:>5}  {e.get('node') or '-':<{width}}{e['event']:<10}"
                f"{e.get('scope') or '-':<18}tool={e.get('tool') or '-'}")
        if e.get("reason"):
            line += f"  reason={e['reason']}"
        print(line)


def print_verify(fw: str, bundle: dict) -> bool:
    head(fw, "verify_bundle")
    report = evidence.verify_bundle(bundle, SIGNER)
    print(f"  ok={report['ok']}")
    print(f"  checks={report['checks']}")
    return bool(report["ok"])


def print_child_attribution(fw: str, bundle: dict) -> None:
    head(fw, "entries attributed to each CHILD node in the bundle")
    nodes = node_agents(bundle)
    for node, d in nodes.items():
        if d["parent"] is None:
            continue
        rows = [(e["seq"], e["event"], e.get("tool"), e.get("scope"))
                for e in bundle["entries"]
                if e.get("node") == node and e["event"] in ("allow", "deny")]
        print(f"  {d['agent']} ({node}): {rows}")


def print_child_guards(fw: str, guard) -> None:
    head(fw, "the child guards")
    graph = guard.graph()
    nodes = graph["nodes"] if isinstance(graph, dict) else []
    for n in nodes:
        if n.get("parent") is None:
            continue
        a = n["authority"]
        ceilings = ", ".join(
            f"{c['key']}={c.get('max', c.get('rank'))}" for c in a["constraints"])
        print(f"  {n['agent']} ({n['id']}): scopes={sorted(a['scopes'])} "
              f"ceilings=[{ceilings}] ttl={a['ttl']} revoked={n['revoked']}")


def print_bodies(fw: str, sink: Iterable) -> None:
    head(fw, "tool bodies that actually ran")
    print(f"  {list(sink)}")


def tail(fw: str, guard) -> bool:
    """The four sections every runner ends with. Returns verify_bundle's ok."""
    bundle = bundle_of(guard)
    print_node_map(fw, bundle)
    print_entries(fw, bundle)
    ok = print_verify(fw, bundle)
    print_child_attribution(fw, bundle)
    return ok
