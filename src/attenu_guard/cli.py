"""
attenu-guard — command-line tool.

  attenu-guard demo                  run the poisoned-summariser demo
  attenu-guard view <log.jsonl>      render an audit log as a delegation tree + verify it
  attenu-guard verify <log>          verify a hash-chained audit log, exit non-zero on tamper
  attenu-guard scenarios <file>      run a declarative authorization scenario (JSON/YAML),
                           exit non-zero if any assertion fails. --coverage prints
                           which reason codes were exercised.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .audit import AuditLog


def _scenarios(args: list[str]):
    from . import scenarios
    return scenarios.main(args)


def _view(path: str):
    entries = AuditLog.load(path)
    ok, reason = AuditLog.verify(entries)
    # reconstruct the tree from spawn events
    children: dict[str, list] = {}
    labels: dict[str, str] = {}
    roots = []
    for e in entries:
        if e["event"] == "root":
            labels[e["node"]] = f'{e["agent"]}  [root]'
            roots.append(e["node"])
        elif e["event"] == "spawn":
            labels[e["node"]] = f'{e["agent"]}  «{e["task"]}»'
            children.setdefault(e["parent"], []).append(e["node"])

    decisions: dict[str, list[str]] = {}
    for e in entries:
        if e["event"] in ("allow", "deny"):
            node = e.get("node", "?")
            mark = "✓" if e["event"] == "allow" else f'✗ {e.get("reason")}'
            decisions.setdefault(node, []).append(f'{e.get("scope")} {mark}')
        elif e["event"] == "kill":
            for n in e.get("revoked", []):
                decisions.setdefault(n, []).append("KILLED")

    def draw(node, prefix=""):
        print(prefix + labels.get(node, node))
        for d in decisions.get(node, []):
            print(prefix + "    · " + d)
        kids = children.get(node, [])
        for i, k in enumerate(kids):
            draw(k, prefix + "    ")

    for r in roots:
        draw(r)
    status = "OK" if ok else f"TAMPERED — {reason}"
    print(f"\naudit chain: {len(entries)} events · verification: {status}")
    return 0 if ok else 2


def _verify(path: str):
    entries = AuditLog.load(path)
    ok, reason = AuditLog.verify(entries)
    print("OK" if ok else f"TAMPERED — {reason}")
    return 0 if ok else 2


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    cmd, *rest = argv
    if cmd == "demo":
        from attenu_guard._demo import main as demo_main
        demo_main()
        return 0
    if cmd == "view" and rest:
        return _view(rest[0])
    if cmd == "verify" and rest:
        return _verify(rest[0])
    if cmd == "scenarios" and rest:
        return _scenarios(rest)
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
