"""
attenu-guard — command-line tool.

  attenu-guard demo                  run the poisoned-summariser demo
  attenu-guard view <log.jsonl>      render an audit log as a delegation tree + verify it
  attenu-guard verify <log|bundle>   verify a hash-chained audit log, or an evidence bundle
                                     (integrity · child ⊆ parent · containment; --hs256-key/--pubkey checks the anchor;
                                      --witness-keys FILE supplies the trusted observer-envelope keys)
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


def _witness_keys(path: str):
    """The trust set for a bundle's observer envelopes, read from `--witness-keys FILE`.

    The file is the `witness_keys` array the interop vectors carry — `[{"kid", "alg",
    "public_key_hex"}]` — or one whole vector case, in which case its `witness_keys` member is
    used. Without a trust set every envelope in a bundle fails `envelope_unknown_witness`, which
    is correct (an unknown key is not a trusted one) and useless as a default, so this is how a
    bundle carrying envelopes is verified from the command line."""
    import json
    parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(parsed, dict) and "witness_keys" in parsed:
        parsed = parsed["witness_keys"]
    if not isinstance(parsed, list):
        raise ValueError(f"{path}: expected a list of {{kid, alg, public_key_hex}}, "
                         f"got {type(parsed).__name__}")
    return parsed


def _verify(args: list):
    """`attenu-guard verify <audit.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
    [--witness-keys FILE]`

    A `.jsonl` audit log: hash-chain integrity. A bundle (`export_bundle` output): integrity, monotonicity
    (child ⊆ parent) and containment from the bundle alone; the signed anchor is verified when a key is given
    and reported as "not checked" otherwise. `--witness-keys FILE` supplies the trusted witness keys for a
    bundle carrying observer envelopes; without it every envelope fails `envelope_unknown_witness`, and the
    output says which flag to pass. Exit 0 = ok, 2 = a check failed, 1 = usage."""
    import json
    path, key_hex, pub_hex, kid, witness_path = None, None, None, None, None
    it = iter(args)
    for a in it:
        if a == "--hs256-key": key_hex = next(it, None)
        elif a == "--pubkey": pub_hex = next(it, None)
        elif a == "--kid": kid = next(it, None)
        elif a == "--witness-keys": witness_path = next(it, None)
        elif path is None: path = a
    if not path:
        print(__doc__); return 1
    text = open(path, encoding="utf-8").read()
    bundle = None
    try:
        parsed = json.loads(text)                       # a bundle is ONE JSON object; a ledger is JSON Lines
        bundle = parsed if isinstance(parsed, dict) and "entries" in parsed else None
    except json.JSONDecodeError:
        bundle = None
    if bundle is not None:
        from attenu_guard import evidence
        signer = None
        if key_hex:
            from attenu_guard.wire import HS256TestSigner
            signer = HS256TestSigner(bytes.fromhex(key_hex), kid=kid or (bundle.get("anchor") or {}).get("kid") or "k1")
        elif pub_hex:
            from attenu_guard.wire import Ed25519Verifier
            signer = Ed25519Verifier(bytes.fromhex(pub_hex), kid=kid or (bundle.get("anchor") or {}).get("kid") or "k1")
        witness_keys = _witness_keys(witness_path) if witness_path else None
        rep = evidence.verify_bundle(bundle, signer, witness_keys=witness_keys)
        c = rep["checks"]
        print(f"integrity={c['integrity']} monotonicity={c['monotonicity']} containment={c['containment']} anchor={c['anchor']} "
              f"nodes={rep['nodes']} actions_checked={rep['actions_checked']}")
        for f in rep["failures"]:
            print(f"  - {f}")
        # A bundle carrying envelopes and no trust set fails every one of them, correctly and
        # unhelpfully: the keys are the caller's to supply and nothing in the bundle can stand
        # in for them. The failure stands; the line says how to make the run meaningful.
        if bundle.get("envelopes") and witness_keys is None:
            print("hint: pass --witness-keys FILE to supply the trusted witness keys")
        print("OK" if rep["ok"] else "FAILED")
        return 0 if rep["ok"] else 2
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
    if cmd in ("-h", "--help") or any(a in ("-h", "--help") for a in rest):
        print(__doc__)
        return 0
    if cmd == "demo":
        from attenu_guard._demo import main as demo_main
        demo_main()
        return 0
    if cmd == "view" and rest:
        return _view(rest[0])
    if cmd == "verify" and rest:
        return _verify(rest)
    if cmd == "scenarios" and rest:
        return _scenarios(rest)
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
