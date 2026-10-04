"""
attenu-guard — command-line tool.

  attenu-guard demo [--audit-path F] run the poisoned-summariser demo; --audit-path writes its
                                     audit log to F, for `attenu-guard view F`
  attenu-guard view <log.jsonl>      render an audit log as a delegation tree + verify it
  attenu-guard verify <log|bundle>   verify a hash-chained audit log, or an evidence bundle
                                     (integrity · child ⊆ parent · containment; --hs256-key/--pubkey checks the anchor;
                                      --witness-keys FILE supplies the trusted observer-envelope keys;
                                      --entries adds one line per entry: its envelope state and the checks that failed on it)
  attenu-guard scenarios <file>      run a declarative authorization scenario (JSON/YAML),
                           exit non-zero if any assertion fails. --coverage prints
                           which reason codes were exercised.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .audit import AuditLog

# A ledger with no entries has nothing to verify. Reporting it OK would be a fail-open: a
# truncated or never-written file would pass the same check as a clean chain.
EMPTY = "EMPTY — no events to verify"


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
    if not entries:
        print(f"audit chain: 0 events · verification: {EMPTY}")
        return 2
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


#: A value printed as it is on an `--entries` line: printable ASCII other than space, `"` and `\`.
_BARE_VALUE = re.compile(r'[!#-\[\]-~]+')


def _entry_value(value) -> str:
    """One value on an `--entries` line.

    The values come from the bundle, which is attacker-supplied, and a line is only worth
    reading if no value can end it early or start a forged one: a `scope` carrying a newline
    and a clean-looking second line would otherwise print a fake entry with the real entry's
    `failed=` attached to it. So a value is printed as it is only when it is printable ASCII
    with no space, `"` or `\\`, and an integer in decimal. Anything else is printed as JSON
    with every character outside printable ASCII escaped as \\uXXXX and spaces as \\u0020, so
    it never contains whitespace and `json.loads` gives the value back."""
    if isinstance(value, str) and _BARE_VALUE.fullmatch(value):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace(" ", "\\u0020")


def _same(a, b) -> bool:
    """Equal and of the same type: `True == 1` in Python, and a seq of `true` is not seq 1."""
    return type(a) is type(b) and a == b


def _failed_by_entry(entries: list, failure_details: list) -> dict:
    """entry index -> the reasons of the findings positioned on that entry, in the order the
    report lists them, each reason once.

    A finding lands on every entry whose own `seq` equals the finding's `seq`, and whose `node`
    and `call_id` equal the finding's wherever the finding carries them. In a ledger whose seqs
    are unique that is one entry. A finding with no `seq` concerns no single entry (a version,
    root, anchor or chain-id failure, or an envelope whose subject names no entry); it is in the
    bundle-level output already and lands on no line."""
    by_seq: dict = {}
    for i, e in enumerate(entries):
        s = e.get("seq")
        if isinstance(s, int) and not isinstance(s, bool):
            by_seq.setdefault(s, []).append(i)
    out: dict = {}
    for d in failure_details:
        seq = d.get("seq")
        if seq is None:
            continue
        if isinstance(seq, int) and not isinstance(seq, bool):
            candidates = by_seq.get(seq, [])
        else:
            candidates = [i for i, e in enumerate(entries) if _same(e.get("seq"), seq)]
        for i in candidates:
            e = entries[i]
            if d.get("node") is not None and not _same(e.get("node"), d["node"]):
                continue
            if d.get("call_id") is not None and not _same(e.get("call_id"), d["call_id"]):
                continue
            reasons = out.setdefault(i, [])
            if d["reason"] not in reasons:
                reasons.append(d["reason"])
    return out


def _entry_lines(entries: list, failure_details: list, envelopes: dict | None = None) -> list:
    """The `--entries` block: `entries:`, then one line per ledger entry, in ledger order.

        seq=<n> event=<event> node=<node> scope=<scope> state=<witness-signed|process-asserted>
        observed=<observed.result> witness=<kid> failed=<check>[,<check>...]

    A key with no value is left out. `state` is the per-entry envelope state `verify_bundle`
    reports, and is left out for a plain ledger (`envelopes=None`). `observed` and `witness` are
    printed only on a `witness-signed` entry: they are what the verifying envelope says, and a
    process-asserted entry has none. `failed` lists the checks whose findings are positioned on
    this entry (`_failed_by_entry`)."""
    failed = _failed_by_entry(entries, failure_details)
    lines = ["entries:"]
    for i, e in enumerate(entries):
        pairs = [("seq", e.get("seq")), ("event", e.get("event")), ("node", e.get("node")),
                 ("scope", e.get("scope"))]
        if envelopes is not None:
            key = e.get("seq", i)                      # the key verify_bundle files states under
            state = envelopes["states"].get(key)
            pairs.append(("state", state))
            if state == "witness-signed":
                pairs.append(("observed", envelopes["results"].get(key)))
                pairs.append(("witness", envelopes.get("witnesses", {}).get(key)))
        if i in failed:
            pairs.append(("failed", ",".join(failed[i])))
        lines.append("  " + " ".join(f"{k}={_entry_value(v)}" for k, v in pairs if v is not None))
    return lines


def _verify(args: list):
    """`attenu-guard verify <audit.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
    [--witness-keys FILE] [--entries]`

    A `.jsonl` audit log: hash-chain integrity. A bundle (`export_bundle` output): integrity, monotonicity
    (child ⊆ parent) and containment from the bundle alone; the signed anchor is verified when a key is given
    and reported as "not checked" otherwise. `--witness-keys FILE` supplies the trusted witness keys for a
    bundle carrying observer envelopes; without it every envelope fails `envelope_unknown_witness`, and the
    output says which flag to pass. A row in that file may carry `not_after` (RFC 3339 UTC); past it the key is
    no longer trusted. A ledger with zero events is reported EMPTY, not OK. `--entries` prints, after all of
    that, `entries:` and one line per entry (`_entry_lines`); without it the output is unchanged. Exit 0 = ok,
    2 = a check failed or there was nothing to check, 1 = usage."""
    path, key_hex, pub_hex, kid, witness_path, per_entry = None, None, None, None, None, False
    it = iter(args)
    for a in it:
        if a == "--hs256-key": key_hex = next(it, None)
        elif a == "--pubkey": pub_hex = next(it, None)
        elif a == "--kid": kid = next(it, None)
        elif a == "--witness-keys": witness_path = next(it, None)
        elif a == "--entries": per_entry = True
        elif path is None: path = a
    if not path:
        print(__doc__); return 1
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:                                   # a wrong path is a usage error, not a traceback
        print(f"cannot read {path}: {e.strerror or e}"); return 1
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
        if per_entry:
            print("\n".join(_entry_lines(bundle.get("entries") or [], rep["failure_details"],
                                         rep["envelopes"])))
        return 0 if rep["ok"] else 2
    entries = AuditLog.load(path)
    if not entries:
        print(EMPTY)
        if per_entry:
            print("\n".join(_entry_lines([], [])))
        return 2
    ok, reason = AuditLog.verify(entries)
    print("OK" if ok else f"TAMPERED — {reason}")
    if per_entry:
        # A plain ledger has one check, the hash chain, and its finding is positioned the way a
        # bundle's integrity finding is: on the first entry the chain does not reproduce at.
        details = []
        if not ok:
            from attenu_guard import evidence
            seq, node = evidence._integrity_position(entries)
            details.append({"reason": "integrity", "seq": seq, "node": node, "call_id": None})
        print("\n".join(_entry_lines(entries, details)))
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
        return demo_main(rest)
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
