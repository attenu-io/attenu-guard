"""
attenu-guard — command-line tool.

  attenu-guard demo [--audit-path F] run the poisoned-summariser demo; --audit-path writes its
                                     audit log to F, for `attenu-guard view F`
  attenu-guard view <log.jsonl>      render an audit log as a delegation tree + verify it
  attenu-guard verify <log|bundle>   verify a hash-chained audit log, or an evidence bundle
                                     (integrity · child ⊆ parent · containment; --hs256-key/--pubkey checks the anchor;
                                      --witness-keys FILE supplies the trusted observer-envelope keys;
                                      --entries adds one line per entry: its envelope state and the checks that failed on it;
                                      a line is key=value tokens split by single spaces, the key before the first "=",
                                      and a value never contains a space; one that starts with " is a JSON string)
  attenu-guard scenarios <file>      run a declarative authorization scenario (JSON/YAML),
                           exit non-zero if any assertion fails. --coverage prints
                           which reason codes were exercised.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import _display
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
    "public_key_hex"}]`, each row optionally with `not_after` — or one whole vector case, in
    which case its `witness_keys` member is used. Without a trust set every envelope in a bundle
    fails `envelope_unknown_witness`, which is correct (an unknown key is not a trusted one) and
    useless as a default, so this is how a bundle carrying envelopes is verified from the
    command line.

    Every row is validated here, by the same `_trusted_witnesses` the verifier runs, so a bad
    row is reported against this file before any bundle is read. Raises `OSError` when the file
    cannot be read, and `ValueError` when it is not a trust set: not JSON, not an array of rows,
    or a row the verifier refuses, whose message names the kid. The messages say nothing a
    particular JSON parser or language would phrase differently."""
    from attenu_guard import evidence
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):   # JSON is UTF-8 text, so both mean "not JSON"
        raise ValueError("the file is not valid JSON") from None
    if isinstance(parsed, dict) and "witness_keys" in parsed:
        parsed = parsed["witness_keys"]
    if not isinstance(parsed, list):
        raise ValueError("expected a JSON array of {kid, alg, public_key_hex} rows, "
                         "or a vector case carrying one as witness_keys")
    evidence._trusted_witnesses(parsed)
    return parsed


def _entry_value(value) -> str:
    """One value on an `--entries` line.

    The values come from the bundle, which is attacker-supplied, and a line is only worth
    reading if no value can end it early or start a forged one: a `scope` carrying a newline
    and a clean-looking second line would otherwise print a fake entry with the real entry's
    `failed=` attached to it. So a value is printed as it is only when it is printable ASCII
    with no space, `"` or `\\`, and an integer in decimal. Anything else is printed by
    `_display.escaped`, the rule the finding messages use too: `json.dumps` with
    `ensure_ascii=True` and compact separators, then every space written as \\u0020. It
    never contains whitespace, and `json.loads` gives the value back."""
    if isinstance(value, str) and _display.BARE.fullmatch(value):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return _display.escaped(value)


def _failed_by_entry(failure_entries: list, failure_details: list) -> dict:
    """entry index -> the reasons of the failures about that entry, in the order the report
    lists them, each reason once.

    `failure_entries` is the verifier's own record of the entry each failure is about, by index
    (`verify_bundle`'s `failure_entries`), so a failure lands on its entry even when that entry's
    seq is missing, null, a bool, a string or a duplicate of another entry's. A failure about no
    single entry (a version, root, anchor or chain-id failure, or an envelope whose subject names
    no entry) is in the bundle-level output already and lands on no line."""
    out: dict = {}
    for index, d in zip(failure_entries, failure_details):
        if index is None:
            continue
        reasons = out.setdefault(index, [])
        if d["reason"] not in reasons:
            reasons.append(d["reason"])
    return out


def _entry_lines(entries: list, failure_entries: list, failure_details: list,
                 envelopes: dict | None = None) -> list:
    """The `--entries` block: `entries:`, then one line per ledger entry, in ledger order.

        seq=<n> event=<event> node=<node> scope=<scope> state=<witness-signed|process-asserted>
        observed=<observed.result> witness=<kid> failed=<check>[,<check>...]

    `seq` is always printed, as the integer when it is integral (`1.0` prints 1), and as
    `seq=null` for an entry that has none. Any other key with no
    value is left out. `state` is left out for a plain ledger (`envelopes=None`); on a bundle it
    is `witness-signed` exactly when `envelopes["witnesses"]` holds this entry's index, which is
    the entry the verifier resolved an envelope to, so of two entries sharing a seq only the one
    the witness signed reads witness-signed. `observed` and `witness` are printed only on such an
    entry: they are what its envelope says. `failed` lists the checks whose failures are about
    this entry (`_failed_by_entry`).

    How a line parses, exactly: two spaces, then `key=value` tokens separated by single spaces.
    No token contains whitespace. The key is the text before the token's first `=`, and keys
    never contain one; a value may (`scope=failed=containment` is the scope "failed=containment").
    A value that starts with `"` is a JSON string, which `json.loads` decodes. Any other value
    is printed as it is: printable ASCII other than space, `"` and `\\`, an integer, `null` for
    an entry with no seq, or the compact JSON of a value that is not a string."""
    from attenu_guard.audit import _int_or
    from attenu_guard.evidence import _state_key
    failed = _failed_by_entry(failure_entries, failure_details)
    lines = ["entries:"]
    for i, e in enumerate(entries):
        pairs = [("event", e.get("event")), ("node", e.get("node")), ("scope", e.get("scope"))]
        if envelopes is not None:
            kid = envelopes["witnesses"].get(i)        # by index: the entry the envelope covers
            if kid is None:
                pairs.append(("state", "process-asserted"))
            else:
                # `results` is keyed the way `states` is (`_state_key`), and for a covered
                # entry the result filed there is its own envelope's.
                pairs += [("state", "witness-signed"),
                          ("observed", envelopes["results"].get(_state_key(e, i))),
                          ("witness", kid)]
        if i in failed:
            pairs.append(("failed", ",".join(failed[i])))
        # `seq` is never left out: an entry without one is exactly the entry a reader must see.
        # An integral seq prints as the integer it is (`1.0` as 1), as the verifier reads it.
        tokens = [f"seq={_entry_value(_int_or(e.get('seq')))}"]
        tokens += [f"{k}={_entry_value(v)}" for k, v in pairs if v is not None]
        lines.append("  " + " ".join(tokens))
    return lines


def _verify(args: list):
    """`attenu-guard verify <audit.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
    [--witness-keys FILE] [--entries]`

    A `.jsonl` audit log: hash-chain integrity. A bundle (`export_bundle` output): integrity, monotonicity
    (child ⊆ parent) and containment from the bundle alone; the signed anchor is verified when a key is given
    and reported as "not checked" otherwise. `--witness-keys FILE` supplies the trusted witness keys for a
    bundle carrying observer envelopes; without it every envelope fails `envelope_unknown_witness`, and the
    output says which flag to pass. A row in that file may carry `not_after` (RFC 3339 UTC); from that time on
    the key is not trusted. A trust file that is not one (not JSON, not an array of rows, or a row the verifier
    refuses) is one line naming the file and, for a bad row, the kid. A ledger with zero events is reported
    EMPTY, not OK. `--entries` prints, after all of that, `entries:` and one line per entry (`_entry_lines`);
    without it the output is unchanged. Exit 0 = ok, 2 = a check failed, there was nothing to check, or the
    trust file is malformed, 1 = usage (a missing argument or a file that cannot be read)."""
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
        witness_keys = None
        if witness_path:
            try:
                witness_keys = _witness_keys(witness_path)
            except OSError as e:                       # unreadable, as for the bundle path above
                print(f"cannot read {witness_path}: {e.strerror or e}"); return 1
            except ValueError as e:                    # read, and not a trust set; a bad row names its kid
                print(f"cannot use --witness-keys {witness_path}: {e}"); return 2
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
            print("\n".join(_entry_lines(bundle.get("entries") or [], rep["failure_entries"],
                                         rep["failure_details"], rep["envelopes"])))
        return 0 if rep["ok"] else 2
    entries = AuditLog.load(path)
    if not entries:
        print(EMPTY)
        if per_entry:
            print("\n".join(_entry_lines([], [], [])))
        return 2
    ok, reason = AuditLog.verify(entries)
    print("OK" if ok else f"TAMPERED — {reason}")
    if per_entry:
        # A plain ledger has one check, the hash chain, and its failure is about the entry a
        # bundle's integrity failure is about: the first one the chain does not reproduce at.
        at, details = [], []
        if not ok:
            from attenu_guard import evidence
            at.append(evidence._integrity_break(entries))
            details.append({"reason": "integrity"})
        print("\n".join(_entry_lines(entries, at, details)))
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
