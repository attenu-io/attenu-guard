"""`attenu-guard verify` on ledgers and bundles, with and without a verifier key; the three sample bundles."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from attenu_guard import cli, evidence  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "examples" / "verify"
KEY = "73616d706c652d6b6579"


def run(*args) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(list(args))
    return rc, out.getvalue()


class TestVerifyCli(unittest.TestCase):
    def test_clean_bundle_with_key_is_ok_and_anchor_verified(self):
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"), "--hs256-key", KEY)
        self.assertEqual(rc, 0); self.assertIn("anchor=verified", out); self.assertIn("OK", out)

    def test_clean_bundle_without_key_is_ok_but_anchor_not_checked(self):
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"))
        self.assertEqual(rc, 0); self.assertIn("anchor=not checked", out)

    def test_tampered_bundle_fails_integrity(self):
        rc, out = run("verify", str(SAMPLES / "tampered.bundle.json"), "--hs256-key", KEY)
        self.assertEqual(rc, 2); self.assertIn("integrity=False", out); self.assertIn("FAILED", out)

    def test_widened_bundle_fails_monotonicity_only(self):
        rep = evidence.verify_bundle(json.loads((SAMPLES / "widened.bundle.json").read_text()), HS256TestSigner(b"sample-key", kid="sample"))
        self.assertFalse(rep["ok"]); self.assertTrue(rep["checks"]["integrity"]); self.assertFalse(rep["checks"]["monotonicity"])
        self.assertTrue(rep["checks"]["containment"]); self.assertEqual(rep["checks"]["anchor"], "verified")

    def test_wrong_key_fails_the_anchor_but_not_the_chain(self):
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"), "--hs256-key", "00")
        self.assertEqual(rc, 2); self.assertIn("anchor=FAILED", out)

    def test_samples_are_reproducible(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("make_samples", SAMPLES / "make_samples.py")
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)  # type: ignore[union-attr]
        fresh = m.clean(); on_disk = json.loads((SAMPLES / "clean.bundle.json").read_text())
        self.assertEqual([e["event"] for e in fresh["entries"]], [e["event"] for e in on_disk["entries"]])

    def test_help_exits_zero_over_a_real_subprocess(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        for args in (["--help"], ["-h"], ["verify", "--help"]):
            proc = subprocess.run([sys.executable, "-m", "attenu_guard.cli", *args],
                                   env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, msg=f"{args}: {proc.stdout}{proc.stderr}")
            self.assertIn("attenu-guard", proc.stdout)

    # ---- observer envelopes: --witness-keys ----------------------------
    def _envelope_bundle(self, td: Path) -> tuple[Path, Path]:
        """A one-envelope bundle and the trust set for it, written into `td`.

        Built from the committed vector corpus, so the bundle here is the same one every
        implementation scores rather than a shape invented for this test."""
        from attenu_guard import vectors
        case = next(c for c in vectors.load_envelope_vectors()["cases"]
                    if c["name"] == "valid_spawn_envelope")
        bundle_path = td / "envelopes.bundle.json"
        keys_path = td / "witness_keys.json"
        bundle_path.write_text(json.dumps(case["bundle"]))
        keys_path.write_text(json.dumps(case["witness_keys"]))
        return bundle_path, keys_path

    def test_a_bundle_with_envelopes_verifies_when_the_trust_set_is_given(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bundle_path, keys_path = self._envelope_bundle(Path(td))
            rc, out = run("verify", str(bundle_path), "--witness-keys", str(keys_path))
            self.assertEqual(rc, 0, out)
            self.assertIn("OK", out)
            self.assertNotIn("hint:", out)

    def test_a_bundle_with_envelopes_and_no_trust_set_fails_and_names_the_flag(self):
        # The defect: every bundle carrying an envelope failed here with no way to pass keys.
        # The failure is still correct — an unknown key is not a trusted one — so it stands,
        # and the output says which flag makes the run meaningful.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bundle_path, _keys = self._envelope_bundle(Path(td))
            rc, out = run("verify", str(bundle_path))
            self.assertEqual(rc, 2)
            self.assertIn("envelope_unknown_witness", out)
            self.assertIn("hint: pass --witness-keys FILE to supply the trusted witness keys",
                          out)
            self.assertIn("FAILED", out)

    def test_no_hint_on_a_bundle_that_carries_no_envelopes(self):
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"))
        self.assertEqual(rc, 0)
        self.assertNotIn("hint:", out)

    def test_the_trust_set_may_be_given_as_a_whole_vector_case(self):
        # `--witness-keys` on a file that IS a vector case, not just its witness_keys array.
        import tempfile
        from attenu_guard import vectors
        case = next(c for c in vectors.load_envelope_vectors()["cases"]
                    if c["name"] == "valid_spawn_envelope")
        with tempfile.TemporaryDirectory() as td:
            bundle_path, _keys = self._envelope_bundle(Path(td))
            whole = Path(td) / "case.json"
            whole.write_text(json.dumps(case))
            rc, out = run("verify", str(bundle_path), "--witness-keys", str(whole))
            self.assertEqual(rc, 0, out)

    def test_a_missing_path_is_a_usage_error_not_a_traceback(self):
        """`verify` on a path that is not there names the path and the reason and exits 1.
        It used to let the open() raise, so a mistyped path (or running the README's line
        from another directory) printed a FileNotFoundError traceback."""
        missing = SAMPLES / "no-such-bundle.json"
        self.assertFalse(missing.exists())
        rc, out = run("verify", str(missing), "--hs256-key", KEY)
        self.assertEqual(rc, 1)
        self.assertIn(f"cannot read {missing}", out)
        self.assertIn("No such file or directory", out)
        self.assertNotIn("Traceback", out)

    def test_an_unreadable_path_is_a_usage_error_too(self):
        """A directory, or anything else open() refuses, takes the same path."""
        rc, out = run("verify", str(SAMPLES), "--hs256-key", KEY)
        self.assertEqual(rc, 1)
        self.assertIn(f"cannot read {SAMPLES}", out)

    def test_ledger_jsonl_still_verifies(self):
        import tempfile
        from attenu_guard import Authority, Guard
        with tempfile.TemporaryDirectory() as td:
            g = Guard.issue("a", Authority(scopes={"x.*"}), audit_path=Path(td) / "l.jsonl")
            g.check("x.read", tool="t")
            rc, out = run("verify", str(Path(td) / "l.jsonl"))
            self.assertEqual(rc, 0); self.assertIn("OK", out)

    def test_the_default_output_is_the_walkthroughs_byte_for_byte(self):
        # examples/verify/README.md prints exactly this. `--entries` only ever appends to it.
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"), "--hs256-key", KEY)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "integrity=True monotonicity=True containment=True anchor=verified "
                              "nodes=3 actions_checked=2\nOK\n")


# =========================================================================
# `verify --entries` (attenu-io/attenu-guard#23) and trust-row expiry (#22)
# =========================================================================
WITNESS_KID = "witness-test"
WITNESS_SEED = bytes(range(32))
ANCHOR_SECRET = b"forged-allow-anchor"


def _witness_keys(not_after=None) -> list:
    public = evidence._ed25519_backend()[2](WITNESS_SEED)
    row = {"kid": WITNESS_KID, "alg": "EdDSA", "public_key_hex": public.hex()}
    if not_after is not None:
        row["not_after"] = not_after
    return [row]


def _forged_allow_bundle(scope: str = "web.search", chain_id: str = "witness-custody-run") -> dict:
    """The separated-custody run of 2026-09-30, bundle (d), rebuilt with the public API.

    A supervisor holding {web.search, docs.write} delegates {docs.write} to a brief-writer. The
    child's docs.write is allowed and its web.search denied. Then the process appends an allow
    of `scope` on the child's node, in chain order, and the witness signs it exactly as it
    signed the honest spawn and allow: it signs what it receives in chain order. The chain,
    the anchor and every envelope verify; containment is the only check that catches it.
    The node ids are `<chain_id>:n0` and `<chain_id>:n1`."""
    from attenu_guard import Authority, Guard
    sup = Guard.issue("supervisor", Authority(scopes={"web.search", "docs.write"}),
                      task="research and write a brief", chain_id=chain_id)
    child = sup.delegate("brief-writer", Authority(scopes={"docs.write"}), task="write the brief")
    child.check("docs.write")
    child.check("web.search")
    ledger = sup.audit_log()
    honest = ledger.entries[2]
    assert (honest["event"], honest["scope"]) == ("allow", "docs.write"), honest
    ledger.append("allow", 5, chain_id=honest["chain_id"], node=honest["node"], scope=scope,
                  tool=None, context={})
    entries = ledger.entries
    envelopes = [evidence.sign_envelope(entries, seq, WITNESS_SEED, kid=WITNESS_KID,
                                        result="indeterminate", at="2026-09-30T07:43:46Z",
                                        method="signs what it receives in chain order")
                 for seq in (1, 2, 4)]
    return evidence.export_bundle(ledger, HS256TestSigner(ANCHOR_SECRET, kid="agent-anchor"),
                                  envelopes=envelopes)


class TestVerifyEntries(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _write(self, name: str, obj) -> str:
        path = self.td / name
        path.write_text(json.dumps(obj))
        return str(path)

    def _verify_both_ways(self, *args) -> tuple:
        """(exit code, the output without --entries, the entry lines --entries added).

        Asserts the two contracts every --entries run keeps: the exit code does not move, and
        the default output comes first, byte for byte, followed by `entries:`."""
        rc_default, default = run("verify", *args)
        rc, out = run("verify", *args, "--entries")
        self.assertEqual(rc, rc_default)
        self.assertNotIn("entries:", default)
        self.assertTrue(out.startswith(default + "entries:\n"), out)
        return rc, default, out[len(default + "entries:\n"):].splitlines()

    def test_a_clean_bundle_with_an_envelope_lists_every_entry_and_fails_none(self):
        from attenu_guard import vectors
        case = next(c for c in vectors.load_envelope_vectors()["cases"]
                    if c["name"] == "valid_spawn_envelope")
        bundle = self._write("bundle.json", case["bundle"])
        keys = self._write("keys.json", case["witness_keys"])
        rc, _default, lines = self._verify_both_ways(bundle, "--witness-keys", keys)
        self.assertEqual(rc, 0)
        expected = []
        for e in case["bundle"]["entries"]:
            line = f"  seq={e['seq']} event={e['event']} node={e['node']}"
            if e.get("scope") is not None:
                line += f" scope={e['scope']}"
            if e["seq"] == 1:   # the spawn the corpus's one envelope covers
                line += " state=witness-signed observed=matched witness=witness-interop-v1"
            else:
                line += " state=process-asserted"
            expected.append(line)
        self.assertEqual(lines, expected)

    def test_the_forged_in_order_allow_is_failed_by_containment_on_its_own_line_only(self):
        bundle = self._write("bundle-d.json", _forged_allow_bundle())
        keys = self._write("keys.json", _witness_keys())
        rc, default, lines = self._verify_both_ways(
            bundle, "--hs256-key", ANCHOR_SECRET.hex(), "--witness-keys", keys)
        self.assertEqual(rc, 2)
        self.assertEqual(default, (
            "integrity=True monotonicity=True containment=False anchor=verified nodes=2 "
            "actions_checked=2\n"
            "  - containment: allow of 'web.search' on witness-custody-run:n1 outside its "
            "authority ['docs.write']\n"
            "FAILED\n"))
        signed = f"state=witness-signed observed=indeterminate witness={WITNESS_KID}"
        self.assertEqual(lines, [
            "  seq=0 event=root node=witness-custody-run:n0 state=process-asserted",
            f"  seq=1 event=spawn node=witness-custody-run:n1 {signed}",
            f"  seq=2 event=allow node=witness-custody-run:n1 scope=docs.write {signed}",
            "  seq=3 event=deny node=witness-custody-run:n1 scope=web.search state=process-asserted",
            f"  seq=4 event=allow node=witness-custody-run:n1 scope=web.search {signed} "
            "failed=containment",
        ])
        self.assertEqual([line for line in lines if "failed=" in line], [lines[4]])

    def test_checks_on_one_entry_are_listed_in_report_order_each_once(self):
        # No trust set: every envelope fails envelope_unknown_witness at the entry it covers,
        # and the forged allow also fails containment, which the report lists first.
        bundle = self._write("bundle-d.json", _forged_allow_bundle())
        rc, _default, lines = self._verify_both_ways(bundle, "--hs256-key", ANCHOR_SECRET.hex())
        self.assertEqual(rc, 2)
        failed = {line.split()[0]: line.split("failed=")[1] for line in lines if "failed=" in line}
        self.assertEqual(failed, {"seq=1": "envelope_unknown_witness",
                                  "seq=2": "envelope_unknown_witness",
                                  "seq=4": "containment,envelope_unknown_witness"})
        self.assertNotIn("state=witness-signed", "\n".join(lines))

    def test_a_finding_that_concerns_no_single_entry_lands_on_no_line(self):
        # A wrong anchor key: integrity(anchor) is about the head of the whole ledger, so it is
        # in the bundle-level output and on no entry.
        rc, default, lines = self._verify_both_ways(str(SAMPLES / "clean.bundle.json"),
                                                    "--hs256-key", "00")
        self.assertEqual(rc, 2)
        self.assertIn("integrity(anchor)", default)
        self.assertTrue(lines)
        self.assertNotIn("failed=", "\n".join(lines))

    def test_a_value_cannot_end_its_line_or_forge_another(self):
        # The forged allow carries a scope written to print as a clean line plus a fake second
        # entry, which would take the real entry's failed=containment onto itself.
        scope = (f"web.search state=witness-signed observed=indeterminate witness={WITNESS_KID}"
                 "\n  seq=5 event=deny node=witness-custody-run:n1 scope=web.search")
        bundle = self._write("bundle-d.json", _forged_allow_bundle(scope))
        keys = self._write("keys.json", _witness_keys())
        rc, _default, lines = self._verify_both_ways(
            bundle, "--hs256-key", ANCHOR_SECRET.hex(), "--witness-keys", keys)
        self.assertEqual(rc, 2)
        self.assertEqual(len(lines), 5)                     # one per entry, no sixth
        self.assertTrue(lines[4].startswith("  seq=4 event=allow "), lines[4])
        self.assertTrue(lines[4].endswith(" failed=containment"), lines[4])
        token = next(t for t in lines[4].split() if t.startswith("scope="))
        self.assertEqual(json.loads(token[len("scope="):]), scope)

    def test_values_print_bare_or_as_whitespace_free_json(self):
        cases = [("docs.write", "docs.write"), ("vectors:n1", "vectors:n1"), (7, "7"),
                 ("", '""'), ("a b", '"a\\u0020b"'), ('q"', '"q\\""'), ("é", '"\\u00e9"'),
                 ("x\ny", '"x\\ny"'), (True, "true"), ([1, "a b"], '[1,"a\\u0020b"]')]
        for value, printed in cases:
            with self.subTest(value=value):
                self.assertEqual(cli._entry_value(value), printed)
                if printed != value:
                    self.assertEqual(json.loads(printed), value)

    def test_a_plain_ledger_lists_its_entries_with_no_envelope_state(self):
        from attenu_guard import Authority, Guard
        log = self.td / "l.jsonl"
        sup = Guard.issue("supervisor", Authority(scopes={"web.search", "docs.write"}),
                          audit_path=log, chain_id="ledger")
        child = sup.delegate("brief-writer", Authority(scopes={"docs.write"}), task="write")
        child.check("docs.write")
        child.check("web.search")
        rc, default, lines = self._verify_both_ways(str(log))
        self.assertEqual((rc, default), (0, "OK\n"))
        self.assertEqual(lines, [
            "  seq=0 event=root node=ledger:n0",
            "  seq=1 event=spawn node=ledger:n1",
            "  seq=2 event=allow node=ledger:n1 scope=docs.write",
            "  seq=3 event=deny node=ledger:n1 scope=web.search",
        ])
        # Rewrite the allow's scope without re-hashing: the chain breaks at that entry, and
        # that entry is the one integrity fails on.
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        rows[2]["scope"] = "web.search"
        log.write_text("".join(json.dumps(r) + "\n" for r in rows))
        rc, default, lines = self._verify_both_ways(str(log))
        self.assertEqual((rc, default), (2, "TAMPERED — hash mismatch at seq 2\n"))
        self.assertEqual([line for line in lines if "failed=" in line],
                         ["  seq=2 event=allow node=ledger:n1 scope=web.search failed=integrity"])
        self.assertNotIn("state=", "\n".join(lines))

    def test_an_empty_ledger_is_still_empty_and_lists_nothing(self):
        log = self.td / "empty.jsonl"
        log.write_text("")
        rc, default, lines = self._verify_both_ways(str(log))
        self.assertEqual((rc, lines), (2, []))
        self.assertIn("EMPTY", default)

    def test_the_flag_may_come_before_the_path(self):
        rc, out = run("verify", "--entries", str(SAMPLES / "clean.bundle.json"), "--hs256-key", KEY)
        self.assertEqual(rc, 0)
        self.assertIn("\nentries:\n  seq=0 event=root ", out)

    def test_witness_keys_rows_honour_not_after_at_the_current_time(self):
        bundle = self._write("bundle.json", _forged_allow_bundle())
        expired = self._write("expired.json", _witness_keys(not_after="2000-01-01T00:00:00Z"))
        rc, out = run("verify", bundle, "--witness-keys", expired, "--entries")
        self.assertEqual(rc, 2)
        self.assertIn(f"envelope_unknown_witness: witness kid='{WITNESS_KID}' alg='EdDSA' is not "
                      "in the trusted witness keys ([]): the key expired at "
                      "not_after='2000-01-01T00:00:00Z'", out)
        self.assertNotIn("state=witness-signed", out)
        # A row still inside its validity verifies as a row without not_after does, so the
        # only remaining finding on this bundle is the forged allow's containment.
        valid = self._write("valid.json", _witness_keys(not_after="9999-12-31T23:59:59Z"))
        rc, out = run("verify", bundle, "--witness-keys", valid)
        self.assertEqual(rc, 2)
        self.assertNotIn("envelope_", out)
        self.assertIn("containment=False", out)


# =========================================================================
# The default output: a bundle value cannot end a line or start a forged one
# =========================================================================
class TestDefaultOutputEscaping(unittest.TestCase):
    """Finding messages print bundle values through `_display.shown`: as they always have when
    the value is printable ASCII without space, `"` or `\\`, as escaped JSON otherwise. Clean
    bundles print byte for byte as before (the walkthrough pin above, the forged-allow pin, and
    tests/test_cli_first_minute.py); these are the bundles that are not clean."""

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _write(self, name: str, obj) -> str:
        path = self.td / name
        path.write_text(json.dumps(obj))
        return str(path)

    def test_a_forged_node_name_cannot_add_a_line_to_the_default_output(self):
        # Printed raw, this node name turns the containment finding into three lines, the
        # middle one reading `OK`, above the real FAILED.
        chain_id = "run\nOK\nx"
        bundle = self._write("bundle.json", _forged_allow_bundle(chain_id=chain_id))
        keys = self._write("keys.json", _witness_keys())
        args = (bundle, "--hs256-key", ANCHOR_SECRET.hex(), "--witness-keys", keys)
        rc, out = run("verify", *args)
        self.assertEqual(rc, 2)
        self.assertEqual(out.splitlines(), [
            "integrity=True monotonicity=True containment=False anchor=verified nodes=2 "
            "actions_checked=2",
            "  - containment: allow of 'web.search' on \"run\\nOK\\nx:n1\" outside its "
            "authority ['docs.write']",
            "FAILED",
        ])
        token = out.splitlines()[1].split(" on ", 1)[1].split(" outside", 1)[0]
        self.assertEqual(json.loads(token), f"{chain_id}:n1")
        # --entries adds exactly the header and one line per entry, nothing more.
        rc, with_entries = run("verify", *args, "--entries")
        self.assertEqual(len(with_entries.splitlines()), 3 + 1 + 5)

    def test_a_ceiling_value_cannot_add_a_line_to_a_monotonicity_finding(self):
        # A spawn the process wrote itself, granting a looser region allow-list than the parent
        # holds, with one region carrying a line break. The ceiling description prints it.
        from attenu_guard import Allow, Authority, Guard
        root = Guard.issue("root", Authority(scopes={"docs.write"}, ceilings=[Allow("region", {"us"})]),
                           chain_id="mono")
        ledger = root.audit_log()
        wider = Authority(scopes={"docs.write"}, ceilings=[Allow("region", {"us", "eu\nOK"})])
        ledger.append("spawn", 1, chain_id="mono", node="mono:n1", parent=ledger.entries[0]["node"],
                      agent="child", task="t", granted=wider.to_wire())
        signer = HS256TestSigner(b"mono", kid="mono")
        bundle = self._write("bundle.json", evidence.export_bundle(ledger, signer))
        rc, out = run("verify", bundle, "--hs256-key", b"mono".hex())
        self.assertEqual(rc, 2)
        self.assertEqual(out.splitlines(), [
            "integrity=True monotonicity=False containment=True anchor=verified nodes=2 "
            "actions_checked=0",
            "  - monotonicity: mono:n1 not ⊆ parent mono:n0 (ceiling region in "
            "[\"eu\\nOK\", us] looser than parent region in [us])",
            "FAILED",
        ])

    def test_ceiling_descriptions_are_unchanged_outside_a_finding(self):
        from attenu_guard import Allow, Authority
        self.assertEqual(Allow("region", {"São Paulo"}).describe(), "region in [São Paulo]")
        self.assertEqual(
            Authority(scopes={"docs.write"}, ceilings=[Allow("region", {"São Paulo"})]).describe(),
            "scopes=[docs.write] ceilings=[region in [São Paulo]] ttl=None")

    def test_a_finding_prints_a_ceiling_as_describe_does_for_bare_values(self):
        # The finding text is rendered in describe()'s own shape; this pins the two together for
        # every built-in, so a change to one that is not made to the other fails here.
        from attenu_guard import Allow, CallLimit, Deny, EgressRank, Prefix, RowLimit, SpendCap
        from attenu_guard.ceilings import describe
        for ceiling in (RowLimit(100), SpendCap(2.5), CallLimit(3), CallLimit(3, "fs.write"),
                        EgressRank("internal"), Allow("region", {"us", "eu"}),
                        Deny("tool", {"shell", "rm"}), Prefix("path", "/tmp/")):
            with self.subTest(ceiling=describe(ceiling)):
                self.assertEqual(evidence._ceiling_in_finding(ceiling), describe(ceiling))

    def test_a_finding_escapes_a_value_that_is_not_bare_and_describe_does_not(self):
        from attenu_guard import Allow
        self.assertEqual(evidence._ceiling_in_finding(Allow("region", {"São Paulo", "us"})),
                         'region in ["S\\u00e3o\\u0020Paulo", us]')

    def test_a_ceiling_this_build_does_not_define_stays_on_one_line(self):
        from attenu_guard.ceilings import ceiling_from_wire, describe
        clean = ceiling_from_wire({"key": "quota", "type": "x-unknown", "max": 1})
        self.assertEqual(evidence._ceiling_in_finding(clean), describe(clean))
        hostile = ceiling_from_wire({"key": "quota\nOK", "type": "x-unknown"})
        text = evidence._ceiling_in_finding(hostile)
        self.assertNotIn("\n", text)
        self.assertEqual(json.loads(text), describe(hostile))

    def test_a_forged_seq_cannot_add_a_line_to_a_plain_ledger_verdict(self):
        from attenu_guard import Authority, Guard
        log = self.td / "l.jsonl"
        Guard.issue("a", Authority(scopes={"x.read"}), audit_path=log)
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        rows[0]["seq"] = "0\nOK"
        log.write_text("".join(json.dumps(r) + "\n" for r in rows))
        rc, out = run("verify", str(log))
        self.assertEqual((rc, out), (2, 'TAMPERED — seq gap at 0 (got "0\\nOK")\n'))


# =========================================================================
# An allow-list or deny-list member is its JSON type and value (attenu-ops#110)
# =========================================================================
def _typed_bundle(root_constraint, *, granted=None, context=None) -> dict:
    """A ledger written entry by entry, so each constraint is in it exactly as given: a root
    holding docs.write under `root_constraint`, then, when `granted` is given, a spawn granted
    docs.write under it, then, when `context` is given, an allow of docs.write with that context
    on the last node defined. The node ids are `typed:n0` and `typed:n1`."""
    from attenu_guard import AuditLog
    def authority(constraint):
        return {"scopes": ["docs.write"], "constraints": [constraint], "ttl": None}
    log = AuditLog()
    log.append("root", 0, chain_id="typed", node="typed:n0", agent="root",
               authority=authority(root_constraint))
    node = "typed:n0"
    if granted is not None:
        log.append("spawn", 1, chain_id="typed", parent="typed:n0", node="typed:n1", agent="child",
                   task="t", requested=authority(granted), granted=authority(granted))
        node = "typed:n1"
    if context is not None:
        log.append("allow", 2, chain_id="typed", node=node, scope="docs.write", tool=None,
                   context=context)
    return evidence.export_bundle(log, HS256TestSigner(b"typed", kid="typed"))


class TestTypedMembersInABundle(unittest.TestCase):
    """`verify_bundle` reads an allow-list or deny-list member as the enforcement point does: by
    its JSON type and value. Python's `True == 1`, so an allow of `tier: true` under
    `one_of: [1]` verified as contained, and a child granted `one_of: [1]` under a parent holding
    `one_of: [true]` verified as a subset of it. The TypeScript verifier reports both."""

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _verify(self, bundle: dict) -> tuple[int, list]:
        path = self.td / "bundle.json"
        path.write_text(json.dumps(bundle))
        rc, out = run("verify", str(path), "--hs256-key", b"typed".hex())
        return rc, out.splitlines()

    def test_an_allow_of_true_under_an_allow_list_of_1_is_outside_the_authority(self):
        allow_1 = {"key": "tier", "type": "allow", "one_of": [1]}
        self.assertEqual(self._verify(_typed_bundle(allow_1, context={"tier": True})), (2, [
            "integrity=True monotonicity=True containment=False anchor=verified nodes=1 "
            "actions_checked=1",
            "  - containment: allow of 'docs.write' on typed:n0 outside its authority ['docs.write']",
            "FAILED",
        ]))
        self.assertEqual(self._verify(_typed_bundle(allow_1, context={"tier": 1}))[0], 0)

    def test_a_child_granted_1_under_a_parent_holding_true_is_not_its_subset(self):
        bundle = _typed_bundle({"key": "tier", "type": "allow", "one_of": [True]},
                               granted={"key": "tier", "type": "allow", "one_of": [1]})
        self.assertEqual(self._verify(bundle), (2, [
            "integrity=True monotonicity=False containment=True anchor=verified nodes=2 "
            "actions_checked=0",
            "  - monotonicity: typed:n1 not ⊆ parent typed:n0 (ceiling tier in [1] looser than "
            "parent tier in [True])",
            "FAILED",
        ]))

    def test_a_list_or_an_object_in_the_context_is_outside_both_lists(self):
        # It raised TypeError out of verify_bundle. Neither list can compare such a value with its
        # members, so an allow of one is outside an allow-list and outside a deny-list alike.
        for constraint in ({"key": "tier", "type": "allow", "one_of": [1]},
                           {"key": "tier", "type": "deny", "not_one_of": [1]}):
            for value in ([1], {"a": 1}):
                with self.subTest(constraint=constraint["type"], value=value):
                    rc, lines = self._verify(_typed_bundle(constraint, context={"tier": value}))
                    self.assertEqual((rc, lines), (2, [
                        "integrity=True monotonicity=True containment=False anchor=verified "
                        "nodes=1 actions_checked=1",
                        "  - containment: allow of 'docs.write' on typed:n0 outside its authority "
                        "['docs.write']",
                        "FAILED",
                    ]))

    def test_a_finding_prints_each_typed_member_as_typescript_does(self):
        from attenu_guard.ceilings import ceiling_from_wire
        deny = ceiling_from_wire({"key": "region", "type": "deny", "not_one_of": ["secret", True, 1]})
        self.assertEqual(evidence._ceiling_in_finding(deny), "region not in [1, True, secret]")
        allow = ceiling_from_wire({"key": "tier", "type": "allow", "one_of": [1.0, "1+"]})
        self.assertEqual(evidence._ceiling_in_finding(allow), "tier in [1, 1+]")


# =========================================================================
# A malformed trust file is one line naming the file and the kid, exit 2
# =========================================================================
class TestMalformedTrustFile(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.bundle = self.td / "bundle.json"
        self.bundle.write_text(json.dumps(_forged_allow_bundle()))

    def tearDown(self):
        self._td.cleanup()

    def _keys(self, content) -> str:
        path = self.td / "keys.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(path)

    def _row(self, **fields) -> list:
        rows = _witness_keys()
        rows[0].update(fields)
        return rows

    def test_a_bad_row_is_one_line_naming_the_file_and_the_kid(self):
        cases = [
            (self._row(not_after="2026-10-05"),
             f"witness key '{WITNESS_KID}': not_after must be an RFC 3339 UTC date-time such as "
             "'2026-10-05T00:00:00Z', got '2026-10-05'"),
            (self._row(not_after=None),
             f"witness key '{WITNESS_KID}': not_after must be an RFC 3339 UTC date-time such as "
             "'2026-10-05T00:00:00Z', got None"),
            (self._row(public_key_hex="zz" * 32),
             f"witness key '{WITNESS_KID}': public_key_hex is not hexadecimal"),
            (self._row(alg="none"),
             f"witness key '{WITNESS_KID}': alg must be 'EdDSA', got 'none'"),
            # A row is read whole: a misspelled `notAfter` read by projection was a key that
            # never expired.
            (self._row(notAfter="2000-01-01T00:00:00Z"),
             f"witness key '{WITNESS_KID}': the row carries members this build does not "
             "evaluate and will not ignore: 'notAfter'"),
            # One kid, one row: the later row used to win, whichever way that pointed.
            (_witness_keys() + _witness_keys(not_after="2000-01-01T00:00:00Z"),
             f"witness key '{WITNESS_KID}': more than one row names this kid"),
        ]
        for rows, reason in cases:
            with self.subTest(reason=reason):
                path = self._keys(rows)
                rc, out = run("verify", str(self.bundle), "--witness-keys", path)
                self.assertEqual((rc, out), (2, f"cannot use --witness-keys {path}: {reason}\n"))

    def test_a_file_that_is_not_a_trust_set_says_so_in_one_line(self):
        for content, reason in (
                ("{not json", "the file is not valid JSON"),
                ({"kid": WITNESS_KID}, "expected a JSON array of {kid, alg, public_key_hex} rows, "
                                       "or a vector case carrying one as witness_keys")):
            with self.subTest(reason=reason):
                path = self._keys(content)
                rc, out = run("verify", str(self.bundle), "--witness-keys", path)
                self.assertEqual((rc, out), (2, f"cannot use --witness-keys {path}: {reason}\n"))

    def test_a_trust_file_that_cannot_be_read_is_a_usage_error(self):
        missing = self.td / "no-such-keys.json"
        rc, out = run("verify", str(self.bundle), "--witness-keys", str(missing))
        self.assertEqual(rc, 1)
        self.assertEqual(out, f"cannot read {missing}: No such file or directory\n")

    def test_no_traceback_over_a_real_subprocess(self):
        path = self._keys(self._row(not_after="2026-10-05T00:00:00+00:00"))
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        proc = subprocess.run([sys.executable, "-m", "attenu_guard.cli", "verify", str(self.bundle),
                               "--witness-keys", path], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(len(proc.stdout.splitlines()), 1)
        self.assertIn(f"witness key '{WITNESS_KID}': not_after", proc.stdout)

    def test_a_good_file_still_verifies(self):
        rc, out = run("verify", str(self.bundle), "--witness-keys", self._keys(_witness_keys()))
        self.assertEqual(rc, 2)                       # the forged allow, and nothing about the keys
        self.assertNotIn("cannot use", out)
        self.assertIn("containment=False", out)


# =========================================================================
# --entries attributes a failure by the index of its entry, never by its seq
# =========================================================================
def _rehashed(entries: list) -> list:
    """Re-hash a ledger from GENESIS, as a forger who edited an entry would."""
    from attenu_guard.audit import GENESIS, _hash
    prev = GENESIS
    for e in entries:
        e["prev_hash"] = prev
        e["hash"] = _hash(prev, {k: v for k, v in e.items() if k != "hash"})
        prev = e["hash"]
    return entries


def _signed_by_hand(subject_entry: dict, seq) -> dict:
    """An envelope naming `seq` whose subject binds `subject_entry`, signed by the test witness.

    Built by hand because `sign_envelope` resolves `seq` the way a verifier does, and so refuses
    to bind an entry that `seq` does not name, which is the forger's envelope this builds."""
    envelope = {"v": evidence.ENVELOPE_VERSION, "typ": evidence.ENVELOPE_TYP,
                "subject": {"chain_id": subject_entry["chain_id"], "node": subject_entry["node"],
                            "seq": seq, "entry_hash": subject_entry["hash"],
                            "event": subject_entry["event"]},
                "observed": {"result": "matched", "at": "2026-10-05T00:00:00Z",
                             "method": "signed by hand"},
                "witness": {"kid": WITNESS_KID, "alg": evidence.ENVELOPE_ALG}}
    sign = evidence._ed25519_backend()[0]
    envelope["sig"] = sign(WITNESS_SEED, evidence.envelope_signing_input(envelope)).hex()
    return envelope


class TestEntriesAttribution(unittest.TestCase):
    """A failure lands on the entry `verify_bundle` says it is about (`failure_entries`), by
    index. A forged entry's seq can be missing, null, a bool, a string, or another entry's, and
    the failure still lands on that entry and on no other."""

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _entries_of(self, bundle, *extra) -> tuple:
        bundle_path = self.td / "bundle.json"
        bundle_path.write_text(json.dumps(bundle))
        keys = self.td / "keys.json"
        keys.write_text(json.dumps(_witness_keys()))
        rc, out = run("verify", str(bundle_path), "--witness-keys", str(keys), "--entries", *extra)
        return rc, out, out.split("entries:\n", 1)[1].splitlines()

    @staticmethod
    def _forged(edit) -> dict:
        """The forged-allow bundle with `edit` applied to its entries, re-hashed, anchor dropped."""
        bundle = _forged_allow_bundle()
        edit(bundle["entries"])
        _rehashed(bundle["entries"])
        del bundle["anchor"]
        return bundle

    def test_an_entry_without_a_seq_prints_seq_null_and_keeps_its_failures(self):
        # The defect: findings about this entry carried seq None, were taken for chain-level
        # ones, and the forged allow printed a clean line under a FAILED verdict.
        for label, edit, failed in (
                ("seq removed", lambda es: es[4].pop("seq"),
                 # The envelope over seq 4 still finds this entry (the index stands in for a
                 # missing seq), and its entry_hash no longer matches.
                 "integrity,containment,envelope_subject_mismatch"),
                ("seq null", lambda es: es[4].update(seq=None),
                 # A null seq finds nothing, so that envelope failure is about no entry.
                 "integrity,containment")):
            with self.subTest(label):
                rc, out, lines = self._entries_of(self._forged(edit))
                self.assertEqual(rc, 2)
                self.assertIn("integrity: seq gap at 4 (got None)", out)
                self.assertEqual(lines[4], "  seq=null event=allow node=witness-custody-run:n1 "
                                           f"scope=web.search state=process-asserted failed={failed}")
                self.assertEqual([line for line in lines if "failed=" in line], [lines[4]])

    def test_a_bool_seq_breaks_the_chain_at_its_own_entry(self):
        # `"seq": true` at index 1 of a re-hashed chain verified with no integrity failure,
        # because True == 1 in Python. It is a seq gap now, about that entry.
        def edit(entries):
            entries[1]["seq"] = True
        bundle = self._forged(edit)
        bundle["envelopes"] = []
        rc, out, lines = self._entries_of(bundle)
        self.assertEqual(rc, 2)
        self.assertIn("integrity=False", out)
        self.assertIn("  - integrity: seq gap at 1 (got True)\n", out)
        self.assertEqual(lines[1], "  seq=true event=spawn node=witness-custody-run:n1 "
                                   "state=process-asserted failed=integrity")
        self.assertTrue(lines[4].endswith(" failed=containment"), lines[4])

    def test_a_string_seq_is_a_seq_gap_about_its_own_entry(self):
        def edit(entries):
            entries[4]["seq"] = "4"
        rc, out, lines = self._entries_of(self._forged(edit))
        self.assertEqual(rc, 2)
        self.assertIn("integrity: seq gap at 4 (got 4)", out)
        self.assertTrue(lines[4].endswith(" failed=integrity,containment"), lines[4])
        self.assertEqual([line for line in lines if "failed=" in line], [lines[4]])

    def test_two_entries_sharing_a_seq_are_told_apart(self):
        # A forged allow inserted after the real one at seq 4, on the same node, with its own
        # call_id. Matching findings by seq and node could not tell the two apart.
        from attenu_guard import vectors
        case = next(c for c in vectors.load_envelope_vectors()["cases"]
                    if c["name"] == "absent_envelope")
        bundle = copy.deepcopy(case["bundle"])
        entries = bundle["entries"]
        self.assertEqual((entries[4]["seq"], entries[4]["event"]), (4, "allow"))
        entries.insert(5, dict(entries[4], scope="crm.export", call_id="ab" * 16))
        _rehashed(entries)
        del bundle["anchor"]
        rc, out, lines = self._entries_of(bundle)
        self.assertEqual(rc, 2)
        self.assertTrue(lines[4].startswith("  seq=4 event=allow node=vectors:n1 scope=crm.read "))
        self.assertTrue(lines[5].startswith("  seq=4 event=allow node=vectors:n1 scope=crm.export "))
        self.assertNotIn("failed=", lines[4])
        self.assertTrue(lines[5].endswith(" failed=integrity,containment"), lines[5])

    def test_of_two_entries_sharing_a_seq_only_the_signed_copy_reads_witness_signed(self):
        # The forged allow given seq 3, the real deny's seq. A subject naming seq 3 covers the
        # later entry, and the witness signs that copy. Read by seq, the deny above it printed
        # witness-signed too, with nothing failing on its line.
        bundle = _forged_allow_bundle()
        entries = bundle["entries"]
        entries[4]["seq"] = 3
        _rehashed(entries)
        del bundle["anchor"]
        bundle["envelopes"] = [evidence.sign_envelope(entries, seq, WITNESS_SEED, kid=WITNESS_KID,
                                                      result="indeterminate",
                                                      at="2026-09-30T07:43:46Z",
                                                      method="signs what it receives in chain order")
                               for seq in (1, 2, 3)]
        self.assertEqual(bundle["envelopes"][2]["subject"]["entry_hash"], entries[4]["hash"])
        rc, out, lines = self._entries_of(bundle)
        self.assertEqual(rc, 2)
        self.assertEqual(lines[3], "  seq=3 event=deny node=witness-custody-run:n1 scope=web.search "
                                   "state=process-asserted")
        self.assertEqual(lines[4], "  seq=3 event=allow node=witness-custody-run:n1 scope=web.search "
                                   f"state=witness-signed observed=indeterminate witness={WITNESS_KID} "
                                   "failed=integrity,containment")

    def test_an_entry_whose_seq_is_true_takes_no_envelope(self):
        # c51: the envelope names seq 1 and binds the very entry carrying "seq": true. True == 1
        # in Python, so the lookup took that entry and it printed witness-signed.
        bundle = _forged_allow_bundle()
        entries = bundle["entries"]
        entries[1]["seq"] = True
        _rehashed(entries)
        del bundle["anchor"]
        bundle["envelopes"] = [_signed_by_hand(entries[1], 1)]
        rc, out, lines = self._entries_of(bundle)
        self.assertEqual(rc, 2)
        self.assertIn("  - envelope_subject_mismatch: no entry at seq 1 in this bundle\n", out)
        self.assertEqual(lines[1], "  seq=true event=spawn node=witness-custody-run:n1 "
                                   "state=process-asserted failed=integrity")

    def test_a_reason_twice_on_one_entry_is_listed_once(self):
        from attenu_guard import vectors
        case = next(c for c in vectors.load_envelope_vectors()["cases"]
                    if c["name"] == "valid_spawn_envelope")
        bundle = copy.deepcopy(case["bundle"])
        envelope = bundle["envelopes"][0]
        bundle["envelopes"] = [envelope, copy.deepcopy(envelope), copy.deepcopy(envelope)]
        report = evidence.verify_bundle(bundle, witness_keys=case["witness_keys"])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_duplicate_subject"] * 2)
        self.assertEqual(report["failure_entries"], [1, 1])
        bundle_path = self.td / "dup.json"
        bundle_path.write_text(json.dumps(bundle))
        keys = self.td / "vector-keys.json"
        keys.write_text(json.dumps(case["witness_keys"]))
        rc, out = run("verify", str(bundle_path), "--witness-keys", str(keys), "--entries")
        self.assertEqual(rc, 2)
        self.assertIn("\n  seq=1 event=spawn node=vectors:n1 state=process-asserted "
                      "failed=envelope_duplicate_subject\n", out)

    def test_an_integral_seq_is_that_integer_in_the_ledger(self):
        # The schema's integer type (JSON Schema 2020-12) counts 1.0 as an integer, and JCS writes
        # 1.0 as 1, so the chain hashes exactly as it did: the ledger verifies, and --entries
        # prints the integer.
        from attenu_guard import Authority, AuditLog, Guard
        g = Guard.issue("a", Authority(scopes={"x.read"}), chain_id="c")
        g.delegate("b", Authority(scopes={"x.read"}), task="t")
        for index, value, printed in ((1, 1.0, "1"), (0, -0.0, "0")):
            with self.subTest(seq=repr(value)):
                entries = [dict(e) for e in g.audit_log().entries]
                entries[index]["seq"] = value
                _rehashed(entries)          # a forger's re-hash changes nothing: JCS writes it as before
                self.assertEqual([e["hash"] for e in entries],
                                 [e["hash"] for e in g.audit_log().entries])
                self.assertEqual(AuditLog.verify(entries), (True, None))
                log = self.td / "l.jsonl"
                log.write_text("".join(json.dumps(e) + "\n" for e in entries))
                rc, out = run("verify", str(log), "--entries")
                self.assertEqual(rc, 0, out)
                self.assertIn(f"\n  seq={printed} event=", out)

    def test_a_seq_that_is_not_an_integer_is_a_gap_in_the_ledger_itself(self):
        from attenu_guard import Authority, AuditLog, Guard
        g = Guard.issue("a", Authority(scopes={"x.read"}), chain_id="c")
        g.delegate("b", Authority(scopes={"x.read"}), task="t")
        for bad, printed in ((True, "True"), (1.5, "1.5"), ("1", "1")):
            with self.subTest(seq=repr(bad)):
                entries = [dict(e) for e in g.audit_log().entries]
                entries[1]["seq"] = bad
                _rehashed(entries)
                self.assertEqual(AuditLog.verify(entries), (False, f"seq gap at 1 (got {printed})"))
                log = self.td / "l.jsonl"
                log.write_text("".join(json.dumps(e) + "\n" for e in entries))
                rc, out = run("verify", str(log), "--entries")
                self.assertEqual(rc, 2)
                self.assertTrue(out.startswith(f"TAMPERED — seq gap at 1 (got {printed})\n"), out)
                self.assertIn(" failed=integrity\n", out.splitlines(True)[3])


# =========================================================================
# An integer past 2**53 from the bundle fails closed, in one line, never a traceback
# =========================================================================
class TestUnsafeIntegers(unittest.TestCase):
    """RFC 8785 has no form for an integer past 2**53, so `canonical.dumps` refuses one, and
    under verification that refusal escaped as a traceback (exit 1: closed, but a crash). A
    producer never writes such a value, so verification reports what it is: an anchor whose
    signature does not verify, or a ledger entry the chain does not reproduce at. Writing and
    signing still raise."""

    BIG = 2 ** 53 + 1                     # 9007199254740993

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _bundle(self, edit) -> str:
        bundle = json.loads((SAMPLES / "clean.bundle.json").read_text())
        edit(bundle)
        path = self.td / "bundle.json"
        path.write_text(json.dumps(bundle))
        return str(path)

    def test_an_anchor_integer_past_2_53_is_a_signature_that_does_not_verify(self):
        head_ok = "integrity=True monotonicity=True containment=True anchor=not checked nodes=3 actions_checked=2"
        head_failed = "integrity=False monotonicity=True containment=True anchor=FAILED nodes=3 actions_checked=2"
        for member, with_key, without_key in (
                ("seq",
                 [head_failed, "  - integrity(anchor): anchor signature invalid", "FAILED"],
                 (0, [head_ok, "OK"])),
                ("v",
                 [head_failed, f"  - anchor_version_mismatch: anchor v={self.BIG} != bundle v=1",
                  "  - integrity(anchor): anchor signature invalid", "FAILED"],
                 (2, [head_ok, f"  - anchor_version_mismatch: anchor v={self.BIG} != bundle v=1",
                      "FAILED"]))):
            with self.subTest(member=member):
                path = self._bundle(lambda b: b["anchor"].update({member: self.BIG}))
                rc, out = run("verify", path, "--hs256-key", KEY)
                self.assertEqual((rc, out.splitlines()), (2, with_key))
                # Without a key the anchor is not checked, so its seq is not read at all.
                rc, out = run("verify", path)
                self.assertEqual((rc, out.splitlines()), without_key)

    def test_a_ledger_integer_past_2_53_is_a_hash_mismatch_at_its_entry(self):
        from attenu_guard import AuditLog
        path = self._bundle(lambda b: b["entries"][1].update(ts=self.BIG))
        rc, out = run("verify", path, "--hs256-key", KEY)
        self.assertEqual(rc, 2)
        self.assertEqual(out.splitlines()[1:], ["  - integrity: hash mismatch at seq 1",
                                                "  - integrity(anchor): hash mismatch at seq 1",
                                                "FAILED"])
        rc, out = run("verify", path, "--entries")
        self.assertEqual(rc, 2)
        self.assertIn("\n  - integrity: hash mismatch at seq 1\nFAILED\n", out)
        self.assertEqual([line for line in out.splitlines() if "failed=" in line],
                         ["  seq=1 event=spawn node=chain:n1 state=process-asserted failed=integrity"])
        # The plain ledger, and the library call under both.
        entries = json.loads(Path(path).read_text())["entries"]
        self.assertEqual(AuditLog.verify(entries), (False, "hash mismatch at seq 1"))
        log = self.td / "l.jsonl"
        log.write_text("".join(json.dumps(e) + "\n" for e in entries))
        self.assertEqual(run("verify", str(log)), (2, "TAMPERED — hash mismatch at seq 1\n"))

    def test_writing_and_signing_still_refuse_it(self):
        from attenu_guard import AuditLog, canonical
        log = AuditLog()
        with self.assertRaises(canonical.UnsafeIntegerError):
            log.append("allow", self.BIG)
        self.assertEqual(log.entries, [])                 # nothing was committed
        log.append("root", 0, chain_id="c", node="c:n0")
        with self.assertRaises(canonical.UnsafeIntegerError):
            log.anchor(HS256TestSigner(b"k", kid="k"), ts=self.BIG)
        with self.assertRaises(canonical.UnsafeIntegerError):
            evidence.export_bundle(log, HS256TestSigner(b"k", kid="k"), ts=self.BIG)


# =========================================================================
# Two leaves whose type verification assumed: an anchor's sig, an allow's scope
# =========================================================================
class TestNonStringLeaves(unittest.TestCase):
    """An anchor `sig` that is not a string reached `bytes.fromhex` (TypeError), and an allow
    `scope` that is not a string reached `startswith` against a wildcard (AttributeError): both
    raised out of verification with exit 1. Each is now the existing finding, in one line."""

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _write(self, obj) -> str:
        path = self.td / "bundle.json"
        path.write_text(json.dumps(obj))
        return str(path)

    def test_an_anchor_sig_that_is_not_a_string(self):
        from attenu_guard import AuditLog
        bundle = json.loads((SAMPLES / "clean.bundle.json").read_text())
        signer = HS256TestSigner(bytes.fromhex(KEY), kid=bundle["anchor"]["kid"])
        head = ("integrity=False monotonicity=True containment=True anchor=FAILED nodes=3 "
                "actions_checked=2")
        for sig, reason in ((None, "anchor signature invalid"),     # null reads as absent
                            (5, "anchor signature not hex"), (True, "anchor signature not hex"),
                            ([1], "anchor signature not hex"), ({"a": 1}, "anchor signature not hex")):
            with self.subTest(sig=repr(sig)):
                anchored = copy.deepcopy(bundle)
                anchored["anchor"]["sig"] = sig
                self.assertEqual(AuditLog.verify_anchor(anchored["entries"], anchored["anchor"],
                                                        signer), (False, reason))
                path = self._write(anchored)
                rc, out = run("verify", path, "--hs256-key", KEY)
                self.assertEqual((rc, out.splitlines()),
                                 (2, [head, f"  - integrity(anchor): {reason}", "FAILED"]))
                # Without a key the anchor is not checked, so its sig is not read.
                self.assertEqual(run("verify", path)[0], 0)

    def test_an_allow_scope_that_is_not_a_string_is_a_containment_failure(self):
        from attenu_guard import Authority, Guard
        g = Guard.issue("a", Authority(scopes={"crm.*"}), chain_id="c")   # a wildcard: startswith
        g.check("crm.read")
        for scope, printed in ((5, "5"), (None, "None"), (True, "True"), (1.5, "1.5"),
                               (["crm.read"], "['crm.read']"), ({"a": 1}, "{'a': 1}")):
            with self.subTest(scope=repr(scope)):
                entries = [dict(e) for e in g.audit_log().entries]
                entries[1]["scope"] = scope
                _rehashed(entries)
                bundle = {"v": 1, "c14n": "JCS", "chain_id": "c", "entries": entries}
                finding = f"containment: allow of {printed} on c:n0 outside its authority ['crm.*']"
                report = evidence.verify_bundle(bundle)
                self.assertEqual((report["failures"], report["failure_entries"]), ([finding], [1]))
                path = self._write(bundle)
                rc, out = run("verify", path)
                self.assertEqual((rc, out.splitlines()), (2, [
                    "integrity=True monotonicity=True containment=False anchor=not checked "
                    "nodes=1 actions_checked=1", f"  - {finding}", "FAILED"]))
                rc, out = run("verify", path, "--entries")
                self.assertEqual(rc, 2)
                line = out.splitlines()[-1]
                self.assertTrue(line.startswith("  seq=1 event=allow node=c:n0 "), line)
                self.assertTrue(line.endswith(" failed=containment"), line)


# =========================================================================
# A widened child fails whatever its parent field says, through the CLI too
# =========================================================================
class TestDelegationStructureCli(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _run(self, edit) -> tuple:
        from attenu_guard import vectors
        case = next(c for c in vectors.load_bundle_vectors()["cases"] if c["name"] == "valid_bundle_v2")
        bundle = copy.deepcopy(case["bundle"])
        edit(bundle["entries"])
        _rehashed(bundle["entries"])
        del bundle["anchor"]
        path = self.td / "bundle.json"
        path.write_text(json.dumps(bundle))
        return run("verify", str(path), "--entries")

    def test_a_widened_child_with_its_parent_removed_fails(self):
        # 0.17.0 and 0.18.0 printed OK for this bundle.
        def widen_and_orphan(entries):
            entries[1]["granted"]["scopes"] = ["admin.delete", "crm.read"]
            del entries[1]["parent"]
        rc, out = self._run(widen_and_orphan)
        self.assertEqual(rc, 2)
        self.assertIn("\n  - monotonicity: vectors:n1 names no parent defined earlier in this "
                      "bundle (parent None)\nFAILED\n", out)
        self.assertIn("\n  seq=1 event=spawn node=vectors:n1 state=process-asserted "
                      "failed=monotonicity\n", out)

    def test_a_node_that_is_not_a_string_is_a_finding_not_a_traceback(self):
        def listed(entries):
            entries[0]["node"] = [1]
        rc, out = self._run(listed)
        self.assertEqual(rc, 2)
        self.assertIn("\n  - root [1]: unreadable authority (node is not a string)\n", out)
        self.assertIn("\n  seq=0 event=root node=[1] state=process-asserted "
                      "failed=unreadable_authority\n", out)


# =========================================================================
# The summary line says how many allows passed through un-gated, when any did
# =========================================================================
class TestUngatedCount(unittest.TestCase):
    """An allow marked `policy: "unlisted"` is excused from containment, by design, so
    `actions_checked` does not count it and a reader could not tell it was there. The summary line
    now ends `ungated=N` when N > 0; a bundle without such allows prints exactly as before."""

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_a_bundle_with_unlisted_allows_says_how_many(self):
        from attenu_guard import Authority, Guard
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=600), chain_id="t")
        g.check("crm.read")
        g.record_passthrough("shell.exec")
        g.record_passthrough("admin.delete")      # outside the node's authority, and not measured
        path = self.td / "bundle.json"
        path.write_text(json.dumps(evidence.export_bundle(g.audit_log(), HS256TestSigner(b"k", kid="k"))))
        summary = ("integrity=True monotonicity=True containment=True anchor=verified nodes=1 "
                   "actions_checked=1 ungated=2")
        rc, out = run("verify", str(path), "--hs256-key", b"k".hex())
        self.assertEqual((rc, out), (0, f"{summary}\nOK\n"))
        rc, out = run("verify", str(path), "--hs256-key", b"k".hex(), "--entries")
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith(f"{summary}\nOK\nentries:\n"), out)
        self.assertEqual(len(out.splitlines()), 3 + 4)

    def test_a_bundle_without_them_prints_as_before(self):
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"), "--hs256-key", KEY)
        self.assertEqual((rc, out), (0, "integrity=True monotonicity=True containment=True "
                                        "anchor=verified nodes=3 actions_checked=2\nOK\n"))
        rc, out = run("verify", str(SAMPLES / "clean.bundle.json"), "--hs256-key", KEY, "--entries")
        self.assertNotIn("ungated", out)


# =========================================================================
# The display rule itself
# =========================================================================
class TestDisplayRule(unittest.TestCase):
    def test_bare_values_print_as_they_always_have(self):
        from attenu_guard import _display
        for value, printed in (("docs.write", "docs.write"), ("vectors:n1", "vectors:n1"),
                               ("max_calls[fs.write]", "max_calls[fs.write]"), (7, "7"),
                               (-3, "-3"), (1.5, "1.5"), (None, "None"), (True, "True")):
            with self.subTest(value=value):
                self.assertEqual(_display.shown(value), printed)

    def test_anything_else_prints_as_whitespace_free_ascii_json(self):
        from attenu_guard import _display
        for value, printed in (("", '""'), ("a b", '"a\\u0020b"'), ("x\ny", '"x\\ny"'),
                               ('q"', '"q\\""'), ("back\\slash", '"back\\\\slash"'),
                               ("é", '"\\u00e9"'), ("\u2028", '"\\u2028"'),
                               ("\u202e", '"\\u202e"'), ("\x7f", '"\\u007f"'),
                               ({"a": [1, "b c"]}, '{"a":[1,"b\\u0020c"]}')):
            with self.subTest(value=value):
                shown = _display.shown(value)
                self.assertEqual(shown, printed)
                self.assertTrue(all(0x21 <= ord(c) <= 0x7e for c in shown), shown)
                self.assertEqual(json.loads(shown), value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
