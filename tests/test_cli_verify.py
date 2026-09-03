"""`attenu-guard verify` on ledgers and bundles, with and without a verifier key; the three sample bundles."""
from __future__ import annotations

import contextlib
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

    def test_ledger_jsonl_still_verifies(self):
        import tempfile
        from attenu_guard import Authority, Guard
        with tempfile.TemporaryDirectory() as td:
            g = Guard.issue("a", Authority(scopes={"x.*"}), audit_path=Path(td) / "l.jsonl")
            g.check("x.read", tool="t")
            rc, out = run("verify", str(Path(td) / "l.jsonl"))
            self.assertEqual(rc, 0); self.assertIn("OK", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
