"""
tests/test_params_c14n_vectors.py — consumes tests/vectors/params_c14n_v1.json, the
language-neutral parity vector file for params_c14n_v1 (docs/execution-binding spec section 4).

Every case is verified against THIS build's attenu_guard.params.commit(); a TypeScript
implementation is meant to consume the same JSON file directly (no Python required) and check
itself the same way. Also checks the committed file is byte-identical to what the generator
produces right now (same discipline as tests/test_wire.py does for the wire-token vectors), and
covers malformed-salt handling (a precondition failure, not a params_c14n_v1 case, so it lives
here rather than in the vector file itself).

stdlib-only (unittest), no pytest:

    python3 tests/test_params_c14n_vectors.py
"""
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import params as params_mod  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent / "vectors" / "params_c14n"
VECTOR_FILE = VECTORS_DIR / "params_c14n_v1.json"


class TestParamsC14nVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_FILE.read_text())

    def test_every_case_matches_this_builds_commit(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["name"]):
                raw_salt = params_mod.decode_salt(case["salt_hex"])
                hash_hex, reason = params_mod.commit(case["params"], raw_salt)
                if case["expect"] == "hash":
                    self.assertIsNone(reason)
                    self.assertEqual(hash_hex, case["hash_hex"])
                else:
                    self.assertEqual(case["expect"], "unsupported")
                    self.assertIsNone(hash_hex)
                    self.assertEqual(reason, params_mod.ParamsHashReason.UNSUPPORTED)

    def test_negative_zero_matches_positive_zero(self):
        by_name = {c["name"]: c for c in self.data["cases"]}
        self.assertEqual(by_name["positive_zero_accept"]["hash_hex"],
                         by_name["negative_zero_accept"]["hash_hex"])

    def test_different_salts_diverge_for_identical_params(self):
        by_name = {c["name"]: c for c in self.data["cases"]}
        a, b = by_name["salt_a_accept"], by_name["salt_b_accept"]
        self.assertEqual(a["params"], b["params"])
        self.assertNotEqual(a["salt_hex"], b["salt_hex"])
        self.assertNotEqual(a["hash_hex"], b["hash_hex"])

    def test_committed_file_matches_what_the_generator_produces_now(self):
        # Same discipline as test_wire.py's vector-drift guard: regenerate in-memory and compare,
        # rather than trusting the committed file was hand-edited correctly.
        sys.path.insert(0, str(VECTORS_DIR))
        import generate_params_c14n  # noqa: E402
        regenerated = generate_params_c14n.generate()
        committed_text = VECTOR_FILE.read_text()
        regenerated_text = json.dumps(regenerated, indent=2, sort_keys=True) + "\n"
        self.assertEqual(committed_text, regenerated_text,
                         "tests/vectors/params_c14n_v1.json drifted from its generator -- "
                         "run tests/vectors/generate_params_c14n.py and review the diff")

    def test_malformed_salt_length_is_rejected(self):
        for bad in ("", "ab", "gg" * 16, "00" * 15, "00" * 17):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    params_mod.decode_salt(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
