"""The -02 vector set (tests/vectors-02/, shipped as attenu_guard.vectors.draft02): every
vector scores under the -02 profile to its declared outcome, the set is byte-deterministic,
both committed copies match the generator and each other, every reject reason is a Table 2
name, and generating the set leaves the twenty -01 files untouched.

stdlib-only: python3 tests/test_vectors_02.py
"""
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests" / "vectors-02"))

from attenu_guard import vectors, wire  # noqa: E402
import generate_02  # noqa: E402

REPO_DIR = _ROOT / "tests" / "vectors-02"
PACKAGE_DIR = _ROOT / "src" / "attenu_guard" / "vectors" / "draft02"
V01_DIR = _ROOT / "tests" / "vectors"
TABLE_2 = {"malformed", "non_canonical", "duplicate_member", "non_finite", "signature_invalid",
           "par_hash_mismatch", "depth_invalid", "principal_altered", "not_narrower", "expired",
           "holder_binding_failed", "revoked", "status_unknown", "audience_mismatch",
           "scope_not_granted", "ceiling_exceeded", "unknown_constraint"}


def _snapshot(directory):
    return {p.name: p.read_bytes() for p in sorted(directory.glob("*.json"))}


COMMITTED_REPO = _snapshot(REPO_DIR)
COMMITTED_PACKAGE = _snapshot(PACKAGE_DIR)
COMMITTED_V01 = _snapshot(V01_DIR)


class TheSetScoresAsDeclared(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.written = generate_02.generate_all()

    def test_every_vector_is_listed_and_shipped(self):
        self.assertEqual(sorted(self.written), sorted(vectors.VECTOR_NAMES_02))
        self.assertEqual(sorted(COMMITTED_REPO), sorted(vectors.VECTOR_NAMES_02))
        self.assertEqual(sorted(COMMITTED_PACKAGE), sorted(vectors.VECTOR_NAMES_02))

    def test_every_vector_scores_to_its_declared_outcome_under_02(self):
        for name, data in vectors.load_vectors_02().items():
            self.assertEqual(data["draft"], "02", name)
            expected = data.get("expect") or data["expect_reject_reason"]
            self.assertEqual(generate_02.score(data), expected, name)

    def test_declared_reasons_are_table_2_names(self):
        for name, data in vectors.load_vectors_02().items():
            if "expect_reject_reason" in data:
                self.assertIn(data["expect_reject_reason"], TABLE_2, name)
                self.assertNotIn("expect", data, name)
            else:
                self.assertEqual(data["expect"], "accept", name)

    def test_the_verifier_block_is_load_bearing(self):
        """The two vectors whose outcome depends on the verifier block flip when it changes."""
        mismatch = vectors.load_vector_02("reject_audience_mismatch.json")
        mismatch["verifier"]["audience"] = generate_02.AUDIENCE
        self.assertEqual(generate_02.score(mismatch), "accept")
        alg = vectors.load_vector_02("reject_alg_not_accepted.json")
        alg["verifier"]["accepted_algs"] = ["HS256"]
        self.assertEqual(generate_02.score(alg), "accept")

    def test_byte_deterministic_and_both_copies_match(self):
        first = _snapshot(REPO_DIR)
        generate_02.generate_all()
        self.assertEqual(first, _snapshot(REPO_DIR))
        self.assertEqual(_snapshot(REPO_DIR), _snapshot(PACKAGE_DIR))
        self.assertEqual(COMMITTED_REPO, first, "the committed tests/vectors-02 copy drifted from the generator")
        self.assertEqual(COMMITTED_PACKAGE, first, "the committed packaged copy drifted from the generator")

    def test_the_01_set_is_untouched(self):
        self.assertEqual(COMMITTED_V01, _snapshot(V01_DIR))
        self.assertEqual(len(COMMITTED_V01), 20)

    def test_every_token_carries_the_02_claims(self):
        for name, data in vectors.load_vectors_02().items():
            if not name.startswith("valid_"):
                continue
            for token in data["tokens"]:
                payload = json.loads(wire.b64url_decode(token.split(".")[1]))
                self.assertEqual(payload["sub"], generate_02.PRINCIPAL, name)
                self.assertIn("client_id", payload, name)
                self.assertIn("cnf", payload, name)
                self.assertTrue(payload["aud"], name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
