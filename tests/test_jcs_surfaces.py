"""JCS is the single hashing/signing format on every non-token surface."""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import Authority, Guard, SpendCap, canonical, evidence  # noqa: E402
from attenu_guard.audit import AuditLog, GENESIS  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402


class TestJCSSurfaces(unittest.TestCase):
    def test_published_audit_schema_requires_the_jcs_marker(self):
        schema = json.loads((_ROOT / "schema" / "agent-audit.schema.json").read_text())
        self.assertIn("c14n", schema["required"])
        self.assertEqual(schema["properties"]["c14n"]["const"], "JCS")

    def test_audit_hash_covers_jcs_and_declares_the_format(self):
        log = AuditLog()
        entry = log.append(
            "custom",
            0,
            context={"\ue000": 2, "\U00010000": 1},
            label="r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}",
            amount=100.0,
        )
        payload = {key: value for key, value in entry.items() if key != "hash"}
        expected = hashlib.sha256(GENESIS.encode() + canonical.dumps(payload)).hexdigest()

        self.assertEqual(entry["c14n"], "JCS")
        self.assertEqual(entry["hash"], expected)
        self.assertEqual(AuditLog.verify([entry]), (True, None))

    def test_non_finite_audit_value_fails_before_mutating_the_log(self):
        log = AuditLog()
        with self.assertRaises(canonical.NonFiniteNumberError):
            log.append("custom", 0, amount=float("nan"))
        self.assertEqual(log.entries, [])
        self.assertEqual(log.head(), (-1, GENESIS))

    def test_chain_integrity_seal_is_over_jcs(self):
        guard = Guard.issue(
            "root",
            Authority({"crm.read"}, [SpendCap(100.0)], ttl=60),
        )
        expected = hmac.new(
            guard._chain._secret,
            canonical.dumps(guard.authority.to_dict()),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(guard._node.seal, expected)
        self.assertTrue(guard._chain.verify_integrity(guard._node))

    def test_audit_and_evidence_anchors_sign_jcs_and_declare_the_format(self):
        signer = HS256TestSigner(b"jcs-anchor", kid="jcs-1")
        guard = Guard.issue("root", Authority({"crm.read"}, [], ttl=60))
        audit_anchor = guard.audit_log().anchor(signer, ts=5)
        audit_body = {key: audit_anchor[key] for key in (
            "v", "c14n", "chain_id", "seq", "head", "ts",
        )}
        self.assertEqual(audit_anchor["c14n"], "JCS")
        self.assertTrue(signer.verify(
            canonical.dumps(audit_body), bytes.fromhex(audit_anchor["sig"]), audit_anchor["kid"],
        ))

        bundle = evidence.export_bundle(guard.audit_log(), signer, ts=5)
        self.assertEqual(bundle["c14n"], "JCS")
        self.assertEqual(bundle["anchor"]["c14n"], "JCS")
        self.assertTrue(evidence.verify_bundle(bundle, signer)["ok"])

    def test_unmarked_audit_and_anchor_artifacts_are_not_accepted(self):
        signer = HS256TestSigner(b"jcs-anchor", kid="jcs-1")
        guard = Guard.issue("root", Authority({"crm.read"}, [], ttl=60))
        entries = guard.audit_log().entries
        entry = dict(entries[0])
        entry.pop("c14n")
        self.assertFalse(AuditLog.verify([entry])[0])

        anchor = guard.audit_log().anchor(signer)
        anchor.pop("c14n")
        self.assertFalse(AuditLog.verify_anchor(entries, anchor, signer)[0])

        bundle = evidence.export_bundle(guard.audit_log(), signer)
        bundle.pop("c14n")
        report = evidence.verify_bundle(bundle, signer)
        self.assertFalse(report["ok"])
        self.assertTrue(any("canonicalization" in failure for failure in report["failures"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
