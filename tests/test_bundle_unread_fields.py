"""`verify_bundle` must not report success on a ledger entry it only partly read.

Ops #109, the bundle half. The token half is in `test_unknown_detail_types.py`.

`LEDGER_FIELDS` existed, but was enforced only on the EXPORT path
(`redaction_report`, reached via `export_bundle(strict=True)`) as a custody
check: "does this bundle carry something that must not leave the premises". It
was never consulted on verify, so the verifier read entries by projection --
picking out the fields it knows and never looking at the rest.

So a producer could add fields to an entry, rehash the chain from genesis
exactly as an honest producer does, and `verify_bundle` returned `ok: True` with
zero failures while those fields stayed invisible in `delegation_graph`.

This is the same defect as the token-side one, on the offline-verifiable audit
trail -- the artefact whose entire purpose is that a third party can check it
without us. Envelopes (`ENVELOPE_MEMBERS`) and anchors already read whole; the
ledger entry was the one structure left.

The rule is reported as a failure rather than raised: `verify_bundle` returns a
report, and an unknown field is a property of the bundle, not an error in the
call.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from attenu_guard import Authority, Guard, evidence  # noqa: E402
from attenu_guard.audit import GENESIS, _hash  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402


def _rehash(entries):
    """Re-chain from genesis, exactly as a producer does.

    Without this the injected field is caught as an integrity failure, which
    proves nothing about whether the verifier READ the field -- only that the
    hash covered it. The point is a bundle whose chain is internally perfect.
    """
    prev = GENESIS
    for e in entries:
        e["prev_hash"] = prev
        e["hash"] = _hash(prev, {k: v for k, v in e.items() if k != "hash"})
        prev = e["hash"]


class UnreadLedgerFieldsAreRefused(unittest.TestCase):

    def setUp(self):
        self.signer = HS256TestSigner(b"\x01" * 32, kid="t")
        wide = Authority(scopes={"crm.*"}, ceilings=[], ttl=3600)
        root = Guard.issue("orchestrator", wide, max_depth=4)
        child = root.delegate("worker", wide, task="t")
        child.check("crm.read")
        self.bundle = evidence.export_bundle(root.audit_log(), self.signer)

    def test_baseline_verifies(self):
        self.assertTrue(evidence.verify_bundle(self.bundle)["ok"])

    def test_control_rehashed_unmodified_still_verifies(self):
        """Proves the rehash helper is faithful.

        Without this, a rejection below could mean nothing more than that the
        test cannot re-chain a ledger correctly.
        """
        b = copy.deepcopy(self.bundle)
        _rehash(b["entries"])
        self.assertTrue(evidence.verify_bundle(b)["ok"])

    def test_injected_fields_are_refused_not_ignored(self):
        b = copy.deepcopy(self.bundle)
        spawn = next(e for e in b["entries"] if e.get("event") == "spawn")
        spawn["deny_scopes"] = ["crm.read"]
        spawn["critical"] = True
        _rehash(b["entries"])

        report = evidence.verify_bundle(b)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["ledger_fields"])
        self.assertTrue(
            any("unknown_ledger_fields" in f for f in report["failures"]),
            f"expected an unknown_ledger_fields failure, got {report['failures']}")

    def test_the_failure_names_every_offending_field(self):
        """A denial a reader cannot act on is only half a fix."""
        b = copy.deepcopy(self.bundle)
        b["entries"][0]["deny_scopes"] = ["crm.read"]
        b["entries"][0]["critical"] = True
        _rehash(b["entries"])
        msg = " ".join(evidence.verify_bundle(b)["failures"])
        self.assertIn("critical", msg)
        self.assertIn("deny_scopes", msg)

    def test_a_clean_bundle_reports_the_check_as_passing(self):
        self.assertTrue(evidence.verify_bundle(self.bundle)["checks"]["ledger_fields"])



class DetailIsALedgerField(unittest.TestCase):
    """`detail` is library-written and belongs in the allow-list.

    It was missing, and that was not cosmetic. `LEDGER_FIELDS` gates
    `export_bundle(strict=True)`, so custody mode raised `EvidenceLeakError` on
    ANY run that refused a delegation -- max_depth, max_fanout, chain_revoked,
    agent_banned, integrity, ttl_expired, or an aggregate ceiling -- reporting a
    field this library wrote as though it were customer data.

    Found by the verify-side check in this release failing on our own omnigent
    example, which is the one place CI exercises a depth refusal end to end.
    """

    def test_a_refused_delegation_exports_strict_and_verifies(self):
        wide = Authority(scopes={"crm.*"}, ceilings=[], ttl=3600)
        root = Guard.issue("orchestrator", wide, max_depth=1)
        child = root.delegate("worker", wide, task="t")
        try:
            child.delegate("grandchild", wide, task="too deep")
        except Exception:
            pass  # the refusal is the point; it writes the spawn_denied entry

        entries = root.audit_log().entries
        denied = [e for e in entries if e.get("event") == "spawn_denied"]
        self.assertTrue(denied, "expected a spawn_denied entry from the depth refusal")
        self.assertIn("detail", denied[0], "the refusal carries a structural detail")

        signer = HS256TestSigner(b"\x01" * 32, kid="t")
        bundle = evidence.export_bundle(root.audit_log(), signer, strict=True)
        report = evidence.verify_bundle(bundle, signer)
        self.assertTrue(report["ok"], report.get("failures"))
        self.assertTrue(report["checks"]["ledger_fields"])

    def test_redaction_report_accepts_it(self):
        wide = Authority(scopes={"crm.*"}, ceilings=[], ttl=3600)
        root = Guard.issue("orchestrator", wide, max_depth=1)
        child = root.delegate("worker", wide, task="t")
        try:
            child.delegate("grandchild", wide, task="too deep")
        except Exception:
            pass
        r = evidence.redaction_report(root.audit_log().entries)
        self.assertTrue(r["ok"], r["violations"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
