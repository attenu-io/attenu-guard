"""
tests/test_bundle_vectors.py — the bundle-level interop vectors
(tests/vectors/bundles/bundle_vectors_v1.json, written by
tests/vectors/generate_bundles.py) and the structured-failure contract they are
scored against (`verify_bundle`'s `failure_details`).

Two things are pinned here:

  1. Every committed case scores exactly as it declares, through BOTH the
     repository copy and the copy that ships inside the installed package —
     accepting cases accept with no failures, rejecting cases reject with every
     declared {reason, seq, node} actually reported at that position.
  2. `failures` and `failure_details` cannot drift apart: same length, same
     order, one structured twin per string, at every failure site in
     evidence.py — including the sites no vector exercises.

stdlib-only (unittest), no pytest:

    python3 tests/test_bundle_vectors.py
"""
import copy
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests" / "vectors"))

from attenu_guard import Authority, Guard, RowLimit  # noqa: E402
from attenu_guard import evidence, vectors  # noqa: E402
from attenu_guard.audit import AuditLog, GENESIS, _hash as _entry_hash  # noqa: E402
from attenu_guard.reasons import BodyState, Capture  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

import generate_bundles  # tests/vectors/generate_bundles.py  # noqa: E402

_REPO_FILE = _ROOT / "tests" / "vectors" / "bundles" / "bundle_vectors_v1.json"
_PACKAGE_FILE = _ROOT / "src" / "attenu_guard" / "vectors" / "bundles" / "bundle_vectors_v1.json"

# The file AS COMMITTED, snapshotted at import — before any test regenerates it, so a copy
# edited by hand fails here rather than being quietly rewritten (same discipline as
# tests/test_wire.py's vector snapshots).
COMMITTED_REPO_BYTES = _REPO_FILE.read_bytes()
COMMITTED_PACKAGE_BYTES = _PACKAGE_FILE.read_bytes()

# The two failure strings that predate this contract and name a NODE before their colon rather
# than a reason token. Their `reason` is stated explicitly by evidence.py instead of being the
# text before the colon; every other failure follows the rule.
_REASON_NOT_IN_MESSAGE = {"unreadable_authority", "unreadable_granted"}


def _signer_for(case):
    return HS256TestSigner(bytes.fromhex(case["signer"]["secret_hex"]), kid=case["signer"]["kid"])


def _positions(report):
    return [{"reason": d["reason"], "seq": d["seq"], "node": d["node"]}
            for d in report["failure_details"]]


# =========================================================================
# The committed vectors
# =========================================================================
class TestBundleVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Regenerate both copies from this source tree, so the vectors are self-checking against
        # this exact build rather than a fixture that can go stale.
        cls.document = generate_bundles.generate_all()

    def test_the_document_declares_its_version_and_every_expected_case(self):
        # `version` is the compatibility contract and does not move when cases are appended —
        # an implementation that scored bundle_vectors_v1 still scores it. `revision` is the
        # additive counter that does move, so a reader can name the corpus they ran.
        self.assertEqual(self.document["version"], "bundle_vectors_v1")
        self.assertEqual(self.document["revision"], "bundle_vectors_v1.1")
        self.assertEqual([c["name"] for c in self.document["cases"]], [
            "valid_bundle_v2",
            "reject_params_mismatch",
            "reject_outcome_without_allow",
            "reject_outcome_before_allow",
            "reject_duplicate_outcome",
            "reject_duplicate_call_id",
            "reject_rehashed_chain",
            "reject_tampered_entry",
            # revision v1.1 — the delegation-containment cases the first two independent runs
            # both asked for. Appended, never inserted: a case's position is stable for life.
            "reject_widened_scope",
            "reject_uncontained_allow",
        ])

    def test_the_delegation_containment_rules_each_have_a_rejecting_case(self):
        # The gap the first two independent runs both reported: integrity and execution binding
        # had rejecting cases, the two checks the library exists for had none. This asserts the
        # corpus keeps covering them, and that each one fails ONLY its own check — a case that
        # also broke integrity would not isolate the rule it is named for.
        by_name = {c["name"]: c for c in self.document["cases"]}
        for name, reason, other in (("reject_widened_scope", "monotonicity", "containment"),
                                    ("reject_uncontained_allow", "containment", "monotonicity")):
            with self.subTest(case=name):
                case = by_name[name]
                self.assertEqual(case["expect"], "reject")
                self.assertEqual([f["reason"] for f in case["expect_failures"]], [reason])
                report = evidence.verify_bundle(case["bundle"], _signer_for(case))
                self.assertFalse(report["checks"][reason])
                self.assertTrue(report["checks"][other])
                self.assertTrue(report["checks"]["integrity"])
                self.assertEqual(report["checks"]["anchor"], "verified")
                self.assertEqual(report["execution_binding"]["failures"], [])
                # Exactly one finding: these two cases have no permitted extras.
                self.assertEqual(_positions(report), case["expect_failures"])

    def test_each_rejecting_case_differs_from_the_valid_bundle_by_one_entry(self):
        # The rule the README states and every case is built on. Compared entry by entry against
        # `valid_bundle_v2`, ignoring the hash chain and the anchor, which every mutation
        # legitimately rewrites. The three cases that insert, transpose or leave the chain broken
        # are exempt from the count, not from the rule.
        base = next(c for c in self.document["cases"] if c["name"] == "valid_bundle_v2")
        base_entries = base["bundle"]["entries"]
        reshaped = {"reject_outcome_before_allow", "reject_duplicate_outcome"}
        for case in self.document["cases"]:
            if case["expect"] != "reject" or case["name"] in reshaped:
                continue
            with self.subTest(case=case["name"]):
                entries = case["bundle"]["entries"]
                self.assertEqual(len(entries), len(base_entries))
                skip = ("hash", "prev_hash")
                differing = [i for i, (a, b) in enumerate(zip(base_entries, entries))
                             if {k: v for k, v in a.items() if k not in skip}
                             != {k: v for k, v in b.items() if k not in skip}]
                self.assertEqual(len(differing), 1,
                                 f"{case['name']} changed entries {differing}, expected exactly 1")

    def test_every_case_is_a_complete_v2_bundle_with_execution_binding(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                bundle = case["bundle"]
                self.assertEqual(bundle["v"], 2)
                self.assertTrue(bundle["anchor"]["sig"])
                events = [e.get("event") for e in bundle["entries"]]
                for required in ("root", "spawn", "allow", "deny", "outcome", "done"):
                    self.assertIn(required, events)
                allow = next(e for e in bundle["entries"] if e.get("event") == "allow")
                for field in ("call_id", "capture", "adapter", "authorized_params_hash"):
                    self.assertIn(field, allow)
                outcome = next(e for e in bundle["entries"] if e.get("event") == "outcome")
                for field in ("call_id", "body_state", "invoked_params_hash"):
                    self.assertIn(field, outcome)
                self.assertTrue(case["description"].strip())

    def test_accepting_cases_verify_with_no_failures(self):
        for case in self.document["cases"]:
            if case["expect"] != "accept":
                continue
            with self.subTest(case=case["name"]):
                report = evidence.verify_bundle(case["bundle"], _signer_for(case))
                self.assertTrue(report["ok"], report["failures"])
                self.assertEqual(report["failures"], [])
                self.assertEqual(report["failure_details"], [])
                self.assertEqual(case["expect_failures"], [])

    def test_every_rejecting_case_reports_each_declared_failure_at_its_declared_position(self):
        for case in self.document["cases"]:
            if case["expect"] != "reject":
                continue
            with self.subTest(case=case["name"]):
                report = evidence.verify_bundle(case["bundle"], _signer_for(case))
                self.assertFalse(report["ok"])
                self.assertTrue(case["expect_failures"],
                                "a rejecting case must declare at least one required failure")
                reported = _positions(report)
                for expected in case["expect_failures"]:
                    self.assertIn(expected, reported)

    def test_the_declared_minimal_set_is_minimal(self):
        # Every declared failure must be one the verifier genuinely reports for THAT bundle —
        # not a hopeful entry that no implementation could satisfy.
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                report = evidence.verify_bundle(case["bundle"], _signer_for(case))
                reasons = {d["reason"] for d in report["failure_details"]}
                for expected in case["expect_failures"]:
                    self.assertIn(expected["reason"], reasons)

    def test_the_two_committed_copies_are_byte_identical(self):
        self.assertEqual(COMMITTED_PACKAGE_BYTES, COMMITTED_REPO_BYTES)

    def test_regeneration_is_byte_deterministic(self):
        # Nothing in the generator reads a clock or the CSPRNG (see its _fixed_entropy), so a
        # second run must reproduce the committed bytes exactly.
        generate_bundles.generate_all()
        self.assertEqual(_REPO_FILE.read_bytes(), COMMITTED_REPO_BYTES)
        self.assertEqual(_PACKAGE_FILE.read_bytes(), COMMITTED_PACKAGE_BYTES)

    def test_the_packaged_copy_is_readable_through_importlib_resources(self):
        # The path an INSTALLED consumer takes — a file missing from the wheel fails here.
        self.assertEqual(vectors.read_bundle_vectors_bytes(), COMMITTED_REPO_BYTES)
        loaded = vectors.load_bundle_vectors()
        self.assertEqual(loaded["version"], "bundle_vectors_v1")
        self.assertEqual(loaded["revision"], "bundle_vectors_v1.1")
        self.assertEqual([c["name"] for c in loaded["cases"]],
                         [c["name"] for c in self.document["cases"]])

    def test_every_packaged_case_scores_as_it_declares(self):
        # Read ONLY through the package accessor, then verify: exactly what a third-party
        # implementer does, minus their own verifier.
        for case in vectors.load_bundle_vectors()["cases"]:
            with self.subTest(case=case["name"]):
                report = evidence.verify_bundle(case["bundle"], _signer_for(case))
                self.assertEqual("accept" if report["ok"] else "reject", case["expect"])
                for expected in case["expect_failures"]:
                    self.assertIn(expected, _positions(report))

    def test_the_generators_self_check_agrees_with_this_suite(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                ok, detail = generate_bundles.check_case(case)
                self.assertTrue(ok, detail)


# =========================================================================
# failures <-> failure_details: the structured twin, at every failure site
# =========================================================================
def _v2_bundle(signer):
    """A small v2 chain with a root, a delegation, an allow+outcome on each node, a deny, and
    both nodes finalized — the shape every mutation below starts from."""
    root = Guard.issue("orchestrator", Authority({"crm.*", "mail.send"}, [RowLimit(100)], ttl=3600),
                       chain_id="t", schema_version=2)
    child = root.delegate("summarizer", Authority({"crm.read"}, [RowLimit(50)], ttl=900),
                          task="summarize")
    adapter = {"module": "m", "version": "1", "hook_path": "h"}
    d1 = root.check("mail.send", authorized_params={"to": "a"}, capture=Capture.WRAPPER_SYNC,
                    adapter=adapter)
    root.record_outcome(d1.call_id, BodyState.RETURNED, invoked_params={"to": "a"}, duration_ms=1)
    d2 = child.check("crm.read", authorized_params={"q": 1}, capture=Capture.WRAPPER_SYNC,
                     adapter=adapter)
    child.check("crm.export")
    child.record_outcome(d2.call_id, BodyState.RETURNED, invoked_params={"q": 1}, duration_ms=2)
    child.complete()
    root.complete()
    return evidence.export_bundle(root.audit_log(), signer)


def _v1_bundle(signer):
    g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60), chain_id="t")
    g.check("crm.read")
    return evidence.export_bundle(g.audit_log(), signer)


def _index_of(bundle, event, occurrence=0):
    seen = -1
    for i, e in enumerate(bundle["entries"]):
        if e.get("event") == event:
            seen += 1
            if seen == occurrence:
                return i
    raise AssertionError(f"no {event} entry #{occurrence} in this bundle")


def _rehash(bundle):
    prev = GENESIS
    for e in bundle["entries"]:
        e["prev_hash"] = prev
        payload = {k: v for k, v in e.items() if k != "hash"}
        e["hash"] = _entry_hash(prev, payload)
        prev = e["hash"]


def _reanchor(bundle, signer):
    anchor = evidence._anchor_for(bundle["entries"], signer, 0)
    anchor["verified"] = AuditLog.verify_anchor(bundle["entries"], anchor, signer)[0]
    bundle["anchor"] = anchor


class TestFailureDetailsTwin(unittest.TestCase):
    """Every string in `failures` has exactly one structured twin in `failure_details`, at the
    same index, at EVERY site that can produce a failure — including the sites no committed
    vector exercises."""

    def setUp(self):
        self.signer = HS256TestSigner(b"k", kid="k")
        self.base = _v2_bundle(self.signer)

    # ---- the mutations, one per failure site ---------------------------
    def _broken(self, mutate, *, rehash=False, reanchor=False):
        bundle = copy.deepcopy(self.base)
        mutate(bundle)
        if rehash:
            _rehash(bundle)
        if reanchor:
            _reanchor(bundle, self.signer)
        return bundle

    def _kill_bundle(self):
        root = Guard.issue("orchestrator", Authority({"crm.read"}, [], ttl=3600), chain_id="t",
                           schema_version=2)
        child = root.delegate("summarizer", Authority({"crm.read"}, [], ttl=900), task="t")
        root.revoke(child.node_id)
        return evidence.export_bundle(root.audit_log(), self.signer)

    def _sites(self):
        """(name, bundle, verify kwargs, reasons this mutation must produce)."""
        def set_entry(index, field, value):
            return lambda b: b["entries"][index].__setitem__(field, value)

        def drop_entry_field(index, field):
            return lambda b: b["entries"][index].pop(field)

        allow_i = _index_of(self.base, "allow")
        outcome_i = _index_of(self.base, "outcome")
        deny_i = _index_of(self.base, "deny")
        spawn_i = _index_of(self.base, "spawn")
        child_allow_i = _index_of(self.base, "allow", 1)
        child_node = self.base["entries"][spawn_i]["node"]

        kill = self._kill_bundle()
        kill_broken = copy.deepcopy(kill)
        kill_broken["entries"][_index_of(kill, "kill")]["pending_at_kill"] = "nope"

        v1 = _v1_bundle(self.signer)
        v1_leak = copy.deepcopy(v1)
        v1_leak["entries"][-1]["call_id"] = "ab" * 16

        def unsupported(b):
            b["v"] = 3
            b["anchor"]["v"] = 3

        return [
            ("unsupported_version", self._broken(unsupported), {}, {"unsupported_version"}),
            ("anchor_version_mismatch", self._broken(lambda b: b["anchor"].__setitem__("v", 1)), {},
             {"anchor_version_mismatch"}),
            ("missing_root", self._broken(lambda b: b["entries"].pop(0)), {}, {"missing_root"}),
            ("root_version_mismatch", self._broken(set_entry(0, "v", 1)), {},
             {"root_version_mismatch", "mixed_entry_versions"}),
            ("mixed_entry_versions", self._broken(set_entry(allow_i, "v", 1)), {},
             {"mixed_entry_versions"}),
            ("expected_head_mismatch", self.base, {"expected_head": (99, "ff" * 32)},
             {"expected_head_mismatch"}),
            ("expected_anchor_mismatch", self.base,
             {"expected_anchor": {"seq": 99, "head": "ff" * 32, "chain_id": "t", "v": 2}},
             {"expected_anchor_mismatch"}),
            ("chain_id_mismatch(entry)", self._broken(set_entry(allow_i, "chain_id", "other")), {},
             {"chain_id_mismatch"}),
            ("chain_id_mismatch(anchor)",
             self._broken(lambda b: b["anchor"].__setitem__("chain_id", "other")), {},
             {"chain_id_mismatch"}),
            ("integrity", self._broken(set_entry(outcome_i, "duration_ms", 99)), {},
             {"integrity", "integrity(anchor)"}),
            ("integrity(anchor)", self._broken(set_entry(outcome_i, "duration_ms", 99), rehash=True),
             {}, {"integrity(anchor)"}),
            ("unreadable_authority", self._broken(set_entry(0, "authority", "not-an-authority"),
                                                  rehash=True, reanchor=True), {},
             {"unreadable_authority"}),
            ("unreadable_granted", self._broken(set_entry(spawn_i, "granted", "not-an-authority"),
                                                rehash=True, reanchor=True), {},
             {"unreadable_granted"}),
            ("monotonicity",
             self._broken(lambda b: b["entries"][spawn_i]["granted"].__setitem__(
                 "scopes", ["crm.read", "pay.transfer"]), rehash=True, reanchor=True), {},
             {"monotonicity"}),
            ("containment", self._broken(set_entry(child_allow_i, "scope", "pay.transfer"),
                                         rehash=True, reanchor=True), {}, {"containment"}),
            ("containment(unknown node)",
             self._broken(set_entry(child_allow_i, "node", "t:n99"), rehash=True, reanchor=True), {},
             {"containment"}),
            ("invalid_root", self._broken(drop_entry_field(0, "params_salt"), rehash=True,
                                          reanchor=True), {}, {"invalid_root"}),
            ("invalid_kill", kill_broken, {}, {"invalid_kill"}),
            ("invalid_allow", self._broken(drop_entry_field(allow_i, "capture"), rehash=True,
                                           reanchor=True), {}, {"invalid_allow"}),
            ("invalid_deny", self._broken(set_entry(deny_i, "capture", Capture.WRAPPER_SYNC),
                                          rehash=True, reanchor=True), {}, {"invalid_deny"}),
            ("invalid_outcome", self._broken(set_entry(outcome_i, "duration_ms", -1), rehash=True,
                                             reanchor=True), {}, {"invalid_outcome"}),
            ("duplicate_call_id",
             self._broken(lambda b: b["entries"][deny_i].__setitem__(
                 "call_id", b["entries"][allow_i]["call_id"]), rehash=True, reanchor=True), {},
             {"duplicate_call_id"}),
            ("duplicate_outcome",
             self._broken(lambda b: b["entries"].insert(outcome_i + 1,
                                                        copy.deepcopy(b["entries"][outcome_i])),
                          rehash=True, reanchor=True), {}, {"duplicate_outcome"}),
            ("outcome_without_allow",
             self._broken(set_entry(outcome_i, "call_id", "cd" * 16), rehash=True, reanchor=True),
             {}, {"outcome_without_allow"}),
            ("cross_ref", self._broken(set_entry(outcome_i, "node", child_node), rehash=True,
                                       reanchor=True), {}, {"cross_ref"}),
            ("params_mismatch",
             self._broken(set_entry(outcome_i, "invoked_params_hash", "ab" * 32), rehash=True,
                          reanchor=True), {}, {"params_mismatch"}),
            ("v2_field_on_v1", v1_leak, {}, {"v2_field_on_v1"}),
        ]

    # ---- the assertions ------------------------------------------------
    def test_every_failure_site_produces_exactly_one_twin_per_string(self):
        for name, bundle, kwargs, expected_reasons in self._sites():
            with self.subTest(site=name):
                report = evidence.verify_bundle(bundle, self.signer, **kwargs)
                failures, details = report["failures"], report["failure_details"]
                self.assertTrue(failures, f"{name}: expected this mutation to fail verification")
                self.assertEqual(len(failures), len(details))
                for i, (message, detail) in enumerate(zip(failures, details)):
                    self.assertEqual(sorted(detail),
                                     ["call_id", "detail", "node", "reason", "seq"])
                    self.assertEqual(detail["detail"], message,
                                     f"{name}: twin {i} does not carry its own string")
                    self.assertIsInstance(detail["reason"], str)
                    self.assertTrue(detail["reason"])
                reasons = {d["reason"] for d in details}
                for expected in expected_reasons:
                    self.assertIn(expected, reasons, f"{name}: reported {sorted(reasons)}")

    def test_the_reason_is_the_token_before_the_colon(self):
        # The documented rule, and the two documented exceptions: those two strings name the
        # node before their colon, so their reason is stated explicitly instead.
        seen_exceptions = set()
        for name, bundle, kwargs, _expected in self._sites():
            with self.subTest(site=name):
                report = evidence.verify_bundle(bundle, self.signer, **kwargs)
                for detail in report["failure_details"]:
                    if detail["reason"] in _REASON_NOT_IN_MESSAGE:
                        seen_exceptions.add(detail["reason"])
                        continue
                    self.assertEqual(detail["reason"], detail["detail"].split(":", 1)[0])
        self.assertEqual(seen_exceptions, _REASON_NOT_IN_MESSAGE,
                         "the documented exceptions must both still be reachable")

    def test_a_positioned_failure_names_a_real_entry(self):
        for name, bundle, kwargs, _expected in self._sites():
            with self.subTest(site=name):
                report = evidence.verify_bundle(bundle, self.signer, **kwargs)
                seqs = {e.get("seq") for e in bundle["entries"]}
                nodes = {e.get("node") for e in bundle["entries"]}
                for detail in report["failure_details"]:
                    if detail["seq"] is not None:
                        self.assertIn(detail["seq"], seqs)
                    if detail["node"] is not None:
                        self.assertIn(detail["node"], nodes)

    def test_a_clean_bundle_reports_neither_list(self):
        report = evidence.verify_bundle(self.base, self.signer)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["failure_details"], [])

    def test_a_v1_bundle_keeps_its_historical_execution_binding_shape(self):
        # The structured twins ride ALONGSIDE the execution_binding sub-report, never inside it:
        # that sub-report's published shape is unchanged.
        report = evidence.verify_bundle(_v1_bundle(self.signer), self.signer)
        self.assertEqual(report["execution_binding"], {"status": "not applicable"})
        self.assertEqual(report["failure_details"], [])

    def test_no_failure_list_is_appended_to_directly(self):
        # Anti-drift: `_FailureLog.add` is the only way a failure enters either list, so a new
        # check cannot add a message without its twin. This trap is what keeps that true.
        source = (_ROOT / "src" / "attenu_guard" / "evidence.py").read_text()
        for forbidden in ("failures.append(", "log.append("):
            self.assertNotIn(forbidden, source,
                             f"use _FailureLog.add(reason, detail, ...) instead of {forbidden}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
