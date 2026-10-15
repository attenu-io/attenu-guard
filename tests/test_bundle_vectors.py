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
        self.assertEqual(self.document["revision"], "bundle_vectors_v1.4")
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
            "reject_increased_ttl",
            "reject_loosened_ceiling",
            # revision v1.2 — the literal-subset base and the four rows that can fail ONLY on
            # ttl or a ceiling (the two v1.1 rows above are also rejected, for a scope reason,
            # by a verifier that compares scope lists literally and skips both dimensions).
            "valid_bundle_v2_literal",
            "reject_increased_ttl_literal",
            "reject_loosened_ceiling_literal",
            "reject_null_ttl_literal",
            "reject_omitted_ceiling_literal",
            # revision v1.3 — an `allow` the chain never authorized (a `policy="unlisted"`
            # passthrough). The only accepting row whose point is a report counter: a verifier
            # that runs it through containment rejects an honest bundle, one that drops it
            # silently understates the run.
            "valid_bundle_v2_ungated_allow",
            # revision v1.4 — the two rules the accepting row above does not imply: the value
            # naming a containment exemption must be one the format defines, and `policy` may
            # appear only on an allow.
            "reject_unknown_policy_value",
            "reject_policy_on_spawn",
        ])

    def test_the_delegation_containment_rules_each_have_a_rejecting_case(self):
        # The gap the first two independent runs both reported: integrity and execution binding
        # had rejecting cases, the two checks the library exists for had none. This asserts the
        # corpus keeps covering them, and that each one fails ONLY its own check — a case that
        # also broke integrity would not isolate the rule it is named for.
        by_name = {c["name"]: c for c in self.document["cases"]}
        for name, reason, other in (("reject_widened_scope", "monotonicity", "containment"),
                                    ("reject_uncontained_allow", "containment", "monotonicity"),
                                    ("reject_increased_ttl", "monotonicity", "containment"),
                                    ("reject_loosened_ceiling", "monotonicity", "containment"),
                                    ("reject_increased_ttl_literal", "monotonicity", "containment"),
                                    ("reject_loosened_ceiling_literal", "monotonicity", "containment"),
                                    ("reject_null_ttl_literal", "monotonicity", "containment"),
                                    ("reject_omitted_ceiling_literal", "monotonicity", "containment")):
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

    def test_each_rejecting_case_differs_from_its_base_by_one_entry(self):
        # The rule the README states and every case is built on. Compared entry by entry against
        # the accepting case it derives from — `valid_bundle_v2`, or `valid_bundle_v2_literal`
        # for the rows whose name ends in `_literal` — ignoring the hash chain and the anchor,
        # which every mutation legitimately rewrites. The three cases that insert, transpose or
        # leave the chain broken are exempt from the count, not from the rule.
        by_name = {c["name"]: c for c in self.document["cases"]}
        reshaped = {"reject_outcome_before_allow", "reject_duplicate_outcome"}
        for case in self.document["cases"]:
            if case["expect"] != "reject" or case["name"] in reshaped:
                continue
            with self.subTest(case=case["name"]):
                # The base a row derives from: the accepting case its description NAMES, and
                # `valid_bundle_v2` when it names none. Selecting on the `_literal` suffix alone
                # silently mis-based revision v1.4's rows, which come off the un-gated bundle
                # and end in neither suffix — they were compared against a base one entry
                # shorter and failed on the count, not on the rule.
                named = [n for n in ("valid_bundle_v2_literal", "valid_bundle_v2_ungated_allow")
                         if n in case["description"]]
                self.assertLessEqual(len(named), 1,
                                     f"{case['name']} names more than one base")
                base_name = named[0] if named else "valid_bundle_v2"
                base_entries = by_name[base_name]["bundle"]["entries"]
                entries = case["bundle"]["entries"]
                self.assertEqual(len(entries), len(base_entries))
                skip = ("hash", "prev_hash")
                differing = [i for i, (a, b) in enumerate(zip(base_entries, entries))
                             if {k: v for k, v in a.items() if k not in skip}
                             != {k: v for k, v in b.items() if k not in skip}]
                self.assertEqual(len(differing), 1,
                                 f"{case['name']} changed entries {differing}, expected exactly 1")

    def test_the_literal_base_differs_from_the_valid_bundle_in_the_root_authority_only(self):
        by_name = {c["name"]: c for c in self.document["cases"]}
        a = by_name["valid_bundle_v2"]["bundle"]["entries"]
        b = by_name["valid_bundle_v2_literal"]["bundle"]["entries"]
        self.assertEqual(len(a), len(b))
        skip = ("hash", "prev_hash")
        differing = [i for i, (x, y) in enumerate(zip(a, b))
                     if {k: v for k, v in x.items() if k not in skip}
                     != {k: v for k, v in y.items() if k not in skip}]
        self.assertEqual(differing, [0])
        self.assertEqual(a[0]["authority"]["scopes"], ["crm.*", "mail.send"])
        self.assertEqual(b[0]["authority"]["scopes"], ["crm.read", "mail.send"])
        self.assertEqual(a[1]["granted"], b[1]["granted"])

    def test_the_literal_rows_show_no_scope_difference_to_a_literal_comparison(self):
        # What revision v1.2 exists for. A verifier that compares scope LISTS and never looks at
        # ttl or ceilings — attenu-guard through 0.11.0 was one — rejects the two v1.1 rows
        # anyway, for a scope reason, at the declared position: crm.read is not literally in
        # {crm.*, mail.send}. Such a verifier passes those rows without ever checking the
        # dimension they are about. On the four v1.2 rows that literal comparison finds nothing,
        # so only a ttl or ceiling check can produce the required failure.
        by_name = {c["name"]: c for c in self.document["cases"]}

        def literal_scope_widening(case):
            es = case["bundle"]["entries"]
            parent = set(es[0]["authority"]["scopes"]); child = set(es[1]["granted"]["scopes"])
            return sorted(child - parent)

        for name in ("reject_increased_ttl", "reject_loosened_ceiling"):
            with self.subTest(case=name):
                self.assertEqual(literal_scope_widening(by_name[name]), ["crm.read"])
        for name in ("reject_increased_ttl_literal", "reject_loosened_ceiling_literal",
                     "reject_null_ttl_literal", "reject_omitted_ceiling_literal"):
            with self.subTest(case=name):
                self.assertEqual(literal_scope_widening(by_name[name]), [])
                # and the only thing that differs from the base is the spawn's ttl or ceilings
                base = by_name["valid_bundle_v2_literal"]["bundle"]["entries"][1]["granted"]
                granted = by_name[name]["bundle"]["entries"][1]["granted"]
                self.assertEqual(granted["scopes"], base["scopes"])
                self.assertTrue(granted["ttl"] != base["ttl"] or granted["constraints"] != base["constraints"])

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
        self.assertEqual(loaded["revision"], "bundle_vectors_v1.4")
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
# The reason vocabulary the README publishes, against the reasons this build
# can actually report
# =========================================================================
class TestReasonVocabulary(unittest.TestCase):
    """`tests/vectors/README.md`'s "Reason vocabulary" section is the agreement an implementer
    cannot derive from prose: a verifier that detects a violation at the right position but
    reports it under a name of its own has not reproduced the corpus. The third independent run
    scored 9 of 17 for exactly that reason and 17 of 17 after adopting these names.

    A table is only worth that if it cannot go stale, so this asserts the two sets are EQUAL —
    a new check in evidence.py cannot ship without a row, and a row cannot outlive its check."""

    SOURCE = (_ROOT / "src" / "attenu_guard" / "evidence.py").read_text()
    README = (_ROOT / "tests" / "vectors" / "README.md").read_text()

    #: `failures.add(f"invalid_{ev}", ...)` is the one reason built from a variable rather than
    #: written literally; `ev` is "allow" or "deny" at that site and nowhere else.
    _INVALID_EVENTS = ("allow", "deny")

    def _envelope_reasons_in_source(self) -> set:
        """Every reason `_score_envelope` can report, read out of its own body.

        The scorer reports through one `report()` helper, so `fail.add` sees the reason as a
        variable and the literal-site regex below cannot see it. Trusting
        `evidence.ENVELOPE_FAILURES` instead made the vocabulary check BLIND for envelopes in
        both directions: a reason added to the scorer without a row here and without a row in
        the README passed, because the tuple was the only thing either side was compared with.
        Reading the call sites is what closes that."""
        import re
        body = self.SOURCE.split("\ndef _score_envelope(", 1)
        self.assertEqual(len(body), 2, "evidence.py has no _score_envelope")
        body = body[1].split("\ndef ", 1)[0]
        found = set(re.findall(r'(?:report|fail\.add)\(\s*"([^"]+)"', body))
        self.assertTrue(found, "no reason literals found in _score_envelope")
        return found

    def test_the_envelope_scorer_reports_exactly_the_declared_envelope_failures(self):
        # Both directions: a reason the scorer can report that ENVELOPE_FAILURES does not name,
        # and a name in ENVELOPE_FAILURES no site can produce, are each a failure here.
        self.assertEqual(self._envelope_reasons_in_source(), set(evidence.ENVELOPE_FAILURES))

    def _reported_reasons(self) -> set:
        import re
        literal = set(re.findall(r'(?:log|fail|failures)\.add\(\s*"([^"]+)"', self.SOURCE))
        # The f-string site, asserted to exist rather than assumed, so the expansion below is
        # not an invention this test carries on its own.
        self.assertIn('failures.add(f"invalid_{ev}"', self.SOURCE)
        literal |= {f"invalid_{ev}" for ev in self._INVALID_EVENTS}
        # The envelope scorer's reasons, read from the scorer rather than taken from the tuple
        # that names them — the tuple is checked against the same reading just above.
        literal |= self._envelope_reasons_in_source()
        return literal

    def _documented_reasons(self) -> set:
        import re
        section = self.README.split("### Reason vocabulary", 1)
        self.assertEqual(len(section), 2, "the README has no 'Reason vocabulary' section")
        body = section[1].split("### Cases", 1)[0]
        return set(re.findall(r"^\| `([^`]+)` \|", body, re.M))

    def test_every_reason_this_build_reports_has_a_row(self):
        missing = sorted(self._reported_reasons() - self._documented_reasons())
        self.assertEqual(missing, [], f"reasons evidence.py reports with no README row: {missing}")

    def test_every_documented_reason_is_one_this_build_can_report(self):
        stale = sorted(self._documented_reasons() - self._reported_reasons())
        self.assertEqual(stale, [], f"README rows for reasons evidence.py cannot report: {stale}")

    def test_the_declared_failures_of_both_corpora_are_all_in_the_vocabulary(self):
        # The per-case `Required:` lines are instances of the table, so nothing a committed case
        # requires may be absent from it.
        documented = self._documented_reasons()
        for loader in (vectors.load_bundle_vectors, vectors.load_envelope_vectors):
            for case in loader()["cases"]:
                for failure in case["expect_failures"]:
                    with self.subTest(case=case["name"], reason=failure["reason"]):
                        self.assertIn(failure["reason"], documented)


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
        done_i = _index_of(self.base, "done")
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
            ("unknown_ledger_event",
             self._broken(set_entry(done_i, "event", "frobnicate"), rehash=True, reanchor=True), {},
             {"unknown_ledger_event"}),
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

    def test_every_positioned_failure_names_its_entry_by_index(self):
        # `failure_entries` is in step with the other two lists, and an index points at the
        # entry carrying the very seq and node its twin names. A failure about no single entry
        # names none. This is what `attenu-guard verify --entries` attributes by.
        for name, bundle, kwargs, _expected in self._sites():
            with self.subTest(site=name):
                report = evidence.verify_bundle(bundle, self.signer, **kwargs)
                indices = report["failure_entries"]
                self.assertEqual(len(indices), len(report["failure_details"]))
                for index, detail in zip(indices, report["failure_details"]):
                    if index is None:
                        self.assertIsNone(detail["node"], detail)
                        continue
                    entry = bundle["entries"][index]
                    self.assertEqual((entry.get("seq"), entry.get("node")),
                                     (detail["seq"], detail["node"]), detail)

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


# =========================================================================
# The delegation structure is read in ledger order, and nothing skips the checks
# =========================================================================
class TestDelegationStructure(unittest.TestCase):
    """Through 0.18.0 a spawn whose `parent` was absent, null, a number or a boolean, or a node
    not in the bundle was never checked for monotonicity, so a child widened past its parent
    verified OK (a list or an object there raised TypeError instead); the watched process writes
    that field. Every spawn's parent must now be a string naming a node the root
    or an earlier spawn defined, not revoked by an earlier kill and not the spawn's own node; a
    node is defined once; an allow is judged against a node defined earlier and not revoked; and
    a node id that is not a string is a finding, never a raise."""

    WIDENED = "admin.delete"

    def setUp(self):
        self.signer = HS256TestSigner(b"k", kid="k")
        self.case = next(c for c in vectors.load_bundle_vectors()["cases"]
                         if c["name"] == "valid_bundle_v2")

    def _verify(self, bundle):
        _rehash(bundle)
        _reanchor(bundle, self.signer)
        return evidence.verify_bundle(bundle, self.signer)

    def _widened(self, set_parent):
        """valid_bundle_v2 with the spawn granted a scope the root does not hold, and its parent
        member set by `set_parent(spawn_entry)`."""
        bundle = copy.deepcopy(self.case["bundle"])
        spawn = bundle["entries"][1]
        self.assertEqual((spawn["event"], spawn["node"], spawn["parent"]),
                         ("spawn", "vectors:n1", "vectors:n0"))
        spawn["granted"]["scopes"] = sorted(set(spawn["granted"]["scopes"]) | {self.WIDENED})
        set_parent(spawn)
        return bundle

    @staticmethod
    def _chain(depth=2, schema_version=1):
        """root t:n0 -> t:n1 (-> t:n2), each holding crm.read, and an allow by the deepest."""
        root = Guard.issue("root", Authority({"crm.read"}, [], ttl=600), chain_id="t",
                           schema_version=schema_version)
        guard = root
        for i in range(depth - 1):
            guard = guard.delegate(f"agent{i}", Authority({"crm.read"}, [], ttl=600), task="t")
        guard.check("crm.read")
        return root, guard

    def _bundle_of(self, root):
        return evidence.export_bundle(root.audit_log(), self.signer)

    def _monotonicity(self, report):
        return [f for f in report["failures"] if f.startswith("monotonicity")]

    def test_a_widened_child_fails_whatever_its_parent_field_says(self):
        stated = "names no parent defined earlier in this bundle"
        for label, set_parent, message in (
                ("intact", lambda s: None,
                 "monotonicity: vectors:n1 not ⊆ parent vectors:n0 (child scopes "
                 "['admin.delete', 'crm.read'] not held by parent)"),
                ("absent", lambda s: s.pop("parent"),
                 f"monotonicity: vectors:n1 {stated} (parent None)"),
                ("null", lambda s: s.update(parent=None),
                 f"monotonicity: vectors:n1 {stated} (parent None)"),
                ("unknown", lambda s: s.update(parent="vectors:n9"),
                 f"monotonicity: vectors:n1 {stated} (parent vectors:n9)"),
                ("empty", lambda s: s.update(parent=""),
                 f'monotonicity: vectors:n1 {stated} (parent "")'),
                ("its own node", lambda s: s.update(parent="vectors:n1"),
                 f"monotonicity: vectors:n1 {stated} (parent vectors:n1)"),
                ("a number", lambda s: s.update(parent=5),
                 f"monotonicity: vectors:n1 {stated} (parent 5)"),
                ("a bool", lambda s: s.update(parent=True),
                 f"monotonicity: vectors:n1 {stated} (parent True)"),
                ("a list", lambda s: s.update(parent=["vectors:n0"]),
                 f"monotonicity: vectors:n1 {stated} (parent ['vectors:n0'])"),
                ("an object", lambda s: s.update(parent={"node": "vectors:n0"}),
                 f'monotonicity: vectors:n1 {stated} (parent {{"node":"vectors:n0"}})')):
            with self.subTest(parent=label):
                report = self._verify(self._widened(set_parent))
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["monotonicity"])
                self.assertEqual(self._monotonicity(report), [message])
                at = report["failures"].index(message)
                self.assertEqual(report["failure_entries"][at], 1)        # the spawn, by index

    def test_a_parent_defined_only_later_is_no_parent(self):
        root, _leaf = self._chain(depth=3)
        bundle = self._bundle_of(root)
        self.assertEqual([(e["node"], e.get("parent")) for e in bundle["entries"][:3]],
                         [("t:n0", None), ("t:n1", "t:n0"), ("t:n2", "t:n1")])
        bundle["entries"][1]["parent"] = "t:n2"
        report = self._verify(bundle)
        self.assertEqual(self._monotonicity(report), [
            "monotonicity: t:n1 names no parent defined earlier in this bundle (parent t:n2)"])

    def test_a_cycle_of_widened_nodes_fails_without_any_missing_parent(self):
        # X's parent is Y and Y's parent is X, both granted admin.delete, so each is ⊆ the other
        # and neither is ever compared with the root, which holds only crm.read. No parent is
        # missing, and through 0.18.0 this verified OK with an allow on admin.delete. A parent
        # defined by an EARLIER entry is what breaks the cycle: X names Y before Y exists.
        root, _leaf = self._chain(depth=3)
        bundle = self._bundle_of(root)
        entries = bundle["entries"]
        x, y, allow = entries[1], entries[2], entries[3]
        self.assertEqual((x["node"], x["parent"], y["node"], y["parent"], allow["event"]),
                         ("t:n1", "t:n0", "t:n2", "t:n1", "allow"))
        widened = dict(x["granted"], scopes=[self.WIDENED, "crm.read"])
        x["parent"], x["granted"], y["granted"] = "t:n2", widened, dict(widened)
        allow["scope"] = self.WIDENED
        report = self._verify(bundle)
        self.assertFalse(report["ok"])
        message = "monotonicity: t:n1 names no parent defined earlier in this bundle (parent t:n2)"
        self.assertEqual(report["failures"], [message])
        self.assertEqual(report["failure_entries"], [1])

    def test_a_node_is_defined_once(self):
        # The second definition of t:n1, widened and from the root, would have been the only
        # one read; a spawn reusing the root's own node is the same defect.
        root, _leaf = self._chain(depth=2)
        bundle = self._bundle_of(root)
        again = dict(bundle["entries"][1], seq=len(bundle["entries"]),
                     granted=dict(bundle["entries"][1]["granted"], scopes=["crm.read", self.WIDENED]))
        reroot = dict(bundle["entries"][1], node="t:n0", seq=len(bundle["entries"]) + 1)
        bundle["entries"] += [again, reroot]
        report = self._verify(bundle)
        self.assertEqual(self._monotonicity(report), [
            "monotonicity: t:n1 is defined a second time in this bundle (first at seq 1)",
            "monotonicity: t:n0 is defined a second time in this bundle (first at seq 0)"])

    def test_a_spawn_from_a_revoked_parent_fails(self):
        root, leaf = self._chain(depth=2)
        root.revoke(leaf.node_id)
        bundle = self._bundle_of(root)
        kill_seq = next(e["seq"] for e in bundle["entries"] if e["event"] == "kill")
        bundle["entries"].append(dict(bundle["entries"][1], node="t:n2", parent="t:n1",
                                      seq=len(bundle["entries"])))
        report = self._verify(bundle)
        self.assertEqual(self._monotonicity(report), [
            f"monotonicity: t:n2 is spawned from t:n1 after t:n1 was revoked at seq {kill_seq}"])

    def test_an_allow_on_a_revoked_node_fails_containment(self):
        root, leaf = self._chain(depth=2)
        root.revoke(leaf.node_id)
        bundle = self._bundle_of(root)
        allow = next(e for e in bundle["entries"] if e["event"] == "allow")
        kill_seq = next(e["seq"] for e in bundle["entries"] if e["event"] == "kill")
        bundle["entries"].append(dict(allow, seq=len(bundle["entries"])))
        report = self._verify(bundle)
        self.assertEqual(report["failures"], [
            f"containment: allow of 'crm.read' on t:n1 after t:n1 was revoked at seq {kill_seq}"])
        self.assertEqual(report["failure_entries"], [len(bundle["entries"]) - 1])

    def test_an_allow_before_its_node_is_defined_is_on_an_unknown_node(self):
        root, _leaf = self._chain(depth=2)
        bundle = self._bundle_of(root)
        entries = bundle["entries"]
        self.assertEqual([e["event"] for e in entries[:3]], ["root", "spawn", "allow"])
        entries[1], entries[2] = entries[2], entries[1]
        for i, e in enumerate(entries):
            e["seq"] = i
        report = self._verify(bundle)
        self.assertEqual(report["failures"], ["containment: allow on unknown node t:n1"])
        self.assertEqual(report["failure_entries"], [1])

    def test_a_context_that_is_not_an_object_fails_containment(self):
        root, _leaf = self._chain(depth=1)
        bundle = self._bundle_of(root)
        bundle["entries"][1]["context"] = [1]
        report = self._verify(bundle)
        self.assertEqual(report["failures"], [
            "containment: allow of 'crm.read' on t:n0 outside its authority ['crm.read']"])

    def test_a_node_that_is_not_a_string_is_a_finding_and_never_a_raise(self):
        for bad in ([1], {"a": 1}, 5, True):
            for event in ("root", "spawn", "allow", "deny", "done", "outcome"):
                with self.subTest(event=event, node=repr(bad)):
                    bundle = copy.deepcopy(self.case["bundle"])
                    at = next(i for i, e in enumerate(bundle["entries"]) if e["event"] == event)
                    bundle["entries"][at]["node"] = bad
                    report = self._verify(bundle)
                    self.assertFalse(report["ok"])
                    reasons = {d["reason"] for d in report["failure_details"]}
                    expected = {"root": "unreadable_authority", "spawn": "unreadable_granted",
                                "allow": "containment"}.get(event, "invalid_node")
                    self.assertIn(expected, reasons)
                    self.assertIn(at, report["failure_entries"])
        # A kill naming nodes that are not strings revokes nothing and raises nothing.
        root, leaf = self._chain(depth=2)
        root.revoke(leaf.node_id)
        bundle = self._bundle_of(root)
        next(e for e in bundle["entries"] if e["event"] == "kill")["revoked"] = [[1], {"a": 1}, 5]
        self.assertTrue(self._verify(bundle)["ok"])

    def test_the_exact_strings_for_a_node_that_is_not_a_string(self):
        bundle = copy.deepcopy(self.case["bundle"])
        bundle["entries"][0]["node"] = [1]
        self.assertIn("root [1]: unreadable authority (node is not a string)",
                      self._verify(bundle)["failures"])
        bundle = copy.deepcopy(self.case["bundle"])
        bundle["entries"][1]["node"] = {"a": 1}
        self.assertIn('spawn {"a":1}: unreadable granted (node is not a string)',
                      self._verify(bundle)["failures"])
        bundle = copy.deepcopy(self.case["bundle"])
        deny_at = next(i for i, e in enumerate(bundle["entries"]) if e["event"] == "deny")
        bundle["entries"][deny_at]["node"] = 5
        self.assertIn(f"invalid_node: seq={deny_at} event='deny' carries node 5, which is not a string",
                      self._verify(bundle)["failures"])

    def test_fuzz_a_widened_child_never_verifies_ok_whatever_its_parent_says(self):
        # Deterministic: one seed, and every draw is a parent value a ledger writer could put
        # there, including well-formed node ids, the child's own id and nodes that do not exist.
        import random
        rng = random.Random(20261005)
        pool = [None, True, False, 0, 1, -1, 1.0, 1.5, "", " ", "vectors:n0", "vectors:n1",
                "vectors:n2", "vectors:n9", "VECTORS:N0", "vectors:n0 ", ["vectors:n0"], [],
                {"node": "vectors:n0"}, {}, "\u0000", "vectors:n0\n"]
        for trial in range(400):
            draw = rng.choice(pool + ["DELETE"] + ["".join(rng.choice("vectors:n0129*.")
                                                           for _ in range(rng.randint(0, 12)))])
            def set_parent(spawn, draw=draw):
                if draw == "DELETE":
                    spawn.pop("parent")
                else:
                    spawn["parent"] = copy.deepcopy(draw)
            with self.subTest(trial=trial, parent=repr(draw)):
                report = self._verify(self._widened(set_parent))
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["monotonicity"])


# =========================================================================
# Monotonicity across EVERY dimension of the lattice, not just scopes
# =========================================================================
class TestMonotonicityDimensions(unittest.TestCase):
    """A delegation widens if it grows on ANY dimension `Authority.is_narrower_than` compares:
    scopes, ceilings, or ttl. Through 0.11.0 the bundle verifier's monotonicity check was gated
    on a literal, non-wildcard-aware scope difference, so a child that only outlived its parent
    or only raised a ceiling was reported ONLY when its scopes happened not to be literally a
    subset. Every widening bundle below verified clean before that gate was removed, and the
    misdirected case reported a scope message for a ttl violation.
    """

    def setUp(self):
        self.signer = HS256TestSigner(b"k", kid="k")
        self.parent = Authority({"crm.read", "mail.send"}, [RowLimit(100)], ttl=3600)

    def _bundle(self, granted_wire, *, parent=None):
        """An honest two-node v2 chain with the spawn's `granted` replaced wholesale, the chain
        re-hashed and a fresh anchor signed over it. That detour is the only way to get an
        unsound delegation into a ledger: `Guard.delegate` refuses to create one, which is why
        this is a verifier test and not a Guard test."""
        root = Guard.issue("orchestrator", parent or self.parent, chain_id="t", schema_version=2)
        child = root.delegate("summarizer", Authority({"crm.read"}, [RowLimit(50)], ttl=900),
                              task="summarize")
        child.complete()
        root.complete()
        bundle = evidence.export_bundle(root.audit_log(), self.signer)
        bundle["entries"][_index_of(bundle, "spawn")]["granted"] = granted_wire
        _rehash(bundle)
        _reanchor(bundle, self.signer)
        return bundle

    @staticmethod
    def _granted(scopes=("crm.read",), max_rows=50, ttl=900):
        constraints = [] if max_rows is None else [{"key": "max_rows", "max": max_rows}]
        return {"scopes": list(scopes), "constraints": constraints, "ttl": ttl}

    def _assert_widens(self, granted, expected_detail, *, parent=None):
        report = evidence.verify_bundle(self._bundle(granted, parent=parent), self.signer)
        self.assertFalse(report["ok"], "a widening delegation must not verify")
        self.assertFalse(report["checks"]["monotonicity"])
        # Integrity stays green: the chain was re-hashed and re-anchored, so monotonicity is
        # the only thing wrong and the failure cannot be an artifact of a broken ledger.
        self.assertTrue(report["checks"]["integrity"])
        self.assertEqual(report["failures"],
                         [f"monotonicity: t:n1 not ⊆ parent t:n0 ({expected_detail})"])
        self.assertEqual([(d["reason"], d["seq"], d["node"]) for d in report["failure_details"]],
                         [("monotonicity", 1, "t:n1")])

    # ---- the two dimensions 0.11.0 accepted ----------------------------
    def test_a_child_that_outlives_its_parent_is_not_narrower(self):
        self._assert_widens(self._granted(ttl=7200), "ttl 7200 > parent 3600")

    def test_a_child_with_a_looser_ceiling_is_not_narrower(self):
        self._assert_widens(self._granted(max_rows=250),
                            "ceiling max_rows<=250 looser than parent max_rows<=100")

    # ---- the two the same relation fails on, by omission ---------------
    def test_a_child_unbounded_where_its_parent_bounds_is_not_narrower(self):
        # Dropping a ceiling is not attenuation: no ceiling means unbounded on that dimension,
        # which is MORE authority than the parent held, not less.
        self._assert_widens(self._granted(max_rows=None),
                            "ceiling max_rows unbounded, parent holds max_rows<=100")

    def test_a_child_that_never_expires_under_a_parent_that_does_is_not_narrower(self):
        self._assert_widens(self._granted(ttl=None), "ttl unbounded, parent 3600")

    # ---- the dimension is named, even when a wildcard hides the scopes --
    def test_a_ttl_widening_under_a_wildcard_parent_names_ttl_not_scopes(self):
        # The misdirected case. {crm.read} is covered by a parent holding {crm.*} but is NOT
        # literally in its scope set, so the old gate fired and printed a scope message for a
        # violation that was entirely about ttl.
        self._assert_widens(self._granted(ttl=7200), "ttl 7200 > parent 3600",
                            parent=Authority({"crm.*"}, [RowLimit(100)], ttl=3600))

    # ---- what must NOT change ------------------------------------------
    def test_the_scope_widening_message_is_unchanged(self):
        self._assert_widens(self._granted(scopes=("crm.read", "pay.transfer")),
                            "child scopes ['pay.transfer'] not held by parent")

    def test_a_scope_widening_under_a_wildcard_parent_keeps_its_historical_wording(self):
        # The published string lists the LITERAL set difference, so a scope the parent covers
        # by wildcard appears in it alongside the one it does not. Unchanged on purpose: it is
        # the wording the released vectors and two independent verifiers already score.
        self._assert_widens(self._granted(scopes=("crm.read", "pay.transfer")),
                            "child scopes ['crm.read', 'pay.transfer'] not held by parent",
                            parent=Authority({"crm.*"}, [RowLimit(100)], ttl=3600))

    def test_an_honestly_narrower_child_still_verifies(self):
        # The other half of the fix: removing the gate must not make a sound delegation fail.
        report = evidence.verify_bundle(
            self._bundle(self._granted(max_rows=10, ttl=60)), self.signer)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["failures"], [])

    def test_an_identical_regrant_still_verifies(self):
        # The boundary of the relation: equal is narrower-or-equal, so a child granted exactly
        # what its parent holds is sound and must not be reported.
        report = evidence.verify_bundle(
            self._bundle({"scopes": ["crm.read", "mail.send"],
                          "constraints": [{"key": "max_rows", "max": 100}], "ttl": 3600}),
            self.signer)
        self.assertTrue(report["ok"], report["failures"])

    def test_the_first_failing_dimension_is_the_one_reported(self):
        # Ceilings are compared before ttl, matching Authority.is_narrower_than, so a child that
        # widens both names the ceiling. One message per unsound delegation, as before.
        self._assert_widens(self._granted(max_rows=250, ttl=7200),
                            "ceiling max_rows<=250 looser than parent max_rows<=100")


# =========================================================================
# Every entry is a JSON object, and its event one its chain's version defines
# =========================================================================
_SCHEMA = _ROOT / "schema" / "agent-audit.schema.json"

_UNKNOWN_EVENT = ("unknown_ledger_event: entry carries an event this verifier does not evaluate "
                  "and will not ignore: ")


def _v1_forbidden_fields(schema) -> set:
    """The fields the schema forbids on a schema_version=1 entry, read from its own condition."""
    for rule in schema["allOf"]:
        cond = rule.get("if", {}).get("properties", {})
        if cond == {"v": {"const": 1}}:
            return {field for alt in rule["then"]["not"]["anyOf"] for field in alt["required"]}
    raise AssertionError("the schema has no schema_version=1 condition")


def _v2_only_events(schema) -> set:
    """The events the schema makes impossible on a schema_version=1 entry: an event whose own
    condition requires a field version 1 forbids."""
    forbidden = _v1_forbidden_fields(schema)
    out = set()
    for rule in schema["allOf"]:
        cond = rule.get("if", {}).get("properties", {})
        if set(cond) == {"event"} and forbidden & set(rule["then"].get("required", [])):
            out.add(cond["event"]["const"])
    return out


class TestEntryShapeAndEventNames(unittest.TestCase):
    """`schema/agent-audit.schema.json` closes the ledger `event` set, and the verifier did not
    enforce it: `valid_bundle_v2` with a `done` renamed `frobnicate` or `""`, re-chained and
    re-anchored, verified ok; an `allow` renamed was read by no check, containment included;
    and a bare `outcome` on a schema_version=1 chain verified, though the schema makes
    `outcome` v2-only. An entry that is not a JSON object, or an `entries` that is not an
    array, raised out of `verify_bundle` instead of reporting. Both entry-level names are
    XuebinMa's (A2A #1575).

    Every expected string here is asserted byte for byte by attenu-guard-ts's
    test/bundle-vectors.test.ts, for the same mutation of the same bundle."""

    def setUp(self):
        self.case = next(c for c in vectors.load_bundle_vectors()["cases"]
                         if c["name"] == "valid_bundle_v2")
        self.signer = _signer_for(self.case)

    def _bundle(self):
        return copy.deepcopy(self.case["bundle"])

    def _rechained(self, edit):
        """valid_bundle_v2 with `edit(entries)` applied, re-chained and re-anchored, so
        integrity is not what fails."""
        bundle = self._bundle()
        edit(bundle["entries"])
        _rehash(bundle)
        _reanchor(bundle, self.signer)
        return bundle

    def _verify(self, bundle, **kwargs):
        return evidence.verify_bundle(bundle, self.signer, **kwargs)

    def _assert_twins(self, report):
        self.assertEqual(len(report["failures"]), len(report["failure_details"]))
        self.assertEqual(len(report["failures"]), len(report["failure_entries"]))
        for message, detail in zip(report["failures"], report["failure_details"]):
            self.assertEqual(detail["detail"], message)
            self.assertEqual(detail["reason"], message.split(":", 1)[0])

    # ---- the sets, against the schema ------------------------------------
    def test_ledger_events_are_the_schema_enum_per_version(self):
        schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
        event = schema["properties"]["event"]
        self.assertEqual(event["type"], "string")
        self.assertEqual(len(event["enum"]), len(set(event["enum"])))
        self.assertEqual(evidence.LEDGER_EVENTS, frozenset(event["enum"]))
        self.assertEqual(sorted(evidence.LEDGER_EVENTS),
                         ["allow", "deny", "done", "kill", "outcome", "root", "spawn",
                          "spawn_denied"])
        # Version 1 has every name but the ones the schema makes impossible there.
        self.assertEqual(_v2_only_events(schema), {"outcome"})
        self.assertIn("outcome=(v2 only)", event["description"])
        self.assertEqual(evidence.LEDGER_EVENTS_V1,
                         frozenset(event["enum"]) - _v2_only_events(schema))
        self.assertIn("event", schema["required"])
        for name in ("LEDGER_EVENTS", "LEDGER_EVENTS_V1"):
            self.assertIsInstance(getattr(evidence, name), frozenset)
            self.assertIn(name, evidence.__all__)

    def test_the_schema_names_exactly_the_ledger_fields(self):
        schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["properties"]), set(evidence.LEDGER_FIELDS))
        # Closed, as LEDGER_FIELDS is: a field outside it fails unknown_ledger_fields, and the
        # schema refuses it too. `context` stays open; it is free-form by contract.
        self.assertIs(schema["additionalProperties"], False)
        self.assertNotIn("additionalProperties", schema["properties"]["context"])
        self.assertEqual(_v1_forbidden_fields(schema), set(evidence._V2_ONLY_FIELDS))
        self.assertEqual(schema["$id"], "https://attenu.io/schemas/agent-audit/v1.json")

    # ---- an event this verifier does not evaluate ------------------------
    def test_an_event_outside_the_eight_fails_at_its_entry(self):
        # Printed by the display rule, as unknown_ledger_fields prints a field name.
        for value, shown in (("frobnicate", "frobnicate"), ("", '""'), ("Done", "Done"),
                             ("done ", '"done\\u0020"'), ("spawn-denied", "spawn-denied"),
                             ("5", "5"), ("None", "None")):
            with self.subTest(event=value):
                report = self._verify(
                    self._rechained(lambda entries: entries[7].update(event=value)))
                message = _UNKNOWN_EVENT + shown
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["ledger_fields"])
                self.assertTrue(report["checks"]["integrity"])
                self.assertEqual(report["failures"], [message])
                self.assertEqual(report["failure_details"], [
                    {"reason": "unknown_ledger_event", "seq": 7, "node": "vectors:n1",
                     "call_id": None, "detail": message}])
                self.assertEqual(report["failure_entries"], [7])

    def test_an_event_that_is_not_a_string_fails_at_its_entry(self):
        # Said to be no string, so the number 5 and null read differently from the strings "5"
        # and "None" above. An absent event reads as None, as an absent seq does.
        for label, edit, shown in (
                ("absent", lambda e: e.pop("event"), "None"),
                ("null", lambda e: e.update(event=None), "None"),
                ("number", lambda e: e.update(event=5), "5"),
                ("boolean", lambda e: e.update(event=True), "True"),
                ("array", lambda e: e.update(event=["done"]), "['done']"),
                ("object", lambda e: e.update(event={"name": "done"}), '{"name":"done"}')):
            with self.subTest(event=label):
                report = self._verify(self._rechained(lambda entries: edit(entries[7])))
                message = f"{_UNKNOWN_EVENT}{shown}, which is not a string"
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["ledger_fields"])
                self.assertEqual(report["failures"], [message])
                self.assertEqual(report["failure_details"], [
                    {"reason": "unknown_ledger_event", "seq": 7, "node": "vectors:n1",
                     "call_id": None, "detail": message}])
                self.assertEqual(report["failure_entries"], [7])

    def test_an_allow_renamed_is_reported_not_skipped(self):
        # Before, the only failure was the outcome it orphaned: the renamed entry itself was
        # read by no check, containment included.
        report = self._verify(
            self._rechained(lambda entries: entries[2].update(event="frobnicate")))
        self.assertFalse(report["ok"])
        self.assertEqual(report["failures"], [
            _UNKNOWN_EVENT + "frobnicate",
            "outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no "
            "allow in this chain"])
        self.assertEqual(report["failure_entries"], [2, 3])
        self._assert_twins(report)

    def test_a_bare_outcome_on_a_schema_version_1_chain_fails_at_its_entry(self):
        # `outcome` is v2-only. A bare one carries no v2-only field, so v2_field_on_v1 does not
        # see it either, and this bundle verified.
        bundle = _v1_bundle(self.signer)
        last = bundle["entries"][-1]
        bundle["entries"].append({"v": 1, "c14n": last["c14n"], "seq": last["seq"] + 1,
                                  "ts": last["ts"], "event": "outcome",
                                  "chain_id": last["chain_id"], "node": last["node"]})
        _rehash(bundle)
        _reanchor(bundle, self.signer)
        report = evidence.verify_bundle(bundle, self.signer)
        message = _UNKNOWN_EVENT + "outcome, a v2-only event on a schema_version=1 chain"
        self.assertFalse(report["ok"])
        self.assertEqual(report["failures"], [message])
        self.assertEqual(report["failure_details"], [
            {"reason": "unknown_ledger_event", "seq": 2, "node": "t:n0", "call_id": None,
             "detail": message}])
        self.assertEqual(report["failure_entries"], [2])
        # The other seven are version 1's own.
        self.assertTrue(evidence.verify_bundle(_v1_bundle(self.signer), self.signer)["ok"])

    def test_each_defect_on_one_entry_is_reported(self):
        def both(entries):
            entries[7]["event"] = "frobnicate"
            entries[7]["critical"] = True
        report = self._verify(self._rechained(both))
        self.assertEqual(report["failures"], [
            _UNKNOWN_EVENT + "frobnicate",
            "unknown_ledger_fields: entry carries fields this verifier does not evaluate and "
            "will not ignore: critical"])
        self.assertEqual(report["failure_entries"], [7, 7])
        self._assert_twins(report)

    def test_every_event_the_schema_names_still_verifies(self):
        # The control: the eight names are read, and nothing above fires on a clean bundle.
        report = self._verify(self._bundle())
        self.assertTrue(report["ok"], report["failures"])
        self.assertTrue(report["checks"]["ledger_fields"])

    # ---- an entry that is not a JSON object -----------------------------
    def test_an_entry_that_is_not_an_object_is_reported_never_raised(self):
        # Chain-level, since it has no seq or node; its index is in the message, and
        # `failure_entries` names it. Nothing else reads it, so it is reported once; the hash
        # chain breaks there, which is the one consequence. Not re-chained: such an entry has
        # no hash to re-chain.
        for value, kind in (("x", "a string"), (None, "null"), ([], "an array"),
                            (["root"], "an array"), (5, "a number"), (1.5, "a number"),
                            (True, "a boolean")):
            with self.subTest(entry=value):
                bundle = self._bundle()
                bundle["entries"][7] = value
                report = self._verify(bundle)
                self.assertFalse(report["ok"])
                self.assertFalse(report["checks"]["ledger_fields"])
                self.assertFalse(report["checks"]["integrity"])
                self.assertTrue(report["checks"]["version"])
                self.assertTrue(report["checks"]["chain_id"])
                self.assertEqual(report["failures"], [
                    f"invalid_ledger_entry: entries[7] is {kind}, not an object",
                    "integrity: seq gap at 7 (got None)",
                    "integrity(anchor): seq gap at 7 (got None)"])
                self.assertEqual(
                    [(d["reason"], d["seq"], d["node"], d["call_id"])
                     for d in report["failure_details"]],
                    [("invalid_ledger_entry", None, None, None),
                     ("integrity", None, None, None),
                     ("integrity(anchor)", None, None, None)])
                self.assertEqual(report["failure_entries"], [7, 7, None])
                self._assert_twins(report)

    def test_two_entries_that_are_not_objects_are_each_positioned(self):
        # By index, never by the value: two nulls are two entries.
        bundle = self._bundle()
        bundle["entries"][3] = None
        bundle["entries"][7] = None
        report = self._verify(bundle)
        self.assertEqual(report["failures"], [
            "invalid_ledger_entry: entries[3] is null, not an object",
            "invalid_ledger_entry: entries[7] is null, not an object",
            "integrity: seq gap at 3 (got None)",
            "integrity(anchor): seq gap at 3 (got None)"])
        self.assertEqual(report["failure_entries"], [3, 7, 3, None])

    def test_an_expected_head_past_an_entry_that_is_not_an_object_is_reported(self):
        bundle = self._bundle()
        head = bundle["entries"][8]["hash"]
        bundle["entries"][8] = None
        report = self._verify(bundle, expected_head=(8, head))
        self.assertIn("expected_head_mismatch: bundle head is (seq=8, hash=None) but the "
                      f"independently retained expected head is (seq=8, hash={head})",
                      report["failures"])
        self.assertFalse(report["ok"])

    # ---- a bundle, or its entries, that is not what the format says -----
    def test_entries_that_is_not_an_array_is_reported_never_raised(self):
        for value, kind in (("x", "a string"), ("", "a string"), ({}, "an object"),
                            ({"0": {}}, "an object"), (5, "a number"), (0, "a number"),
                            (False, "a boolean")):
            with self.subTest(entries=value):
                bundle = self._bundle()
                bundle["entries"] = value
                report = self._verify(bundle)
                message = f"invalid_bundle: entries is {kind}, not an array"
                self.assertEqual(report["failures"], [message])
                self.assertEqual(report["failure_details"], [
                    {"reason": "invalid_bundle", "seq": None, "node": None, "call_id": None,
                     "detail": message}])
                self.assertEqual(report["failure_entries"], [None])
                self.assertFalse(report["ok"])
                self.assertEqual(report["checks"], {
                    "integrity": False, "monotonicity": False, "containment": False,
                    "anchor": "not checked", "version": False, "ledger_fields": False,
                    "chain_id": False, "root": False, "expected_anchor": "not checked",
                    "envelopes": "not checked"})
                self.assertEqual((report["nodes"], report["actions_checked"], report["ungated"]),
                                 (0, 0, 0))
                self.assertEqual(report["chain_id"], "vectors")
                self.assertEqual(report["execution_binding"], {"status": "not applicable"})
                self.assertEqual(report["envelopes"]["status"], "not checked")
                self.assertEqual(report["verified_against"], "bundle_anchor")

    def test_absent_or_null_entries_are_still_an_empty_ledger(self):
        for label, edit in (("absent", lambda b: b.pop("entries")),
                            ("null", lambda b: b.update(entries=None)),
                            ("empty", lambda b: b.update(entries=[]))):
            with self.subTest(entries=label):
                bundle = self._bundle()
                edit(bundle)
                report = evidence.verify_bundle(bundle)
                self.assertEqual(report["failures"],
                                 ["missing_root: bundle has 0 root event(s), expected exactly 1"])

    def test_a_bundle_that_is_not_an_object_is_reported_never_raised(self):
        for value, kind in (([], "an array"), ("x", "a string"), (None, "null"),
                            (5, "a number"), (True, "a boolean")):
            with self.subTest(bundle=value):
                report = self._verify(value)
                message = f"invalid_bundle: the bundle is {kind}, not an object"
                self.assertEqual(report["failures"], [message])
                self.assertEqual(report["failure_entries"], [None])
                self.assertFalse(report["ok"])
                self.assertIsNone(report["chain_id"])
                self._assert_twins(report)



# =========================================================================
# Hostile bundle content is reported or skipped by every public reader, never raised
# =========================================================================
#: One value of each JSON kind, and the empty ones Python counts as false.
_KINDS = (None, True, 0, 1.5, "", "x", [], ["x"], {}, {"a": 1})

#: TypeScript's answer for one mutation per field value the Python verifier hashed or compared and
#: raised on: (failure, seq, node, failure_entries index), in report order. Re-chained and
#: re-anchored. attenu-guard-ts's test/bundle-vectors.test.ts asserts the same rows.
_FIELD_CASES = {
    "v=[] at 4": ((lambda es: es[4].update(v=[])), [
        ("mixed_entry_versions: entries declare v in [[]], bundle v=2", 4, "vectors:n1", 4)]),
    "v={'a': 1} at 4, v=[] at 6": ((lambda es: (es[4].update(v={"a": 1}), es[6].update(v=[]))), [
        ("mixed_entry_versions: entries declare v in [[], {'a': 1}], bundle v=2", 4, "vectors:n1", 4)]),
    "seq=[] at 4": ((lambda es: es[4].update(seq=[])), [
        ("integrity: seq gap at 4 (got [])", [], "vectors:n1", 4),
        ("integrity(anchor): seq gap at 4 (got [])", None, None, None),
        ("outcome_before_allow: call_id 15d42567717e39b8ff1881a14ec42f96 outcome seq 6 not after "
         "allow seq []", 6, "vectors:n1", 6)]),
    "seq='x' at 3": ((lambda es: es[3].update(seq="x")), [
        ("integrity: seq gap at 3 (got x)", "x", "vectors:n0", 3),
        ("integrity(anchor): seq gap at 3 (got x)", None, None, None),
        ("outcome_before_allow: call_id eb099aeb221783e1442261f15df4fb35 outcome seq x not after "
         "allow seq 2", "x", "vectors:n0", 3)]),
    "seq=true at 2": ((lambda es: es[2].update(seq=True)), [
        ("integrity: seq gap at 2 (got True)", True, "vectors:n0", 2),
        ("integrity(anchor): seq gap at 2 (got True)", None, None, None),
        ("outcome_before_allow: call_id eb099aeb221783e1442261f15df4fb35 outcome seq 3 not after "
         "allow seq True", 3, "vectors:n0", 3)]),
    "call_id=[] at 2": ((lambda es: es[2].update(call_id=[])), [
        ("invalid_allow: call_id missing or malformed ([]) (seq 2)", 2, "vectors:n0", 2),
        ("outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow "
         "in this chain", 3, "vectors:n0", 3)]),
    "capture={} at 2": ((lambda es: es[2].update(capture={})), [
        ("invalid_allow: capture {} not a known value (seq 2)", 2, "vectors:n0", 2),
        ("outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow "
         "in this chain", 3, "vectors:n0", 3)]),
    "params_hash_reason=[] at 2": ((lambda es: (es[2].pop("authorized_params_hash"),
                                                es[2].update(params_hash_reason=[]))), [
        ("invalid_allow: params_hash_reason [] not a known value (seq 2)", 2, "vectors:n0", 2),
        ("outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow "
         "in this chain", 3, "vectors:n0", 3)]),
    "body_state=[] at 3": ((lambda es: es[3].update(body_state=[])), [
        ("invalid_outcome: body_state [] not a known value (seq 3)", 3, "vectors:n0", 3)]),
    "call_id=5 at 2 and 5": ((lambda es: (es[2].update(call_id=5), es[5].update(call_id=5))), [
        ("invalid_allow: call_id missing or malformed (5) (seq 2)", 2, "vectors:n0", 2),
        ("duplicate_call_id: call_id 5 on seq 5 (deny) already used at seq 2 (allow)", 5,
         "vectors:n1", 5),
        ("invalid_deny: call_id missing or malformed (5) (seq 5)", 5, "vectors:n1", 5),
        ("outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow "
         "in this chain", 3, "vectors:n0", 3)]),
}


class TestHostileBundleContent(unittest.TestCase):
    """`verify_bundle`'s 0.13.0 note says it never raises. It raised on an `anchor` that is not
    an object, on `envelopes` that are not an array, and on field values it hashed or compared:
    a list or an object as `v`, `seq`, `call_id`, `capture`, `params_hash_reason` or
    `body_state`, and a string `seq` beside an integer one. `delegation_graph`, `denials`,
    `verify_envelopes` and `redaction_report` raised on a bundle, its entries, or an entry that
    was not what the format says. Every public reader now reports what it cannot read, by its
    own convention, or skips it; the signing helpers raise their documented ValueError.
    attenu-guard-ts's test/bundle-vectors.test.ts asserts the same strings and shapes."""

    def setUp(self):
        self.case = next(c for c in vectors.load_bundle_vectors()["cases"]
                         if c["name"] == "valid_bundle_v2")
        self.signer = _signer_for(self.case)

    def _bundle(self):
        return copy.deepcopy(self.case["bundle"])

    def _rechained(self, edit):
        bundle = self._bundle()
        edit(bundle["entries"])
        _rehash(bundle)
        _reanchor(bundle, self.signer)
        return bundle

    # ---- verify_bundle ----------------------------------------------------
    def test_an_anchor_that_is_not_an_object_is_an_invalid_bundle(self):
        for value, kind in (("x", "a string"), ("", "a string"), (5, "a number"),
                            (0, "a number"), (True, "a boolean"), (False, "a boolean"),
                            ([], "an array"), (["x"], "an array")):
            for signer in (None, self.signer):
                with self.subTest(anchor=value, key=signer is not None):
                    bundle = self._bundle()
                    bundle["anchor"] = value
                    report = evidence.verify_bundle(bundle, signer)
                    self.assertEqual(report["failures"],
                                     [f"invalid_bundle: anchor is {kind}, not an object"])
                    self.assertEqual(report["failure_entries"], [None])
                    self.assertFalse(report["ok"])
        bundle = self._bundle()
        bundle["anchor"] = None                 # null is an absent anchor, as before
        self.assertTrue(evidence.verify_bundle(bundle)["ok"])

    def test_envelopes_that_are_not_an_array_are_an_invalid_bundle(self):
        for value, kind in (("x", "a string"), (5, "a number"), (True, "a boolean"),
                            ({}, "an object"), ({"v": 1}, "an object")):
            with self.subTest(envelopes=value):
                bundle = self._bundle()
                bundle["envelopes"] = value
                report = evidence.verify_bundle(bundle, self.signer)
                self.assertEqual(report["failures"],
                                 [f"invalid_bundle: envelopes is {kind}, not an array"])
                self.assertEqual(report["checks"]["envelopes"], "not checked")
        bundle = self._bundle()
        bundle["envelopes"] = None              # null is no envelope, as before
        report = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["checks"]["envelopes"], "verified")

    def test_each_unreadable_member_is_reported(self):
        bundle = self._bundle()
        bundle.update(entries="x", anchor=5, envelopes={})
        report = evidence.verify_bundle(bundle, self.signer)
        self.assertEqual(report["failures"], [
            "invalid_bundle: entries is a string, not an array",
            "invalid_bundle: anchor is a number, not an object",
            "invalid_bundle: envelopes is an object, not an array"])
        self.assertEqual(report["failure_entries"], [None, None, None])

    def test_field_values_it_hashed_or_compared_report_as_typescript_does(self):
        for label, (edit, expected) in _FIELD_CASES.items():
            with self.subTest(case=label):
                report = evidence.verify_bundle(self._rechained(edit), self.signer)
                self.assertEqual(
                    [(m, d["seq"], d["node"], at) for m, d, at in
                     zip(report["failures"], report["failure_details"], report["failure_entries"])],
                    expected)

    def test_a_value_rfc_8785_cannot_write_is_a_hash_mismatch_never_a_raise(self):
        # Python's json reads NaN, Infinity and a lone surrogate, none of which RFC 8785 writes, so
        # no hash reproduces over such an entry; NonFiniteNumberError and LoneSurrogateError
        # escaped `verify_bundle`. The TypeScript parser refuses them; its verifier reads them, from
        # a caller, the same way.
        for value in (float("nan"), float("inf"), chr(0xD800)):
            with self.subTest(value=repr(value)):
                bundle = self._bundle()
                bundle["entries"][3]["error_code"] = value
                report = evidence.verify_bundle(bundle, self.signer)
                self.assertIn("integrity: hash mismatch at seq 3", report["failures"])
                self.assertIn("integrity(anchor): hash mismatch at seq 3", report["failures"])
                self.assertEqual(AuditLog.verify(bundle["entries"]), (False, "hash mismatch at seq 3"))
        bundle = self._bundle()
        bundle["anchor"]["ts"] = float("nan")
        self.assertEqual(AuditLog.verify_anchor(bundle["entries"], bundle["anchor"], self.signer),
                         (False, "anchor signature invalid"))

    # ---- delegation_graph and denials --------------------------------------
    def test_the_graph_and_denials_skip_what_they_cannot_read(self):
        for value in (None, "x", 5, True, [], ["x"]):
            with self.subTest(bundle=value):
                self.assertEqual(evidence.delegation_graph(value),
                                 {"chain_id": None, "nodes": {}, "edges": []})
                self.assertEqual(evidence.denials(value), [])
        for value in ("x", 5, True, {}, {"0": {}}):
            with self.subTest(entries=value):
                bundle = self._bundle()
                bundle["entries"] = value
                self.assertEqual(evidence.delegation_graph(bundle),
                                 {"chain_id": "vectors", "nodes": {}, "edges": []})
                self.assertEqual(evidence.denials(bundle), [])
        # An entry that is not an object names no node and folds into no row.
        bundle = self._bundle()
        bundle["entries"][5] = None                       # the one deny
        self.assertEqual(evidence.delegation_graph(bundle)["nodes"]["vectors:n1"]["denies"], 0)
        self.assertEqual(evidence.denials(bundle), [])
        bundle = self._bundle()
        bundle["entries"][1] = "x"                        # the spawn: vectors:n1 is never defined
        graph = evidence.delegation_graph(bundle)
        self.assertEqual((sorted(graph["nodes"]), graph["edges"]), (["vectors:n0"], []))
        self.assertIsNone(evidence.denials(bundle)[0]["agent"])

    def test_the_graph_and_denials_read_values_of_any_kind(self):
        bundle = self._bundle()
        bundle["entries"][5]["disposition"] = ["x"]
        self.assertEqual(
            evidence.delegation_graph(bundle)["nodes"]["vectors:n1"]["denials_by_disposition"],
            {"['x']": 1})
        self.assertEqual(evidence.denials(bundle)[0]["disposition"], ["x"])
        # Read as Python reads `disposition or reason`: an empty disposition names none.
        for empty in ("", 0, []):
            bundle = self._bundle()
            bundle["entries"][5]["disposition"] = empty
            self.assertEqual(
                evidence.delegation_graph(bundle)["nodes"]["vectors:n1"]["denials_by_disposition"],
                {"scope_not_granted": 1})
        bundle = self._bundle()
        deny = bundle["entries"][5]
        deny.update(node={"id": "n1"}, scope=["a", "b"], tool={"t": 1})
        twin = copy.deepcopy(deny)
        twin["seq"] = "z"
        bundle["entries"].insert(6, twin)
        self.assertEqual(evidence.delegation_graph(bundle)["nodes"]["vectors:n1"]["denies"], 0)
        rows = evidence.denials(bundle)
        self.assertEqual([(r["node"], r["agent"], r["scope"], r["tool"], r["count"],
                           r["first_seq"], r["last_seq"]) for r in rows],
                         [({"id": "n1"}, None, ["a", "b"], {"t": 1}, 2, 5, "z")])
        # Rows are in the order each first occurs, whatever their seqs are.
        bundle = self._bundle()
        later = copy.deepcopy(bundle["entries"][5])
        later.update(scope="crm.delete", seq="a")
        bundle["entries"].insert(6, later)
        bundle["entries"][5]["seq"] = 9
        self.assertEqual([r["scope"] for r in evidence.denials(bundle)],
                         ["crm.export", "crm.delete"])
        # A parent that is not a string names no node, so it is no edge.
        bundle = self._bundle()
        bundle["entries"][1]["parent"] = 5
        self.assertEqual(evidence.delegation_graph(bundle)["edges"], [])

    # ---- verify_envelopes ----------------------------------------------------
    def test_verify_envelopes_reports_a_bundle_it_cannot_read(self):
        self.assertEqual(evidence.verify_envelopes(None), {
            "ok": False, "status": "not checked", "count": 0, "witness_signed": [],
            "states": {}, "results": {}, "witnesses": {}, "lines": {},
            "failures": ["invalid_bundle: the bundle is null, not an object"],
            "failure_details": [{"reason": "invalid_bundle", "seq": None, "node": None,
                                 "call_id": None,
                                 "detail": "invalid_bundle: the bundle is null, not an object"}],
            "failure_entries": [None]})
        for member, value, message in (
                ("entries", 5, "invalid_bundle: entries is a number, not an array"),
                ("envelopes", "x", "invalid_bundle: envelopes is a string, not an array")):
            bundle = self._bundle()
            bundle[member] = value
            report = evidence.verify_envelopes(bundle)
            self.assertEqual((report["ok"], report["failures"]), (False, [message]))
        bundle = self._bundle()
        bundle["anchor"] = 5                    # not read here
        self.assertTrue(evidence.verify_envelopes(bundle)["ok"])
        bundle = self._bundle()
        bundle["entries"][7] = None             # an entry with no members: filed by its index
        report = evidence.verify_envelopes(bundle)
        self.assertTrue(report["ok"])
        self.assertEqual(report["states"][7], "process-asserted")

    def test_an_entry_whose_seq_is_a_boolean_keeps_its_own_state(self):
        # A dict took `true` for 1, so the entry at seq 1 and the one whose seq is true shared
        # one state, and the report listed eight states for nine entries.
        bundle = self._rechained(lambda es: es[0].update(seq=True))
        for report in (evidence.verify_envelopes(bundle),
                       evidence.verify_bundle(bundle, self.signer)["envelopes"]):
            self.assertEqual(len(report["states"]), 9)
            self.assertEqual((report["states"]["true"], report["states"][1]),
                             ("process-asserted", "process-asserted"))

    # ---- redaction_report ------------------------------------------------------
    def test_redaction_report_reports_what_it_cannot_read(self):
        for value, kind in (("x", "a string"), (None, "null"), ({}, "an object")):
            self.assertEqual(evidence.redaction_report(value), {
                "ok": False, "violations": [{"event_index": None, "event": None, "entries": kind}]})
        entries = self._bundle()["entries"]
        entries[3], entries[7] = ["x"], None
        self.assertEqual(evidence.redaction_report(entries), {"ok": False, "violations": [
            {"event_index": 3, "event": None, "entry": "an array"},
            {"event_index": 7, "event": None, "entry": "null"}]})
        for context, violations in (
                ("x", [{"event_index": 2, "event": "allow", "context": "a string"}]),
                (["rows", ["x"]], [{"event_index": 2, "event": "allow", "context": "an array"}]),
                ([], []), (None, [])):
            entries = self._bundle()["entries"]
            entries[2]["context"] = context
            self.assertEqual(evidence.redaction_report(entries, context_allowlist={"rows"}),
                             {"ok": not violations, "violations": violations})

    # ---- the signing helpers -----------------------------------------------------
    def test_the_signing_helpers_raise_their_documented_value_error(self):
        seed = bytes(range(32))
        for call, message in (
                (lambda: evidence.envelope_subject("x", 1), "entries is a string, not an array"),
                (lambda: evidence.envelope_subject(None, 1), "entries is null, not an array"),
                (lambda: evidence.envelope_subject([None, None], 1),
                 "envelope v1 defines no subject for event None"),
                (lambda: evidence.sign_envelope(5, 1, seed, kid="w", at="t", method="m"),
                 "entries is a number, not an array"),
                (lambda: evidence.envelope_signing_input(None), "an envelope is null, not an object"),
                (lambda: evidence.envelope_signing_input(["x"]),
                 "an envelope is an array, not an object")):
            with self.assertRaises(ValueError) as raised:
                call()
            self.assertEqual(str(raised.exception), message)
        entries = self._bundle()["entries"]
        entries[1]["event"] = ["spawn"]
        with self.assertRaises(ValueError) as raised:
            evidence.envelope_subject(entries, 1)
        self.assertEqual(str(raised.exception), "envelope v1 defines no subject for event ['spawn']")

    # ---- AuditLog ------------------------------------------------------------------
    def test_auditlog_reports_entries_that_are_not_an_array(self):
        anchor = self._bundle()["anchor"]
        for value, kind in ((None, "null"), ("x", "a string"), (5, "a number"),
                            ({}, "an object")):
            expected = (False, f"entries is {kind}, not an array")
            self.assertEqual(AuditLog.verify(value), expected)
            self.assertEqual(AuditLog.verify_anchor(value, anchor, self.signer), expected)
        for value in (None, "x", 5, []):
            ok, _why = AuditLog.verify_anchor(self._bundle()["entries"], value, self.signer)
            self.assertFalse(ok)

    # ---- the class, swept --------------------------------------------------------
    def test_no_public_reader_raises_on_a_value_of_any_kind_in_any_top_level_field(self):
        readers = {
            "verify_bundle": lambda b: evidence.verify_bundle(b),
            "verify_bundle(key)": lambda b: evidence.verify_bundle(b, self.signer),
            "verify_bundle(head)": lambda b: evidence.verify_bundle(b, self.signer,
                                                                    expected_head=(8, "f" * 64)),
            "delegation_graph": evidence.delegation_graph,
            "denials": evidence.denials,
            "verify_envelopes": evidence.verify_envelopes,
            "redaction_report": lambda b: evidence.redaction_report(
                b.get("entries") if isinstance(b, dict) else b, context_allowlist={"rows"}),
            "AuditLog.verify": lambda b: AuditLog.verify(b.get("entries") if isinstance(b, dict)
                                                         else b),
        }
        bundles = []
        for value in _KINDS:
            bundles.append(value)
            for member in ("entries", "anchor", "envelopes", "v", "chain_id"):
                bundle = self._bundle()
                bundle[member] = value
                bundles.append(bundle)
            for i in range(9):
                if not isinstance(value, dict):
                    bundle = self._bundle()
                    bundle["entries"][i] = value
                    bundles.append(bundle)
            for i in (0, 1, 2, 3, 5, 7):        # root, spawn, allow, outcome, deny, done
                for field in sorted(evidence.LEDGER_FIELDS):
                    bundles.append(self._rechained(
                        lambda es, i=i, field=field: es[i].__setitem__(field, copy.deepcopy(value))))
        for bundle in bundles:
            for name, read in readers.items():
                try:
                    read(bundle)
                except Exception as exc:  # noqa: BLE001 - the assertion is that nothing raises
                    self.fail(f"{name} raised {type(exc).__name__}: {exc} on {bundle!r:.200}")

    def test_no_public_reader_raises_on_a_value_of_any_kind_in_a_nested_member(self):
        # The members inside an entry or an envelope that a reader reads: the root's authority and
        # a spawn's granted (scopes, constraints, ttl, a scope, a constraint and its members), an
        # allow's context and adapter, an outcome's receipt, a kill's revoked and pending_at_kill,
        # and every member of an envelope. A ttl that was a string, an array or an object raised
        # through 0.19.1.
        def put(bundle, path, value):
            target = bundle
            for key in path[:-1]:
                if isinstance(target, dict) and not isinstance(target.get(key), (dict, list)):
                    target[key] = {"type": "t", "ref": "r", "digest": "0" * 64} if key == "receipt" else {}
                target = target[key]
            target[path[-1]] = copy.deepcopy(value)

        envelope_case = next(c for c in vectors.load_envelope_vectors()["cases"]
                             if c["name"] == "valid_spawn_envelope")
        root = Guard.issue("root", Authority({"crm.read"}, [], ttl=600), chain_id="k",
                           schema_version=2)
        child = root.delegate("c", Authority({"crm.read"}, [], ttl=60), task="t")
        root.revoke(child.node_id)
        kill = evidence.export_bundle(root.audit_log(), self.signer)
        kill_at = next(i for i, e in enumerate(kill["entries"]) if e["event"] == "kill")
        paths = []
        for at, member in ((0, "authority"), (1, "granted")):
            for tail in (["scopes"], ["constraints"], ["ttl"], ["scopes", 0], ["constraints", 0],
                         ["constraints", 0, "key"], ["constraints", 0, "max"],
                         ["constraints", 0, "zz"]):
                paths.append((self.case["bundle"], None, ["entries", at, member, *tail], True))
        for tail in (["context", "rows"], ["context", "spend"], ["context", "egress"],
                     ["adapter", "module"], ["adapter", "version"], ["adapter", "hook_path"]):
            paths.append((self.case["bundle"], None, ["entries", 2, *tail], True))
        for tail in (["receipt"], ["receipt", "type"], ["receipt", "ref"], ["receipt", "digest"]):
            paths.append((self.case["bundle"], None, ["entries", 3, *tail], True))
        for tail in (["revoked"], ["revoked", 0], ["pending_at_kill"]):
            paths.append((kill, None, ["entries", kill_at, *tail], True))
        for tail in (["v"], ["typ"], ["subject"], ["observed"], ["witness"], ["sig"],
                     ["subject", "chain_id"], ["subject", "node"], ["subject", "seq"],
                     ["subject", "entry_hash"], ["subject", "event"], ["observed", "result"],
                     ["observed", "at"], ["observed", "method"], ["witness", "kid"],
                     ["witness", "alg"]):
            paths.append((envelope_case["bundle"], envelope_case["witness_keys"],
                          ["envelopes", 0, *tail], False))
        readers = {
            "verify_bundle": lambda b, wk: evidence.verify_bundle(b),
            "verify_bundle(key)": lambda b, wk: evidence.verify_bundle(b, self.signer, witness_keys=wk),
            "delegation_graph": lambda b, wk: evidence.delegation_graph(b),
            "denials": lambda b, wk: evidence.denials(b),
            "verify_envelopes": lambda b, wk: evidence.verify_envelopes(b, witness_keys=wk),
            "redaction_report": lambda b, wk: evidence.redaction_report(b["entries"],
                                                                         context_allowlist={"rows"}),
        }
        for base, witness_keys, path, rechain in paths:
            for value in _KINDS:
                bundle = copy.deepcopy(base)
                put(bundle, path, value)
                if rechain:
                    _rehash(bundle)
                    _reanchor(bundle, self.signer)
                for name, read in readers.items():
                    try:
                        read(bundle, witness_keys)
                    except Exception as exc:  # noqa: BLE001 - the assertion is that nothing raises
                        self.fail(f"{name} raised {type(exc).__name__}: {exc} at {path} = {value!r}")


# =========================================================================
# The root's authority and a spawn's granted are read whole, member by member
# =========================================================================
#: (case, edit, failures): (failure, seq, node, failure_entries index), in report order.
#: Re-chained and re-anchored. attenu-guard-ts's test/bundle-vectors.test.ts asserts the same rows.
_N0_UNKNOWN = ("containment: allow on unknown node vectors:n0", 2, "vectors:n0", 2)
_N1_UNKNOWN = ("containment: allow on unknown node vectors:n1", 4, "vectors:n1", 4)
_AUTHORITY_CASES = (
    ("root ttl 'x'", lambda es: es[0]["authority"].update(ttl="x"),
     [("root vectors:n0: unreadable authority (ttl is a string, not a number)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("root ttl []", lambda es: es[0]["authority"].update(ttl=[]),
     [("root vectors:n0: unreadable authority (ttl is an array, not a number)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("spawn ttl true", lambda es: es[1]["granted"].update(ttl=True),
     [("spawn vectors:n1: unreadable granted (ttl is a boolean, not a number)", 1, "vectors:n1", 1),
      _N1_UNKNOWN]),
    ("spawn ttl {}", lambda es: es[1]["granted"].update(ttl={}),
     [("spawn vectors:n1: unreadable granted (ttl is an object, not a number)", 1, "vectors:n1", 1),
      _N1_UNKNOWN]),
    ("root authority null", lambda es: es[0].update(authority=None),
     [("root vectors:n0: unreadable authority (authority is null, not an object)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("root authority absent", lambda es: es[0].pop("authority"),
     [("root vectors:n0: unreadable authority (authority is null, not an object)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("spawn granted 'x'", lambda es: es[1].update(granted="x"),
     [("spawn vectors:n1: unreadable granted (granted is a string, not an object)", 1, "vectors:n1", 1),
      _N1_UNKNOWN]),
    ("root scopes 'crm.*'", lambda es: es[0]["authority"].update(scopes="crm.*"),
     [("root vectors:n0: unreadable authority (scopes is a string, not an array)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("spawn scopes null", lambda es: es[1]["granted"].update(scopes=None),
     [("spawn vectors:n1: unreadable granted (scopes is null, not an array)", 1, "vectors:n1", 1),
      _N1_UNKNOWN]),
    ("root scope 5", lambda es: es[0]["authority"]["scopes"].__setitem__(0, 5),
     [("root vectors:n0: unreadable authority (a scope is a number, not a string)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("root constraints null", lambda es: es[0]["authority"].update(constraints=None),
     [("root vectors:n0: unreadable authority (constraints is null, not an array)", 0, "vectors:n0", 0),
      _N0_UNKNOWN]),
    ("spawn constraints {}", lambda es: es[1]["granted"].update(constraints={}),
     [("spawn vectors:n1: unreadable granted (constraints is an object, not an array)", 1, "vectors:n1", 1),
      _N1_UNKNOWN]),
)


class TestAuthorityReadWhole(unittest.TestCase):
    """A root's `authority.ttl` or a spawn's `granted.ttl` that was a string, an array or an
    object raised `TypeError` out of `verify_bundle` (and `attenu-guard verify`) in every release
    from 0.4.0 through 0.19.1; a boolean was read as 1 or 0. attenu-guard-ts read it as
    unbounded, so a root `ttl: "x"` verified there. A member of either object that is not the
    type the wire format gives it is now an unreadable authority, positioned on that entry, in
    both implementations: `ttl` a number or null, `scopes` and `constraints` arrays, a scope a
    string, and the object itself an object."""

    def setUp(self):
        self.case = next(c for c in vectors.load_bundle_vectors()["cases"]
                         if c["name"] == "valid_bundle_v2")
        self.signer = _signer_for(self.case)

    def _rechained(self, edit):
        bundle = copy.deepcopy(self.case["bundle"])
        edit(bundle["entries"])
        _rehash(bundle)
        _reanchor(bundle, self.signer)
        return bundle

    def test_a_member_of_the_wrong_type_is_an_unreadable_authority(self):
        for label, edit, expected in _AUTHORITY_CASES:
            with self.subTest(case=label):
                for signer in (self.signer, None):
                    report = evidence.verify_bundle(self._rechained(edit), signer)
                    self.assertFalse(report["ok"])
                    self.assertFalse(report["checks"]["monotonicity"])
                    self.assertEqual(
                        [(m, d["seq"], d["node"], at) for m, d, at in
                         zip(report["failures"], report["failure_details"], report["failure_entries"])],
                        expected)

    def test_a_ttl_that_is_not_finite_is_an_unreadable_authority(self):
        # Python's json reads NaN and Infinity, and RFC 8785 writes neither, so the chain cannot
        # reproduce over one either; the authority is unreadable on its own account. An integer
        # past the double range is an int here and Infinity to JSON.parse: the same message.
        for value in (float("nan"), float("inf"), 10**400):
            bundle = copy.deepcopy(self.case["bundle"])
            bundle["entries"][1]["granted"]["ttl"] = value
            failures = evidence.verify_bundle(bundle, self.signer)["failures"]
            self.assertIn("spawn vectors:n1: unreadable granted (ttl is not a finite number)", failures)

    def test_a_readable_authority_still_verifies(self):
        # The controls: a null ttl is unbounded, a number of either kind is a bound, an absent
        # member is the empty default.
        for label, edit in (("root ttl null", lambda es: es[0]["authority"].update(ttl=None)),
                            ("root ttl 10**12", lambda es: es[0]["authority"].update(ttl=10**12)),
                            ("spawn ttl 1.5", lambda es: es[1]["granted"].update(ttl=1.5)),
                            ("root constraints absent", lambda es: es[0]["authority"].pop("constraints"))):
            with self.subTest(case=label):
                report = evidence.verify_bundle(self._rechained(edit), self.signer)
                self.assertTrue(report["ok"], report["failures"])

    def test_the_views_read_an_unreadable_authority_as_none(self):
        bundle = self._rechained(lambda es: es[0]["authority"].update(ttl="x"))
        self.assertEqual(evidence.delegation_graph(bundle)["nodes"]["vectors:n0"]["scopes"], [])
        self.assertEqual(len(evidence.denials(bundle)), 1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
