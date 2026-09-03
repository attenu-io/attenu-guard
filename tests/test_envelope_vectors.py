"""tests/test_envelope_vectors.py — the observer-envelope interop vectors
(tests/vectors/envelopes/envelope_vectors_v1.json, written by
tests/vectors/generate_envelopes.py) and the envelope contract they are scored against.

Three things are pinned here:

  1. Every committed case scores exactly as it declares, through BOTH the repository copy and
     the copy that ships inside the installed package — the verdict, every declared
     {reason, seq, node} at its position, AND the per-entry state for every entry in the chain.
  2. The two scoring rules that bind where an extra failure may land: an envelope failure lands
     only on the hop that envelope covers, never on a hop coverage skipped; and no chain-level
     integrity failure is ever raised because an envelope failed.
  3. The properties that make individual rows non-vacuous — the reordered envelope really is in
     a non-canonical source order, the non-canonical row's bytes really do differ from JCS of
     what they parse to, and the unanchored row really has no anchor.

stdlib-only (unittest), no pytest:

    python3 tests/test_envelope_vectors.py
"""
import copy
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests" / "vectors"))

from attenu_guard import canonical, evidence, vectors  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

import generate_envelopes  # tests/vectors/generate_envelopes.py  # noqa: E402

_REPO_FILE = _ROOT / "tests" / "vectors" / "envelopes" / "envelope_vectors_v1.json"
_PACKAGE_FILE = _ROOT / "src" / "attenu_guard" / "vectors" / "envelopes" / "envelope_vectors_v1.json"

# The file AS COMMITTED, snapshotted at import — before any test regenerates it, so a copy
# edited by hand fails here rather than being quietly rewritten (the discipline the token and
# bundle vector suites already follow).
COMMITTED_REPO_BYTES = _REPO_FILE.read_bytes()
COMMITTED_PACKAGE_BYTES = _PACKAGE_FILE.read_bytes()

CASE_NAMES = [
    # v0 of the envelope design (A2A #1575), as amended by v0.1 — the fifteen rows as posted.
    "valid_spawn_envelope",
    "valid_allow_envelope",
    "valid_jcs_reorder",
    "absent_envelope",
    "indeterminate_result",
    "reject_rehashed_chain_sparse",
    "reject_subject_mismatch",
    "reject_bad_signature",
    "reject_unknown_version",
    "reject_non_canonical",
    "reject_member_without_bump",
    "reject_masked_bundle_mutation",
    "reject_rehashed_chain_anchored",
    "reject_rehashed_chain_unanchored",
    "reject_unknown_witness",
    # Appended at @safal207's proposal. Cases are appended, never inserted: nothing above moves.
    "reject_locator_mismatch",
    # Appended at revision v1.1, with the duplicate-subject rule it pins.
    "reject_duplicate_subject",
]

# The failures a chain mutation, the envelope's own contents, or the array they sit in can
# produce, and the row that is required to produce each. Every one of the seven named failures
# has a row.
REQUIRED_BY_ROW = {
    "reject_rehashed_chain_sparse": "envelope_subject_mismatch",
    "reject_subject_mismatch": "envelope_subject_mismatch",
    "reject_bad_signature": "envelope_bad_signature",
    "reject_unknown_version": "envelope_unknown_version",
    "reject_non_canonical": "envelope_non_canonical",
    "reject_member_without_bump": "envelope_unknown_member",
    "reject_masked_bundle_mutation": "envelope_subject_mismatch",
    "reject_rehashed_chain_anchored": "envelope_subject_mismatch",
    "reject_rehashed_chain_unanchored": "envelope_subject_mismatch",
    "reject_unknown_witness": "envelope_unknown_witness",
    "reject_locator_mismatch": "envelope_subject_mismatch",
    "reject_duplicate_subject": "envelope_duplicate_subject",
}


def _signer_for(case):
    if case["signer"] is None:
        return None
    return HS256TestSigner(bytes.fromhex(case["signer"]["secret_hex"]), kid=case["signer"]["kid"])


def _envelope_bytes_for(case):
    raw = case.get("raw_hex")
    return [bytes.fromhex(raw)] if raw is not None else None


def _verify(case):
    return evidence.verify_bundle(case["bundle"], _signer_for(case),
                                  witness_keys=case["witness_keys"],
                                  envelope_bytes=_envelope_bytes_for(case))


def _positions(report):
    return [{"reason": d["reason"], "seq": d["seq"], "node": d["node"]}
            for d in report["failure_details"]]


def _states(report):
    return {str(seq): state for seq, state in report["envelopes"]["states"].items()}


class TestEnvelopeVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Regenerate both copies from this source tree, so the vectors are self-checking against
        # this exact build rather than a fixture that can go stale.
        cls.document = generate_envelopes.generate_all()
        cls.by_name = {c["name"]: c for c in cls.document["cases"]}

    def test_the_document_declares_its_version_and_every_expected_case(self):
        # `version` is the compatibility contract and does not move when cases are appended;
        # `revision` is the additive counter that does.
        self.assertEqual(self.document["version"], "envelope_vectors_v1")
        self.assertEqual(self.document["revision"], "envelope_vectors_v1.1")
        self.assertEqual([c["name"] for c in self.document["cases"]], CASE_NAMES)

    def test_every_case_carries_the_two_envelope_specific_fields(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                # The trust set, which is what makes reject_bad_signature and
                # reject_unknown_witness checkable from the file alone.
                self.assertEqual([k["kid"] for k in case["witness_keys"]],
                                 list(generate_envelopes.TRUSTED_KIDS))
                for key in case["witness_keys"]:
                    self.assertEqual(key["alg"], "EdDSA")
                    self.assertEqual(len(bytes.fromhex(key["public_key_hex"])), 32)
                # The per-entry state, covering EVERY entry, not only the covered ones.
                self.assertEqual(sorted(case["expect_states"], key=int),
                                 [str(e["seq"]) for e in case["bundle"]["entries"]])
                self.assertTrue(set(case["expect_states"].values())
                                <= {"witness-signed", "process-asserted"})
                self.assertTrue(case["description"].strip())

    def test_the_untrusted_witness_key_appears_in_no_case(self):
        # reject_unknown_witness is only a real case while its key stays out of every trust set.
        unlisted = generate_envelopes.WITNESS_KID_UNLISTED
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                self.assertNotIn(unlisted, [k["kid"] for k in case["witness_keys"]])
        named = self.by_name["reject_unknown_witness"]["bundle"]["envelopes"][0]["witness"]["kid"]
        self.assertEqual(named, unlisted)

    def test_expect_failures_carries_only_reason_seq_and_node(self):
        # The corpus scoring contract: implementations compare these dicts for EQUALITY, so a
        # new key here silently fails every conformant verifier.
        for case in self.document["cases"]:
            for failure in case["expect_failures"]:
                with self.subTest(case=case["name"]):
                    self.assertEqual(set(failure), {"reason", "seq", "node"})

    def test_accepting_cases_verify_with_no_failures_and_report_their_states(self):
        for case in self.document["cases"]:
            if case["expect"] != "accept":
                continue
            with self.subTest(case=case["name"]):
                report = _verify(case)
                self.assertTrue(report["ok"], report["failures"])
                self.assertEqual(report["failures"], [])
                self.assertEqual(case["expect_failures"], [])
                self.assertEqual(_states(report), case["expect_states"])

    def test_every_rejecting_case_reports_each_declared_failure_at_its_declared_position(self):
        for case in self.document["cases"]:
            if case["expect"] != "reject":
                continue
            with self.subTest(case=case["name"]):
                report = _verify(case)
                self.assertFalse(report["ok"])
                self.assertTrue(case["expect_failures"],
                                "a rejecting case must declare at least one required failure")
                reported = _positions(report)
                for expected in case["expect_failures"]:
                    self.assertIn(expected, reported)
                self.assertEqual(_states(report), case["expect_states"])

    def test_the_declared_minimal_set_is_minimal(self):
        # Every declared failure must be one the verifier genuinely reports for THAT bundle.
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                reasons = {d["reason"] for d in _verify(case)["failure_details"]}
                for expected in case["expect_failures"]:
                    self.assertIn(expected["reason"], reasons)

    def test_each_named_envelope_failure_has_a_row_that_requires_it(self):
        required = set()
        for name, reason in REQUIRED_BY_ROW.items():
            with self.subTest(case=name):
                declared = [f["reason"] for f in self.by_name[name]["expect_failures"]]
                self.assertIn(reason, declared)
                required.add(reason)
        self.assertEqual(required, set(evidence.ENVELOPE_FAILURES))

    # ---- the two scoring rules from envelope v0.1, section 5 ------------
    def test_an_envelope_failure_lands_only_on_a_hop_that_envelope_covers(self):
        for case in self.document["cases"]:
            covered = {e["subject"]["seq"] for e in case["bundle"].get("envelopes", [])
                       if isinstance(e.get("subject"), dict) and "seq" in e["subject"]}
            with self.subTest(case=case["name"]):
                for detail in _verify(case)["failure_details"]:
                    if detail["reason"].startswith("envelope_"):
                        self.assertIn(detail["seq"], covered,
                                      f"{case['name']}: {detail['reason']} landed at seq "
                                      f"{detail['seq']}, which no envelope covers")

    def test_the_sparse_row_reports_at_the_covered_hop_and_never_at_the_skipped_one(self):
        # The rule made concrete: the mutated entry carries no envelope, so nothing may be
        # reported there even though it is where the edit happened.
        case = self.by_name["reject_rehashed_chain_sparse"]
        covered = [e["subject"]["seq"] for e in case["bundle"]["envelopes"]]
        self.assertEqual(covered, [generate_envelopes.ALLOW_SEQ])
        envelope_failures = [(d["reason"], d["seq"]) for d in _verify(case)["failure_details"]
                             if d["reason"].startswith("envelope_")]
        self.assertEqual(envelope_failures,
                         [("envelope_subject_mismatch", generate_envelopes.ALLOW_SEQ)])

    def test_no_chain_level_integrity_failure_is_raised_because_an_envelope_failed(self):
        # The rows whose anchor is fresh (masked mutation) or absent (unanchored) must produce
        # NO integrity failure at all — that one comes from a real anchor mismatch and nothing
        # else. The two rows that do declare it carry the ORIGINAL anchor over a rewritten chain.
        for name in ("reject_masked_bundle_mutation", "reject_rehashed_chain_unanchored"):
            with self.subTest(case=name):
                report = _verify(self.by_name[name])
                self.assertEqual([d["reason"] for d in report["failure_details"]],
                                 ["envelope_subject_mismatch"])
                self.assertTrue(report["checks"]["integrity"])
                self.assertTrue(report["checks"]["monotonicity"])
                self.assertTrue(report["checks"]["containment"])
                self.assertEqual(report["execution_binding"]["failures"], [])
        for name in ("reject_rehashed_chain_sparse", "reject_rehashed_chain_anchored"):
            with self.subTest(case=name):
                self.assertEqual(_verify(self.by_name[name])["checks"]["anchor"], "FAILED")

    # ---- the rows that would be vacuous if built carelessly -------------
    def test_the_reorder_row_is_in_a_non_canonical_source_order_at_every_level(self):
        # If this envelope were written with its members sorted, the row would be a duplicate of
        # valid_spawn_envelope and would test nothing. The file is read as committed BYTES here,
        # because the order only exists in the byte stream.
        case = json.loads(COMMITTED_REPO_BYTES)["cases"][CASE_NAMES.index("valid_jcs_reorder")]
        envelope = case["bundle"]["envelopes"][0]
        for label, obj in (("envelope", envelope), ("subject", envelope["subject"]),
                           ("observed", envelope["observed"]), ("witness", envelope["witness"])):
            with self.subTest(object=label):
                self.assertNotEqual(list(obj), sorted(obj))
        # Every OTHER object in the file is sorted, so this is the one deliberate exception.
        others = json.loads(COMMITTED_REPO_BYTES)["cases"][0]["bundle"]["envelopes"][0]
        self.assertEqual(list(others), sorted(others))

    def test_the_reorder_row_is_the_same_envelope_as_the_spawn_row(self):
        reordered = self.by_name["valid_jcs_reorder"]["bundle"]["envelopes"][0]
        original = self.by_name["valid_spawn_envelope"]["bundle"]["envelopes"][0]
        self.assertEqual(reordered["sig"], original["sig"])
        self.assertEqual(canonical.dumps(reordered), canonical.dumps(original))

    def test_the_reorder_row_declares_the_exact_jcs_preimage_the_signature_covers(self):
        # Scored on both halves: it accepts, AND the bytes the verifier canonicalized equal
        # `canonical_hex`. Those are the bytes themselves, not a digest over them.
        case = self.by_name["valid_jcs_reorder"]
        envelope = case["bundle"]["envelopes"][0]
        self.assertEqual(evidence.envelope_signing_input(envelope).hex(), case["canonical_hex"])
        self.assertEqual(bytes.fromhex(case["canonical_hex"]),
                         canonical.dumps({k: v for k, v in envelope.items() if k != "sig"}))
        self.assertTrue(_verify(case)["ok"])

    def test_the_non_canonical_row_supplies_bytes_that_differ_from_jcs_of_what_they_parse_to(self):
        case = self.by_name["reject_non_canonical"]
        raw = bytes.fromhex(case["raw_hex"])
        envelope = case["bundle"]["envelopes"][0]
        self.assertEqual(json.loads(raw), envelope)          # they parse to the same object
        self.assertNotEqual(raw, canonical.dumps(envelope))  # and are not its canonical form
        # Without the received bytes the failure cannot be raised at all: the parse discarded
        # the only trace of it. This is exactly why the row carries them.
        blind = evidence.verify_bundle(case["bundle"], _signer_for(case),
                                       witness_keys=case["witness_keys"])
        self.assertNotIn("envelope_non_canonical",
                         [d["reason"] for d in blind["failure_details"]])

    def test_the_absent_row_carries_no_envelopes_member_at_all(self):
        case = self.by_name["absent_envelope"]
        self.assertNotIn("envelopes", case["bundle"])
        report = _verify(case)
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["envelopes"], "not present")
        self.assertEqual(set(report["envelopes"]["states"].values()), {"process-asserted"})
        self.assertEqual(set(report["envelopes"]["lines"].values()), {"process-asserted"})

    def test_the_unanchored_row_is_the_only_one_with_no_signer_and_no_anchor(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                unanchored = case["name"] == "reject_rehashed_chain_unanchored"
                self.assertEqual(case["signer"] is None, unanchored)
                self.assertEqual("anchor" not in case["bundle"], unanchored)

    def test_the_report_line_prints_the_state_and_the_result_together(self):
        for name, expected in (("valid_spawn_envelope", "witness-signed (matched)"),
                               ("indeterminate_result", "witness-signed (indeterminate)")):
            with self.subTest(case=name):
                lines = _verify(self.by_name[name])["envelopes"]["lines"]
                self.assertEqual(lines[generate_envelopes.SPAWN_SEQ], expected)
                # A process-asserted entry gets no result.
                self.assertEqual(lines[0], "process-asserted")

    def test_every_ledger_is_the_shared_chain_apart_from_the_declared_ts_mutation(self):
        # The one-change rule, at the ledger level: every case runs on `valid_bundle_v2`'s own
        # nine entries, and the four chain-mutation rows differ from it in one member of one
        # entry. `hash`/`prev_hash` are excluded — every mutation legitimately rewrites them.
        mutated = {"reject_rehashed_chain_sparse", "reject_masked_bundle_mutation",
                   "reject_rehashed_chain_anchored", "reject_rehashed_chain_unanchored"}
        base = self.by_name["valid_spawn_envelope"]["bundle"]["entries"]
        skip = ("hash", "prev_hash")
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                entries = case["bundle"]["entries"]
                self.assertEqual(len(entries), len(base))
                differing = [i for i, (a, b) in enumerate(zip(base, entries))
                             if {k: v for k, v in a.items() if k not in skip}
                             != {k: v for k, v in b.items() if k not in skip}]
                if case["name"] in mutated:
                    self.assertEqual(differing, [generate_envelopes.SPAWN_SEQ])
                    self.assertEqual(entries[generate_envelopes.SPAWN_SEQ]["ts"],
                                     generate_envelopes.MUTATED_TS)
                else:
                    self.assertEqual(differing, [])

    # ---- both copies, and the packaged path -----------------------------
    def test_the_two_committed_copies_are_byte_identical(self):
        self.assertEqual(COMMITTED_PACKAGE_BYTES, COMMITTED_REPO_BYTES)

    def test_regeneration_is_byte_deterministic(self):
        # Nothing in the generator reads a clock or the CSPRNG, and Ed25519 signing is itself
        # deterministic, so a second run must reproduce the committed bytes exactly.
        generate_envelopes.generate_all()
        self.assertEqual(_REPO_FILE.read_bytes(), COMMITTED_REPO_BYTES)
        self.assertEqual(_PACKAGE_FILE.read_bytes(), COMMITTED_PACKAGE_BYTES)

    def test_the_packaged_copy_is_readable_through_importlib_resources(self):
        # The path an INSTALLED consumer takes — a file missing from the wheel fails here.
        self.assertEqual(vectors.read_envelope_vectors_bytes(), COMMITTED_REPO_BYTES)
        loaded = vectors.load_envelope_vectors()
        self.assertEqual(loaded["version"], "envelope_vectors_v1")
        self.assertEqual(loaded["revision"], "envelope_vectors_v1.1")
        self.assertEqual([c["name"] for c in loaded["cases"]], CASE_NAMES)

    def test_every_packaged_case_scores_as_it_declares(self):
        # Read ONLY through the package accessor, then verify: exactly what a third-party
        # implementer does, minus their own verifier.
        for case in vectors.load_envelope_vectors()["cases"]:
            with self.subTest(case=case["name"]):
                report = _verify(case)
                self.assertEqual("accept" if report["ok"] else "reject", case["expect"])
                self.assertEqual(_states(report), case["expect_states"])
                for expected in case["expect_failures"]:
                    self.assertIn(expected, _positions(report))

    def test_the_generators_self_check_agrees_with_this_suite(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["name"]):
                ok, detail = generate_envelopes.check_case(case)
                self.assertTrue(ok, detail)


# =========================================================================
# The envelope surface itself, at the sites no committed case reaches
# =========================================================================
class TestEnvelopeSurface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = copy.deepcopy(generate_envelopes.gen_cases()[0])   # valid_spawn_envelope
        cls.entries = cls.case["bundle"]["entries"]
        cls.seed = generate_envelopes.SEEDS[generate_envelopes.WITNESS_KID]

    def _envelope(self, **kwargs):
        return evidence.sign_envelope(self.entries, generate_envelopes.SPAWN_SEQ, self.seed,
                                      kid=generate_envelopes.WITNESS_KID,
                                      at=generate_envelopes.OBSERVED_AT,
                                      method=generate_envelopes.OBSERVED_METHOD, **kwargs)

    def _report(self, envelopes, **kwargs):
        bundle = copy.deepcopy(self.case["bundle"])
        bundle["envelopes"] = envelopes
        kwargs.setdefault("witness_keys", self.case["witness_keys"])
        return evidence.verify_envelopes(bundle, **kwargs)

    def test_the_third_result_reports_its_own_line(self):
        # `not_matched` appears in no committed case; the report line has to carry it anyway.
        report = self._report([self._envelope(result="not_matched")])
        self.assertTrue(report["ok"])
        self.assertEqual(report["lines"][generate_envelopes.SPAWN_SEQ],
                         "witness-signed (not_matched)")

    def test_a_result_outside_the_vocabulary_cannot_be_signed(self):
        with self.assertRaises(ValueError):
            self._envelope(result="probably")

    def test_an_allow_subject_carries_call_id_and_a_spawn_subject_does_not(self):
        allow = evidence.envelope_subject(self.entries, generate_envelopes.ALLOW_SEQ)
        spawn = evidence.envelope_subject(self.entries, generate_envelopes.SPAWN_SEQ)
        self.assertEqual(set(allow), evidence.ENVELOPE_SUBJECT_MEMBERS["allow"])
        self.assertEqual(set(spawn), evidence.ENVELOPE_SUBJECT_MEMBERS["spawn"])
        self.assertEqual(allow["call_id"], self.entries[generate_envelopes.ALLOW_SEQ]["call_id"])

    def test_v1_defines_no_subject_for_any_other_event(self):
        # seq 3 is an `outcome`; seq 0 is the `root`. Neither has a v1 subject.
        for seq in (0, 3):
            with self.subTest(seq=seq):
                with self.assertRaises(ValueError):
                    evidence.envelope_subject(self.entries, seq)

    def test_an_envelope_naming_an_event_v1_has_no_subject_for_is_a_subject_mismatch(self):
        envelope = self._envelope()
        envelope["subject"]["event"] = "outcome"
        report = self._report([_resign(envelope)])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_subject_mismatch"])

    def test_a_subject_missing_a_required_member_is_a_subject_mismatch(self):
        # The other direction from reject_member_without_bump: ADDED is unknown_member, MISSING
        # is subject_mismatch. No committed row exercises this one.
        envelope = self._envelope()
        del envelope["subject"]["chain_id"]
        report = self._report([_resign(envelope)])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_subject_mismatch"])
        self.assertEqual(report["failure_details"][0]["seq"], generate_envelopes.SPAWN_SEQ)

    def test_a_member_added_outside_the_subject_is_also_unknown_member(self):
        for where in ("envelope", "observed", "witness"):
            with self.subTest(where=where):
                envelope = self._envelope()
                target = envelope if where == "envelope" else envelope[where]
                target["note"] = "extra"
                report = self._report([_resign(envelope)])
                self.assertEqual([d["reason"] for d in report["failure_details"]],
                                 ["envelope_unknown_member"])

    def test_a_different_typ_is_an_unknown_version(self):
        envelope = self._envelope()
        envelope["typ"] = "delegation-event-observation-v2"
        report = self._report([_resign(envelope)])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_unknown_version"])

    def test_a_subject_naming_a_seq_this_bundle_has_no_entry_for(self):
        envelope = self._envelope()
        envelope["subject"]["seq"] = 99
        report = self._report([_resign(envelope)])
        detail = report["failure_details"][0]
        self.assertEqual(detail["reason"], "envelope_subject_mismatch")
        self.assertEqual((detail["seq"], detail["node"]), (99, None))

    def test_no_trust_set_is_an_empty_one_rather_than_a_skipped_check(self):
        report = self._report([self._envelope()], witness_keys=None)
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_unknown_witness"])

    def test_a_trust_set_may_be_given_as_a_plain_kid_to_key_mapping(self):
        _sign, _verify_sig, public = evidence._ed25519_backend()
        keys = {generate_envelopes.WITNESS_KID: public(self.seed)}
        self.assertTrue(self._report([self._envelope()], witness_keys=keys)["ok"])

    def test_a_bundle_with_no_envelopes_reports_every_entry_process_asserted(self):
        report = self._report([])
        self.assertTrue(report["ok"])
        self.assertEqual(set(report["states"].values()), {"process-asserted"})
        self.assertEqual(report["witness_signed"], [])

    def test_export_bundle_omits_the_envelopes_member_when_there_are_none(self):
        from attenu_guard import Authority, Guard, RowLimit
        from attenu_guard.wire import HS256TestSigner as _S
        signer = _S(b"k", kid="k")
        guard = Guard.issue("a", Authority({"crm.read"}, [RowLimit(1)], ttl=60), chain_id="t")
        guard.check("crm.read")
        self.assertNotIn("envelopes", evidence.export_bundle(guard.audit_log(), signer))
        with_envelope = evidence.export_bundle(guard.audit_log(), signer, envelopes=[{"x": 1}])
        self.assertEqual(with_envelope["envelopes"], [{"x": 1}])

    # ---- one entry, at most one envelope (v1.1) -------------------------
    def test_a_second_envelope_over_a_covered_entry_is_a_duplicate_subject(self):
        # The committed row scores the two-valid-envelopes case; this pins the surface it
        # reports through, including that the first witness's result survives in `results`.
        report = self._report([self._envelope(),
                               self._envelope(result="not_matched")])
        self.assertFalse(report["ok"])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_duplicate_subject"])
        detail = report["failure_details"][0]
        self.assertEqual((detail["seq"], detail["node"]),
                         (generate_envelopes.SPAWN_SEQ,
                          self.entries[generate_envelopes.SPAWN_SEQ]["node"]))
        self.assertEqual(report["states"][generate_envelopes.SPAWN_SEQ], "process-asserted")
        self.assertEqual(report["witness_signed"], [])
        self.assertEqual(report["lines"][generate_envelopes.SPAWN_SEQ], "process-asserted")
        self.assertEqual(report["results"][generate_envelopes.SPAWN_SEQ], "matched")

    def test_the_duplicate_rule_makes_the_score_independent_of_array_order(self):
        # The defect this rule closes: with the states keyed by seq and overwritten per
        # envelope, the SAME two envelopes in the other order reported the other result and no
        # failure at all. Both orders now reject, at the same position.
        first, second = self._envelope(), self._envelope(result="not_matched")
        forward = self._report([first, second])
        backward = self._report([second, first])
        for report in (forward, backward):
            self.assertFalse(report["ok"])
            self.assertEqual([d["reason"] for d in report["failure_details"]],
                             ["envelope_duplicate_subject"])
            self.assertEqual(report["states"][generate_envelopes.SPAWN_SEQ], "process-asserted")

    def test_an_entry_claimed_by_a_broken_envelope_is_claimed(self):
        # "Valid or not": the FIRST envelope names seq 1 and fails on its own subject, so a
        # later honest one over the same entry is still the second observation of it. Both are
        # reported, and the entry is not witness-signed.
        broken = copy.deepcopy(self._envelope())
        broken["subject"]["entry_hash"] = "0" * 64
        report = self._report([_resign(broken), self._envelope()])
        self.assertFalse(report["ok"])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_subject_mismatch", "envelope_duplicate_subject"])
        self.assertEqual(report["states"][generate_envelopes.SPAWN_SEQ], "process-asserted")

    def test_envelopes_over_different_entries_are_not_duplicates(self):
        # The rule is per ENTRY. Two envelopes covering two hops is the ordinary sparse case.
        allow = evidence.sign_envelope(self.entries, generate_envelopes.ALLOW_SEQ, self.seed,
                                       kid=generate_envelopes.WITNESS_KID,
                                       at=generate_envelopes.OBSERVED_AT,
                                       method=generate_envelopes.OBSERVED_METHOD)
        report = self._report([self._envelope(), allow])
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["witness_signed"],
                         sorted([generate_envelopes.SPAWN_SEQ, generate_envelopes.ALLOW_SEQ]))

    def test_a_duplicate_naming_a_seq_this_bundle_has_no_entry_for_is_not_a_duplicate(self):
        # An entry is claimed only once `subject.seq` FINDS one: two envelopes naming a seq that
        # is not in the bundle are two subject mismatches, not a duplicate of each other.
        stray = copy.deepcopy(self._envelope())
        stray["subject"]["seq"] = 99
        report = self._report([_resign(stray), _resign(copy.deepcopy(stray))])
        self.assertEqual([d["reason"] for d in report["failure_details"]],
                         ["envelope_subject_mismatch", "envelope_subject_mismatch"])

    def test_export_bundle_refuses_to_redact_and_carry_envelopes_in_one_call(self):
        # Redaction rewrites every entry hash, so envelopes signed over the unredacted ledger
        # would ship bound to entries that no longer exist and fail envelope_subject_mismatch.
        from attenu_guard import Authority, Guard, RowLimit
        from attenu_guard.wire import HS256TestSigner as _S
        signer = _S(b"k", kid="k")
        guard = Guard.issue("a", Authority({"crm.read"}, [RowLimit(1)], ttl=60), chain_id="t")
        guard.delegate("b", Authority({"crm.read"}, [RowLimit(1)], ttl=30), task="secret prompt")
        redacted = evidence.export_bundle(guard.audit_log(), signer, redact_task=True)
        envelope = evidence.sign_envelope(redacted["entries"], 1, self.seed,
                                          kid=generate_envelopes.WITNESS_KID,
                                          at=generate_envelopes.OBSERVED_AT,
                                          method=generate_envelopes.OBSERVED_METHOD)
        with self.assertRaises(ValueError) as raised:
            evidence.export_bundle(guard.audit_log(), signer, redact_task=True,
                                   envelopes=[envelope])
        self.assertIn("sign envelopes over the redacted ledger", str(raised.exception))
        # The documented order works: export redacted, sign over ITS entries, export again.
        bundle = evidence.export_bundle(guard.audit_log(), signer, redact_task=True)
        bundle["envelopes"] = [envelope]
        keys = {generate_envelopes.WITNESS_KID: evidence._ed25519_backend()[2](self.seed)}
        report = evidence.verify_envelopes(bundle, witness_keys=keys)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["witness_signed"], [1])


def _resign(envelope):
    return generate_envelopes._resign(envelope)


if __name__ == "__main__":
    unittest.main(verbosity=2)
