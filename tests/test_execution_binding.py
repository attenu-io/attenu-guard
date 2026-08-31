"""
tests/test_execution_binding.py — the 0.9.0 execution-binding layer
(docs/execution-binding spec, referenced throughout as "spec section N"):
call_id, capture/adapter, record_outcome, the pending/complete/kill lifecycle,
params_c14n_v1 commitments, and the offline verifier's `execution_binding`
report. Section 10 of the spec is the vector list this file works through.

stdlib-only (unittest), no pytest:

    python3 tests/test_execution_binding.py
"""
import copy
import math
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import Authority, Guard, RowLimit, CommittedAuditError
from attenu_guard import evidence, canonical, params as params_mod
from attenu_guard.guard import DuplicateOutcomeError
from attenu_guard.reasons import Capture, BodyState, ReasonCode, CompletionResult
from attenu_guard.wire import HS256TestSigner

_HEX64 = "ab" * 32


def _v2_root(**kwargs):
    return Guard.issue("orchestrator", Authority({"crm.read", "mail.send"}, [RowLimit(100)], ttl=3600),
                       schema_version=2, **kwargs)


def _adapter():
    return {"module": "test", "version": "0", "hook_path": "t"}


# =========================================================================
# call_id, the locked transition, CommittedAuditError.decision
# =========================================================================
class TestCallIdTransition(unittest.TestCase):
    def test_v1_chain_never_allocates_call_id_or_refuses_finalized(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))     # schema_version=1 default
        d = g.check("crm.read")
        self.assertIsNone(d.call_id)
        g.complete()
        # v1: complete() never gates check() — informational marker only, unchanged from before 0.9.0
        self.assertTrue(g.check("crm.read"))

    def test_v1_chain_rejects_execution_binding_kwargs(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))
        with self.assertRaises(ValueError):
            g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        with self.assertRaises(ValueError):
            g.check("crm.read", authorized_params={"x": 1})

    def test_allow_and_deny_both_carry_call_id_and_they_are_unique(self):
        g = _v2_root()
        allow = g.check("crm.read")
        deny = g.check("pay.transfer")
        self.assertIsNotNone(allow.call_id)
        self.assertIsNotNone(deny.call_id)
        self.assertNotEqual(allow.call_id, deny.call_id)
        self.assertRegex(allow.call_id, r"^[0-9a-f]{32}$")

    def test_node_finalized_refuses_further_check_calls_on_v2(self):
        g = _v2_root()
        g.complete()
        d = g.check("crm.read")
        self.assertFalse(d)
        self.assertEqual(d.reasons[0].code, ReasonCode.NODE_FINALIZED)
        self.assertIsNotNone(d.call_id)     # a deny still carries a call_id

    def test_call_id_unavailable_is_fail_closed_and_restores_meters(self):
        g = _v2_root()
        g.check("crm.read", context={"rows": 1})   # meter now at 1
        before = g._chain.calls_so_far(g.node_id, "*")
        with patch("os.urandom", side_effect=OSError("no entropy")):
            d = g.check("crm.read", context={"rows": 1})
        self.assertFalse(d)
        self.assertEqual(d.reasons[0].code, ReasonCode.CALL_ID_UNAVAILABLE)
        after = g._chain.calls_so_far(g.node_id, "*")
        self.assertEqual(before, after, "meters must be restored on a pre-commit failure")
        # nothing was appended for the failed attempt
        events = [e["event"] for e in g.audit_log().entries]
        self.assertEqual(events.count("allow") + events.count("deny"), 1)

    def test_committed_audit_error_carries_entry_and_decision(self):
        class _ExplodingSink:
            def write(self, payload):
                raise OSError("disk full")

        g = _v2_root()
        g.audit_log().sinks = (_ExplodingSink(),)
        with self.assertRaises(CommittedAuditError) as ctx:
            g.check("crm.read", context={"rows": 1})
        err = ctx.exception
        self.assertTrue(err.decision.allowed)
        self.assertIsNotNone(err.decision.call_id)
        self.assertEqual(err.entry.get("call_id"), err.decision.call_id)
        # spec: "the guard registers an allowed call as pending before raising"
        self.assertIn(err.decision.call_id, g._chain.pending_for(g.node_id))

    def test_record_denial_also_gets_a_call_id_on_v2(self):
        g = _v2_root()
        d = g.record_denial(ReasonCode.NO_AUTHORITY, "unmapped tool", tool="mystery")
        self.assertFalse(d)
        self.assertIsNotNone(d.call_id)

    def test_post_commit_file_write_failure_is_also_a_committed_audit_error(self):
        # A DIFFERENT persistence path than the sink test above: the audit-path file write
        # itself fails (here: the path now names a directory, so .open("a") raises).
        import tempfile
        d = tempfile.mkdtemp(prefix="attenu-post-commit-")
        audit_path = Path(d) / "ledger.jsonl"
        g = _v2_root(audit_path=audit_path)
        audit_path.unlink()
        audit_path.mkdir()                    # put a directory where the ledger file was
        with self.assertRaises(CommittedAuditError) as ctx:
            g.check("crm.read")
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        self.assertTrue(ctx.exception.decision.allowed)

    def test_retry_after_committed_audit_error_is_a_new_call_with_no_shared_statement(self):
        class _ExplodingSink:
            def __init__(self):
                self.calls = 0
            def write(self, payload):
                self.calls += 1
                if self.calls == 1:
                    raise OSError("disk full")

        g = _v2_root()
        sink = _ExplodingSink()
        g.audit_log().sinks = (sink,)
        with self.assertRaises(CommittedAuditError) as ctx:
            g.check("crm.read")
        first_call_id = ctx.exception.decision.call_id
        retry = g.check("crm.read")   # the caller retries the same logical operation
        self.assertNotEqual(first_call_id, retry.call_id)
        allows = [e for e in g.audit_log().entries if e["event"] == "allow"]
        self.assertEqual(len(allows), 2)
        # neither record states they were attempts at one logical operation
        for e in allows:
            self.assertNotIn("retry_of", e)
            self.assertNotIn("attempt", e)


class TestV1Unchanged(unittest.TestCase):
    """Codex review, item 8: a v1 chain must be byte-and-type unchanged by 0.9.0."""

    def test_complete_returns_a_plain_bool_on_v1(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))   # schema_version=1
        result = g.complete()
        self.assertIs(type(result), bool)
        self.assertIs(result, True)
        self.assertIs(g.complete(), False)

    def test_decision_to_dict_has_no_call_id_key_on_v1(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))
        d = g.check("crm.read")
        self.assertNotIn("call_id", d.to_dict())

    def test_decision_to_dict_has_call_id_key_on_v2(self):
        g = _v2_root()
        d = g.check("crm.read")
        self.assertIn("call_id", d.to_dict())
        self.assertEqual(d.to_dict()["call_id"], d.call_id)

    def test_audit_overwrite_forbidden_on_v2(self):
        import tempfile
        p = Path(tempfile.mkdtemp(prefix="attenu-ov-")) / "l.jsonl"
        with self.assertRaises(ValueError):
            Guard.issue("a", Authority({"crm.read"}, [], ttl=60), schema_version=2,
                       audit_path=p, audit_overwrite=True)

    def test_audit_overwrite_still_works_on_v1(self):
        import tempfile
        p = Path(tempfile.mkdtemp(prefix="attenu-ov-")) / "l.jsonl"
        p.write_text('{"seq": 0}\n')
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60), audit_path=p, audit_overwrite=True)
        self.assertTrue(g.check("crm.read"))


# =========================================================================
# capture / adapter on the allow entry
# =========================================================================
class TestAtomicityAndRollback(unittest.TestCase):
    """Codex review, items 1-2: complete()/revoke()/strike-policy-kill must be atomic under the
    chain lock, and EVERY pre-commit check()/record_outcome() failure must roll back — not only
    the CSPRNG-unavailable case."""

    def _assert_blocks_a_concurrent_check(self, trigger):
        """Patch Chain.pending_for so that its FIRST call (made from inside the locked operation
        under test) spawns a concurrent g.check() in another thread and records whether that
        thread finished within a short window. If the operation under test truly holds the chain
        lock for its whole duration, the concurrent check() blocks on the same lock and does NOT
        finish in time; if the lock were released early (the bug Codex reproduced), it would."""
        g = _v2_root()
        result = {}
        original = g._chain.pending_for
        hit = threading.Event()

        def patched(node_id):
            value = original(node_id)
            if not hit.is_set():
                hit.set()
                def concurrent():
                    result["decision"] = g.check("crm.read")
                    result["finished"] = True
                t = threading.Thread(target=concurrent)
                t.start()
                t.join(timeout=0.2)
                result.setdefault("finished", False)
            return value

        g._chain.pending_for = patched
        try:
            trigger(g)
        finally:
            g._chain.pending_for = original
        self.assertFalse(result.get("finished"),
                         "a concurrent check() completed WHILE the operation under test still "
                         "held the chain lock -- not atomic")
        return g

    def test_complete_is_atomic_under_the_lock(self):
        def trigger(g):
            g.complete()
        self._assert_blocks_a_concurrent_check(trigger)

    def test_revoke_is_atomic_under_the_lock(self):
        def trigger(g):
            g.revoke()
        self._assert_blocks_a_concurrent_check(trigger)

    def test_pre_commit_canonicalization_failure_restores_meters_and_propagates(self):
        g = Guard.issue("a", Authority({"crm.read"}, [RowLimit(100)], ttl=60), schema_version=2)
        before = g._chain.calls_so_far(g.node_id, "*")
        with self.assertRaises(canonical.CanonicalizationError):
            g.check("crm.read", context={"rows": 1, "note": "\ud800"})   # a lone surrogate: fails _hash() pre-commit
        after = g._chain.calls_so_far(g.node_id, "*")
        self.assertEqual(before, after, "meters must be restored on ANY pre-commit failure, not only CSPRNG")
        self.assertEqual(len(g.audit_log().entries), 1)   # just the root -- nothing was appended

    def test_record_outcome_pre_commit_failure_leaves_the_call_id_unresolved(self):
        g = _v2_root()
        d = g.check("crm.read")
        bad_receipt = {"type": "\ud800", "ref": "x", "digest": _HEX64}
        with self.assertRaises(canonical.CanonicalizationError):
            g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1, receipt=bad_receipt)
        # NOT marked outcomed, STILL pending -- the outcome was never actually committed
        self.assertFalse(g._chain.is_outcomed(d.call_id))
        self.assertIn(d.call_id, g._chain.pending_for(g.node_id))
        # a corrected retry succeeds, exactly once
        entry = g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        self.assertEqual(entry["event"], "outcome")
        with self.assertRaises(DuplicateOutcomeError):
            g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)


class TestCaptureAdapter(unittest.TestCase):
    def test_capture_requires_adapter(self):
        g = _v2_root()
        with self.assertRaises(ValueError):
            g.check("crm.read", capture=Capture.WRAPPER_SYNC)

    def test_adapter_requires_all_three_keys(self):
        g = _v2_root()
        with self.assertRaises(ValueError):
            g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter={"module": "m"})

    def test_unknown_capture_value_rejected(self):
        g = _v2_root()
        with self.assertRaises(ValueError):
            g.check("crm.read", capture="something_else", adapter=_adapter())

    def test_capture_and_adapter_land_on_the_allow_entry_only(self):
        g = _v2_root()
        g.check("crm.read", capture=Capture.FRAMEWORK_POST_HOOK, adapter=_adapter())
        g.check("pay.transfer", capture=Capture.FRAMEWORK_POST_HOOK, adapter=_adapter())
        allow = next(e for e in g.audit_log().entries if e["event"] == "allow")
        deny = next(e for e in g.audit_log().entries if e["event"] == "deny")
        self.assertEqual(allow["capture"], Capture.FRAMEWORK_POST_HOOK)
        self.assertEqual(allow["adapter"], _adapter())
        self.assertNotIn("capture", deny)
        self.assertNotIn("adapter", deny)


# =========================================================================
# pending / complete() / kill's pending_at_kill
# =========================================================================
class TestPendingAndLifecycle(unittest.TestCase):
    def test_only_allow_enters_the_pending_set(self):
        g = _v2_root()
        allow = g.check("crm.read")
        deny = g.check("pay.transfer")
        self.assertIn(allow.call_id, g._chain.pending_for(g.node_id))
        self.assertNotIn(deny.call_id, g._chain.pending_for(g.node_id))

    def test_complete_refuses_while_pending_and_reports_the_call_ids(self):
        g = _v2_root()
        d = g.check("crm.read")
        cr = g.complete()
        self.assertIsInstance(cr, CompletionResult)
        self.assertFalse(cr)
        self.assertEqual(cr.pending_call_ids, (d.call_id,))
        self.assertFalse(g.is_complete)

    def test_complete_succeeds_once_the_outcome_is_recorded(self):
        g = _v2_root()
        d = g.check("crm.read")
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=5)
        cr = g.complete()
        self.assertTrue(cr)
        self.assertEqual(cr.pending_call_ids, ())

    def test_kill_snapshots_pending_without_clearing_and_late_outcome_is_accepted(self):
        g = _v2_root()
        d = g.check("crm.read")
        revoked = g.revoke()
        kill_entry = next(e for e in g.audit_log().entries if e["event"] == "kill")
        self.assertEqual(kill_entry["pending_at_kill"], [d.call_id])
        # not cleared: still pending after the kill
        self.assertIn(d.call_id, g._chain.pending_for(g.node_id))
        # a late true record is accepted
        entry = g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=3)
        self.assertEqual(entry["event"], "outcome")
        self.assertNotIn(d.call_id, g._chain.pending_for(g.node_id))

    def test_kill_with_nothing_pending_still_writes_an_empty_list(self):
        g = _v2_root()
        g.revoke()
        kill_entry = next(e for e in g.audit_log().entries if e["event"] == "kill")
        self.assertEqual(kill_entry["pending_at_kill"], [])

    def test_v1_kill_never_carries_pending_at_kill(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))
        g.revoke()
        kill_entry = next(e for e in g.audit_log().entries if e["event"] == "kill")
        self.assertNotIn("pending_at_kill", kill_entry)


# =========================================================================
# record_outcome(): body_state vocabulary, conditional fields, duplicates
# =========================================================================
class TestRecordOutcome(unittest.TestCase):
    def test_v1_chain_refuses_record_outcome(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))
        with self.assertRaises(ValueError):
            g.record_outcome("x" * 32, BodyState.RETURNED, duration_ms=1)

    def test_every_body_state_and_its_conditional_error_code(self):
        for state in (BodyState.RETURNED, BodyState.ABANDONED, BodyState.DEFERRED):
            with self.subTest(state=state):
                g = _v2_root()
                d = g.check("crm.read")
                entry = g.record_outcome(d.call_id, state, duration_ms=1)
                self.assertEqual(entry["body_state"], state)
                self.assertNotIn("error_code", entry)

        g = _v2_root()
        d = g.check("crm.read")
        entry = g.record_outcome(d.call_id, BodyState.RAISED, error_code="ValueError", duration_ms=1)
        self.assertEqual(entry["error_code"], "ValueError")

    def test_error_code_required_exactly_when_raised(self):
        g = _v2_root()
        d = g.check("crm.read")
        with self.assertRaises(ValueError):
            g.record_outcome(d.call_id, BodyState.RAISED, duration_ms=1)   # missing error_code
        d2 = g.check("crm.read")
        with self.assertRaises(ValueError):
            g.record_outcome(d2.call_id, BodyState.RETURNED, error_code="X", duration_ms=1)  # illegal here

    def test_unknown_body_state_rejected(self):
        g = _v2_root()
        d = g.check("crm.read")
        with self.assertRaises(ValueError):
            g.record_outcome(d.call_id, "executed", duration_ms=1)

    def test_duration_ms_must_be_a_non_negative_int(self):
        g = _v2_root()
        for bad in (-1, 1.5, True, "1"):
            with self.subTest(bad=bad):
                d = g.check("crm.read")
                with self.assertRaises(ValueError):
                    g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=bad)

    def test_exactly_one_outcome_per_call_id(self):
        g = _v2_root()
        d = g.check("crm.read")
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        with self.assertRaises(DuplicateOutcomeError):
            g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)

    def test_concurrent_duplicate_outcome_append_exactly_one_wins(self):
        g = _v2_root()
        d = g.check("crm.read")
        results = []

        def attempt():
            try:
                g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
                results.append("ok")
            except DuplicateOutcomeError:
                results.append("dup")

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("dup"), 7)
        outcomes = [e for e in g.audit_log().entries if e["event"] == "outcome"]
        self.assertEqual(len(outcomes), 1)

    def test_malformed_receipt_rejected(self):
        g = _v2_root()
        d = g.check("crm.read")
        with self.assertRaises(ValueError):
            g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1, receipt={"type": "x"})

    def test_receipt_carried_verbatim_and_unverified(self):
        g = _v2_root()
        d = g.check("crm.read")
        receipt = {"type": "otel", "ref": "span-1", "digest": "ab" * 32}
        entry = g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1, receipt=receipt)
        self.assertEqual(entry["receipt"], receipt)


# =========================================================================
# params_c14n_v1 (docs/execution-binding spec section 4)
# =========================================================================
class TestParamsCommitment(unittest.TestCase):
    def test_safe_integer_boundary_and_one_past_it(self):
        salt = bytes(16)
        h, reason = params_mod.commit({"n": canonical.MAX_SAFE_INTEGER}, salt)
        self.assertIsNotNone(h); self.assertIsNone(reason)
        h2, reason2 = params_mod.commit({"n": canonical.MAX_SAFE_INTEGER + 1}, salt)
        self.assertIsNone(h2); self.assertEqual(reason2, params_mod.ParamsHashReason.UNSUPPORTED)

    def test_integral_float_beyond_the_bound_is_unsupported_even_though_canonical_dumps_tolerates_it(self):
        salt = bytes(16)
        # canonical.dumps itself still accepts this (a pinned JCS-divergence-class test relies on
        # it — see tests/test_canonical.py); params_c14n_v1 closes the gap itself, in front.
        self.assertEqual(canonical.dumps(1e16), b"10000000000000000")
        h, reason = params_mod.commit({"n": 1e16}, salt)
        self.assertIsNone(h)
        self.assertEqual(reason, params_mod.ParamsHashReason.UNSUPPORTED)

    def test_ordinary_fractional_float_within_range_is_fine(self):
        # Every binary64 double beyond roughly 2**52 in magnitude IS mathematically integral —
        # there is no such thing as "a large non-integral float" to test here; that is exactly
        # why the check is "integral AND out of range", not "out of range" alone.
        salt = bytes(16)
        h, reason = params_mod.commit({"n": 3.14159}, salt)
        self.assertIsNotNone(h); self.assertIsNone(reason)

    def test_negative_zero_hashes_identically_to_positive_zero(self):
        salt = bytes(16)
        h_pos, _ = params_mod.commit({"n": 0.0}, salt)
        h_neg, _ = params_mod.commit({"n": -0.0}, salt)
        self.assertEqual(h_pos, h_neg)

    def test_non_finite_numbers_are_unsupported(self):
        salt = bytes(16)
        for bad in (math.nan, math.inf, -math.inf):
            with self.subTest(bad=bad):
                h, reason = params_mod.commit({"n": bad}, salt)
                self.assertIsNone(h)
                self.assertEqual(reason, params_mod.ParamsHashReason.UNSUPPORTED)

    def test_lone_surrogates_are_unsupported(self):
        salt = bytes(16)
        h, reason = params_mod.commit({"s": "\ud800"}, salt)
        self.assertIsNone(h)
        self.assertEqual(reason, params_mod.ParamsHashReason.UNSUPPORTED)

    def test_unsupported_python_object_is_unsupported(self):
        salt = bytes(16)
        h, reason = params_mod.commit({"s": object()}, salt)
        self.assertIsNone(h)
        self.assertEqual(reason, params_mod.ParamsHashReason.UNSUPPORTED)

    def test_raw_salt_vs_hex_salt_hashing(self):
        raw = bytes.fromhex("11" * 16)
        h1, _ = params_mod.commit({"x": 1}, raw)
        h2, _ = params_mod.commit({"x": 1}, params_mod.decode_salt("11" * 16))
        self.assertEqual(h1, h2)

    def test_decode_salt_rejects_the_wrong_length(self):
        with self.assertRaises(ValueError):
            params_mod.decode_salt("ab")

    def test_authorized_and_invoked_hashes_are_independent_and_absence_is_distinguishable(self):
        g = _v2_root()
        # deployment opt-out: no hash, no reason field at all
        d = g.check("crm.read")
        allow = next(e for e in g.audit_log().entries if e["event"] == "allow" and e["call_id"] == d.call_id)
        self.assertNotIn("authorized_params_hash", allow)
        self.assertNotIn("params_hash_reason", allow)

        # attempted but unsupported: hash absent, reason present
        d2 = g.check("crm.read", authorized_params={"n": 1e16})
        allow2 = next(e for e in g.audit_log().entries if e["event"] == "allow" and e["call_id"] == d2.call_id)
        self.assertNotIn("authorized_params_hash", allow2)
        self.assertEqual(allow2["params_hash_reason"], "unsupported")

        # matching commitments on both sides
        d3 = g.check("crm.read", authorized_params={"x": 1})
        g.record_outcome(d3.call_id, BodyState.RETURNED, invoked_params={"x": 1}, duration_ms=1)
        allow3 = next(e for e in g.audit_log().entries if e["event"] == "allow" and e["call_id"] == d3.call_id)
        outcome3 = next(e for e in g.audit_log().entries if e["event"] == "outcome" and e["call_id"] == d3.call_id)
        self.assertEqual(allow3["authorized_params_hash"], outcome3["invoked_params_hash"])

        # a substitution IS visible because both hashes exist
        d4 = g.check("crm.read", authorized_params={"x": 1})
        g.record_outcome(d4.call_id, BodyState.RETURNED, invoked_params={"x": 2}, duration_ms=1)
        allow4 = next(e for e in g.audit_log().entries if e["event"] == "allow" and e["call_id"] == d4.call_id)
        outcome4 = next(e for e in g.audit_log().entries if e["event"] == "outcome" and e["call_id"] == d4.call_id)
        self.assertNotEqual(allow4["authorized_params_hash"], outcome4["invoked_params_hash"])

    def test_invoked_params_unsupported_is_independent_of_the_authorized_side(self):
        g = _v2_root()
        d = g.check("crm.read", authorized_params={"x": 1})   # authorized side: supported
        entry = g.record_outcome(d.call_id, BodyState.RETURNED, invoked_params={"n": 1e16}, duration_ms=1)
        self.assertNotIn("invoked_params_hash", entry)
        self.assertEqual(entry["params_hash_reason"], "unsupported")
        allow = next(e for e in g.audit_log().entries if e["event"] == "allow" and e["call_id"] == d.call_id)
        self.assertIn("authorized_params_hash", allow)   # the allow side is unaffected

    def test_params_salt_is_fixed_for_the_chain_and_written_once_on_root(self):
        g = _v2_root()
        root = g.audit_log().entries[0]
        self.assertRegex(root["params_salt"], r"^[0-9a-f]{32}$")
        child = g.delegate("summarizer", Authority({"crm.read"}, [], ttl=60), task="t")
        self.assertIs(g._chain, child._chain)
        self.assertEqual(g._chain.params_salt, child._chain.params_salt)


# =========================================================================
# The offline verifier's execution_binding report (spec section 5)
# =========================================================================
def _bundle_for(guard, signer):
    return evidence.export_bundle(guard.audit_log(), signer)


class TestVerifierExecutionBinding(unittest.TestCase):
    def setUp(self):
        self.signer = HS256TestSigner(b"k", kid="k")

    def test_v1_bundle_reports_not_applicable(self):
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=60))
        g.check("crm.read")
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        self.assertEqual(rep["execution_binding"], {"status": "not applicable"})

    def test_clean_aggregate_when_every_promised_call_is_observed(self):
        g = _v2_root()
        d = g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        g.complete()
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(eb["aggregate"], "clean")
        self.assertEqual(eb["per_call"][d.call_id], "observed")
        self.assertEqual(eb["per_node_lifecycle"][g.node_id], "finalized")

    def test_abandoned_call_is_observed_and_leaves_the_aggregate_clean(self):
        g = _v2_root()
        d = g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        g.record_outcome(d.call_id, BodyState.ABANDONED, duration_ms=1)
        g.complete()
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(eb["per_call"][d.call_id], "observed")
        self.assertEqual(eb["aggregate"], "clean")

    def test_pre_hook_only_is_unobserved_and_makes_the_aggregate_incomplete(self):
        g = _v2_root()
        g.check("crm.read", capture=Capture.PRE_HOOK_ONLY, adapter=_adapter())
        g.complete()
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(list(eb["per_call"].values()), ["unobserved"])
        self.assertEqual(eb["aggregate"], "incomplete")

    def test_in_progress_node_is_a_snapshot_not_a_verdict_but_still_incomplete(self):
        g = _v2_root()
        g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        # never record_outcome, never complete()
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(eb["per_node_lifecycle"][g.node_id], "in_progress")
        self.assertEqual(eb["aggregate"], "incomplete")

    def test_unaccounted_call_in_a_finalized_node_is_failed(self):
        g = _v2_root()
        d = g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        # complete() would refuse while pending — reach a finalized node with an
        # unaccounted call only by forging a 'done' entry directly on the ledger.
        entries = copy.deepcopy(g.audit_log().entries)
        entries.append({"v": 2, "c14n": "JCS", "seq": len(entries), "ts": 99,
                        "event": "done", "chain_id": g.chain_id, "node": g.node_id, "agent": "orchestrator",
                        "prev_hash": entries[-1]["hash"]})
        entries[-1]["hash"] = evidence._rehash(entries[-1]["prev_hash"], {k: v for k, v in entries[-1].items() if k != "hash"})
        anchor = evidence._anchor_for(entries, self.signer)
        bundle = {"v": 2, "c14n": "JCS", "chain_id": g.chain_id, "entries": entries, "anchor": anchor}
        rep = evidence.verify_bundle(bundle, self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(eb["per_node_lifecycle"][g.node_id], "finalized")
        self.assertEqual(eb["aggregate"], "failed")

    def test_revoked_with_pending_is_incomplete(self):
        g = _v2_root()
        g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        g.revoke()
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(eb["per_node_lifecycle"][g.node_id], "revoked_with_pending")
        self.assertEqual(eb["aggregate"], "incomplete")

    def test_cleanly_revoked_node_with_nothing_pending_does_not_force_incomplete(self):
        g = _v2_root()
        d = g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        g.revoke()
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        eb = rep["execution_binding"]
        self.assertEqual(eb["per_node_lifecycle"][g.node_id], "revoked")
        self.assertEqual(eb["aggregate"], "clean")

    def test_outcome_without_allow(self):
        g = _v2_root()
        g.check("crm.read")
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        entries.append({"v": 2, "c14n": "JCS", "seq": len(entries), "ts": 99, "event": "outcome",
                        "chain_id": g.chain_id, "node": g.node_id, "call_id": "ab" * 16,
                        "body_state": "returned", "duration_ms": 1, "prev_hash": entries[-1]["hash"]})
        entries[-1]["hash"] = evidence._rehash(entries[-1]["prev_hash"], {k: v for k, v in entries[-1].items() if k != "hash"})
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("outcome_without_allow:") for f in rep["execution_binding"]["failures"]))
        self.assertEqual(rep["execution_binding"]["aggregate"], "failed")

    def test_duplicate_outcome_in_the_ledger(self):
        g = _v2_root()
        d = g.check("crm.read")
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        dup = copy.deepcopy(entries[-1])
        dup["seq"] = len(entries)
        dup["prev_hash"] = entries[-1]["hash"]
        dup["hash"] = evidence._rehash(dup["prev_hash"], {k: v for k, v in dup.items() if k != "hash"})
        entries.append(dup)
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("duplicate_outcome:") for f in rep["execution_binding"]["failures"]))

    def test_duplicate_call_id_across_allow_and_deny(self):
        g = _v2_root()
        allow_d = g.check("crm.read")
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        forged_deny = {"v": 2, "c14n": "JCS", "seq": len(entries), "ts": 99, "event": "deny",
                       "chain_id": g.chain_id, "node": g.node_id, "scope": "pay.transfer", "tool": None,
                       "context": {}, "reason": ReasonCode.SCOPE_NOT_GRANTED, "reasons": [],
                       "disposition": "out_of_authority", "call_id": allow_d.call_id,
                       "prev_hash": entries[-1]["hash"]}
        forged_deny["hash"] = evidence._rehash(forged_deny["prev_hash"], {k: v for k, v in forged_deny.items() if k != "hash"})
        entries.append(forged_deny)
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("duplicate_call_id:") for f in rep["execution_binding"]["failures"]))

    def test_outcome_before_allow(self):
        g = _v2_root()
        d = g.check("crm.read")
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        allow_idx = next(i for i, e in enumerate(entries) if e["event"] == "allow")
        outcome_idx = next(i for i, e in enumerate(entries) if e["event"] == "outcome")
        entries[outcome_idx]["seq"], entries[allow_idx]["seq"] = entries[allow_idx]["seq"], entries[outcome_idx]["seq"]
        # re-chain from scratch so integrity itself still passes and only the binding check is isolated
        entries.sort(key=lambda e: e["seq"])
        prev = evidence._GENESIS
        for e in entries:
            e["prev_hash"] = prev
            e["hash"] = evidence._rehash(prev, {k: v for k, v in e.items() if k != "hash"})
            prev = e["hash"]
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("outcome_before_allow:") for f in rep["execution_binding"]["failures"]))

    def test_cross_ref_outcome_on_a_different_node(self):
        g = _v2_root()
        d = g.check("crm.read")
        child = g.delegate("summarizer", Authority({"crm.read"}, [], ttl=60), task="t")
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        entries.append({"v": 2, "c14n": "JCS", "seq": len(entries), "ts": 99, "event": "outcome",
                        "chain_id": g.chain_id, "node": child.node_id, "call_id": d.call_id,
                        "body_state": "returned", "duration_ms": 1, "prev_hash": entries[-1]["hash"]})
        entries[-1]["hash"] = evidence._rehash(entries[-1]["prev_hash"], {k: v for k, v in entries[-1].items() if k != "hash"})
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("cross_ref:") for f in rep["execution_binding"]["failures"]))

    def test_params_mismatch(self):
        g = _v2_root()
        d = g.check("crm.read", authorized_params={"x": 1})
        g.record_outcome(d.call_id, BodyState.RETURNED, invoked_params={"x": 2}, duration_ms=1)
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        self.assertTrue(any(f.startswith("params_mismatch:") for f in rep["execution_binding"]["failures"]))
        self.assertEqual(rep["execution_binding"]["aggregate"], "failed")

    def test_params_coverage_axis_independent_of_aggregate(self):
        g = _v2_root()
        d = g.check("crm.read")   # no authorized_params at all -> deployment opted out
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        g.complete()               # finalize the node so the aggregate CAN be clean
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        self.assertEqual(rep["execution_binding"]["aggregate"], "clean")
        self.assertEqual(rep["execution_binding"]["params_coverage"], "none")

    def test_mixed_entry_versions_rejected(self):
        g = _v2_root()
        g.check("crm.read")
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        entries[1] = {**entries[1], "v": 1}
        # deliberately not re-hashed: tampering the version alone is enough to isolate this check;
        # integrity will also fail, which is fine — we assert the specific failure is present.
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("mixed_entry_versions:") for f in rep["failures"]))
        self.assertEqual(rep["execution_binding"], {"status": "not applicable"})

    def test_root_version_mismatch(self):
        g = _v2_root()
        bundle = _bundle_for(g, self.signer)
        bundle["v"] = 1     # bundle claims v1 while the root entry says v2
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("root_version_mismatch:") for f in rep["failures"]))

    def test_invalid_allow_malformed_call_id(self):
        g = _v2_root()
        g.check("crm.read")
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        idx = next(i for i, e in enumerate(entries) if e["event"] == "allow")
        entries[idx]["call_id"] = "not-hex"
        prev = entries[idx - 1]["hash"]
        for e in entries[idx:]:
            e["prev_hash"] = prev
            e["hash"] = evidence._rehash(prev, {k: v for k, v in e.items() if k != "hash"})
            prev = e["hash"]
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("invalid_allow:") for f in rep["execution_binding"]["failures"]))

    def test_invalid_outcome_missing_error_code_on_raised(self):
        g = _v2_root()
        d = g.check("crm.read")
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        bundle = _bundle_for(g, self.signer)
        entries = bundle["entries"]
        idx = next(i for i, e in enumerate(entries) if e["event"] == "outcome")
        entries[idx]["body_state"] = "raised"
        prev = entries[idx - 1]["hash"]
        for e in entries[idx:]:
            e["prev_hash"] = prev
            e["hash"] = evidence._rehash(prev, {k: v for k, v in e.items() if k != "hash"})
            prev = e["hash"]
        bundle["anchor"] = evidence._anchor_for(entries, self.signer)
        rep = evidence.verify_bundle(bundle, self.signer)
        self.assertTrue(any(f.startswith("invalid_outcome:") for f in rep["execution_binding"]["failures"]))

    def test_verification_never_consults_current_authority_state(self):
        # a revocation that happens LATER does not retroactively invalidate an earlier allow's record
        g = _v2_root()
        d = g.check("crm.read", capture=Capture.WRAPPER_SYNC, adapter=_adapter())
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        g.revoke()   # after the fact
        rep = evidence.verify_bundle(_bundle_for(g, self.signer), self.signer)
        self.assertEqual(rep["execution_binding"]["per_call"][d.call_id], "observed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
