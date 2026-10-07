"""Findings of the independent security review of the -02 implementation (spec/02-impl,
2026-10-07), each as a test that failed before its fix. Numbering follows the review.

stdlib-only: python3 tests/test_draft02_review_fixes.py
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import Authority, AuthorityError, CallLimit, Guard, RowLimit, wire  # noqa: E402
from attenu_guard import draft02 as d  # noqa: E402
from attenu_guard.wire import WireError, WireReasonCode  # noqa: E402

SECRET = b"review-fixes-fixed-secret"
PRINCIPAL = "acct:finance-ops@example.com"
AUD = "https://crm.example.com"


def A02(scopes, ceilings=(), ttl=600):
    return Authority(scopes, ceilings, ttl, profile="02")


def _signer():
    return wire.HS256TestSigner(SECRET, kid="test")


def _cnf(node):
    return {"jkt": f"thumb-{node.agent_id}"}


def _payload(token):
    return json.loads(wire.b64url_decode(token.split(".")[1]))


def _resign(token, mutate):
    header_b64 = token.split(".")[0]
    payload = _payload(token)
    mutate(payload)
    payload_b64 = wire._encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{wire.b64url_encode(_signer().sign(signing_input))}"


def _repair(tokens):
    tokens = list(tokens)
    for i in range(1, len(tokens)):
        h, pl, _ = tokens[i - 1].split(".")
        expected = wire.b64url_encode(hashlib.sha256(f"{h}.{pl}".encode("ascii")).digest())
        if _payload(tokens[i]).get("par_hash") != expected:
            tokens[i] = _resign(tokens[i], lambda p, e=expected: p.__setitem__("par_hash", e))
    return tokens


def _chain02():
    root = Guard.issue("orchestrator", A02({"crm.*"}, [RowLimit(100), CallLimit(10)], ttl=3600), max_depth=4)
    child = root.delegate("summarizer", A02({"crm.read"}, [RowLimit(10), CallLimit(5)], ttl=900), task="t")
    leaf = child.delegate("formatter", A02({"crm.read"}, [RowLimit(5), CallLimit(2)], ttl=300), task="t")
    return root, child, leaf


def _mint02(leaf, **kw):
    args = dict(principal=PRINCIPAL, aud=AUD, draft="02", cnf=_cnf)
    args.update(kw)
    return wire.serialize_chain(leaf, _signer(), **args)


def _reject(tc, tokens, reason, **kw):
    kw.setdefault("draft", "02")
    with tc.assertRaises(WireError) as cm:
        wire.load(tokens, _signer(), **kw)
    tc.assertEqual(cm.exception.reason, reason, cm.exception.message)
    return cm.exception


class Finding1_SubtreeBoundNeverFedFromANodeMeter(unittest.TestCase):
    """BLOCKER: `_auto_meter` filled a per-subtree total from the node's own call count, so
    three nodes each holding max_subtree max_calls<=2 made six calls under a bound of two."""

    def test_six_calls_under_a_subtree_bound_of_two_are_all_denied_when_no_total_is_held(self):
        root = Guard.issue("root", A02({"a.b"}, [d.MaxSubtree("max_calls", 2)]))
        k1 = root.delegate("k1", A02({"a.b"}, [d.MaxSubtree("max_calls", 2)]), "t")
        k2 = root.delegate("k2", A02({"a.b"}, [d.MaxSubtree("max_calls", 2)]), "t")
        allowed = [bool(g.check("a.b")) for g in (root, k1, k2) for _ in range(2)]
        self.assertEqual(allowed.count(True), 0, "a subtree total the guard does not hold must deny")

    def test_a_subtree_total_supplied_through_the_trusted_channel_is_enforced(self):
        root = Guard.issue("root", A02({"a.b"}, [d.MaxSubtree("max_calls", 2)]))
        self.assertTrue(root.check("a.b", totals={"calls_subtree_total": 2}))
        self.assertFalse(root.check("a.b", totals={"calls_subtree_total": 3}))

    def test_the_lifetime_call_bound_is_still_metered_by_the_guard(self):
        root = Guard.issue("root", A02({"a.b"}, [CallLimit(2)]))
        self.assertEqual([bool(root.check("a.b")) for _ in range(3)], [True, True, False])
        generic = Authority.from_wire(root.authority.to_wire(), profile="02")
        g2 = Guard.issue("root2", generic)
        self.assertEqual([bool(g2.check("a.b")) for _ in range(3)], [True, True, False])


class Finding2_AudienceIsNotOptInAtStep8(unittest.TestCase):
    def test_permits_denies_when_no_audience_was_ever_supplied(self):
        v = wire.load(_mint02(_chain02()[2]), _signer(), draft="02")
        denied = v.permits("crm.read", {"rows": 1, "calls": 1})
        self.assertFalse(denied)
        self.assertEqual(denied.reasons[0].code, WireReasonCode.AUDIENCE_MISMATCH)
        self.assertTrue(v.permits("crm.read", {"rows": 1, "calls": 1}, audience=AUD))

    def test_an_audience_confirmed_at_load_carries_into_permits(self):
        v = wire.load(_mint02(_chain02()[2]), _signer(), draft="02", audience=AUD)
        self.assertTrue(v.permits("crm.read", {"rows": 1, "calls": 1}))
        self.assertFalse(v.permits("crm.read", {"rows": 1, "calls": 1}, audience="https://evil.example"))

    def test_the_default_profile_is_unchanged(self):
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60), max_depth=2)
        v = wire.load(wire.serialize_chain(root, _signer()), _signer())
        self.assertTrue(v.permits("crm.read"))


class Finding3_RunningTotalsCannotComeFromTheCallerContext(unittest.TestCase):
    """The #110 `_scope` class: the context an adapter fills from tool arguments decided the
    running total, so `spend_total: 0` beside `spend: 1e6` passed a lifetime bound of 100."""

    def test_a_total_in_the_caller_context_is_ignored_and_the_bound_denies(self):
        g = Guard.issue("r2", A02({"pay.send"}, [d.MaxLifetime("max_spend", 100)]))
        self.assertFalse(g.check("pay.send", context={"spend": 1_000_000, "spend_total": 0}))
        self.assertFalse(g.check("pay.send", context={"spend": 1, "spend_total": 0}))

    def test_totals_come_only_from_the_trusted_parameter(self):
        g = Guard.issue("r2", A02({"pay.send"}, [d.MaxLifetime("max_spend", 100)]))
        self.assertTrue(g.check("pay.send", context={"spend": 1}, totals={"spend_total": 99}))
        self.assertFalse(g.check("pay.send", context={"spend": 1}, totals={"spend_total": 101}))
        # The caller's copy of the key never shadows the trusted one.
        self.assertFalse(g.check("pay.send", context={"spend": 1, "spend_total": 0}, totals={"spend_total": 101}))

    def test_the_same_on_a_verified_chain(self):
        root = Guard.issue("o", A02({"pay.send"}, [d.MaxLifetime("max_spend", 100)]), max_depth=2)
        v = wire.load(_mint02(root), _signer(), draft="02", audience=AUD)
        self.assertFalse(v.permits("pay.send", {"spend": 1, "spend_total": 0}))
        self.assertTrue(v.permits("pay.send", {"spend": 1}, totals={"spend_total": 50}))

    def test_authority_permits_strips_totals_from_the_context_under_02(self):
        a = A02({"a.b"}, [d.MaxSubtree("max_spend", 10)])
        self.assertFalse(a.permits("a.b", {"spend_subtree_total": 1}))
        self.assertTrue(a.permits("a.b", {}, totals={"spend_subtree_total": 10}))


class Finding4_NewlineScopes(unittest.TestCase):
    def test_a_trailing_newline_is_not_a_literal_scope(self):
        for s in ("crm.read\n", "crm.*\n", "User.Read\n", "crm.read\r"):
            self.assertIsNone(d.classify_scope(s), repr(s))

    def test_a_chain_carrying_a_newline_scope_is_malformed(self):
        tokens = _mint02(_chain02()[2])
        tokens[2] = _resign(tokens[2], lambda p: p["authorization_details"][0].__setitem__("scopes", ["crm.read\n"]))
        _reject(self, tokens, WireReasonCode.MALFORMED)


class Finding5_TheDefaultPathIsBehaviourIdenticalToMain(unittest.TestCase):
    def test_a_01_chain_with_client_id_and_per_hop_sub_verifies_under_01(self):
        root = Guard.issue("orchestrator", Authority({"crm.*"}, [], ttl=600), max_depth=3)
        child = root.delegate("summarizer", Authority({"crm.read"}, [], ttl=300), task="t")
        tokens = wire.serialize_chain(child, _signer())
        tokens[0] = _resign(tokens[0], lambda p: p.__setitem__("client_id", "orchestrator"))
        tokens[1] = _resign(tokens[1], lambda p: p.__setitem__("client_id", "summarizer"))
        tokens = _repair(tokens)
        self.assertNotEqual(_payload(tokens[0])["sub"], _payload(tokens[1])["sub"], "precondition: per-hop sub")
        self.assertIsNotNone(wire.load(tokens, _signer()))

    def test_the_02_profile_still_denies_an_altered_principal(self):
        tokens = _mint02(_chain02()[2])
        tokens[1] = _resign(tokens[1], lambda p: p.__setitem__("sub", "acct:mallory"))
        _reject(self, _repair(tokens), WireReasonCode.PRINCIPAL_ALTERED)


class Finding6_OutcomeNamesFollowTable2(unittest.TestCase):
    def test_altered_sub_with_a_broken_par_hash_is_par_hash_mismatch(self):
        tokens = _mint02(_chain02()[2])
        tokens[2] = _resign(tokens[2], lambda p: (p.__setitem__("sub", "acct:mallory"),
                                                  p.__setitem__("par_hash", "AAAA")))
        _reject(self, tokens, WireReasonCode.PAR_HASH_MISMATCH)

    def test_a_child_exp_past_its_parents_with_the_same_iat_is_expired(self):
        tokens = _mint02(_chain02()[2])
        parent_exp = _payload(tokens[1])["exp"]
        tokens[2] = _resign(tokens[2], lambda p: p.__setitem__("exp", parent_exp + 10))
        _reject(self, tokens, WireReasonCode.EXPIRED)

    def test_a_child_raising_del_max_depth_is_not_narrower(self):
        tokens = _mint02(_chain02()[2])
        root_max = _payload(tokens[0])["del_max_depth"]
        tokens[2] = _resign(tokens[2], lambda p: p.__setitem__("del_max_depth", root_max + 50))
        _reject(self, tokens, WireReasonCode.NOT_NARROWER)
        tokens = _mint02(_chain02()[2])
        tokens[2] = _resign(tokens[2], lambda p: p.__setitem__("del_max_depth", root_max))
        self.assertIsNotNone(wire.load(tokens, _signer(), draft="02"), "an equal bound is fine")


class Finding7_CnfNeedsAConfirmationMember(unittest.TestCase):
    def test_an_object_without_a_confirmation_member_is_malformed(self):
        tokens = _mint02(_chain02()[2])
        tokens[2] = _resign(tokens[2], lambda p: p.__setitem__("cnf", {"note": "x"}))
        self.assertIn("cnf", _reject(self, tokens, WireReasonCode.MALFORMED).message)
        with self.assertRaises(WireError):
            _mint02(_chain02()[2], cnf={"note": "x"})

    def test_jkt_and_jwk_are_accepted(self):
        for cnf in ({"jkt": "t"}, {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "AA"}}):
            self.assertIsNotNone(wire.load(_mint02(_chain02()[2], cnf=cnf), _signer(), draft="02"))


class Finding8_AcceptedAlgsIsAListOfStrings(unittest.TestCase):
    def test_a_bare_string_is_refused_as_configuration(self):
        tokens = _mint02(_chain02()[2])
        with self.assertRaises(TypeError):
            wire.load(tokens, _signer(), draft="02", accepted_algs="HS256")
        with self.assertRaises(TypeError):
            wire.load(tokens, _signer(), draft="02", accepted_algs=["HS256", 5])


class Finding9_MixedProfilesAreARefusedDelegation(unittest.TestCase):
    def test_meet_raises_authority_error_not_narrower(self):
        with self.assertRaises(AuthorityError) as cm:
            A02({"a.b"}).meet(Authority({"a.b"}, [], 600))
        self.assertEqual(cm.exception.reason, "not_narrower")

    def test_guard_delegate_records_spawn_denied(self):
        root = Guard.issue("root", A02({"a.b"}))
        with self.assertRaises(AuthorityError):
            root.delegate("kid", Authority({"a.b"}, [], 600), "t")
        self.assertIn("spawn_denied", [e["event"] for e in root.audit_log()])


if __name__ == "__main__":
    unittest.main(verbosity=2)
