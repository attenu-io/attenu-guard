"""The -02 profile of the wire format and the offline verification algorithm
(draft-asor-wimse-agent-delegation-chain-02, Sections 3, 4.4, 6 and 6.2), opted into with
`draft="02"` on `wire.serialize`, `wire.serialize_chain` and `wire.load`.

Every test here is paired with an assertion that the DEFAULT path ("01") is unchanged: the
twenty published vectors, every adapter and every pre-existing test keep verifying as before.

stdlib-only: python3 tests/test_wire_02.py
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import Allow, Authority, CallLimit, EgressRank, Guard, RowLimit, SpendCap, wire  # noqa: E402
from attenu_guard import draft02 as d  # noqa: E402
from attenu_guard import vectors  # noqa: E402
from attenu_guard.wire import WireError, WireReasonCode  # noqa: E402

SECRET = b"test-wire-02-fixed-secret"
PRINCIPAL = "acct:finance-ops@example.com"
AUD = "https://crm.example.com"
ORDER = ["none", "internal", "any"]


def _signer(alg_kid="test"):
    return wire.HS256TestSigner(SECRET, kid=alg_kid)


def _cnf(node):
    return {"jkt": f"thumb-{node.agent_id}"}


def _chain(profile="02"):
    root = Guard.issue("orchestrator",
                       Authority({"crm.*", "mail.send", "User.Read"},
                                 [RowLimit(1000), EgressRank("any"), CallLimit(10), SpendCap(100)],
                                 ttl=3600, profile=profile),
                       max_depth=4)
    child = root.delegate("summarizer",
                          Authority({"crm.read", "User.Read"},
                                    [RowLimit(100), EgressRank("internal"), CallLimit(5), SpendCap(60)],
                                    ttl=900, profile=profile), task="summarize")
    leaf = child.delegate("formatter",
                          Authority({"crm.read"}, [RowLimit(10), EgressRank("none"), CallLimit(2), SpendCap(10)],
                                    ttl=300, profile=profile), task="format")
    return root, child, leaf


def _mint(leaf=None, **kw):
    leaf = leaf or _chain()[2]
    args = dict(principal=PRINCIPAL, aud=AUD, draft="02", cnf=_cnf)
    args.update(kw)
    return wire.serialize_chain(leaf, _signer(), **args)


def _payload(token):
    return json.loads(wire.b64url_decode(token.split(".")[1]))


def _resign(token, mutate, signer=None):
    """Mutate a token's payload and re-sign it (valid signature, canonical bytes), so a
    test fails on the rule under test and never incidentally on JCS or the signature."""
    signer = signer or _signer()
    header_b64 = token.split(".")[0]
    payload = _payload(token)
    mutate(payload)
    payload_b64 = wire._encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{wire.b64url_encode(signer.sign(signing_input))}"


def _reject(testcase, tokens, reason, **kw):
    kw.setdefault("draft", "02")
    with testcase.assertRaises(WireError) as cm:
        wire.load(tokens, _signer(), **kw)
    testcase.assertEqual(cm.exception.reason, reason, cm.exception.message)
    return cm.exception


class MintingUnderTheNewProfile(unittest.TestCase):
    def test_a_minted_chain_carries_the_02_claim_layout(self):
        tokens = _mint()
        payloads = [_payload(t) for t in tokens]
        self.assertEqual([p["sub"] for p in payloads], [PRINCIPAL] * 3)
        self.assertEqual([p["client_id"] for p in payloads], ["orchestrator", "summarizer", "formatter"])
        self.assertEqual([p["aud"] for p in payloads], [AUD] * 3)
        self.assertEqual([p["cnf"] for p in payloads],
                         [{"jkt": "thumb-orchestrator"}, {"jkt": "thumb-summarizer"}, {"jkt": "thumb-formatter"}])
        constraints = payloads[0]["authorization_details"][0]["constraints"]
        self.assertIn({"key": "egress", "rank": "any", "order": ORDER}, constraints)
        self.assertIn({"key": "max_calls", "max_lifetime": 10}, constraints)
        self.assertIn({"key": "max_rows", "max": 1000}, constraints)
        self.assertEqual(payloads[0]["authorization_details"][0]["scopes"], ["User.Read", "crm.*", "mail.send"])

    def test_minting_refuses_what_the_02_verifier_would_reject(self):
        leaf = _chain()[2]
        for kw, needle in ((dict(principal=None), "principal"), (dict(principal=""), "principal"),
                           (dict(aud=None), "aud"), (dict(aud=[]), "aud"), (dict(aud=[5]), "aud"),
                           (dict(cnf=None), "cnf"), (dict(cnf={}), "cnf")):
            with self.assertRaises(WireError, msg=kw) as cm:
                _mint(leaf, **kw)
            self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)
            self.assertIn(needle, cm.exception.message)

    def test_a_default_profile_authority_is_re_expressed_under_02(self):
        root = Guard.issue("o", Authority({"crm.*"}, [CallLimit(3), EgressRank("internal")], ttl=60), max_depth=2)
        tokens = _mint(root)
        self.assertEqual(_payload(tokens[0])["authorization_details"][0]["constraints"],
                         [{"key": "egress", "order": ORDER, "rank": "internal"},
                          {"key": "max_calls", "max_lifetime": 3}])
        self.assertIsInstance(wire.load(tokens, _signer(), draft="02").leaf_authority.ceilings[0], d.Rank)

    def test_the_default_profile_mints_exactly_as_before(self):
        root = Guard.issue("o", Authority({"crm.*"}, [CallLimit(3), EgressRank("internal")], ttl=60), max_depth=2)
        payload = _payload(wire.serialize(root, _signer()))
        self.assertEqual(payload["sub"], "o")
        self.assertNotIn("client_id", payload)
        self.assertNotIn("cnf", payload)
        self.assertIsNone(payload["aud"])
        self.assertEqual(payload["authorization_details"][0]["constraints"],
                         [{"key": "egress", "rank": "internal"}, {"key": "max_calls", "max": 3}])


class ClaimRulesAtParse(unittest.TestCase):
    """Section 3: every claim rule is `malformed`, checked before step 1, on every token."""

    def test_a_conformant_chain_verifies(self):
        v = wire.load(_mint(), _signer(), draft="02", audience=AUD)
        self.assertEqual(v.draft, "02")
        self.assertEqual(sorted(v.leaf_authority.scopes), ["crm.read"])

    def test_missing_client_id(self):
        tokens = _mint()
        tokens[1] = _resign(tokens[1], lambda p: p.pop("client_id"))
        # The child's signing input changed, so repair the grandchild's commitment: the rule
        # under test must be the only thing wrong.
        tokens = _repair(tokens)
        self.assertIn("client_id", _reject(self, tokens, WireReasonCode.MALFORMED).message)

    def test_aud_null_missing_or_empty(self):
        for mutate in (lambda p: p.__setitem__("aud", None), lambda p: p.pop("aud"),
                       lambda p: p.__setitem__("aud", []), lambda p: p.__setitem__("aud", [1])):
            tokens = _mint()
            tokens[2] = _resign(tokens[2], mutate)
            self.assertIn("aud", _reject(self, tokens, WireReasonCode.MALFORMED).message)

    def test_an_audience_array_is_accepted_and_checked(self):
        tokens = _mint(aud=["https://a.example", AUD])
        self.assertIsNotNone(wire.load(tokens, _signer(), draft="02", audience=AUD))
        self.assertIsNotNone(wire.load(tokens, _signer(), draft="02"))      # no audience given: not checked
        _reject(self, tokens, WireReasonCode.AUDIENCE_MISMATCH, audience="https://other.example")

    def test_audience_mismatch_at_load_and_in_permits(self):
        tokens = _mint()
        _reject(self, tokens, WireReasonCode.AUDIENCE_MISMATCH, audience="https://other.example")
        v = wire.load(tokens, _signer(), draft="02")
        denied = v.permits("crm.read", {"rows": 1, "spend": 1}, totals={"calls": 1}, audience="https://other.example")
        self.assertFalse(denied)
        self.assertEqual(denied.reasons[0].code, WireReasonCode.AUDIENCE_MISMATCH)
        self.assertTrue(v.permits("crm.read", {"rows": 1, "spend": 1}, totals={"calls": 1}, audience=AUD))

    def test_missing_cnf_on_any_token(self):
        for i in range(3):
            tokens = _mint()
            tokens[i] = _resign(tokens[i], lambda p: p.pop("cnf"))
            tokens = _repair(tokens)
            self.assertIn("cnf", _reject(self, tokens, WireReasonCode.MALFORMED).message)

    def test_principal_altered_and_empty_root_principal(self):
        tokens = _mint()
        forged = list(tokens)
        forged[1] = _resign(tokens[1], lambda p: p.__setitem__("sub", "acct:someone-else"))
        forged = _repair(forged)
        _reject(self, forged, WireReasonCode.PRINCIPAL_ALTERED)
        stripped = list(tokens)
        stripped[0] = _resign(tokens[0], lambda p: p.__setitem__("sub", ""))
        stripped = _repair(stripped)
        self.assertIn("sub", _reject(self, stripped, WireReasonCode.MALFORMED).message)

    def test_parse_rules_precede_the_signature_check_so_the_root_is_covered(self):
        """A root carrying a detail type the verifier does not implement is malformed even when
        its signature is also wrong: the -02 classifies at parse, before step 1."""
        tokens = _mint()
        bad = _resign(tokens[0], lambda p: p["authorization_details"][0].__setitem__("type", "acme_policy"))
        h, pl, sig = bad.split(".")
        corrupted = f"{h}.{pl}.{wire.b64url_encode(bytes(b ^ 0xFF for b in wire.b64url_decode(sig)))}"
        self.assertIn("agent_delegation", _reject(self, [corrupted], WireReasonCode.MALFORMED).message)

    def test_the_01_vectors_are_malformed_under_02_and_unchanged_under_01(self):
        for name, data in vectors.load_vectors().items():
            signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]), kid=data["signer"]["kid"])
            with self.assertRaises(WireError) as cm:
                wire.load(data["tokens"], signer, now=data["now"], draft="02")
            # JSON-level rejections keep their own Table 2 names, since parsing precedes the
            # -02 claim checks; every other -01 vector lacks client_id and cnf, so it is malformed.
            self.assertIn(cm.exception.reason, (WireReasonCode.MALFORMED, WireReasonCode.NON_FINITE,
                                                WireReasonCode.DUPLICATE_MEMBER), name)
            try:
                wire.load(data["tokens"], signer, now=data["now"])
                outcome = "accept"
            except WireError as e:
                outcome = e.reason
            self.assertEqual(outcome, data.get("expect") or data["expect_reject_reason"], name)

    def test_an_02_chain_is_malformed_under_the_default_profile(self):
        """The -02 constraint shapes (`order`, `max_lifetime`) are members the -01 verifier does
        not read, and it refuses what it cannot evaluate. No transition mode (draft -02 3.1)."""
        _reject(self, _mint(), WireReasonCode.MALFORMED, draft="01")


class AlgorithmList(unittest.TestCase):
    def test_an_alg_off_the_list_is_denied_even_though_its_signature_verifies(self):
        tokens = _mint()
        e = _reject(self, tokens, WireReasonCode.SIGNATURE_INVALID, accepted_algs=["EdDSA", "ES256"])
        self.assertIn("accepted list", e.message)
        self.assertIsNotNone(wire.load(tokens, _signer(), draft="02", accepted_algs=["HS256", "EdDSA"]))
        self.assertIsNotNone(wire.load(tokens, _signer(), draft="02"))     # defaults to the signer's own

    def test_the_list_is_honoured_under_01_only_when_given(self):
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60), max_depth=2)
        tokens = wire.serialize_chain(root, _signer())
        self.assertIsNotNone(wire.load(tokens, _signer()))
        with self.assertRaises(WireError) as cm:
            wire.load(tokens, _signer(), accepted_algs=["EdDSA"])
        self.assertEqual(cm.exception.reason, WireReasonCode.SIGNATURE_INVALID)


class AuthorityRulesOnTheWire(unittest.TestCase):
    def _leaf_detail(self, tokens, mutate):
        tokens = list(tokens)
        tokens[2] = _resign(tokens[2], lambda p: mutate(p["authorization_details"][0]))
        return tokens

    def test_opaque_scopes_round_trip_and_narrow_by_byte_identity(self):
        root = Guard.issue("o", Authority({"User.Read", "repo:status"}, [], ttl=60, profile="02"), max_depth=3)
        child = root.delegate("c", Authority({"repo:status"}, [], ttl=30, profile="02"), task="t")
        tokens = _mint(child)
        v = wire.load(tokens, _signer(), draft="02", audience=AUD)
        self.assertEqual(sorted(v.leaf_authority.scopes), ["repo:status"])
        self.assertTrue(v.permits("repo:status"))
        self.assertFalse(v.permits("User.Read"))

    def test_kieran_sweeneys_cases(self):
        """wildcard over opaque and opaque over wildcard are not_narrower; a case-folded child
        is not_narrower; a wildcard over a literal under the same prefix verifies."""
        tokens = _mint()
        over_opaque = self._leaf_detail(tokens, lambda det: det.__setitem__("scopes", ["crm.Read"]))
        _reject(self, over_opaque, WireReasonCode.NOT_NARROWER)
        root = Guard.issue("o", Authority({"drive.Read"}, [], ttl=60, profile="02"), max_depth=3)
        child = root.delegate("c", Authority({"drive.Read"}, [], ttl=30, profile="02"), task="t")
        ctoks = _mint(child)
        ctoks[1] = _resign(ctoks[1], lambda p: p["authorization_details"][0].__setitem__("scopes", ["drive.*"]))
        _reject(self, ctoks, WireReasonCode.NOT_NARROWER)
        ctoks = _mint(child)
        ctoks[1] = _resign(ctoks[1], lambda p: p["authorization_details"][0].__setitem__("scopes", ["drive.read"]))
        _reject(self, ctoks, WireReasonCode.NOT_NARROWER)
        self.assertIsNotNone(wire.load(_mint(), _signer(), draft="02"))   # crm.* covers crm.read

    def test_invalid_scopes_are_malformed(self):
        for bad in ("*", "crm.*.read", "User.*", "crm.re*"):
            tokens = self._leaf_detail(_mint(), lambda det, b=bad: det.__setitem__("scopes", [b]))
            _reject(self, tokens, WireReasonCode.MALFORMED)

    def test_cumulative_bounds_narrow_only_and_never_cross_types(self):
        tokens = self._leaf_detail(_mint(), lambda det: [c.__setitem__("max_lifetime", 50)
                                                         for c in det["constraints"] if "max_lifetime" in c])
        _reject(self, tokens, WireReasonCode.NOT_NARROWER)
        # A lifetime bound where the parent holds a per-action `max` on the same key: no inference.
        tokens = self._leaf_detail(_mint(), lambda det: det["constraints"].__setitem__(
            [i for i, c in enumerate(det["constraints"]) if c["key"] == "max_spend"][0],
            {"key": "max_spend", "max_lifetime": 1}))
        _reject(self, tokens, WireReasonCode.NOT_NARROWER)
        # max_subtree narrows like the others once both hold it.
        root = Guard.issue("o", Authority({"a.b"}, [d.MaxSubtree("spend", 100)], ttl=60, profile="02"), max_depth=3)
        child = root.delegate("c", Authority({"a.b"}, [d.MaxSubtree("spend", 40)], ttl=30, profile="02"), task="t")
        ok = _mint(child)
        self.assertIsNotNone(wire.load(ok, _signer(), draft="02"))
        wider = list(ok)
        wider[1] = _resign(ok[1], lambda p: p["authorization_details"][0]["constraints"][0].__setitem__("max_subtree", 400))
        _reject(self, wider, WireReasonCode.NOT_NARROWER)

    def test_a_cumulative_constraint_with_no_total_held_denies_at_step_8(self):
        v = wire.load(_mint(), _signer(), draft="02", audience=AUD)
        self.assertFalse(v.permits("crm.read", {"rows": 1, "spend": 1}), "no `calls` total: deny")
        self.assertTrue(v.permits("crm.read", {"rows": 1, "spend": 1}, totals={"calls": 2}))
        self.assertFalse(v.permits("crm.read", {"rows": 1, "spend": 1}, totals={"calls": 3}))

    def test_rank_ordering_rules(self):
        tokens = self._leaf_detail(_mint(), lambda det: [c.__setitem__("order", ["none", "any"])
                                                         for c in det["constraints"] if "rank" in c])
        _reject(self, tokens, WireReasonCode.NOT_NARROWER)
        tokens = self._leaf_detail(_mint(), lambda det: [c.pop("order") for c in det["constraints"] if "rank" in c])
        _reject(self, tokens, WireReasonCode.MALFORMED)
        tokens = self._leaf_detail(_mint(), lambda det: [c.__setitem__("rank", "everywhere")
                                                         for c in det["constraints"] if "rank" in c])
        _reject(self, tokens, WireReasonCode.MALFORMED)

    def test_one_constraint_per_key_and_type(self):
        tokens = self._leaf_detail(_mint(), lambda det: det["constraints"].append({"key": "max_rows", "max": 5}))
        self.assertIn("one per (key, type)", _reject(self, tokens, WireReasonCode.MALFORMED).message)
        # A range (min + max on one key) on both hops verifies.
        root = Guard.issue("o", Authority({"a.b"}, [d.Min("t", 1), d.Max("t", 10)], ttl=60, profile="02"), max_depth=3)
        child = root.delegate("c", Authority({"a.b"}, [d.Min("t", 2), d.Max("t", 9)], ttl=30, profile="02"), task="t")
        v = wire.load(_mint(child), _signer(), draft="02")
        self.assertEqual(len(v.leaf_authority.ceilings_for("t")), 2)

    def test_closed_objects_and_the_single_detail(self):
        cases = {
            "constraint member": lambda det: det["constraints"][0].__setitem__("note", "x"),
            "detail member": lambda det: det.__setitem__("actions", ["read"]),
            "unknown type": lambda det: det.__setitem__("type", "acme_policy"),
        }
        for name, mutate in cases.items():
            _reject(self, self._leaf_detail(_mint(), mutate), WireReasonCode.MALFORMED)
        tokens = _mint()
        tokens[2] = _resign(tokens[2], lambda p: p["authorization_details"].append(
            {"type": "agent_delegation", "scopes": [], "constraints": []}))
        self.assertIn("exactly one", _reject(self, tokens, WireReasonCode.MALFORMED).message)

    def test_a_single_unimplemented_constraint_type_fails_closed_not_malformed(self):
        tokens = self._leaf_detail(_mint(), lambda det: det["constraints"].append({"key": "quota", "cap": 5}))
        v = wire.load(tokens, _signer(), draft="02", audience=AUD)
        decision = v.permits("crm.read", {"rows": 1, "spend": 1}, totals={"calls": 1})
        self.assertFalse(decision)
        self.assertEqual(decision.reasons[0].code, "unknown_constraint")

    def test_an_unsafe_integer_is_malformed(self):
        """The canonical encoder refuses to write 2^53, so the token is built from raw bytes,
        as the -01 generator's reject_unsafe_integer vector is."""
        tokens = _mint()
        h_b64, p_b64, _ = tokens[2].split(".")
        raw = wire.b64url_decode(p_b64).replace(b'"exp":300', b'"exp":9007199254740992', 1)
        self.assertNotEqual(raw, wire.b64url_decode(p_b64))
        signing_input = f"{h_b64}.{wire.b64url_encode(raw)}".encode("ascii")
        forged = f"{h_b64}.{wire.b64url_encode(raw)}.{wire.b64url_encode(_signer().sign(signing_input))}"
        _reject(self, [tokens[0], tokens[1], forged], WireReasonCode.MALFORMED)

    def test_a_reissued_parent_is_not_the_instance_the_child_commits_to(self):
        """Section 5 of the -02: a child presented with a re-issued parent (new jti/iat/exp)
        rather than the instance it was issued under is denied at step 2."""
        tokens = _mint()
        reissued_parent = _resign(tokens[1], lambda p: (p.__setitem__("jti", "chain:n1-reissued"),
                                                        p.__setitem__("iat", 10), p.__setitem__("exp", 910)))
        _reject(self, [tokens[0], reissued_parent, tokens[2]], WireReasonCode.PAR_HASH_MISMATCH)


class OutcomeNames(unittest.TestCase):
    def test_table_2_names_the_library_can_report(self):
        for name in ("malformed", "non_canonical", "duplicate_member", "non_finite", "signature_invalid",
                     "par_hash_mismatch", "depth_invalid", "principal_altered", "not_narrower", "expired",
                     "audience_mismatch"):
            self.assertIn(name, vars(WireReasonCode).values())


def _repair(tokens):
    """Recompute par_hash down the chain after an earlier token was re-signed, so a test
    isolates the rule it is about from par_hash_mismatch."""
    import hashlib
    signer = _signer()
    tokens = list(tokens)
    for i in range(1, len(tokens)):
        h, pl, _ = tokens[i - 1].split(".")
        prev_input = f"{h}.{pl}".encode("ascii")
        expected = wire.b64url_encode(hashlib.sha256(prev_input).digest())
        if _payload(tokens[i]).get("par_hash") != expected:
            tokens[i] = _resign(tokens[i], lambda p, e=expected: p.__setitem__("par_hash", e), signer)
    return tokens


if __name__ == "__main__":
    unittest.main(verbosity=2)
