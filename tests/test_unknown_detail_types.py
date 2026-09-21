"""A verifier must not report success on a token it did not fully read.

Ops #109. Found while working through how a deployment carries its own policy
vocabulary alongside ours. The draft's answer is that a deployment with its
own policy vocabulary registers its own `authorization_details` type rather than
forking the verifier -- see the last paragraph of "Scope Syntax and Wildcards":

    This wildcard-covering rule applies only to the "scopes" member of the
    "agent_delegation" authorization detail type defined in {{authority}}; other
    authorization detail types, if defined, specify their own scope semantics.

Before this change, that route failed open. `_authority_from_payload` read
`details[0]` and never looked at the rest, so a token carrying `agent_delegation`
first and a second detail after it verified clean while the second detail was
discarded without a signal. Demonstrated end-to-end on the released
`valid_chain` vector: a trailing detail carrying `deny_scopes: ["crm.read"]` was
dropped and `permits("crm.read")` still returned allowed -- the verifier
permitted the action the issuer's own detail forbade.

The failure was silent in exactly one direction, which is the dangerous one: an
ignored detail that RESTRICTS authority is lost, while one that GRANTS extra
authority is harmless because ignoring it leaves the chain more restrictive.

The rule taken here is the same shape and the same place as the draft's existing
MUST for invalid scopes ("A verifier that encounters one MUST reject the
Delegation Token as malformed before evaluating subsumption"): reject what we
cannot evaluate, rather than ignore it. Rejecting is also the loosenable
direction -- if a future revision defines ignorable/critical marking per RFC 9396,
accepting more is a compatible change, whereas starting permissive and tightening
later would break deployments.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from attenu_guard import canonical, wire  # noqa: E402
from attenu_guard.wire import WireError, WireReasonCode  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


OURS = {"type": "agent_delegation", "scopes": ["crm.read"], "constraints": []}
FOREIGN = {"type": "acme_site_policy", "deny_scopes": ["crm.read"]}


def _payload(details):
    return {"iat": 0, "exp": 100, "authorization_details": details}


class UnknownDetailTypesRejected(unittest.TestCase):
    """The unit-level rule, on every ordering."""

    def test_single_known_detail_still_loads(self):
        a = wire._authority_from_payload(_payload([OURS]))
        self.assertEqual(sorted(a.scopes), ["crm.read"])

    def test_known_first_then_foreign_is_rejected(self):
        """The ordering that used to verify clean while dropping the foreign entry."""
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([OURS, FOREIGN]))
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_foreign_first_still_rejected(self):
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([FOREIGN, OURS]))
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_foreign_alone_still_rejected(self):
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([FOREIGN]))
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_two_agent_delegation_details_are_rejected(self):
        """Ambiguous rather than foreign: which one is the Authority?

        The draft says Authority is expressed by "an" authorization detail whose
        type is agent_delegation, and never says which element to take when
        several are present. Taking the first silently picked a winner the
        document never nominated.
        """
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([OURS, dict(OURS, scopes=["crm.write"])]))
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_message_names_the_offending_entry(self):
        """A denial a deployer cannot act on is only half a fix."""
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([OURS, FOREIGN]))
        self.assertIn("acme_site_policy", cm.exception.message)


class MembersInsideASingleDetail(unittest.TestCase):
    """The half that bites, and the half the first fix missed.

    The cardinality rule above only sees a SECOND entry. A single
    `agent_delegation` object carrying extra members sailed through it, because
    the loader cherry-picked `scopes` and `constraints` and discarded the rest.

    This is not shape-hunting. RFC 9396 section 2 gives every authorization
    detail object a set of common members -- `actions`, `locations`,
    `datatypes`, `identifier`, `privileges` -- and the draft's token format says
    "An array of authorization detail objects {{RFC9396}}", so an issuer
    expressing a restriction that way is doing the sanctioned thing and having
    it silently dropped.
    """

    def test_rfc9396_common_members_are_refused(self):
        for member, value in (
            ("actions", ["read"]),
            ("locations", ["https://api.example.com"]),
            ("datatypes", ["contacts"]),
            ("identifier", "acct-1"),
            ("privileges", ["read"]),
        ):
            with self.subTest(member=member):
                with self.assertRaises(WireError) as cm:
                    wire._authority_from_payload(_payload([dict(OURS, **{member: value})]))
                self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_a_restricting_member_is_refused_rather_than_dropped(self):
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([dict(OURS, deny_scopes=["crm.read"])]))
        self.assertIn("deny_scopes", cm.exception.message)

    def test_critical_is_refused(self):
        """`critical: true` means "do not ignore me". Ignoring it was the worst case."""
        with self.assertRaises(WireError) as cm:
            wire._authority_from_payload(_payload([dict(OURS, critical=True)]))
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)


class MembersInsideAConstraint(unittest.TestCase):
    """One level deeper again, in the draft's own constraint vocabulary."""

    def _auth(self, constraint):
        from attenu_guard.authority import Authority
        return Authority.from_wire(
            {"scopes": ["crm.read"], "constraints": [constraint], "ttl": 10})

    def test_one_typed_value_still_loads(self):
        self.assertEqual(len(self._auth({"key": "max_rows", "max": 100}).ceilings), 1)

    def test_a_second_typed_value_is_refused_not_resolved(self):
        """`min` alongside `max` used to keep the max and drop the floor.

        The result was byte-identical to a constraint that never carried a
        floor, so nothing downstream could tell the difference. `min` is a
        first-class type in the draft's vocabulary, and the draft allows one
        typed value per object, which makes two malformed rather than a thing to
        silently resolve.
        """
        with self.assertRaises(ValueError) as cm:
            self._auth({"key": "max_rows", "max": 100, "min": 9999})
        self.assertIn("min", str(cm.exception))

    def test_an_unknown_member_inside_a_known_constraint_is_refused(self):
        with self.assertRaises(ValueError):
            self._auth({"key": "max_rows", "max": 100, "bogus": 1})

    def test_normalising_ceilings_are_not_rejected(self):
        """The false positive that nearly shipped, and the gap that hid it.

        A first version of this rule compared whole VALUES: parse the
        constraint, re-emit it, refuse if the result was not the input. That
        cannot tell "we ignored a member" from "we normalised a value", and
        three built-ins legitimately normalise -- `Allow`/`Deny` emit `one_of` /
        `not_one_of` sorted and hold them as frozensets, and `to_wire` omits
        `field` when it equals `key`.

        RFC 8785 canonicalises object member ORDER and never reorders array
        elements, and the draft puts no ordering or uniqueness requirement on
        `one_of`. So every case below is a conformant constraint a third-party
        issuer may legitimately send, and value equality called all four
        malformed. On a release whose subject is reading tokens correctly,
        refusing correct tokens is the worse failure.

        These cases exist because NO vector or fixture in either repo carries an
        `allow`, `deny` or `prefix` constraint -- the "all 116 constraint
        objects round-trip exactly" regression check only ever exercised the
        four ceilings that emit what they read, so it passed vacuously.
        """
        for label, c in (
            ("one_of unsorted", {"key": "region", "type": "allow",
                                 "one_of": ["us-west", "us-east"]}),
            ("not_one_of unsorted", {"key": "region", "type": "deny",
                                     "not_one_of": ["b", "a"]}),
            ("one_of with a duplicate", {"key": "region", "type": "allow",
                                         "one_of": ["a", "a"]}),
            ("explicit field equal to key", {"key": "region", "type": "allow",
                                             "one_of": ["us"], "field": "region"}),
        ):
            with self.subTest(case=label):
                auth = self._auth(c)          # must not raise
                self.assertEqual(len(auth.ceilings), 1)

    def test_a_rewritten_key_is_refused(self):
        """`key` is the one member whose VALUE is load-bearing.

        Subsumption pairs ceilings by `key`, so a rewritten key is a different
        dimension, not a cosmetic difference. `CallLimit` rewrites it when
        `applies_to` is present -- "max_calls" becomes "max_calls[fs.write]" --
        and the member test cannot see that, because the member set is
        unchanged. On a root token, which has no parent to be subsumed against,
        the issuer wrote `max_calls: 5` and got a ceiling that bounds only
        `fs.write`.

        Checked on its own rather than by returning to whole-value equality,
        which is what rejected conformant tokens a revision ago.
        """
        with self.assertRaises(ValueError):
            self._auth({"key": "max_calls", "type": "max_calls",
                        "max": 5, "applies_to": "fs.write"})

    def test_our_own_call_limit_emission_still_loads(self):
        """The other half of the rule above: it must not refuse what we emit."""
        from attenu_guard.ceilings import CallLimit
        wire = CallLimit(5, applies_to="fs.write").to_wire()
        self.assertEqual(wire["key"], "max_calls[fs.write]")
        self.assertEqual(len(self._auth(wire).ceilings), 1)

    def test_field_is_exempt_only_on_evidence_it_was_parsed(self):
        """The exemption must fire on evidence, not coincidence.

        `ctx_field_of` falls back to a hardcoded `ctx_field` and then to `key`,
        so for the metered built-ins -- which never read `field` in `from_wire`
        at all -- it returns the input's value by coincidence, and `field` rode
        through unread. A custom ceiling deriving `ctx_field` from its own input
        made it fire unconditionally.

        The test is now the attribute the constructor actually populated.
        Allow/Deny/Prefix carry `field` as a real parsed attribute; the metered
        built-ins do not, so they fall through to the refusal.
        """
        for c in ({"key": "max_rows", "max": 5, "field": "rows"},
                  {"key": "max_spend", "max": 5, "field": "spend"},
                  {"key": "max_calls", "max": 5, "field": "calls"},
                  {"key": "egress", "rank": "none", "field": "egress"}):
            with self.subTest(constraint=c):
                with self.assertRaises(ValueError):
                    self._auth(c)

    def test_an_unknown_constraint_TYPE_still_fails_closed_not_parse_error(self):
        """The distinction worth keeping.

        The draft requires an unknown constraint type to DENY the action, never
        to be treated as unconstrained. `_UnknownCeiling` does that, and it
        preserves its whole dict, so it round-trips and must not be turned into
        a parse error by the rule above -- that would lose the deny.
        """
        auth = self._auth({"key": "max_widgets", "max": 5})
        self.assertEqual(len(auth.ceilings), 1)
        self.assertFalse(auth.permits("crm.read", {}).allowed)


class EndToEndOnTheReleasedVector(unittest.TestCase):
    """The regression that matters: the published chain, re-signed, full `load()`.

    A unit call on `_authority_from_payload` would pass even if `load()` reached
    the authority by some other path, so this drives the real entry point over
    the bytes we actually ship.
    """

    @classmethod
    def setUpClass(cls):
        here = os.path.dirname(__file__)
        path = os.path.join(here, "..", "src", "attenu_guard", "vectors", "valid_chain.json")
        with open(path) as fh:
            cls.vector = json.load(fh)
        cls.secret = bytes.fromhex(cls.vector["signer"]["secret_hex"])
        cls.signer = wire.HS256TestSigner(cls.secret, kid=cls.vector["signer"]["kid"])

    def _resign(self, hdr_b64: str, payload_obj) -> str:
        raw = canonical.dumps(payload_obj)
        if isinstance(raw, str):
            raw = raw.encode()
        p = _b64u(raw)
        sig = hmac.new(self.secret, f"{hdr_b64}.{p}".encode(), hashlib.sha256).digest()
        return f"{hdr_b64}.{p}.{_b64u(sig)}"

    def _leaf_with(self, extra_details):
        """Rebuild the leaf with `extra_details` appended.

        The LEAF is mutated on purpose: no child commits to it through `par_hash`,
        so the only difference from the published chain is the inserted entry.
        """
        hdr, payload_b64, _ = self.vector["tokens"][-1].split(".")
        payload = json.loads(_unb64u(payload_b64))
        payload["authorization_details"].extend(extra_details)
        return list(self.vector["tokens"][:-1]) + [self._resign(hdr, payload)]

    def test_control_resigned_unchanged_still_verifies(self):
        """Proves the re-signing method itself is sound.

        Without this, a rejection below could just mean the test signs badly.
        """
        hdr, payload_b64, _ = self.vector["tokens"][-1].split(".")
        payload = json.loads(_unb64u(payload_b64))
        tokens = list(self.vector["tokens"][:-1]) + [self._resign(hdr, payload)]
        chain = wire.load(tokens, self.signer, now=self.vector["now"])
        self.assertTrue(chain.permits("crm.read").allowed)

    def test_published_vector_unmodified_still_verifies(self):
        chain = wire.load(self.vector["tokens"], self.signer, now=self.vector["now"])
        self.assertTrue(chain.permits("crm.read").allowed)

    def test_appended_foreign_detail_is_refused_not_ignored(self):
        """The regression. This chain used to verify clean and permit crm.read."""
        tokens = self._leaf_with([FOREIGN])
        with self.assertRaises(WireError) as cm:
            wire.load(tokens, self.signer, now=self.vector["now"])
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def _leaf_mutating_detail(self, **members):
        """Rebuild the leaf with `members` merged INTO its single detail."""
        hdr, payload_b64, _ = self.vector["tokens"][-1].split(".")
        payload = json.loads(_unb64u(payload_b64))
        payload["authorization_details"][0].update(members)
        return list(self.vector["tokens"][:-1]) + [self._resign(hdr, payload)]

    def test_a_member_inside_the_single_detail_is_refused(self):
        """The regression the first fix missed.

        This chain carries ONE authorization detail, so the cardinality rule
        never fires. Before the member check it verified clean and still
        permitted crm.read while `deny_scopes` said not to.
        """
        tokens = self._leaf_mutating_detail(deny_scopes=["crm.read"])
        with self.assertRaises(WireError) as cm:
            wire.load(tokens, self.signer, now=self.vector["now"])
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_a_member_inside_a_constraint_is_refused(self):
        hdr, payload_b64, _ = self.vector["tokens"][-1].split(".")
        payload = json.loads(_unb64u(payload_b64))
        payload["authorization_details"][0]["constraints"][0]["min"] = 9999
        tokens = list(self.vector["tokens"][:-1]) + [self._resign(hdr, payload)]
        with self.assertRaises(WireError) as cm:
            wire.load(tokens, self.signer, now=self.vector["now"])
        self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED)

    def test_canonicalization_is_not_what_stops_it(self):
        """JCS must not be mistaken for the protection.

        The first reproduction was rejected `non_canonical` only because the test
        re-serialized with `json.dumps`. Going through `canonical.dumps` produced
        a token the verifier accepted, so the guarantee has to come from the
        detail-type rule and not from canonicalization. This asserts the failure
        is the rule, never NON_CANONICAL.
        """
        tokens = self._leaf_with([FOREIGN])
        with self.assertRaises(WireError) as cm:
            wire.load(tokens, self.signer, now=self.vector["now"])
        self.assertNotEqual(cm.exception.reason, WireReasonCode.NON_CANONICAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
