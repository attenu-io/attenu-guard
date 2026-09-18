"""Principal binding and invariance — draft -02, R5 of draft-reece-wimse-cross-org-delegation.

R5 asks for TWO things and the -01 met only the first in spirit: convey the on-behalf-of
principal along the chain, AND let a relying party verify that intermediaries did not alter
it. Until this change `sub` carried the ACTING AGENT (RFC 9068 Section 2.2's no-resource-owner
branch), nothing in the draft said what `sub` named, and no verification step read it.

The -02 layout, committed publicly on the WIMSE list 2026-09-17:
  * `sub`        the accountable principal whose grant the chain acts under. IDENTICAL in
                 every DT_i.
  * `client_id`  the agent that acted at that hop. Varies per hop.
  * verification denies on any change to `sub` along the chain.

Backward compatibility is not optional: the twenty published -01 vector files are frozen and
byte-stable, and third parties have vendored them. A chain is only subject to the new check
when it is -02 shaped, which is signalled by `client_id` being present.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from attenu_guard import Authority, Guard, RowLimit  # noqa: E402
from attenu_guard import wire  # noqa: E402

SECRET = b"test-secret-for-principal-invariance"
PRINCIPAL = "acct:finance-ops@example.com"


def _signer():
    return wire.HS256TestSigner(SECRET, kid="test")


def _chain():
    root = Guard.issue("orchestrator",
                       Authority(scopes={"crm.*"}, ceilings=[RowLimit(1000)], ttl=3600),
                       max_depth=4)
    child = root.delegate("summarizer",
                          Authority(scopes={"crm.read"}, ceilings=[RowLimit(100)], ttl=900),
                          task="summarize")
    leaf = child.delegate("formatter",
                          Authority(scopes={"crm.read"}, ceilings=[RowLimit(10)], ttl=300),
                          task="format")
    return root, child, leaf


def _payload(token):
    import base64, json
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _resign(payload, header_b64, signer):
    """Re-encode a tampered payload with the library's OWN canonical encoder and
    sign it properly, so the forged token is validly signed and canonical. These
    tests must fail on the principal check, never incidentally on JCS or on the
    signature."""
    from attenu_guard.wire import _encode_part, b64url_encode
    payload_b64 = _encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{b64url_encode(signer.sign(signing_input))}"


class PrincipalGoesInSubAgentGoesInClientId(unittest.TestCase):
    def test_every_hop_carries_the_same_principal_and_its_own_agent(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer, principal=PRINCIPAL, aud="https://crm.example.com")
        subs = [_payload(t)["sub"] for t in tokens]
        agents = [_payload(t)["client_id"] for t in tokens]
        self.assertEqual(subs, [PRINCIPAL] * 3,
                         "sub must be the accountable principal, identical at every hop")
        self.assertEqual(agents, ["orchestrator", "summarizer", "formatter"],
                         "client_id must be the agent that acted at that hop")

    def test_a_conformant_minted_chain_verifies(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer, principal=PRINCIPAL, aud="https://crm.example.com")
        verified = wire.load(tokens, signer)
        self.assertIsNotNone(verified)


class IntermediaryCannotAlterThePrincipal(unittest.TestCase):
    """The half of R5 the -01 did not meet."""

    def test_a_child_swapping_sub_is_denied(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer, principal=PRINCIPAL, aud="https://crm.example.com")
        header_b64 = tokens[1].split(".")[0]
        tampered = _payload(tokens[1])
        tampered["sub"] = "acct:someone-else@example.com"
        forged = _resign(tampered, header_b64, signer)

        # The forged token is validly SIGNED — this is not a signature test.
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([tokens[0], forged, tokens[2]], signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.PRINCIPAL_ALTERED)

    def test_the_leaf_cannot_claim_a_different_principal(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer, principal=PRINCIPAL, aud="https://crm.example.com")
        header_b64 = tokens[2].split(".")[0]
        tampered = _payload(tokens[2])
        tampered["sub"] = "acct:attacker@example.com"
        forged = _resign(tampered, header_b64, signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([tokens[0], tokens[1], forged], signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.PRINCIPAL_ALTERED)

    def test_an_02_chain_without_a_principal_on_the_root_is_malformed(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer, principal=PRINCIPAL, aud="https://crm.example.com")
        header_b64 = tokens[0].split(".")[0]
        stripped = _payload(tokens[0])
        stripped["sub"] = ""
        forged = _resign(stripped, header_b64, signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([forged, tokens[1], tokens[2]], signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.MALFORMED)


class TheFrozenMinusOneShapeStillVerifies(unittest.TestCase):
    """The twenty published vector files are byte-stable and vendored by third parties.
    A chain with no `client_id` keeps the -01 meaning of `sub` and is not subject to the
    invariance check, so it must still load."""

    def test_a_legacy_chain_puts_the_agent_in_sub_and_verifies(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer)          # no principal= : -01 shape
        payloads = [_payload(t) for t in tokens]
        self.assertEqual([p["sub"] for p in payloads],
                         ["orchestrator", "summarizer", "formatter"])
        for p in payloads:
            self.assertNotIn("client_id", p)
        self.assertIsNotNone(wire.load(tokens, signer))

    def test_a_legacy_chain_with_differing_subs_is_not_rejected_by_the_new_check(self):
        """Differing `sub` is NORMAL in the -01 shape: it is the agent id. The new check
        must not fire, or every pre-existing chain breaks."""
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer)
        subs = [_payload(t)["sub"] for t in tokens]
        self.assertNotEqual(len(set(subs)), 1, "precondition: the -01 subs differ")
        self.assertIsNotNone(wire.load(tokens, signer))


if __name__ == "__main__":
    unittest.main(verbosity=2)
