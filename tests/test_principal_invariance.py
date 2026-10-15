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
byte-stable, and third parties have vendored them. The check is a rule of the -02 profile
(`wire.load(..., draft="02")`) and never runs on the default path, whatever claims a token
carries: the default path is the -01 algorithm, behaviour-identical to every earlier release
(security review of 2026-10-07, finding 5).
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


AUD = "https://crm.example.com"


def _cnf(node):
    return {"jkt": f"thumb-{node.agent_id}"}


def _mint02(leaf):
    return wire.serialize_chain(leaf, _signer(), principal=PRINCIPAL, aud=AUD, draft="02", cnf=_cnf)


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
        tokens = _mint02(leaf)
        subs = [_payload(t)["sub"] for t in tokens]
        agents = [_payload(t)["client_id"] for t in tokens]
        self.assertEqual(subs, [PRINCIPAL] * 3,
                         "sub must be the accountable principal, identical at every hop")
        self.assertEqual(agents, ["orchestrator", "summarizer", "formatter"],
                         "client_id must be the agent that acted at that hop")

    def test_a_conformant_minted_chain_verifies(self):
        _r, _c, leaf = _chain()
        tokens = _mint02(leaf)
        verified = wire.load(tokens, _signer(), draft="02")
        self.assertIsNotNone(verified)


class IntermediaryCannotAlterThePrincipal(unittest.TestCase):
    """The half of R5 the -01 did not meet."""

    def test_a_child_swapping_sub_is_denied(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = _mint02(leaf)
        header_b64 = tokens[1].split(".")[0]
        tampered = _payload(tokens[1])
        tampered["sub"] = "acct:someone-else@example.com"
        forged = _resign(tampered, header_b64, signer)
        # The grandchild's commitment is repaired so that the ONLY thing wrong is the sub;
        # the forged token is validly signed, so this is not a signature test either.
        chain = _repair([tokens[0], forged, tokens[2]], signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(chain, signer, draft="02")
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.PRINCIPAL_ALTERED)

    def test_the_leaf_cannot_claim_a_different_principal(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = _mint02(leaf)
        header_b64 = tokens[2].split(".")[0]
        tampered = _payload(tokens[2])
        tampered["sub"] = "acct:attacker@example.com"
        forged = _resign(tampered, header_b64, signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([tokens[0], tokens[1], forged], signer, draft="02")
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.PRINCIPAL_ALTERED)

    def test_an_02_chain_without_a_principal_on_the_root_is_malformed(self):
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = _mint02(leaf)
        header_b64 = tokens[0].split(".")[0]
        stripped = _payload(tokens[0])
        stripped["sub"] = ""
        forged = _resign(stripped, header_b64, signer)
        chain = _repair([forged, tokens[1], tokens[2]], signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(chain, signer, draft="02")
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.MALFORMED)


class TheFrozenMinusOneShapeStillVerifies(unittest.TestCase):
    """The twenty published vector files are byte-stable and vendored by third parties.
    The default path is the -01 algorithm: `sub` is the agent id there, differs per hop, and
    is never compared, whether or not a token also carries `client_id`."""

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

    def test_a_01_chain_that_also_carries_client_id_verifies_under_the_default_path(self):
        """Finding 5 of the 2026-10-07 security review: the check used to fire whenever any
        token carried client_id, which changed the default path's behaviour."""
        _r, _c, leaf = _chain()
        signer = _signer()
        tokens = wire.serialize_chain(leaf, signer)
        for i, agent in enumerate(("orchestrator", "summarizer", "formatter")):
            header_b64 = tokens[i].split(".")[0]
            p = _payload(tokens[i])
            p["client_id"] = agent
            tokens[i] = _resign(p, header_b64, signer)
        tokens = _repair(tokens, signer)
        self.assertNotEqual(len({_payload(t)["sub"] for t in tokens}), 1)
        self.assertIsNotNone(wire.load(tokens, signer))


def _repair(tokens, signer):
    """Recompute par_hash down the chain after an earlier token was re-signed."""
    import hashlib
    tokens = list(tokens)
    for i in range(1, len(tokens)):
        h, pl, _ = tokens[i - 1].split(".")
        expected = wire.b64url_encode(hashlib.sha256(f"{h}.{pl}".encode("ascii")).digest())
        p = _payload(tokens[i])
        if p.get("par_hash") != expected:
            p["par_hash"] = expected
            tokens[i] = _resign(p, tokens[i].split(".")[0], signer)
    return tokens


if __name__ == "__main__":
    unittest.main(verbosity=2)
