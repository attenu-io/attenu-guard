"""
tests/test_wire.py — unit tests for the Delegation Token wire format
(src/attenu_guard/wire.py), per
docs/draft-asor-wimse-agent-delegation-chain-00.md.

stdlib-only (unittest), no pytest, runs with bare `python3`:

    python3 tests/test_wire.py

Also regenerates and loads tests/vectors/*.json (via tests/vectors/generate.py)
as part of this run, so the interop vectors are self-checking against this
exact source tree on every run, not a static fixture that can silently drift.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests" / "vectors"))

from attenu_guard import Authority, Guard, RowLimit, EgressRank, SpendCap  # noqa: E402
from attenu_guard import wire  # noqa: E402
from attenu_guard import vectors  # noqa: E402  (the shipped copy of tests/vectors/)

import generate as vectors_generate  # tests/vectors/generate.py  # noqa: E402

SECRET = b"test-wire-fixed-secret-do-not-use-in-production"

# The vectors AS COMMITTED, snapshotted at import — before any test regenerates
# them. Comparing the two copies after a regeneration would only ever compare
# what the generator just wrote; this catches a copy edited by hand, which is the
# way the two directories would actually drift.
_REPO_VECTORS_DIR = _ROOT / "tests" / "vectors"
_PACKAGE_VECTORS_DIR = _ROOT / "src" / "attenu_guard" / "vectors"


def _committed(directory):
    return {p.name: p.read_bytes() for p in sorted(directory.glob("*.json"))}


COMMITTED_REPO_VECTORS = _committed(_REPO_VECTORS_DIR)
COMMITTED_PACKAGE_VECTORS = _committed(_PACKAGE_VECTORS_DIR)


def _signer(kid="test"):
    return wire.HS256TestSigner(SECRET, kid=kid)


def _base_chain(max_depth=6):
    """orchestrator -> summarizer -> formatter, the same shape as
    examples/poisoned_summarizer.py: a broad root attenuated twice."""
    root = Guard.issue(
        "orchestrator",
        Authority(scopes={"crm.*", "mail.send"},
                  ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        max_depth=max_depth,
    )
    child = root.delegate(
        "summarizer",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize Q3 pipeline",
    )
    grandchild = child.delegate(
        "formatter",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(100)], ttl=300),
        task="format for slides",
    )
    return root, child, grandchild


def _decode(token):
    header_b64, payload_b64, _sig_b64 = token.split(".")
    return (json.loads(wire.b64url_decode(header_b64)),
            json.loads(wire.b64url_decode(payload_b64)))


def _resign(header_b64, payload, signer):
    payload_b64 = wire._encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = wire.b64url_encode(signer.sign(signing_input))
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _tamper_leaf(token, signer, mutate):
    """Mutate `token`'s payload and re-sign it. Safe ONLY on the LAST token
    of a chain: nothing downstream commits (via par_hash) to a leaf token's
    signing input, so this cannot accidentally also trip
    par_hash_mismatch as a side effect of the tamper under test — it
    isolates whatever check `mutate`'s change is meant to violate."""
    header_b64, payload_b64, _sig_b64 = token.split(".")
    payload = json.loads(wire.b64url_decode(payload_b64))
    mutate(payload)
    return _resign(header_b64, payload, signer)


def _tamper_root_and_repair_chain(tokens, signer, mutate):
    """Mutate `tokens[0]`'s (the root's) payload, re-sign it, and propagate:
    recompute par_hash and re-sign every following token so the result stays
    fully self-consistent (valid signatures, correct byte-commitments)
    EXCEPT for whatever invariant `mutate` deliberately breaks on the root.
    Needed because ANY change to the root's payload changes its exact
    signing bytes, which would otherwise make the next token's par_hash stop
    matching — i.e. a naively-tampered chain would (correctly, but for the
    wrong reason) be rejected at the par_hash step instead of at the check
    this helper is meant to let a test isolate."""
    tokens = list(tokens)
    header0_b64, payload0_b64, _sig0_b64 = tokens[0].split(".")
    payload0 = json.loads(wire.b64url_decode(payload0_b64))
    mutate(payload0)
    tokens[0] = _resign(header0_b64, payload0, signer)

    prev_signing_input = f"{header0_b64}.{wire._encode_part(payload0)}".encode("ascii")
    for i in range(1, len(tokens)):
        h_b64, p_b64, _s_b64 = tokens[i].split(".")
        payload = json.loads(wire.b64url_decode(p_b64))
        payload["par_hash"] = wire.b64url_encode(hashlib.sha256(prev_signing_input).digest())
        tokens[i] = _resign(h_b64, payload, signer)
        prev_signing_input = f"{h_b64}.{wire._encode_part(payload)}".encode("ascii")
    return tokens


# =========================================================================
# base64url helpers
# =========================================================================
class TestBase64Url(unittest.TestCase):
    def test_round_trip_arbitrary_bytes(self):
        for data in (b"", b"a", b"ab", b"abc", b"abcd", bytes(range(256))):
            self.assertEqual(wire.b64url_decode(wire.b64url_encode(data)), data)

    def test_no_padding_and_url_safe_alphabet(self):
        encoded = wire.b64url_encode(b"\xfb\xff\xbe\xff\xfe")
        self.assertNotIn("=", encoded)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)


# =========================================================================
# serialize() -> load(): single-token round trip
# =========================================================================
class TestSingleTokenRoundTrip(unittest.TestCase):
    def test_scopes_ceilings_ttl_preserved_exactly(self):
        signer = _signer()
        authority = Authority(
            scopes={"crm.read", "crm.write", "mail.send"},
            ceilings=[RowLimit(4321), SpendCap(12.5), EgressRank("internal")],
            ttl=1800,
        )
        root = Guard.issue("orchestrator", authority)
        token = wire.serialize(root, signer, iat=0)
        vc = wire.load([token], signer)

        self.assertEqual(vc.leaf_authority, authority)
        self.assertEqual(vc.leaf_authority.scopes, authority.scopes)
        self.assertEqual(vc.leaf_authority.ceilings, authority.ceilings)
        self.assertEqual(vc.leaf_authority.ttl, authority.ttl)
        self.assertEqual(vc.depth, 0)
        self.assertEqual(vc.tokens, (token,))

    def test_header_and_claim_shape(self):
        signer = _signer(kid="root-key-7")
        root = Guard.issue("orchestrator", Authority({"crm.read"}, [RowLimit(10)], ttl=60),
                           max_depth=5)
        token = wire.serialize(root, signer, iss="my-issuer", aud="my-audience", iat=1000)
        header, payload = _decode(token)

        self.assertEqual(header, {"typ": "at+jwt", "alg": "HS256", "kid": "root-key-7"})
        self.assertEqual(payload["iss"], "my-issuer")
        self.assertEqual(payload["sub"], "orchestrator")
        self.assertEqual(payload["aud"], "my-audience")
        self.assertEqual(payload["iat"], 1000)
        self.assertEqual(payload["exp"], 1060)          # iat + ttl
        self.assertEqual(payload["del_depth"], 0)
        self.assertEqual(payload["del_max_depth"], 6)   # chain.max_depth(5) + 1 — see wire.py
        self.assertNotIn("par_hash", payload)
        self.assertEqual(payload["authorization_details"], [{
            "type": "agent_delegation",
            "scopes": ["crm.read"],
            "constraints": [{"key": "max_rows", "max": 10}],
        }])
        self.assertIn("jti", payload)

    def test_default_jti_is_the_node_id_not_random(self):
        # Determinism matters for reproducible vectors: no uuid4() anywhere
        # on the serialize path.
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root, signer)
        _header, payload = _decode(token)
        self.assertEqual(payload["jti"], root.node_id)

    def test_explicit_jti_is_honored(self):
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root, signer, jti="custom-jti-123")
        _header, payload = _decode(token)
        self.assertEqual(payload["jti"], "custom-jti-123")

    def test_ttl_none_raises_malformed(self):
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=None))
        with self.assertRaises(wire.WireError) as ctx:
            wire.serialize(root, signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.MALFORMED)

    def test_serialize_accepts_a_bare_node_with_explicit_max_depth(self):
        # guard_or_node also accepts a bare chain.Node (no Guard wrapper);
        # del_max_depth then has no chain to read, so it must be explicit.
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root._node, signer, max_depth=9)
        _header, payload = _decode(token)
        self.assertEqual(payload["del_max_depth"], 9)

    def test_serialize_bare_root_node_without_max_depth_raises(self):
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        with self.assertRaises(wire.WireError) as ctx:
            wire.serialize(root._node, signer)   # no chain, no explicit max_depth
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.MALFORMED)


# =========================================================================
# serialize_chain() -> load(): a valid, attenuating 3-hop chain
# =========================================================================
class TestValidChain(unittest.TestCase):
    def test_three_hop_chain_verifies(self):
        signer = _signer()
        _root, _child, leaf = _base_chain()
        tokens = wire.serialize_chain(leaf, signer)
        self.assertEqual(len(tokens), 3)

        vc = wire.load(tokens, signer)
        self.assertEqual(vc.depth, 2)
        self.assertEqual(vc.leaf_authority, leaf.authority)
        self.assertEqual(vc.leaf_authority.ceiling("max_rows").max_rows, 100)

    def test_permits_delegates_to_leaf_authority(self):
        signer = _signer()
        _root, _child, leaf = _base_chain()
        tokens = wire.serialize_chain(leaf, signer)
        vc = wire.load(tokens, signer)

        self.assertTrue(vc.permits("crm.read", {"rows": 50}))
        denied = vc.permits("crm.read", {"rows": 5000})  # leaf caps max_rows at 100
        self.assertFalse(denied)
        self.assertEqual(denied.reasons[0].constraint, "max_rows")
        self.assertFalse(vc.permits("mail.send"))         # dropped before the leaf

    def test_del_depth_and_par_hash_shape_along_the_chain(self):
        signer = _signer()
        _root, _child, leaf = _base_chain()
        tokens = wire.serialize_chain(leaf, signer)
        _h0, p0 = _decode(tokens[0])
        _h1, p1 = _decode(tokens[1])
        _h2, p2 = _decode(tokens[2])

        self.assertEqual((p0["del_depth"], p1["del_depth"], p2["del_depth"]), (0, 1, 2))
        self.assertNotIn("par_hash", p0)
        self.assertIn("par_hash", p1)
        self.assertIn("par_hash", p2)
        self.assertLessEqual(p1["exp"], p0["exp"])
        self.assertLessEqual(p2["exp"], p1["exp"])

    def test_par_hash_is_sha256_of_parents_exact_signing_input(self):
        signer = _signer()
        _root, _child, leaf = _base_chain()
        tokens = wire.serialize_chain(leaf, signer)
        header0_b64, payload0_b64, _sig0 = tokens[0].split(".")
        parent_signing_input = f"{header0_b64}.{payload0_b64}".encode("ascii")
        expected = wire.b64url_encode(hashlib.sha256(parent_signing_input).digest())
        _h1, p1 = _decode(tokens[1])
        self.assertEqual(p1["par_hash"], expected)

    def test_maximal_structural_depth_chain_still_verifies(self):
        # Regression test for the chain.max_depth -> del_max_depth "+1"
        # fix documented in wire.py's module docstring: a chain built all
        # the way to the in-process Chain's own max_depth ceiling (the
        # deepest chain the library will EVER actually construct) must
        # still pass its own wire-level depth check, not be rejected by it.
        signer = _signer()
        md = 4
        root = Guard.issue("a0", Authority({"x"}, [RowLimit(1000)], ttl=100), max_depth=md)
        cur = root
        for i in range(md):
            cur = cur.delegate(f"a{i+1}", Authority({"x"}, [RowLimit(1000 - i)],
                                                     ttl=100 - i), task="t")
        self.assertEqual(cur._node.depth, md)
        tokens = wire.serialize_chain(cur, signer)
        vc = wire.load(tokens, signer)
        self.assertEqual(vc.depth, md)

    def test_serialize_chain_requires_a_guard(self):
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        with self.assertRaises(TypeError):
            wire.serialize_chain(root._node, signer)  # bare Node: no chain to traverse


# =========================================================================
# Adversarial vectors — each MUST be rejected, for the specific right reason
# =========================================================================
class TestAdversarialRejections(unittest.TestCase):
    def setUp(self):
        self.signer = _signer()
        _root, _child, self.leaf = _base_chain()
        self.tokens = wire.serialize_chain(self.leaf, self.signer)

    # (a) widened scope in a child
    def test_widened_scope_is_rejected(self):
        def widen(payload):
            scopes = set(payload["authorization_details"][0]["scopes"])
            scopes.add("pay.transfer")   # never granted anywhere up the chain
            payload["authorization_details"][0]["scopes"] = sorted(scopes)

        tampered = list(self.tokens)
        tampered[-1] = _tamper_leaf(tampered[-1], self.signer, widen)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.NOT_NARROWER)

    # (b) exceeded ceiling in a child
    def test_exceeded_ceiling_is_rejected(self):
        def loosen(payload):
            for c in payload["authorization_details"][0]["constraints"]:
                if c.get("key") == "max_rows":
                    c["max"] = 999_999_999

        tampered = list(self.tokens)
        tampered[-1] = _tamper_leaf(tampered[-1], self.signer, loosen)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.NOT_NARROWER)

    # (c) spliced parent: swap a (real) child onto a different, broader,
    # honestly-signed parent token it was never actually delegated under
    def test_spliced_parent_is_rejected(self):
        broad_root = Guard.issue(
            "attacker-broad-root",
            Authority(scopes={"crm.*", "mail.send", "pay.transfer"},
                      ceilings=[RowLimit(10**9), EgressRank("any")], ttl=999_999),
        )
        broad_root_token = wire.serialize(broad_root, self.signer)
        spliced = [broad_root_token, self.tokens[1]]  # real child, foreign parent
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(spliced, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.PAR_HASH_MISMATCH)

    # (d) depth beyond del_max_depth
    def test_depth_beyond_max_is_rejected(self):
        def shrink(payload):
            # chain has 3 tokens (leaf del_depth=2); need n(2) < del_max_depth,
            # so shrinking to 2 makes 2 < 2 False.
            payload["del_max_depth"] = 2

        tampered = _tamper_root_and_repair_chain(self.tokens, self.signer, shrink)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.DEPTH_INVALID)

    # (e) non-monotonic exp
    def test_nonmonotonic_exp_is_rejected(self):
        def mint_later(payload):
            # Shift iat AND exp together: ttl (duration) is unchanged and
            # still satisfies subsumption, but absolute exp now exceeds the
            # parent's absolute exp — isolates the monotonic-exp check from
            # ttl subsumption (bumping exp alone would inflate the
            # reconstructed ttl too and get caught as not_narrower instead).
            delta = 100_000
            payload["iat"] += delta
            payload["exp"] += delta

        tampered = list(self.tokens)
        tampered[-1] = _tamper_leaf(tampered[-1], self.signer, mint_later)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.EXPIRED)

    # (f) bad signature: flip a byte
    def test_bad_signature_is_rejected(self):
        header_b64, payload_b64, sig_b64 = self.tokens[-1].split(".")
        sig = bytearray(wire.b64url_decode(sig_b64))
        sig[0] ^= 0xFF
        tampered = list(self.tokens)
        tampered[-1] = f"{header_b64}.{payload_b64}.{wire.b64url_encode(bytes(sig))}"
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.SIGNATURE_INVALID)

    # ---- a few extra structural edge cases, beyond the required six ------
    def test_empty_chain_is_malformed(self):
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([], self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.MALFORMED)

    def test_alg_confusion_is_rejected(self):
        # The header's declared alg is swapped; even though the ORIGINAL
        # signature bytes are carried over, they no longer verify against
        # the new header+payload bytes AND the alg no longer matches the
        # signer's — both are legitimate reasons this must fail closed.
        header_b64, payload_b64, sig_b64 = self.tokens[0].split(".")
        header = json.loads(wire.b64url_decode(header_b64))
        header["alg"] = "none"
        new_header_b64 = wire._encode_part(header)
        tampered_root = f"{new_header_b64}.{payload_b64}.{sig_b64}"
        tampered = [tampered_root] + list(self.tokens[1:])
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.SIGNATURE_INVALID)

    def test_root_must_not_carry_par_hash(self):
        def add_par_hash(payload):
            payload["par_hash"] = wire.b64url_encode(b"not-actually-a-hash-of-anything")

        tampered = list(self.tokens)
        tampered[0] = _tamper_leaf(tampered[0], self.signer, add_par_hash)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.MALFORMED)

    def test_del_depth_out_of_sequence_is_rejected(self):
        # Tamper the LEAF (last token): nothing downstream commits to its
        # signing input via par_hash, so this isolates the depth-sequence
        # check itself rather than also disturbing byte-commitments further
        # down the chain (see _tamper_root_and_repair_chain's docstring for
        # why that matters when the tamper target is NOT the last token).
        def skip(payload):
            payload["del_depth"] = 5

        tampered = list(self.tokens)
        tampered[-1] = _tamper_leaf(tampered[-1], self.signer, skip)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load(tampered, self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.DEPTH_INVALID)


# =========================================================================
# root_key_ids
# =========================================================================
class TestRootKeyIds(unittest.TestCase):
    def test_root_kid_in_allowlist_is_accepted(self):
        signer = _signer(kid="root-7")
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root, signer)
        vc = wire.load([token], signer, root_key_ids={"root-7", "root-8"})
        self.assertEqual(vc.depth, 0)

    def test_root_kid_not_in_allowlist_is_rejected(self):
        signer = _signer(kid="root-untrusted")
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root, signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([token], signer, root_key_ids={"root-7"})
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.SIGNATURE_INVALID)


# =========================================================================
# now / exp interaction
# =========================================================================
class TestExpiry(unittest.TestCase):
    def test_now_past_exp_is_rejected(self):
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=10))
        token = wire.serialize(root, signer, iat=0)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([token], signer, now=11)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.EXPIRED)

    def test_now_at_exp_boundary_is_accepted(self):
        signer = _signer()
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=10))
        token = wire.serialize(root, signer, iat=0)
        vc = wire.load([token], signer, now=10)  # now == exp: still valid
        self.assertEqual(vc.depth, 0)


# =========================================================================
# HS256TestSigner
# =========================================================================
class TestHS256TestSigner(unittest.TestCase):
    def test_alg_is_HS256(self):
        self.assertEqual(wire.HS256TestSigner(b"k").alg, "HS256")

    def test_default_kid_is_test(self):
        self.assertEqual(wire.HS256TestSigner(b"k").kid, "test")

    def test_verify_rejects_wrong_secret(self):
        s1, s2 = wire.HS256TestSigner(b"secret-one"), wire.HS256TestSigner(b"secret-two")
        sig = s1.sign(b"hello")
        self.assertTrue(s1.verify(b"hello", sig))
        self.assertFalse(s2.verify(b"hello", sig))

    def test_isinstance_of_signer_protocol(self):
        self.assertIsInstance(wire.HS256TestSigner(b"k"), wire.Signer)


# =========================================================================
# Ed25519Signer — self-skips if `cryptography` is not installed
# =========================================================================
class TestEd25519Signer(unittest.TestCase):
    def setUp(self):
        try:
            self.signer = wire.Ed25519Signer.generate(kid="prod-1")
        except ImportError:
            raise unittest.SkipTest("cryptography not installed; Ed25519Signer is optional")

    def test_alg_is_EdDSA(self):
        self.assertEqual(self.signer.alg, "EdDSA")

    def test_round_trip_single_token(self):
        root = Guard.issue("o", Authority({"crm.read"}, [RowLimit(10)], ttl=60))
        token = wire.serialize(root, self.signer)
        vc = wire.load([token], self.signer)
        self.assertEqual(vc.leaf_authority, root.authority)

    def test_round_trip_chain(self):
        _root, _child, leaf = _base_chain()
        tokens = wire.serialize_chain(leaf, self.signer)
        vc = wire.load(tokens, self.signer)
        self.assertEqual(vc.depth, 2)

    def test_verify_fails_for_a_different_keypair(self):
        other = wire.Ed25519Signer.generate(kid="other")
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root, self.signer)
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([token], other)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.SIGNATURE_INVALID)

    def test_flipped_byte_signature_is_rejected(self):
        root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
        token = wire.serialize(root, self.signer)
        header_b64, payload_b64, sig_b64 = token.split(".")
        sig = bytearray(wire.b64url_decode(sig_b64))
        sig[-1] ^= 0x01
        tampered = f"{header_b64}.{payload_b64}.{wire.b64url_encode(bytes(sig))}"
        with self.assertRaises(wire.WireError) as ctx:
            wire.load([tampered], self.signer)
        self.assertEqual(ctx.exception.reason, wire.WireReasonCode.SIGNATURE_INVALID)

    # ---- Slice 1 / Plan A, Task 8: public-key-only verification + key-file round trip ----
    def test_verifier_checks_an_anchor_with_the_public_key_only(self):
        from attenu_guard import evidence
        pub = self.signer.public_bytes_raw()
        g = Guard.issue("a", Authority({"crm.read"}, [], ttl=None), task="t"); g.check("crm.read", tool="q")
        bundle = evidence.export_bundle(g.audit_log(), self.signer)
        verifier = wire.Ed25519Verifier(pub, kid="prod-1")               # what a console / auditor / ingest server holds
        self.assertTrue(evidence.verify_bundle(bundle, verifier)["ok"])
        bundle["entries"][-1]["tool"] = "tampered"                        # any rewrite fails under the public key
        self.assertFalse(evidence.verify_bundle(bundle, verifier)["ok"])
        with self.assertRaises(RuntimeError):
            verifier.sign(b"x")                                           # a verifier must not be able to sign
        other = wire.Ed25519Signer.generate(kid="other")
        self.assertFalse(wire.Ed25519Verifier(other.public_bytes_raw(), kid="other").verify(b"m", self.signer.sign(b"m")))

    def test_ecdsa_p256_verifier_accepts_a_der_signature_over_the_anchor_input(self):
        """What a KMS-backed anchor looks like to a verifier: ECDSA P-256 (KMS has no Ed25519), SPKI DER public key,
        DER signature. The verifier side lives in the shim so an auditor needs no cloud SDK."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        sk = ec.generate_private_key(ec.SECP256R1())
        spki = sk.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        v = wire.ECDSAP256Verifier(spki, kid="kms-1")
        msg = b'{"chain_id":"c","head":"h","seq":3,"ts":0,"v":1}'
        sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
        self.assertTrue(v.verify(msg, sig)); self.assertFalse(v.verify(msg + b"x", sig))
        with self.assertRaises(RuntimeError):
            v.sign(b"x")

    def test_private_key_round_trips_through_raw_bytes(self):
        raw = self.signer.private_bytes_raw()                             # what a key file stores (32 bytes)
        self.assertEqual(len(raw), 32)
        again = wire.Ed25519Signer.from_private_bytes(raw, kid="prod-1")
        self.assertEqual(again.public_bytes_raw(), self.signer.public_bytes_raw())
        self.assertTrue(self.signer.verify(b"m", again.sign(b"m")))


class TestEd25519SignerMissingDependency(unittest.TestCase):
    """Simulate `cryptography` being unavailable (regardless of whether it
    actually is installed in THIS environment) and assert Ed25519Signer
    fails with a clear, actionable ImportError instead of a confusing
    traceback — and that nothing about constructing/using HS256TestSigner
    or calling serialize()/load() with it ever touches `cryptography`."""

    def test_clear_import_error_when_cryptography_missing(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("simulated: cryptography not installed")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = fake_import
        try:
            with self.assertRaises(ImportError) as ctx:
                wire.Ed25519Signer.generate()
            msg = str(ctx.exception)
            self.assertIn("cryptography", msg)
            self.assertIn("pip install", msg)
            self.assertIn("HS256TestSigner", msg)

            # HS256 path must be entirely unaffected by cryptography being
            # "unavailable" — it never imports it in the first place.
            signer = wire.HS256TestSigner(b"k")
            root = Guard.issue("o", Authority({"crm.read"}, [], ttl=60))
            token = wire.serialize(root, signer)
            vc = wire.load([token], signer)
            self.assertEqual(vc.depth, 0)
        finally:
            builtins.__import__ = real_import


# =========================================================================
# Interop vectors (tests/vectors/*.json) — regenerated deterministically at
# the start of this run, then loaded back from disk and verified against
# THIS build, so the vectors are self-checking.
# =========================================================================
class TestInteropVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors_dir = _ROOT / "tests" / "vectors"
        cls.written = vectors_generate.generate_all(cls.vectors_dir)

    def test_generator_wrote_every_expected_file(self):
        expected = {
            "valid_chain.json", "reject_widened_scope.json",
            "reject_exceeded_ceiling.json", "reject_spliced_parent.json",
            "reject_depth_exceeded.json", "reject_nonmonotonic_exp.json",
            "reject_bad_signature.json", "reject_wildcard_widening.json",
        }
        self.assertEqual(set(self.written), expected)
        for filename in expected:
            self.assertTrue((self.vectors_dir / filename).exists())

    def test_valid_chain_vector_is_accepted(self):
        data = json.loads((self.vectors_dir / "valid_chain.json").read_text())
        self.assertEqual(data["expect"], "accept")
        signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]),
                                      kid=data["signer"]["kid"])
        vc = wire.load(data["tokens"], signer, now=data["now"])
        self.assertGreaterEqual(vc.depth, 0)

    def test_every_reject_vector_is_rejected_with_its_declared_reason(self):
        for filename in sorted(self.written):
            if not filename.startswith("reject_"):
                continue
            with self.subTest(vector=filename):
                data = json.loads((self.vectors_dir / filename).read_text())
                signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]),
                                              kid=data["signer"]["kid"])
                with self.assertRaises(wire.WireError) as ctx:
                    wire.load(data["tokens"], signer, now=data["now"])
                self.assertEqual(ctx.exception.reason, data["expect_reject_reason"])

    def test_vectors_are_byte_deterministic_across_regeneration(self):
        # No randomness anywhere on the wire path (no uuid4, no time.time()):
        # regenerating must reproduce identical JSON, token-for-token.
        again = vectors_generate.generate_all(self.vectors_dir)
        self.assertEqual(self.written, again)


# =========================================================================
# The SHIPPED copy of the vectors (src/attenu_guard/vectors/) — package data,
# so `pip install attenu-guard` carries them and an independent implementation
# in any language can score itself without cloning this repository.
# =========================================================================
class TestPackagedVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # generate.py is the single writer for BOTH copies; run it here too so
        # this class does not depend on another class having run first.
        cls.written = vectors_generate.generate_all()
        cls.repo_dir = _REPO_VECTORS_DIR
        cls.package_dir = _PACKAGE_VECTORS_DIR

    def test_the_two_committed_copies_are_byte_identical(self):
        # The guard against drift: one artifact, serialised once, written to two
        # places. Asserted on what was COMMITTED (snapshotted at import), so a
        # copy edited by hand fails here rather than being quietly regenerated.
        self.assertEqual(sorted(COMMITTED_PACKAGE_VECTORS), sorted(vectors.VECTOR_NAMES))
        self.assertEqual(sorted(COMMITTED_REPO_VECTORS), sorted(vectors.VECTOR_NAMES))
        for filename in vectors.VECTOR_NAMES:
            with self.subTest(vector=filename):
                self.assertEqual(COMMITTED_PACKAGE_VECTORS[filename],
                                 COMMITTED_REPO_VECTORS[filename])

    def test_the_generator_writes_both_copies_identically(self):
        # ...and the complement: that the writer itself cannot start emitting
        # different bytes to the two destinations.
        self.assertEqual(sorted(self.written), sorted(vectors.VECTOR_NAMES))
        for filename in sorted(self.written):
            with self.subTest(vector=filename):
                self.assertEqual((self.package_dir / filename).read_bytes(),
                                 (self.repo_dir / filename).read_bytes())

    def test_importlib_resources_reads_every_declared_vector(self):
        # The path an INSTALLED consumer takes — not a filesystem path into a
        # checkout. A file missing from a wheel fails here, not silently.
        for filename in vectors.VECTOR_NAMES:
            with self.subTest(vector=filename):
                self.assertEqual(vectors.read_vector_bytes(filename),
                                 (self.repo_dir / filename).read_bytes())
        self.assertEqual(sorted(vectors.load_vectors()), sorted(vectors.VECTOR_NAMES))
        self.assertEqual(vectors.load_vector("valid_chain.json")["expect"], "accept")

    def test_an_unknown_vector_name_is_refused(self):
        with self.assertRaises(KeyError):
            vectors.read_vector_bytes("../wire.py")

    def test_every_packaged_vector_scores_as_it_declares(self):
        # Read ONLY through the package accessor, then verify: this is exactly
        # what a third-party implementer does, minus their own verifier.
        for filename, data in vectors.load_vectors().items():
            with self.subTest(vector=filename):
                signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]),
                                              kid=data["signer"]["kid"])
                try:
                    wire.load(data["tokens"], signer, now=data["now"])
                    outcome = "accept"
                except wire.WireError as e:
                    outcome = e.reason
                self.assertEqual(outcome, data.get("expect") or data["expect_reject_reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
