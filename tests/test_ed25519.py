"""tests/test_ed25519.py — the stdlib Ed25519 in `attenu_guard._ed25519`, pinned against
RFC 8032's own test vectors and, where `cryptography` is installed, against OpenSSL.

This module exists so the observer-envelope corpus can be signed and scored with no
third-party dependency (see `_ed25519`'s docstring). That is only worth anything if the
implementation is actually Ed25519, which is what the RFC vectors below establish, and if it
produces the SAME bytes as the production signer, which is what makes a fixture generated on
one machine byte-identical to one generated on another.

stdlib-only (unittest), no pytest:

    python3 tests/test_ed25519.py
"""
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import _ed25519  # noqa: E402

# RFC 8032, section 7.1 ("Test Vectors for Ed25519"): (seed, public, message, signature), hex.
RFC_8032_VECTORS = [
    (  # TEST 1 — empty message
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (  # TEST 2 — one byte
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (  # TEST 3 — two bytes
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (  # TEST SHA(abc) — a 64-byte message
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]


class TestRfc8032Vectors(unittest.TestCase):
    def test_the_public_key_is_derived_from_the_seed(self):
        for seed, public, _msg, _sig in RFC_8032_VECTORS:
            with self.subTest(public=public[:16]):
                self.assertEqual(_ed25519.public_key(bytes.fromhex(seed)).hex(), public)

    def test_signing_reproduces_the_rfc_signature_byte_for_byte(self):
        # Ed25519 is deterministic: one signature per (key, message), no CSPRNG. This is the
        # property the committed envelope fixture's byte-identity rests on.
        for seed, _public, message, signature in RFC_8032_VECTORS:
            with self.subTest(signature=signature[:16]):
                got = _ed25519.sign(bytes.fromhex(seed), bytes.fromhex(message))
                self.assertEqual(got.hex(), signature)

    def test_verification_accepts_each_rfc_signature(self):
        for _seed, public, message, signature in RFC_8032_VECTORS:
            with self.subTest(public=public[:16]):
                self.assertTrue(_ed25519.verify(bytes.fromhex(public), bytes.fromhex(message),
                                                bytes.fromhex(signature)))


class TestVerificationRejects(unittest.TestCase):
    def setUp(self):
        seed, public, message, signature = RFC_8032_VECTORS[1]
        self.seed = bytes.fromhex(seed)
        self.public = bytes.fromhex(public)
        self.message = bytes.fromhex(message)
        self.signature = bytes.fromhex(signature)

    def test_a_flipped_signature_bit(self):
        bad = bytearray(self.signature)
        bad[0] ^= 0x01
        self.assertFalse(_ed25519.verify(self.public, self.message, bytes(bad)))

    def test_a_flipped_message_bit(self):
        self.assertFalse(_ed25519.verify(self.public, b"\x73", self.signature))

    def test_another_key(self):
        other = _ed25519.public_key(bytes.fromhex(RFC_8032_VECTORS[0][0]))
        self.assertFalse(_ed25519.verify(other, self.message, self.signature))

    def test_a_non_canonical_scalar_is_rejected(self):
        # S >= L is the malleability the RFC's section 5.1.7 check exists to close: without it a
        # second, different signature verifies for the same message.
        malleable = self.signature[:32] + ((int.from_bytes(self.signature[32:], "little")
                                            + _ed25519._L) % (1 << 256)).to_bytes(32, "little")
        self.assertFalse(_ed25519.verify(self.public, self.message, malleable))

    def test_malformed_inputs_return_false_rather_than_raising(self):
        self.assertFalse(_ed25519.verify(b"", self.message, self.signature))
        self.assertFalse(_ed25519.verify(self.public, self.message, b"\x00" * 63))
        # 32 bytes that decode to no point on the curve.
        self.assertFalse(_ed25519.verify(b"\xff" * 32, self.message, self.signature))


class TestAgreesWithOpenSSL(unittest.TestCase):
    """Where `cryptography` is installed, the two backends must agree — same public key, same
    signature bytes, and each verifying the other's. This is what lets the envelope generator
    prefer OpenSSL when it is there and still write identical fixture bytes when it is not."""

    def setUp(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        except ImportError:
            self.skipTest("cryptography is not installed")

    def test_both_backends_produce_the_same_bytes(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        for seed_hex, _public, message_hex, _sig in RFC_8032_VECTORS:
            with self.subTest(seed=seed_hex[:16]):
                seed, message = bytes.fromhex(seed_hex), bytes.fromhex(message_hex)
                private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                openssl_public = private.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertEqual(_ed25519.public_key(seed), openssl_public)
                openssl_sig = private.sign(message)
                self.assertEqual(_ed25519.sign(seed, message), openssl_sig)
                self.assertTrue(_ed25519.verify(openssl_public, message, openssl_sig))
                private.public_key().verify(_ed25519.sign(seed, message), message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
