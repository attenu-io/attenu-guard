"""Ed25519 (RFC 8032, PureEdDSA over edwards25519), stdlib-only.

WHY this exists, given `wire.Ed25519Signer` already wraps `cryptography`.

The observer-envelope corpus (`attenu_guard.vectors.load_envelope_vectors`) is signed with
Ed25519 — the envelope contract fixes `witness.alg` at `EdDSA` and defines no other value, so
the vectors cannot fall back to the published-secret HS256 the bundle anchors use. The corpus
also has to be scorable with nothing but `pip install attenu-guard`, which installs zero
dependencies, and it has to regenerate byte-identically in a CI job that installs none. Those
two facts together mean the package needs an Ed25519 verifier that does not require
`cryptography`. This is it.

`sign()` is here for the same reason: `tests/vectors/generate_envelopes.py` runs in that
dependency-free job. Ed25519 signatures are deterministic (RFC 8032 section 5.1.6: the nonce is
derived from the key and the message, never from a CSPRNG), so this implementation and OpenSSL
produce the SAME 64 bytes for the same key and message — which is what lets the committed
fixture be byte-identical no matter which backend generated it. `tests/test_ed25519.py` pins
that against RFC 8032's own test vectors and, where `cryptography` is installed, against it.

NOT constant-time. Big-int arithmetic in CPython branches and allocates on secret-dependent
values, so `sign()` here leaks timing about the private key and MUST NOT hold a production
signing key — use `wire.Ed25519Signer` (OpenSSL) for that. It is used in this package only to
sign fixed, published test keys. `verify()` touches no secret at all: everything it reads is
public by construction (a public key, a message, a signature), so the timing objection does not
apply to it, and it is the function the shipped corpus and the envelope verifier actually use.
"""
from __future__ import annotations

import hashlib

__all__ = ["sign", "verify", "public_key", "SIGNATURE_SIZE", "KEY_SIZE"]

#: Raw key size in bytes — a seed, and a public key, are both 32 bytes (RFC 8032 section 5.1).
KEY_SIZE = 32
#: Raw signature size in bytes: R (32) || S (32).
SIGNATURE_SIZE = 64

_P = 2**255 - 19                                                    # field prime
_L = 2**252 + 27742317777372353535851937790883648493                # order of the base point
_D = (-121665 * pow(121666, _P - 2, _P)) % _P                       # curve constant
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)                                # sqrt(-1) mod p
_BASE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _add(pt1: tuple, pt2: tuple) -> tuple:
    """Extended-coordinate point addition (X, Y, Z, T), Hisil-Wong-Carter-Dawson."""
    x1, y1, z1, t1 = pt1
    x2, y2, z2, t2 = pt2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * t1 * _D * t2) % _P
    d = (2 * z1 * z2) % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _mul(pt: tuple, scalar: int) -> tuple:
    """Scalar multiplication by double-and-add. Not constant-time — see the module docstring."""
    out = (0, 1, 1, 0)                                              # the neutral element
    while scalar > 0:
        if scalar & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        scalar >>= 1
    return out


def _equal(pt1: tuple, pt2: tuple) -> bool:
    """Projective equality: (X1/Z1, Y1/Z1) == (X2/Z2, Y2/Z2), cross-multiplied."""
    x1, y1, z1, _ = pt1
    x2, y2, z2, _ = pt2
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    """The x matching this y and sign bit on edwards25519, or None if the point is not on it."""
    if y >= _P:
        return None
    x2 = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode_point(raw: bytes) -> tuple | None:
    """Decode a 32-byte little-endian point encoding (RFC 8032 section 5.1.3), or None."""
    if len(raw) != KEY_SIZE:
        return None
    value = int.from_bytes(raw, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def _encode_point(pt: tuple) -> bytes:
    x, y, z, _ = pt
    z_inv = pow(z, _P - 2, _P)
    x, y = (x * z_inv) % _P, (y * z_inv) % _P
    return (y | ((x & 1) << 255)).to_bytes(KEY_SIZE, "little")


def _base_point() -> tuple:
    bx, by = _BASE
    return (bx, by, 1, (bx * by) % _P)


def _secret_expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != KEY_SIZE:
        raise ValueError(f"an Ed25519 seed is {KEY_SIZE} bytes, got {len(seed)}")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8            # clear the low 3 bits
    scalar |= 1 << 254                  # set bit 254, clear bit 255
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    """The 32-byte raw public key for a 32-byte private seed."""
    scalar, _ = _secret_expand(seed)
    return _encode_point(_mul(_base_point(), scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    """The 64-byte raw Ed25519 signature over `message` under the private `seed`.

    Deterministic per RFC 8032, so the bytes match any conformant implementation. Not
    constant-time: see the module docstring — published test keys only."""
    scalar, prefix = _secret_expand(seed)
    encoded_public = _encode_point(_mul(_base_point(), scalar))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    encoded_r = _encode_point(_mul(_base_point(), r))
    k = int.from_bytes(hashlib.sha512(encoded_r + encoded_public + message).digest(), "little") % _L
    s = (r + k * scalar) % _L
    return encoded_r + s.to_bytes(KEY_SIZE, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True when `signature` is a valid Ed25519 signature over `message` under `public`.

    Returns False rather than raising on any malformed input — a verifier's answer to
    "is this signature good?" is no, not an exception."""
    if len(public) != KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    point_a = _decode_point(public)
    if point_a is None:
        return False
    encoded_r = signature[:KEY_SIZE]
    point_r = _decode_point(encoded_r)
    if point_r is None:
        return False
    s = int.from_bytes(signature[KEY_SIZE:], "little")
    if s >= _L:                       # a non-canonical S is malleable; reject it (RFC 8032 §5.1.7)
        return False
    k = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % _L
    return _equal(_mul(_base_point(), s), _add(point_r, _mul(point_a, k)))
