"""
params.py — the `params_c14n_v1` argument commitment (docs/execution-binding spec section 4).

Two observations, two hashes: `authorized_params_hash` (on the `allow` entry, from what `check()`
was called with) and `invoked_params_hash` (on the `outcome` entry, from what the body-owning
wrapper observed immediately before the actual invocation). Substitution between them is visible
only because both exist; neither raw value is ever logged.

Commitment: `SHA-256(raw_salt || UTF8(JCS(params)))`, lowercase hex — `raw_salt` is the chain's
16-byte `params_salt` (see chain.py), fixed for the chain's lifetime; `JCS(params)` reuses
`canonical.dumps` verbatim (RFC 8785), so the numeric domain and encoding rules are identical to
every other signing surface in this library.

One extra restriction beyond what `canonical.dumps` itself enforces: `canonical.py`'s general
signing surface (audit hashes, wire tokens) already rejects an out-of-range Python `int`, but
tolerates an out-of-range INTEGRAL `float` (e.g. `1e20`) — deliberately; see
`tests/test_canonical.py`'s pinned JCS divergence-class vectors, which this module does not
touch. `params_c14n_v1` cannot tolerate that asymmetry: a cross-runtime consumer (JSON/JS has no
int/float distinction) cannot tell the two host types apart once serialized, so this profile
closes the gap itself, in front of `canonical.dumps`, without changing the shared canonicalizer.

Outside the domain (either reason): no hash, and the caller writes `params_hash_reason:
"unsupported"` on the record whose hash is absent — never raises. A caller that never attempts a
commitment at all (the `_UNSET` sentinel in guard.py) writes neither field; "unsupported" and
"never attempted" are deliberately distinguishable states, not folded into one.
"""
from __future__ import annotations

import hashlib
import math

from . import canonical

__all__ = ["ParamsHashReason", "PARAMS_C14N_VERSION", "SALT_HEX_LEN", "decode_salt", "commit"]

PARAMS_C14N_VERSION = "params_c14n_v1"
SALT_HEX_LEN = 32   # 16 raw bytes, hex-encoded


class ParamsHashReason:
    UNSUPPORTED = "unsupported"   # outside the params_c14n_v1 domain — no hash was computed
    ALL = frozenset({UNSUPPORTED})


def decode_salt(params_salt_hex: str) -> bytes:
    """The 16 raw bytes a chain's `params_salt` (32 lowercase hex chars, on the `root` entry)
    decodes to. Raises ValueError on anything else — a malformed salt must fail loudly, not
    silently hash against the wrong number of bytes."""
    raw = bytes.fromhex(params_salt_hex)
    if len(raw) != 16:
        raise ValueError(f"params_salt must decode to 16 raw bytes; got {len(raw)} from {params_salt_hex!r}")
    return raw


def _has_unsafe_integral_float(value) -> bool:
    """True if `value` contains, anywhere in its structure, a float that is mathematically
    integral and exceeds ±canonical.MAX_SAFE_INTEGER — the one gap `canonical.dumps` itself
    leaves open for floats (see the module docstring)."""
    t = type(value)
    if t is float:
        return math.isfinite(value) and value == math.trunc(value) and abs(value) > canonical.MAX_SAFE_INTEGER
    if t is dict:
        return any(_has_unsafe_integral_float(v) for v in value.values())
    if t is list or t is tuple:
        return any(_has_unsafe_integral_float(v) for v in value)
    return False


def commit(params, raw_salt: bytes) -> tuple[str | None, str | None]:
    """`(hash_hex, reason)`. `hash_hex` is the lowercase-hex `params_c14n_v1` commitment, or None
    if `params` is outside the domain — in which case `reason == ParamsHashReason.UNSUPPORTED`.
    Exactly one of the two is non-None."""
    if _has_unsafe_integral_float(params):
        return None, ParamsHashReason.UNSUPPORTED
    try:
        encoded = canonical.dumps(params)      # UTF8(JCS(params)) — canonical.dumps already returns UTF-8 bytes
    except canonical.CanonicalizationError:
        return None, ParamsHashReason.UNSUPPORTED
    h = hashlib.sha256()
    h.update(raw_salt)
    h.update(encoded)
    return h.hexdigest(), None
