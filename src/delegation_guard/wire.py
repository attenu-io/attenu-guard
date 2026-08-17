"""
wire.py — the Delegation Token: wire format + offline verification.

Reference implementation of the token defined by
docs/draft-asor-wimse-agent-delegation-chain-00.md (the Internet-Draft), per
the contract in docs/V0.2-SPEC.md's "wire.py" section. A Delegation Token is a
compact, JWT-shaped, JWS-signed object (draft {{token-format}}) that carries
one hop's `Authority` (draft {{authority}}) plus enough chain-linkage state
(`del_depth`, `del_max_depth`, `par_hash`) that an Enforcement Point can verify
an entire Delegation Chain **offline** — no call to an authorization server —
using exactly the algorithm in draft {{verify}}.

Hard constraint (docs/V0.2-SPEC.md): this module's core path is stdlib-only
(json, base64, hmac, hashlib, dataclasses, typing). The optional Ed25519
production signer needs the third-party `cryptography` package, so it is
imported lazily, INSIDE `Ed25519Signer`'s methods only — never at module import
time. Importing `wire` and using `HS256TestSigner` never requires
`cryptography` to be installed.

Design choice — determinism over wall-clock time: nothing in this module ever
calls `time.time()`. `serialize()`/`serialize_chain()` take an explicit `iat`
(default 0) and `load()` takes an explicit `now` (default 0); callers supply
real timestamps when they have them. This is deliberate, not an oversight: (a)
it keeps test vectors and interop fixtures byte-for-byte reproducible, and (b)
the in-process `Chain`'s injected clock (`chain.py`'s `MonotonicClock`, or a
test double) is a *relative* clock used only for local TTL bookkeeping
(`time.monotonic()`-style — no epoch meaning) and must never leak onto the
wire as if it were an epoch timestamp.

Interface note — `del_max_depth` vs. `Chain.max_depth` (an off-by-one this
module resolves deliberately, not a bug): the draft defines `del_max_depth` as
"the maximum permitted chain LENGTH" (a token *count*), and its verification
step 3 checks `n < del_max_depth` where `n` is the leaf's `del_depth` (a
0-based index, so chain length = n + 1). `chain.py`'s `Chain.max_depth`,
by contrast, bounds the maximum *depth index* a node may reach
(`add_child` rejects when `parent.depth + 1 > self.max_depth`, so a chain
built up to that ceiling has a root at depth 0 and a deepest leaf at depth
`max_depth` — i.e. `max_depth + 1` tokens). Emitting `del_max_depth =
chain.max_depth` verbatim would therefore make the *deepest chain the library
itself will ever construct* fail its own wire verification (n == del_max_depth
=> not < del_max_depth). So when `del_max_depth` is derived from a `Guard`
(the normal path), this module emits `chain.max_depth + 1` — the equivalent
bound restated in the draft's own units — so that "the library would have
allowed building this chain" and "the offline verifier accepts this chain"
stay the same claim, exactly as `Authority.is_narrower_than` already
guarantees for attenuation itself (see authority.py's module docstring).

Out of scope for v0.2 (documented, not silently dropped — see `load()`):
holder-binding / DPoP proof verification (draft {{binding}}) and Token Status
List revocation (draft {{revocation}}) — draft {{verify}} steps 6 and 7.
Neither `cnf` nor a status-list reference is checked by `load()` here.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Mapping, Protocol, runtime_checkable

from .authority import Authority
from .reasons import Decision, ReasonCode

__all__ = [
    "Signer", "HS256TestSigner", "Ed25519Signer",
    "WireError", "WireReasonCode", "VerifiedChain",
    "serialize", "serialize_chain", "load",
    "b64url_encode", "b64url_decode",
]


# =========================================================================
# base64url helpers (stdlib `base64`, padding stripped per RFC 7515 §2)
# =========================================================================

def b64url_encode(data: bytes) -> str:
    """RFC 7515 base64url: standard base64 with `+`/`/` -> `-`/`_`, no `=` padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Inverse of `b64url_encode`; re-pads to a multiple of 4 before decoding."""
    if isinstance(s, bytes):
        s = s.decode("ascii")
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _canonical_json(obj) -> bytes:
    # Deterministic bytes for a given dict: same key order every time
    # (sort_keys), no incidental whitespace (compact separators). This is
    # what makes `par_hash` reproducible and independent of dict insertion
    # order — mirrors audit.py's `_canonical`/chain.py's `_seal`.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _encode_part(obj: dict) -> str:
    return b64url_encode(_canonical_json(obj))


# =========================================================================
# Signer protocol + the two shipped implementations
# =========================================================================

@runtime_checkable
class Signer(Protocol):
    """The pluggable signing/verification backend a Delegation Token is
    minted and checked against. `alg` is the JOSE algorithm identifier that
    goes in the token header (draft {{token-format}}: "a fully-specified
    algorithm {{RFC9864}}")."""
    alg: str

    def sign(self, signing_input: bytes) -> bytes: ...

    def verify(self, signing_input: bytes, sig: bytes, key_id: str | None) -> bool: ...


@dataclass(frozen=True)
class HS256TestSigner:
    """stdlib HMAC-SHA256 signer (`hmac` + `hashlib` only). This is the
    DEFAULT signer for tests, examples, and local dev — it needs no
    third-party install.

    NOT FOR PRODUCTION. HMAC is symmetric: `sign()` and `verify()` use the
    identical secret, so anyone able to *verify* a token is also able to
    *forge* one. That precludes the property the draft is built around —
    "public offline verification at an untrusted enforcement point"
    (draft {{security}}, "Why not macaroons") — because every verifier would
    have to hold the minting secret. Use `Ed25519Signer` in production; this
    class exists purely so the wire format, `load()`'s verification
    algorithm, and the interop test vectors can be exercised end-to-end with
    zero installs.
    """
    secret: bytes
    kid: str = "test"
    alg: str = field(default="HS256", init=False, repr=False)

    def sign(self, signing_input: bytes) -> bytes:
        return hmac.new(self.secret, signing_input, hashlib.sha256).digest()

    def verify(self, signing_input: bytes, sig: bytes, key_id: str | None = None) -> bool:
        # key_id is accepted for interface parity with multi-key signers but
        # not used for key *selection* here — this signer holds exactly one
        # secret, so there is nothing to look up. Comparison is
        # constant-time (hmac.compare_digest) to avoid a signature-forgery
        # timing oracle.
        expected = self.sign(signing_input)
        return hmac.compare_digest(expected, sig)


def _require_ed25519():
    """Lazily import the one `cryptography` submodule Ed25519Signer needs.
    Called only from inside Ed25519Signer's methods (see the class) — never
    at module import time, so `import delegation_guard.wire` and
    `HS256TestSigner` never require `cryptography` to be installed."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:
        raise ImportError(
            "Ed25519Signer requires the optional 'cryptography' package, "
            "which is not installed in this environment. Install it with:\n\n"
            "    pip install cryptography\n\n"
            "For dependency-free tests/dev with no install required, use "
            "delegation_guard.wire.HS256TestSigner instead — but note that "
            "signer is symmetric (HMAC) and explicitly NOT for production; "
            "see its docstring."
        ) from e
    return ed25519


class Ed25519Signer:
    """The production signer per the draft ("Implementations MUST support
    Ed25519 {{RFC8032}} {{RFC8037}}", draft {{token-format}}); JOSE alg
    "EdDSA". Public-key, so — unlike `HS256TestSigner` — a verifier never
    needs the signing secret, which is exactly the property the draft
    requires for offline verification at an untrusted edge.

    Requires the optional `cryptography` package. That import is lazy and
    happens ONLY inside this class's methods (`__init__`, `public_bytes_raw`)
    — never at module scope — so the stdlib-only core keeps working with zero
    installs when `cryptography` isn't present; only constructing an
    `Ed25519Signer` requires it, with a clear, actionable `ImportError` if
    it's missing (see `_require_ed25519`).
    """
    alg = "EdDSA"

    def __init__(self, private_key=None, *, kid: str = "ed25519-1"):
        ed25519 = _require_ed25519()
        if private_key is None:
            private_key = ed25519.Ed25519PrivateKey.generate()
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.kid = kid

    @classmethod
    def generate(cls, *, kid: str = "ed25519-1") -> "Ed25519Signer":
        """Convenience: a signer wrapping a freshly generated keypair."""
        return cls(kid=kid)

    def sign(self, signing_input: bytes) -> bytes:
        return self._private_key.sign(signing_input)

    def verify(self, signing_input: bytes, sig: bytes, key_id: str | None = None) -> bool:
        try:
            self._public_key.verify(sig, signing_input)
            return True
        except Exception:
            # cryptography raises InvalidSignature (and, for malformed input,
            # other exception types); any failure to verify means "no".
            return False

    def public_bytes_raw(self) -> bytes:
        """The 32-byte raw Ed25519 public key — for distributing a trust
        anchor out of band or embedding in a JWK. Lazily imports
        `cryptography.hazmat.primitives.serialization`, same discipline as
        `__init__`."""
        from cryptography.hazmat.primitives import serialization
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


# =========================================================================
# Errors / reason codes
# =========================================================================

class WireReasonCode:
    """Wire-verification-specific reason codes, string constants (same
    pattern as reasons.ReasonCode — see that module). `EXPIRED` is not
    reinvented: it aliases `reasons.ReasonCode.EXPIRED` verbatim (identical
    string, identical meaning: a time-bound invariant failed), covering both
    "now is past exp" and "exp is not monotonic along the chain" — the draft
    treats both as the same class of check (draft {{verify}} step 5)."""
    SIGNATURE_INVALID = "signature_invalid"
    PAR_HASH_MISMATCH = "par_hash_mismatch"
    DEPTH_INVALID = "depth_invalid"
    NOT_NARROWER = "not_narrower"
    MALFORMED = "malformed"
    EXPIRED = ReasonCode.EXPIRED  # "expired" — reuse, don't reinvent


class WireError(Exception):
    """Raised by `load()` on the FIRST verification failure (draft
    {{verify}}: "denying on the first failure") — offline chain verification
    is fail-fast/fail-closed, not an aggregation of every problem found."""

    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason}: {message}" if message else reason)


# =========================================================================
# Authority <-> authorization_details (draft {{authority}})
# =========================================================================

def _authority_detail(authority: Authority) -> dict:
    """One RFC 9396 authorization detail object for `authority`, per draft
    {{authority}}. Built from the CORE's own `Authority.to_wire()` (never
    hand-rolled) — `ttl` is deliberately dropped here: token lifetime is
    carried once, at the top level, via the standard `iat`/`exp` claims
    (RFC 9068), not duplicated inside authorization_details where it could
    drift out of sync with them."""
    wire = authority.to_wire()
    return {
        "type": "agent_delegation",
        "scopes": wire["scopes"],
        "constraints": wire["constraints"],
    }


def _authority_from_payload(payload: Mapping) -> Authority:
    """Inverse of `_authority_detail`, reconstituting the FULL Authority
    (including ttl, recovered as `exp - iat`) so that `load()` can hand the
    exact same `Authority.is_narrower_than` the core uses for attenuation —
    see draft {{subsumption}} vs. authority.py's `is_narrower_than` docstring
    ("the library relation and the token relation MUST be identical")."""
    details = payload.get("authorization_details")
    if not isinstance(details, list) or not details:
        raise WireError(WireReasonCode.MALFORMED, "authorization_details missing or empty")
    d0 = details[0]
    if not isinstance(d0, Mapping) or d0.get("type") != "agent_delegation":
        raise WireError(WireReasonCode.MALFORMED,
                         "authorization_details[0].type must be 'agent_delegation'")
    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
        raise WireError(WireReasonCode.MALFORMED, "iat/exp missing or not numeric")
    wire = {
        "scopes": d0.get("scopes", []),
        "constraints": d0.get("constraints", []),
        "ttl": exp - iat,
    }
    try:
        return Authority.from_wire(wire)
    except Exception as e:  # malformed constraint shape etc.
        raise WireError(WireReasonCode.MALFORMED, f"invalid authorization_details: {e}") from e


# =========================================================================
# Node/Guard duck-typing — accept either a Guard or a bare chain.Node
# =========================================================================

def _resolve(guard_or_node):
    """Return (node, chain_or_None). `Guard` (the normal case) carries both
    `._node` and `._chain` — the latter is what lets a ROOT token learn its
    `del_max_depth`. A bare `chain.Node` has no chain reference, so
    `del_max_depth` must be supplied explicitly via `serialize(...,
    max_depth=...)` when serializing a root Node standalone."""
    node = getattr(guard_or_node, "_node", guard_or_node)
    for attr in ("authority", "agent_id", "depth", "node_id"):
        if not hasattr(node, attr):
            raise TypeError(
                f"serialize() needs a Guard or a chain.Node-like object "
                f"(missing {attr!r}); got {type(guard_or_node).__name__}")
    chain = getattr(guard_or_node, "_chain", None)
    return node, chain


# =========================================================================
# serialize() — one Delegation Token
# =========================================================================

def _build_token(node, signer: Signer, *, iss: str, aud, jti, iat: int,
                  del_max_depth: int | None, par_hash: str | None) -> str:
    authority = node.authority
    if authority.ttl is None:
        raise WireError(
            WireReasonCode.MALFORMED,
            "Authority.ttl is None; a Delegation Token requires a finite "
            "ttl to compute the required 'exp' claim (RFC 9068)")

    header = {"typ": "at+jwt", "alg": signer.alg, "kid": getattr(signer, "kid", None)}
    payload = {
        "iss": iss,
        "sub": node.agent_id,
        "aud": aud,
        "iat": iat,
        "exp": iat + authority.ttl,
        "jti": jti if jti is not None else node.node_id,
        "authorization_details": [_authority_detail(authority)],
        "del_depth": node.depth,
    }
    if del_max_depth is not None:
        payload["del_max_depth"] = del_max_depth
    if par_hash is not None:
        payload["par_hash"] = par_hash

    header_b64 = _encode_part(header)
    payload_b64 = _encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = b64url_encode(signer.sign(signing_input))
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def serialize(guard_or_node, signer: Signer, *, iss: str = "delegation-guard",
              aud=None, jti: str | None = None, iat: int = 0,
              max_depth: int | None = None) -> str:
    """Emit ONE Delegation Token for `guard_or_node` (a `Guard`, or a bare
    `chain.Node`) as a compact JWT: `b64url(header).b64url(payload).b64url(sig)`.

    Header: `{"typ":"at+jwt","alg":signer.alg,"kid":<signer.kid>}`.
    Payload: the RFC 9068 access-token claims (`iss`, `sub`=agent_id, `aud`,
    `iat`, `exp`=iat+ttl, `jti`), `authorization_details` built from
    `Authority.to_wire()` (draft {{authority}}), and `del_depth`. The ROOT
    token (`node.depth == 0`) additionally carries `del_max_depth`: sourced
    from `guard._chain.max_depth + 1` when a `Guard` was passed (see the
    module docstring for the "+1" — it is intentional, not an off-by-one
    bug), or from the explicit `max_depth=` kwarg when serializing a bare
    root `Node` with no chain reference.

    This function never sets `par_hash` — that is chain-linkage state
    (draft {{chain-linkage}}), meaningful only in the context of a specific
    parent token's exact bytes, and is the job of `serialize_chain()`.

    `iat` defaults to 0 and is never derived from a real clock (see the
    module docstring on determinism) — pass a real epoch-seconds value
    explicitly if you want one.
    """
    node, chain = _resolve(guard_or_node)
    del_max_depth = None
    if node.depth == 0:
        if max_depth is not None:
            del_max_depth = max_depth
        elif chain is not None:
            del_max_depth = chain.max_depth + 1
        else:
            raise WireError(
                WireReasonCode.MALFORMED,
                "root token (depth 0) requires del_max_depth; pass a Guard "
                "(reads chain.max_depth) or serialize(..., max_depth=N)")
    return _build_token(node, signer, iss=iss, aud=aud, jti=jti, iat=iat,
                        del_max_depth=del_max_depth, par_hash=None)


# =========================================================================
# serialize_chain() — every node root -> leaf, linked by par_hash
# =========================================================================

def _root_to_leaf_path(chain, leaf_node_id: str) -> list:
    """Walk `chain.nodes` from `leaf_node_id` up via `.parent_id` to the
    root, then reverse -> root-first order (draft order: DT_0 ... DT_n)."""
    path = []
    nid = leaf_node_id
    while nid is not None:
        node = chain.nodes[nid]
        path.append(node)
        nid = node.parent_id
    path.reverse()
    return path


def serialize_chain(leaf_guard, signer: Signer, *, iss: str = "delegation-guard",
                    aud=None, iat: int = 0) -> list[str]:
    """Serialize every node from root to `leaf_guard`, inclusive, as a
    Delegation Chain: `[DT_0, DT_1, ..., DT_n]` (draft {{chain-linkage}}).

    `leaf_guard` MUST be a `Guard` (chain traversal needs `._chain`, unlike
    the single-token `serialize()`, which also accepts a bare `Node`).

    Every DT_i for i > 0 carries `par_hash` = base64url(SHA-256(DT_{i-1}'s
    JWS Signing Input)) — the exact bytes `ASCII(b64url(header)) + "." +
    ASCII(b64url(payload))` of the PARENT token, per draft {{token-format}}.
    This is the byte-commitment that binds a child to one specific parent's
    serialized bytes and makes chain splicing detectable (draft
    {{security}}, "Chain splicing").

    All tokens share one `iat`/`iss`/`aud` and are signed by the same
    `signer` (see `load()`'s docstring for why: this reference
    implementation treats one signer as one trust anchor for a whole chain).
    Using a single shared `iat` also means `exp = iat + ttl` is automatically
    non-increasing along the chain for free, because `ttl` itself can only
    narrow (see `Authority.meet`) — `load()` still checks `exp` monotonicity
    independently and explicitly (draft {{verify}} step 5), since a
    real-world chain minted over time, with different `iat` per hop, is not
    guaranteed that for free.
    """
    node, chain = _resolve(leaf_guard)
    if chain is None:
        raise TypeError(
            "serialize_chain() requires a Guard (needs chain traversal via "
            "._chain); got a bare Node with no chain reference")

    path = _root_to_leaf_path(chain, node.node_id)
    tokens: list[str] = []
    prev_signing_input: bytes | None = None
    for n in path:
        del_max_depth = chain.max_depth + 1 if n.depth == 0 else None
        par_hash = None
        if n.depth != 0:
            par_hash = b64url_encode(hashlib.sha256(prev_signing_input).digest())
        token = _build_token(n, signer, iss=iss, aud=aud, jti=None, iat=iat,
                             del_max_depth=del_max_depth, par_hash=par_hash)
        header_b64, payload_b64, _sig_b64 = token.split(".")
        prev_signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        tokens.append(token)
    return tokens


# =========================================================================
# load() — the offline verification algorithm (draft {{verify}})
# =========================================================================

@dataclass(frozen=True)
class VerifiedChain:
    """The result of a chain that passed every check in `load()`. Carries
    only what an Enforcement Point needs post-verification: the leaf's
    Authority (the only authority that ever gets checked against an
    attempted action — draft {{verify}} step 8) and enough of the raw
    material for logging/debugging."""
    tokens: tuple[str, ...]
    payloads: tuple[dict, ...]
    leaf_authority: Authority
    depth: int
    del_max_depth: int

    def permits(self, scope: str, ctx: Mapping | None = None) -> Decision:
        """Authorize `scope` (with request context `ctx`) against the LEAF
        authority — draft {{verify}} step 8. Delegates entirely to
        `Authority.permits`; no policy logic is reimplemented here."""
        return self.leaf_authority.permits(scope, ctx)


def _parse_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise WireError(WireReasonCode.MALFORMED,
                        f"expected 3 dot-separated parts, got {len(parts)}")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        sig = b64url_decode(sig_b64)
    except Exception as e:
        raise WireError(WireReasonCode.MALFORMED, f"could not decode token: {e}") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise WireError(WireReasonCode.MALFORMED, "header/payload must be JSON objects")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return header, payload, sig, signing_input


def load(tokens: list[str], signer: Signer, *, root_key_ids=None, now: int = 0) -> VerifiedChain:
    """Run the Offline Verification Algorithm (draft {{verify}}) over
    `tokens` (`[DT_0, ..., DT_n]`, root-first) and, on success, return a
    `VerifiedChain`. Denies on the FIRST failure by raising `WireError`
    (`.reason` is one of the `WireReasonCode` constants) — this mirrors the
    draft's own wording ("denying on the first failure") and this library's
    general fail-closed posture (see ceilings.py's unknown-constraint
    handling for the same philosophy elsewhere in the codebase).

    `signer` verifies every token in the chain — this reference
    implementation's simplifying trust model is ONE signer/key material per
    whole chain (matching `serialize_chain`, which signs every hop with the
    same `signer`). `root_key_ids`, if given, additionally restricts which
    `kid` the ROOT token (DT_0) may present ("DT_0 MUST verify under a
    trusted root key" — draft {{verify}} step 1); a production multi-issuer
    deployment would generalize `signer` into a `kid`-keyed resolver, which
    is a straightforward extension left out of this reference implementation.

    Steps performed, in the draft's own order:
      1. JWS signature of every DT_i (+ alg-confusion guard: the header's
         declared `alg` must equal `signer.alg` — never trust the header's
         own claim about which algorithm verifies it).
      2. `par_hash` byte-commitment for every i > 0, compared in constant
         time (`hmac.compare_digest`, over hex digests).
      3. `del_depth`/`del_max_depth` bounds.
      4. Subsumption: `Authority.from_wire(DT_i) .is_narrower_than
         Authority.from_wire(DT_{i-1})` for every i > 0 — REUSES the core's
         own relation (authority.py); not reimplemented here.
      5. Time: `now <= exp` (and `now >= nbf` if present) for every DT_i, and
         `exp` non-increasing along the chain.

    OUT OF SCOPE for v0.2 (not silently skipped — documented here and in the
    module docstring): step 6 (`cnf`/DPoP holder-binding proof) and step 7
    (Token Status List revocation). Neither is checked.
    """
    if not tokens:
        raise WireError(WireReasonCode.MALFORMED, "empty token chain")

    parsed = [_parse_token(t) for t in tokens]

    # ---- step 1: signatures ------------------------------------------------
    for i, (header, _payload, sig, signing_input) in enumerate(parsed):
        if header.get("alg") != signer.alg:
            raise WireError(WireReasonCode.SIGNATURE_INVALID,
                            f"token[{i}] header alg {header.get('alg')!r} != "
                            f"signer alg {signer.alg!r}")
        kid = header.get("kid")
        if i == 0 and root_key_ids is not None and kid not in root_key_ids:
            raise WireError(WireReasonCode.SIGNATURE_INVALID,
                            f"root token kid {kid!r} not in trusted root_key_ids")
        if not signer.verify(signing_input, sig, kid):
            raise WireError(WireReasonCode.SIGNATURE_INVALID,
                            f"token[{i}] signature does not verify")

    # ---- step 2: par_hash byte-commitment (constant-time, over hex) -------
    if "par_hash" in parsed[0][1]:
        raise WireError(WireReasonCode.MALFORMED,
                        "DT_0 (del_depth 0) MUST NOT carry par_hash")
    for i in range(1, len(parsed)):
        prev_signing_input = parsed[i - 1][3]
        expected_hex = hashlib.sha256(prev_signing_input).hexdigest()
        got_b64 = parsed[i][1].get("par_hash")
        if not isinstance(got_b64, str):
            raise WireError(WireReasonCode.PAR_HASH_MISMATCH,
                            f"token[{i}] missing par_hash")
        try:
            got_hex = b64url_decode(got_b64).hex()
        except Exception as e:
            raise WireError(WireReasonCode.MALFORMED,
                            f"token[{i}] par_hash is not valid base64url: {e}") from e
        if not hmac.compare_digest(expected_hex, got_hex):
            raise WireError(WireReasonCode.PAR_HASH_MISMATCH,
                            f"token[{i}] par_hash does not match parent token[{i-1}]'s "
                            f"signing input (splice, wrong parent, or tampered parent)")

    # ---- step 3: del_depth / del_max_depth ---------------------------------
    root_payload = parsed[0][1]
    if root_payload.get("del_depth") != 0:
        raise WireError(WireReasonCode.DEPTH_INVALID, "DT_0.del_depth must be 0")
    del_max_depth = root_payload.get("del_max_depth")
    if not isinstance(del_max_depth, int) or isinstance(del_max_depth, bool) or del_max_depth <= 0:
        raise WireError(WireReasonCode.DEPTH_INVALID,
                        "DT_0.del_max_depth must be a positive integer")
    n = len(parsed) - 1
    if not (n < del_max_depth):
        raise WireError(WireReasonCode.DEPTH_INVALID,
                        f"chain length {n + 1} exceeds del_max_depth {del_max_depth} "
                        f"(need leaf del_depth {n} < del_max_depth)")
    for i, (_h, payload, _s, _si) in enumerate(parsed):
        if payload.get("del_depth") != i:
            raise WireError(WireReasonCode.DEPTH_INVALID,
                            f"token[{i}].del_depth = {payload.get('del_depth')!r}, expected {i}")

    # ---- step 4: subsumption (reuse Authority.is_narrower_than) -----------
    authorities = [_authority_from_payload(p) for (_h, p, _s, _si) in parsed]
    for i in range(1, len(authorities)):
        if not authorities[i].is_narrower_than(authorities[i - 1]):
            raise WireError(WireReasonCode.NOT_NARROWER,
                            f"token[{i}] authority is not narrower than token[{i-1}]'s "
                            f"(widened scope, loosened/dropped ceiling, or looser ttl)")

    # ---- step 5: time -------------------------------------------------------
    prev_exp = None
    for i, (_h, payload, _s, _si) in enumerate(parsed):
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            raise WireError(WireReasonCode.MALFORMED, f"token[{i}] missing numeric exp")
        nbf = payload.get("nbf")
        if nbf is not None and now < nbf:
            raise WireError(WireReasonCode.EXPIRED,
                            f"token[{i}] not yet valid: now={now} < nbf={nbf}")
        if now > exp:
            raise WireError(WireReasonCode.EXPIRED,
                            f"token[{i}] expired: now={now} > exp={exp}")
        if prev_exp is not None and exp > prev_exp:
            raise WireError(WireReasonCode.EXPIRED,
                            f"token[{i}] exp={exp} exceeds parent token[{i-1}] exp={prev_exp} "
                            f"(exp must be monotonic non-increasing along the chain)")
        prev_exp = exp

    # ---- steps 6-7: OUT OF SCOPE for v0.2 (see docstring) ------------------
    #   step 6: cnf/DPoP holder-binding proof — not checked.
    #   step 7: Token Status List revocation — not checked.

    leaf_payload = parsed[-1][1]
    return VerifiedChain(
        tokens=tuple(tokens),
        payloads=tuple(p for (_h, p, _s, _si) in parsed),
        leaf_authority=authorities[-1],
        depth=leaf_payload.get("del_depth"),
        del_max_depth=del_max_depth,
    )
