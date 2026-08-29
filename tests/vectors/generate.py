"""
tests/vectors/generate.py — deterministic offline-verification test vectors
for the Delegation Token wire format, per
docs/draft-asor-wimse-agent-delegation-chain-00.md (the Internet-Draft).

These are the IETF interoperability artifact the draft's "Reference
Implementation and Test Vectors" section promises: a chain that MUST verify,
and a set of adversarial chains that MUST each be rejected for a specific,
declared reason — so an independent implementation (in any language) can
load these JSON files and check its own offline verifier against them
without needing this repository's Python at all.

stdlib-only, runnable with bare `python3`, no network, no randomness (every
byte is deterministic — same output on every run, on every machine):

    python3 tests/vectors/generate.py

This module is the SINGLE writer for both copies of the vectors. Each file is
serialised once and those exact bytes are written to two places: this directory,
which the README, the Internet-Draft and several docs cite by path, and
src/attenu_guard/vectors/, which ships inside the installed package so that an
independent implementation can score itself with nothing but
`pip install attenu-guard` — no clone, no repository layout to know about.
Neither copy is derived from the other, so neither can lag behind it;
tests/test_wire.py asserts they are byte-identical on every run.

See README.md in this directory for the file format and how to use these
vectors from another implementation.
"""
from __future__ import annotations   # `Path | None` in a signature, on Python 3.9

import hashlib
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import Authority, Guard, RowLimit, EgressRank  # noqa: E402
from attenu_guard import wire  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent
# The shipped copy: package data, so `pip install attenu-guard` carries the
# vectors. See attenu_guard.vectors for the accessor an installed consumer uses.
PACKAGE_VECTORS_DIR = _ROOT / "src" / "attenu_guard" / "vectors"

# A published, fixed, well-known secret — deliberately NOT a secret in any
# real sense (it's printed in this source file and in every emitted vector).
# HS256 is symmetric (see wire.HS256TestSigner's docstring): holding this
# value lets you both verify AND forge tokens, so these vectors exercise the
# wire FORMAT and the offline verification ALGORITHM, not a production trust
# boundary. They are stdlib-only on purpose, so generation and interop
# checking never require installing anything (matching this repo's
# zero-dependency test discipline).
SECRET = b"attenu-guard-interop-vectors-v1-fixed-secret"
KID = "interop-v1"


def _signer() -> wire.HS256TestSigner:
    return wire.HS256TestSigner(SECRET, kid=KID)


def _decode_payload(token: str) -> dict:
    _h, payload_b64, _s = token.split(".")
    return json.loads(wire.b64url_decode(payload_b64))


def _resign(header_b64: str, payload: dict, signer: wire.Signer) -> str:
    payload_b64 = wire._encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = wire.b64url_encode(signer.sign(signing_input))
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _sign_raw(header_json: bytes, payload_json: bytes, signer: wire.Signer) -> str:
    """Sign exact JSON bytes for parser-rejection vectors that a dict cannot represent."""
    header_b64 = wire.b64url_encode(header_json)
    payload_b64 = wire.b64url_encode(payload_json)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{wire.b64url_encode(signer.sign(signing_input))}"


def _tamper_leaf(token: str, signer: wire.Signer, mutate) -> str:
    """Mutate `token`'s payload and re-sign it. Safe to use ONLY on the last
    (leaf) token of a chain: nothing downstream references a leaf token's
    signing input via par_hash, so this cannot accidentally also trip
    par_hash_mismatch as a side effect of the tamper under test."""
    header_b64, payload_b64, _sig_b64 = token.split(".")
    payload = json.loads(wire.b64url_decode(payload_b64))
    mutate(payload)
    return _resign(header_b64, payload, signer)


def _tamper_root_and_repair_chain(tokens: list, signer: wire.Signer, mutate) -> list:
    """Mutate `tokens[0]`'s (the root's) payload, re-sign it, and propagate:
    recompute `par_hash` and re-sign every following token so the result is
    fully self-consistent (valid signatures, correct byte-commitments) EXCEPT
    for whatever specific invariant `mutate` deliberately breaks on the root.

    Needed only when the tamper target is the root: any other change to the
    root's payload changes its exact signing bytes, which would otherwise
    make the very NEXT token's par_hash stop matching — i.e. loading the
    naively-tampered chain would (correctly, but for the wrong reason) be
    rejected at the par_hash step instead of at the check this vector is
    meant to isolate.
    """
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


def _base_chain(max_depth: int = 6):
    """The canonical 3-hop chain every vector starts from: a broad
    orchestrator delegating to a read-only summarizer delegating to a
    further-restricted formatter — the same shape as
    examples/poisoned_summarizer.py, for a consistent story across the repo."""
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


def _vector(description: str, tokens: list, *, expect: str = None,
            expect_reject_reason: str = None, now: int = 0) -> dict:
    data = {
        "description": description,
        "signer": {"alg": "HS256", "kid": KID, "secret_hex": SECRET.hex()},
        "now": now,
        "tokens": tokens,
    }
    if expect is not None:
        data["expect"] = expect
    if expect_reject_reason is not None:
        data["expect_reject_reason"] = expect_reject_reason
    return data


# =========================================================================
# The one MUST-verify vector
# =========================================================================

def gen_valid_chain() -> dict:
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)
    return _vector(
        "A valid 3-hop attenuating Delegation Chain (orchestrator -> "
        "summarizer -> formatter). Each hop's Authority is strictly "
        "narrower than its parent's: scopes shrink from {crm.*, mail.send} "
        "to {crm.read}; the max_rows ceiling narrows 100000 -> 5000 -> 100; "
        "ttl narrows 3600 -> 900 -> 300. MUST verify.",
        tokens, expect="accept",
    )


# =========================================================================
# Adversarial vectors — each MUST be rejected, for the declared reason
# =========================================================================

def gen_reject_widened_scope() -> dict:
    """(a) widened scope in a child."""
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)

    def widen(payload):
        scopes = set(payload["authorization_details"][0]["scopes"])
        scopes.add("pay.transfer")  # never granted anywhere up this chain
        payload["authorization_details"][0]["scopes"] = sorted(scopes)

    tokens[-1] = _tamper_leaf(tokens[-1], signer, widen)
    return _vector(
        "Adversarial: the leaf (formatter) token's scopes are widened to "
        "include 'pay.transfer', which no ancestor granted, then re-signed. "
        "MUST be rejected: the leaf is no longer a subset of its parent's "
        "scopes (subsumption rule 1).",
        tokens, expect_reject_reason=wire.WireReasonCode.NOT_NARROWER,
    )


def gen_reject_exceeded_ceiling() -> dict:
    """(b) exceeded ceiling in a child."""
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)

    def loosen(payload):
        for c in payload["authorization_details"][0]["constraints"]:
            if c.get("key") == "max_rows":
                c["max"] = 10_000_000  # far beyond the parent's 5000

    tokens[-1] = _tamper_leaf(tokens[-1], signer, loosen)
    return _vector(
        "Adversarial: the leaf token's max_rows ceiling is loosened to "
        "10,000,000 (parent caps it at 5,000), then re-signed. MUST be "
        "rejected: the parent's constraint no longer subsumes the child's "
        "(subsumption rule 2).",
        tokens, expect_reject_reason=wire.WireReasonCode.NOT_NARROWER,
    )


def gen_reject_spliced_parent() -> dict:
    """(c) spliced parent — a real child paired with a different, broader,
    honestly-signed root it was never actually delegated under."""
    signer = _signer()
    _root, _child, leaf = _base_chain()
    real_tokens = wire.serialize_chain(leaf, signer)

    broad_root = Guard.issue(
        "attacker-controlled-broad-root",
        Authority(scopes={"crm.*", "mail.send", "pay.transfer"},
                  ceilings=[RowLimit(10**9), EgressRank("any")], ttl=999_999),
        max_depth=6,
    )
    broad_root_token = wire.serialize(broad_root, signer)

    spliced = [broad_root_token, real_tokens[1]]
    return _vector(
        "Adversarial: the real, validly-issued 'summarizer' child token "
        "(real_tokens[1] from the valid chain) is presented together with a "
        "DIFFERENT, broader, honestly-signed root token as its purported "
        "parent, instead of the root it was actually delegated under. The "
        "child's par_hash still commits to the ORIGINAL root's exact "
        "signing bytes, so it does not match this substituted root. MUST be "
        "rejected by the byte-commitment check (draft Chain Linkage) even "
        "though the substituted root is broad enough that subsumption alone "
        "would not necessarily have caught the splice.",
        spliced, expect_reject_reason=wire.WireReasonCode.PAR_HASH_MISMATCH,
    )


def gen_reject_depth_exceeded() -> dict:
    """(d) depth beyond del_max_depth."""
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)

    def shrink_max_depth(payload):
        payload["del_max_depth"] = 2  # chain has 3 tokens (leaf del_depth=2); 2 < 2 is False

    tokens = _tamper_root_and_repair_chain(tokens, signer, shrink_max_depth)
    return _vector(
        "Adversarial: the root's del_max_depth is tampered down to 2 while "
        "the chain has 3 tokens (leaf del_depth=2), violating the required "
        "'n < del_max_depth'. Every other invariant is left intact "
        "(signatures re-signed, par_hash repaired at each hop) so this "
        "vector isolates the depth check specifically. MUST be rejected.",
        tokens, expect_reject_reason=wire.WireReasonCode.DEPTH_INVALID,
    )


def gen_reject_nonmonotonic_exp() -> dict:
    """(e) non-monotonic exp.

    Shifts the leaf's `iat` AND `exp` by the same delta, simulating a leaf
    that was actually minted much later than its parent. This leaves ttl
    (exp - iat, the token's DURATION) unchanged at 300s, so subsumption
    (verification step 4 — the parent's ttl still bounds the child's) keeps
    passing; only the ABSOLUTE exp timestamp now exceeds the parent's,
    isolating the monotonic-exp check (step 5) from ttl subsumption (step
    4). Bumping only `exp` (leaving `iat` alone) would instead inflate the
    reconstructed ttl too and get caught by step 4 first as `not_narrower`
    — a real, useful failure, but the WRONG one for this vector to name.
    """
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)

    def mint_later(payload):
        delta = 100_000  # far exceeds the parent's exp (900)
        payload["iat"] += delta
        payload["exp"] += delta

    tokens[-1] = _tamper_leaf(tokens[-1], signer, mint_later)
    return _vector(
        "Adversarial: the leaf token's iat and exp are both shifted forward "
        "by 100000s (simulating a much-later minting time), then re-signed. "
        "ttl (duration) is unchanged and still satisfies subsumption, but "
        "the leaf's absolute exp now exceeds its parent's absolute exp "
        "(summarizer exp=900), breaking the required non-increasing-exp "
        "property along the chain. MUST be rejected.",
        tokens, expect_reject_reason=wire.WireReasonCode.EXPIRED,
    )


def gen_reject_bad_signature() -> dict:
    """(f) bad signature — flip a byte."""
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)

    header_b64, payload_b64, sig_b64 = tokens[-1].split(".")
    sig = bytearray(wire.b64url_decode(sig_b64))
    sig[0] ^= 0xFF  # flip a byte
    tokens[-1] = f"{header_b64}.{payload_b64}.{wire.b64url_encode(bytes(sig))}"
    return _vector(
        "Adversarial: one byte of the leaf token's signature is flipped "
        "(no re-sign — the point is a corrupted/forged signature). MUST be "
        "rejected.",
        tokens, expect_reject_reason=wire.WireReasonCode.SIGNATURE_INVALID,
    )


def gen_reject_wildcard_widening() -> dict:
    """(g) wildcard widening — a child claiming a wildcard its parent never held.

    The inverse of the accepting direction valid_chain.json already exercises,
    where the summarizer's concrete 'crm.read' sits legitimately UNDER the
    root's 'crm.*'. Turning that round is an attenuation break, not a
    formatting one, and it is the case a verifier is most likely to get wrong:
    'crm.*' and 'crm.read' plainly relate to each other, so a matcher that
    asks only whether a parent scope and a child scope are wildcard-COMPATIBLE
    — rather than whether the parent's set COVERS the child's — accepts it in
    both directions and lets a leaf hand itself crm.export and crm.delete.
    """
    signer = _signer()
    _root, _child, leaf = _base_chain()
    tokens = wire.serialize_chain(leaf, signer)

    def widen_to_wildcard(payload):
        # The parent (summarizer) holds exactly {'crm.read'} — a concrete scope,
        # never a wildcard — so nothing up this chain grants 'crm.*' to a leaf.
        payload["authorization_details"][0]["scopes"] = ["crm.*"]

    tokens[-1] = _tamper_leaf(tokens[-1], signer, widen_to_wildcard)
    return _vector(
        "Adversarial: the leaf (formatter) token's scopes are replaced with "
        "the wildcard 'crm.*', then re-signed. Its parent (summarizer) holds "
        "only the concrete scope 'crm.read', so the leaf now claims strictly "
        "more than its parent ever held — 'crm.*' also covers crm.export, "
        "crm.delete and every other crm scope. This is the INVERSE of the "
        "legitimate direction in valid_chain.json, where a concrete "
        "'crm.read' sits under a 'crm.*' parent: wildcards narrow downward "
        "only. MUST be rejected: a child's wildcard is permitted only when an "
        "ancestor granted a wildcard that covers it, so a verifier that "
        "merely tests whether the parent's and child's scopes are "
        "wildcard-compatible, without checking WHICH side is the broader one, "
        "will wrongly accept this (subsumption rule 1).",
        tokens, expect_reject_reason=wire.WireReasonCode.NOT_NARROWER,
    )


def gen_reject_wildcard_boundary() -> dict:
    """(h) wildcard prefix boundary — a child claiming a NEIGHBOURING namespace
    that merely shares the parent wildcard's letters.

    reject_wildcard_widening.json covers a child claiming a wildcard its parent
    never held; this covers the other half of the same rule, where the wildcard
    is the PARENT's and the question is how far it reaches. 'crm.*' covers
    'crm.' + anything, so the boundary is the separator, not the letters: a
    verifier that implements the wildcard by stripping '.*' and asking
    scope.startswith('crm') accepts 'crmx.read', because that string does start
    with 'crm' — and an attacker who wants a namespace next door to the one it
    was granted writes exactly that. The reference implementation strips only
    the '*' and keeps the dot (Authority._scope_covers), so the neighbouring
    namespace does not match.
    """
    signer = _signer()
    _root, child, _leaf = _base_chain()
    # Presented as the 2-hop prefix of the canonical chain, so the token under
    # test is the LEAF and _tamper_leaf is safe: the parent whose wildcard is at
    # issue is the root, and no par_hash downstream commits to what we change.
    tokens = wire.serialize_chain(child, signer)

    def hop_the_boundary(payload):
        # The root holds {'crm.*', 'mail.send'}; 'crmx.read' shares the wildcard's
        # letters but not its segment boundary, so no ancestor grants it.
        payload["authorization_details"][0]["scopes"] = ["crmx.read"]

    tokens[-1] = _tamper_leaf(tokens[-1], signer, hop_the_boundary)
    return _vector(
        "Adversarial: the leaf (summarizer) token's scopes are replaced with "
        "'crmx.read', then re-signed, under a root that holds the wildcard "
        "'crm.*'. MUST be rejected: 'crm.*' covers 'crm.' followed by anything, "
        "so it reaches crm.read and crm.export but stops at the segment "
        "boundary — 'crmx.read' is a different namespace, granted by no "
        "ancestor. This vector exists because the boundary is exactly what a "
        "prefix match loses: a verifier that strips the '.*' and tests "
        "scope.startswith('crm') accepts 'crmx.read', since that string does "
        "start with 'crm'. Stripping only the '*' — keeping the dot, and "
        "testing startswith('crm.') — is the correct rule (subsumption rule 1).",
        tokens, expect_reject_reason=wire.WireReasonCode.NOT_NARROWER,
    )


# =========================================================================
# RFC 8785 separating vectors
# =========================================================================

def _jcs_probe(value, *, agent_id: str = "jcs-probe") -> list[str]:
    signer = _signer()
    root = Guard.issue(agent_id, Authority({"probe.read"}, [], ttl=60), max_depth=1)
    token = wire.serialize(root, signer)
    header_b64, payload_b64, _signature = token.split(".")
    payload = json.loads(wire.b64url_decode(payload_b64))
    payload["jcs_probe"] = value
    return [_resign(header_b64, payload, signer)]


def gen_valid_jcs_integral_float() -> dict:
    return _vector(
        "JCS separating case: an integral binary64 value is emitted as 100, not 100.0.",
        _jcs_probe(100.0), expect="accept",
    )


def gen_valid_jcs_exponent_form() -> dict:
    return _vector(
        "JCS separating case: 1e-6 and 1e16 use ECMAScript decimal form at both boundaries.",
        _jcs_probe([1e-6, 1e16]), expect="accept",
    )


def gen_valid_jcs_non_ascii() -> dict:
    return _vector(
        "JCS separating case: a non-ASCII subject is raw UTF-8 rather than an ASCII escape.",
        _jcs_probe("non-ascii", agent_id="r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}"),
        expect="accept",
    )


def gen_valid_jcs_utf16_key_order() -> dict:
    return _vector(
        "JCS separating case: object member names are ordered by UTF-16 code units.",
        _jcs_probe({"\ue000": 2, "\U00010000": 1}), expect="accept",
    )


def gen_valid_jcs_big_integer() -> dict:
    return _vector(
        "JCS separating case: Python's arbitrary-precision integer is serialized through binary64.",
        _jcs_probe(2**60 + 1), expect="accept",
    )


def _raw_valid_root() -> tuple[bytes, bytes, wire.Signer]:
    signer = _signer()
    root = Guard.issue("parser-probe", Authority({"probe.read"}, [], ttl=60), max_depth=1)
    header_b64, payload_b64, _signature = wire.serialize(root, signer).split(".")
    return wire.b64url_decode(header_b64), wire.b64url_decode(payload_b64), signer


def gen_reject_non_finite() -> dict:
    header, payload, signer = _raw_valid_root()
    payload = payload.replace(b'"exp":60', b'"exp":NaN', 1)
    return _vector(
        "Invalid JSON/JCS separating case: NaN is rejected before verification.",
        [_sign_raw(header, payload, signer)],
        expect_reject_reason=wire.WireReasonCode.NON_FINITE,
    )


def gen_reject_duplicate_member() -> dict:
    header, payload, signer = _raw_valid_root()
    payload = payload.replace(b'"del_depth":0', b'"del_depth":0,"del_depth":0', 1)
    return _vector(
        "Invalid JSON/JCS separating case: duplicate member names are rejected, never last-value-wins.",
        [_sign_raw(header, payload, signer)],
        expect_reject_reason=wire.WireReasonCode.DUPLICATE_MEMBER,
    )


def gen_reject_unmarked_canonicalization() -> dict:
    header, payload, signer = _raw_valid_root()
    header_obj = json.loads(header)
    header_obj.pop("c14n")
    header = wire._canonical_json(header_obj)
    return _vector(
        "Unmarked pre-JCS token: rejected because JCS is the only supported canonicalization.",
        [_sign_raw(header, payload, signer)],
        expect_reject_reason=wire.WireReasonCode.CANONICALIZATION_REQUIRED,
    )


GENERATORS = {
    "valid_chain.json": gen_valid_chain,
    "reject_widened_scope.json": gen_reject_widened_scope,
    "reject_exceeded_ceiling.json": gen_reject_exceeded_ceiling,
    "reject_spliced_parent.json": gen_reject_spliced_parent,
    "reject_depth_exceeded.json": gen_reject_depth_exceeded,
    "reject_nonmonotonic_exp.json": gen_reject_nonmonotonic_exp,
    "reject_bad_signature.json": gen_reject_bad_signature,
    "reject_wildcard_widening.json": gen_reject_wildcard_widening,
    "reject_wildcard_boundary.json": gen_reject_wildcard_boundary,
    "valid_jcs_integral_float.json": gen_valid_jcs_integral_float,
    "valid_jcs_exponent_form.json": gen_valid_jcs_exponent_form,
    "valid_jcs_non_ascii.json": gen_valid_jcs_non_ascii,
    "valid_jcs_utf16_key_order.json": gen_valid_jcs_utf16_key_order,
    "valid_jcs_big_integer.json": gen_valid_jcs_big_integer,
    "reject_non_finite.json": gen_reject_non_finite,
    "reject_duplicate_member.json": gen_reject_duplicate_member,
    "reject_unmarked_canonicalization.json": gen_reject_unmarked_canonicalization,
}


def generate_all(out_dir: Path = VECTORS_DIR,
                 package_dir: Path | None = PACKAGE_VECTORS_DIR) -> dict:
    """Write every vector file to `out_dir` AND, unless `package_dir` is None, to
    the packaged copy; return {filename: data} so callers (e.g.
    tests/test_wire.py) can self-check without re-reading from disk.

    Each vector's JSON is serialised ONCE and the same string is written to both
    destinations, so the two are byte-identical by construction rather than by a
    copy step that could be skipped. Deterministic: calling this twice writes
    byte-identical files."""
    destinations = [out_dir] + ([package_dir] if package_dir is not None else [])
    for d in destinations:
        d.mkdir(parents=True, exist_ok=True)
    written = {}
    for filename, gen in GENERATORS.items():
        data = gen()
        text = json.dumps(data, indent=2, sort_keys=True) + "\n"
        for d in destinations:
            (d / filename).write_text(text)
        written[filename] = data
    return written


def _self_check(written: dict) -> bool:
    """Verify every vector against THIS build's wire.load() immediately
    after generating it, so generate.py never emits a vector its own
    reference implementation would score differently than declared."""
    ok = True
    for filename, data in sorted(written.items()):
        signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]),
                                      kid=data["signer"]["kid"])
        try:
            wire.load(data["tokens"], signer, now=data["now"])
            outcome = "accept"
        except wire.WireError as e:
            outcome = e.reason
        expected = data.get("expect") or data.get("expect_reject_reason")
        status = "OK" if outcome == expected else "MISMATCH"
        ok = ok and (status == "OK")
        print(f"  self-check {filename}: expected={expected!r} got={outcome!r}  [{status}]")
    return ok


def main() -> int:
    written = generate_all()
    print(f"wrote {len(written)} vector file(s) to {VECTORS_DIR.relative_to(_ROOT)}/ "
          f"and {PACKAGE_VECTORS_DIR.relative_to(_ROOT)}/:")
    for filename in sorted(written):
        print(f"  {filename}")
    print("\nself-checking against this build's attenu_guard.wire ...")
    ok = _self_check(written)
    print("\nALL VECTORS SELF-CONSISTENT" if ok else "\nVECTOR SELF-CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
