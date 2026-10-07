"""
tests/vectors-02/generate_02.py — deterministic offline-verification test vectors for
draft-asor-wimse-agent-delegation-chain-02, the second, separately named set.

The twenty -01 vectors in tests/vectors/ are byte-stable and are not touched by this
generator (it writes only tests/vectors-02/ and the packaged src/attenu_guard/vectors/draft02/).
They do not conform to the -02: no `cnf`, no `client_id`, `aud` null. This set does, and
adds a vector for every rule the -02 introduces, accepting and rejecting, each naming the
outcome of the -02's Table 2 it must produce.

Every vector is scored under the -02 profile: `wire.load(tokens, signer, now=now, draft="02",
accepted_algs=verifier["accepted_algs"], audience=verifier["audience"])`. The `verifier`
block is new in this set: step 1 needs the verifier's accepted-algorithm list and step 8
needs the audience it answers to, and neither can be read from the tokens.

stdlib-only, no network, no randomness; running it twice writes byte-identical files:

    python3 tests/vectors-02/generate_02.py

Credits: `valid_opaque_exact`, `reject_wildcard_over_opaque` and `reject_opaque_over_wildcard`
are Kieran Sweeney's cases from the WIMSE list thread of 2026-10-06/07 (cred-ninja/protocol,
commit 06e2957, proposed-vectors/), re-minted here in this set's claim layout and signed with
this set's key; the scope values and the declared outcomes are his.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import Authority, CallLimit, EgressRank, Guard, RowLimit, SpendCap  # noqa: E402
from attenu_guard import draft02 as d  # noqa: E402
from attenu_guard import wire  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent
PACKAGE_VECTORS_DIR = _ROOT / "src" / "attenu_guard" / "vectors" / "draft02"

# A published, fixed, well-known secret, as in the -01 set: these vectors exercise the wire
# format and the verification algorithm, never a production trust boundary.
SECRET = b"attenu-guard-interop-vectors-draft02-fixed-secret"
KID = "interop-02"
PRINCIPAL = "acct:finance-ops@example.com"
AUDIENCE = "https://crm.example.com"
ACCEPTED_ALGS = ["HS256"]
ORDER = ["none", "internal", "any"]


def _signer() -> wire.HS256TestSigner:
    return wire.HS256TestSigner(SECRET, kid=KID)


def _cnf(node) -> dict:
    """A deterministic stand-in for the holder key's JWK thumbprint (RFC 7800 / RFC 9449
    `jkt`): the base64url SHA-256 of the agent id. Step 6 is not scored by this set, so no
    real key is behind it; the claim is present and shaped as the -02 requires."""
    digest = hashlib.sha256(f"holder-key:{node.agent_id}".encode()).digest()
    return {"jkt": base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")}


def _payload(token: str) -> dict:
    return json.loads(wire.b64url_decode(token.split(".")[1]))


def _resign(header_b64: str, payload: dict, signer: wire.Signer) -> str:
    payload_b64 = wire._encode_part(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{wire.b64url_encode(signer.sign(signing_input))}"


def _sign_raw(header_json: bytes, payload_json: bytes, signer: wire.Signer) -> str:
    header_b64 = wire.b64url_encode(header_json)
    payload_b64 = wire.b64url_encode(payload_json)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return f"{header_b64}.{payload_b64}.{wire.b64url_encode(signer.sign(signing_input))}"


def _tamper(tokens: list, index: int, mutate, signer=None) -> list:
    """Mutate `tokens[index]`'s payload, re-sign it, and repair every later token's
    `par_hash` (re-signing each), so the chain is fully self-consistent EXCEPT for the one
    invariant `mutate` breaks. Needed for any token but the leaf, whose signing input nothing
    downstream commits to."""
    signer = signer or _signer()
    tokens = list(tokens)
    h_b64, p_b64, _ = tokens[index].split(".")
    payload = json.loads(wire.b64url_decode(p_b64))
    mutate(payload)
    tokens[index] = _resign(h_b64, payload, signer)
    prev_signing_input = ".".join(tokens[index].split(".")[:2]).encode("ascii")
    for i in range(index + 1, len(tokens)):
        h, p, _ = tokens[i].split(".")
        payload = json.loads(wire.b64url_decode(p))
        payload["par_hash"] = wire.b64url_encode(hashlib.sha256(prev_signing_input).digest())
        tokens[i] = _resign(h, payload, signer)
        prev_signing_input = ".".join(tokens[i].split(".")[:2]).encode("ascii")
    return tokens


def _detail(payload: dict) -> dict:
    return payload["authorization_details"][0]


def _constraint(payload: dict, key: str, ctype: str) -> dict:
    for c in _detail(payload)["constraints"]:
        if c["key"] == key and ctype in c:
            return c
    raise KeyError((key, ctype))


def A(scopes, ceilings, ttl):
    return Authority(scopes, ceilings, ttl, profile="02")


def _base_chain(max_depth: int = 6):
    """The canonical 3-hop chain of this set. Beside the -01 set's shape it carries an opaque
    provider scope (`User.Read`), a lifetime call bound, and a per-action and a per-subtree
    bound on one key (`max_spend`), so the new constraint types are in the accepting case."""
    root = Guard.issue("orchestrator",
                       A({"crm.*", "mail.send", "User.Read"},
                         [RowLimit(100_000), EgressRank("any"), CallLimit(50), SpendCap(500),
                          d.MaxSubtree("max_spend", 1000)], ttl=3600),
                       max_depth=max_depth)
    child = root.delegate("summarizer",
                          A({"crm.read", "User.Read"},
                            [RowLimit(5_000), EgressRank("none"), CallLimit(10), SpendCap(60),
                             d.MaxSubtree("max_spend", 400)], ttl=900),
                          task="summarize Q3 pipeline")
    leaf = child.delegate("formatter",
                          A({"crm.read"},
                            [RowLimit(100), EgressRank("none"), CallLimit(2), SpendCap(10),
                             d.MaxSubtree("max_spend", 100)], ttl=300),
                          task="format for slides")
    return root, child, leaf


def _mint(leaf, aud=AUDIENCE) -> list:
    return wire.serialize_chain(leaf, _signer(), principal=PRINCIPAL, aud=aud, draft="02", cnf=_cnf)


def _vector(description: str, tokens: list, *, expect: str = None, expect_reject_reason: str = None,
            now: int = 0, audience: str = AUDIENCE, accepted_algs=None) -> dict:
    data = {
        "description": description,
        "draft": "02",
        "signer": {"alg": "HS256", "kid": KID, "secret_hex": SECRET.hex()},
        "verifier": {"accepted_algs": list(accepted_algs or ACCEPTED_ALGS), "audience": audience},
        "now": now,
        "tokens": tokens,
    }
    if expect is not None:
        data["expect"] = expect
    if expect_reject_reason is not None:
        data["expect_reject_reason"] = expect_reject_reason
    return data


R = wire.WireReasonCode


# =========================================================================
# Accepting vectors
# =========================================================================

def gen_valid_chain() -> dict:
    _r, _c, leaf = _base_chain()
    return _vector(
        "A valid 3-hop attenuating Delegation Chain under the -02 (orchestrator -> summarizer -> "
        "formatter). Every token carries the Principal in sub (identical), the Acting Agent in "
        "client_id, a string aud naming the verifier, and cnf. Scopes shrink from {crm.*, mail.send, "
        "User.Read} to {crm.read}; max_rows 100000 -> 5000 -> 100; the lifetime call bound "
        "50 -> 10 -> 2; max_spend carries a per-action max (500 -> 60 -> 10) and a per-subtree "
        "bound (1000 -> 400 -> 100) on one key; the egress rank carries its order; ttl 3600 -> 900 "
        "-> 300. MUST verify.",
        _mint(leaf), expect="accept")


def gen_valid_audience_array() -> dict:
    _r, _c, leaf = _base_chain()
    return _vector(
        "aud as a non-empty array (RFC 7519 Section 4.1.3) that includes the verifier's "
        "audience. MUST verify: step 8's audience check passes when any member names the "
        "Enforcement Point.",
        _mint(leaf, aud=["https://files.example.com", AUDIENCE]), expect="accept")


def gen_valid_opaque_exact() -> dict:
    root = Guard.issue("orchestrator", A({"User.Read", "repo:status"}, [], ttl=3600), max_depth=2)
    worker = root.delegate("worker", A({"repo:status"}, [], ttl=900), task="status")
    return _vector(
        "Scope classes: the root grants two provider-native opaque scopes, 'User.Read' and "
        "'repo:status'; the child requests 'repo:status' byte for byte. Opaque scopes narrow by "
        "exact equality. MUST be accepted; under the -01 grammar both tokens are malformed, which "
        "is the interop gap the opaque form closes. Case contributed by Kieran Sweeney.",
        _mint(worker), expect="accept")


def gen_valid_range_min_max() -> dict:
    root = Guard.issue("orchestrator", A({"hr.read"}, [d.Min("tenure_years", 1), d.Max("tenure_years", 30)],
                                         ttl=3600), max_depth=2)
    worker = root.delegate("worker", A({"hr.read"}, [d.Min("tenure_years", 2), d.Max("tenure_years", 10)],
                                       ttl=900), task="screen")
    return _vector(
        "One constraint per (key, type): a 'min' and a 'max' on one key form a range, and each "
        "narrows on its own axis (floor 1 -> 2 tightened upward, ceiling 30 -> 10 tightened "
        "downward). MUST verify. A verifier that admits one constraint per KEY rejects this chain "
        "as malformed and is wrong under the -02.",
        _mint(worker), expect="accept")


def gen_valid_unknown_constraint_identical() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _mint(leaf)
    tokens = _tamper(tokens, 1, lambda p: _detail(p)["constraints"].append({"key": "quota", "units": 5}))
    tokens = _tamper(tokens, 2, lambda p: _detail(p)["constraints"].append({"key": "quota", "units": 5}))
    return _vector(
        "A constraint of a type this set does not define ('units'), carried identically by the "
        "summarizer and the formatter. It is a single typed value in a closed object, so it is "
        "not malformed; a verifier that does not implement it treats the chain as subsumed only "
        "because the child's constraint is byte-identical to the parent's, and denies every "
        "action at step 8 (fail closed). The chain MUST verify; what step 8 then does is outside "
        "this vector.",
        tokens, expect="accept")


# =========================================================================
# Section 3: claims
# =========================================================================

def gen_reject_principal_altered() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 1, lambda p: p.__setitem__("sub", "acct:someone-else@example.com"))
    return _vector(
        "The summarizer token carries a different sub than the root, re-signed, with every "
        "par_hash repaired so the chain is otherwise valid. The Principal MUST be identical in "
        "every token (step 3). MUST be rejected: principal_altered.",
        tokens, expect_reject_reason=R.PRINCIPAL_ALTERED)


def gen_reject_root_without_principal() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 0, lambda p: p.__setitem__("sub", ""))
    return _vector(
        "DT_0's sub is the empty string, re-signed and the chain repaired. A chain whose root "
        "names no Principal is malformed (Section 3), before any step runs. MUST be rejected: "
        "malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_missing_client_id() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: p.pop("client_id"))
    return _vector(
        "The leaf token omits client_id, the REQUIRED claim naming the Acting Agent. MUST be "
        "rejected: malformed. (This is also what every -01 vector is under the -02.)",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_aud_null() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: p.__setitem__("aud", None))
    return _vector(
        "The leaf token's aud is null, which RFC 7519 Section 4.1.3 does not allow and the -02 "
        "names malformed. MUST be rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_aud_empty_array() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: p.__setitem__("aud", []))
    return _vector(
        "The leaf token's aud is an empty array. An audience is a string or a NON-EMPTY array of "
        "strings. MUST be rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_audience_mismatch() -> dict:
    _r, _c, leaf = _base_chain()
    return _vector(
        "A valid chain whose leaf aud ('https://crm.example.com') does not name the verifier "
        "this vector is scored at ('https://files.example.com', the verifier block's audience). "
        "Step 8 applies RFC 9068 Section 4's audience check to DT_n. MUST be rejected: "
        "audience_mismatch. The same chain verifies at its own audience (valid_chain.json).",
        _mint(leaf), expect_reject_reason=R.AUDIENCE_MISMATCH, audience="https://files.example.com")


def gen_reject_missing_cnf() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 1, lambda p: p.pop("cnf"))
    return _vector(
        "The summarizer token omits cnf. Every token of a chain is holder-bound (Sections 3 and "
        "7), and a verifier that sees no request still checks the claim's presence and shape. "
        "MUST be rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_unsafe_integer() -> dict:
    root = Guard.issue("parser-probe", A({"probe.read"}, [], ttl=60), max_depth=1)
    token = wire.serialize(root, _signer(), principal=PRINCIPAL, aud=AUDIENCE, draft="02", cnf=_cnf)
    h_b64, p_b64, _ = token.split(".")
    header, payload = wire.b64url_decode(h_b64), wire.b64url_decode(p_b64)
    unsafe = payload.replace(b'"exp":60', b'"exp":9007199254740992', 1)
    assert unsafe != payload
    return _vector(
        "exp is 2^53, one past the largest integer a binary64 number represents exactly. "
        "Section 3 of the -02 makes such an integer malformed (JCS numbers are IEEE 754 "
        "doubles). MUST be rejected: malformed.",
        [_sign_raw(header, unsafe, _signer())], expect_reject_reason=R.MALFORMED)


# =========================================================================
# Section 6 step 1: the accepted-algorithm list
# =========================================================================

def gen_reject_alg_not_accepted() -> dict:
    _r, _c, leaf = _base_chain()
    return _vector(
        "A valid chain, correctly signed with HS256, scored by a verifier whose accepted list is "
        "['EdDSA'] (the verifier block). Step 1 denies a token whose alg is not on the list even "
        "where the signature verifies. MUST be rejected: signature_invalid. The same chain "
        "verifies under ['HS256'] (valid_chain.json).",
        _mint(leaf), expect_reject_reason=R.SIGNATURE_INVALID, accepted_algs=["EdDSA"])


# =========================================================================
# Section 4.1: the three-form scope grammar
# =========================================================================

def _two_hop(root_scopes, child_scopes) -> list:
    root = Guard.issue("orchestrator", A(set(root_scopes), [], ttl=3600), max_depth=2)
    worker = root.delegate("worker", A(set(root_scopes), [], ttl=900), task="t")
    tokens = _mint(worker)
    return _tamper(tokens, 1, lambda p: _detail(p).__setitem__("scopes", list(child_scopes)))


def gen_reject_wildcard_over_opaque() -> dict:
    return _vector(
        "Scope classes: the root grants the wildcard 'drive.*'; the child requests 'drive.Read'. "
        "The uppercase R fails literal-scope, so 'drive.Read' is an opaque scope, and a wildcard "
        "never covers an opaque scope, even one that shares its prefix. MUST be rejected: "
        "not_narrower. A verifier that compares by raw prefix accepts this chain and is wrong. "
        "Case contributed by Kieran Sweeney.",
        _two_hop(["drive.*"], ["drive.Read"]), expect_reject_reason=R.NOT_NARROWER)


def gen_reject_opaque_over_wildcard() -> dict:
    return _vector(
        "Scope classes: the root grants the opaque scope 'drive.Read'; the child requests the "
        "wildcard 'drive.*'. An opaque scope covers only a byte-identical opaque scope and never "
        "a wildcard. MUST be rejected: not_narrower. Case contributed by Kieran Sweeney.",
        _two_hop(["drive.Read"], ["drive.*"]), expect_reject_reason=R.NOT_NARROWER)


def gen_reject_opaque_case_folded() -> dict:
    return _vector(
        "No case folding: the root grants 'User.Read'; the child requests 'user.read'. The child "
        "is a literal scope and the parent an opaque one, and neither covers the other. MUST be "
        "rejected: not_narrower.",
        _two_hop(["User.Read"], ["user.read"]), expect_reject_reason=R.NOT_NARROWER)


def gen_reject_mixed_case_wildcard() -> dict:
    return _vector(
        "'User.*' matches none of the three forms: not literal or wildcard (uppercase), not "
        "opaque (it contains '*'). An invalid scope makes the token malformed before subsumption. "
        "MUST be rejected: malformed.",
        _two_hop(["User.Read"], ["User.*"]), expect_reject_reason=R.MALFORMED)


# =========================================================================
# Section 4.2 / 4.3: constraint types and subsumption
# =========================================================================

def gen_reject_max_lifetime_widened() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _constraint(p, "max_calls", "max_lifetime").__setitem__(
        "max_lifetime", 1000))
    return _vector(
        "The leaf's lifetime call bound is raised to 1000 under a parent bound of 10. A chain-only "
        "verifier checks a child's cumulative bounds for narrowing only. MUST be rejected: "
        "not_narrower (rule 2).",
        tokens, expect_reject_reason=R.NOT_NARROWER)


def gen_reject_max_subtree_widened() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _constraint(p, "max_spend", "max_subtree").__setitem__(
        "max_subtree", 5000))
    return _vector(
        "The leaf's per-subtree spend bound is raised to 5000 under a parent bound of 400, while "
        "its per-action max (10 under 60) is untouched. The two types on one key narrow "
        "independently. MUST be rejected: not_narrower (rule 2).",
        tokens, expect_reject_reason=R.NOT_NARROWER)


def gen_reject_cross_type_lifetime_for_max() -> dict:
    _r, _c, leaf = _base_chain()

    def swap(payload):
        c = _constraint(payload, "max_rows", "max")
        del c["max"]
        c["max_lifetime"] = 1
    tokens = _tamper(_mint(leaf), 2, swap)
    return _vector(
        "The leaf replaces its per-action max_rows bound with a max_lifetime of 1 on the same key. "
        "No inference is made across types: a lifetime bound, however small, does not satisfy "
        "the parent's per-action 'max', which is now absent in the child (rule 3). MUST be "
        "rejected: not_narrower.",
        tokens, expect_reject_reason=R.NOT_NARROWER)


def gen_reject_rank_order_mismatch() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _constraint(p, "egress", "rank").__setitem__(
        "order", ["none", "any"]))
    return _vector(
        "The leaf's egress rank carries the order ['none', 'any'] under a parent carrying "
        "['none', 'internal', 'any']. Its rank 'none' is the same string, but a child's order MUST "
        "be identical to its parent's, element for element. MUST be rejected: not_narrower.",
        tokens, expect_reject_reason=R.NOT_NARROWER)


def gen_reject_rank_without_order() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _constraint(p, "egress", "rank").pop("order"))
    return _vector(
        "The leaf's egress rank has no order member, which is the -01 shape. Under the -02 the "
        "ordering travels with the constraint and a rank without it is malformed. MUST be "
        "rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_rank_outside_order() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _constraint(p, "egress", "rank").__setitem__(
        "rank", "everywhere"))
    return _vector(
        "The leaf's egress rank is 'everywhere', which is not a member of its order. MUST be "
        "rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_duplicate_key_type() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _detail(p)["constraints"].append({"key": "max_rows", "max": 50}))
    return _vector(
        "The leaf carries two 'max' constraints on max_rows (100 and 50). A detail MUST NOT carry "
        "two constraints with the same key and the same type, and a verifier rejects rather than "
        "choosing one. MUST be rejected: malformed. Contrast valid_range_min_max.json, where the "
        "two types differ.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_constraint_extra_member() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _constraint(p, "max_rows", "max").__setitem__("note", "soft"))
    return _vector(
        "The leaf's max_rows constraint carries a member its type does not define ('note'). A "
        "constraint object is closed: key, one typed value, and the members that type adds. MUST "
        "be rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


# =========================================================================
# Section 4 / 4.4: the authorization detail
# =========================================================================

def gen_reject_detail_extra_member() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: _detail(p).__setitem__("actions", ["read"]))
    return _vector(
        "The leaf's agent_delegation detail carries an 'actions' member (an RFC 9396 common "
        "member this type does not use). The detail carries no members other than type, scopes "
        "and constraints; a verifier that ignored it would report success on a detail it had not "
        "fully read. MUST be rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_second_detail() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 2, lambda p: p["authorization_details"].append(
        {"type": "agent_delegation", "scopes": ["crm.read"], "constraints": []}))
    return _vector(
        "The leaf carries two authorization details. Under the -02 a token carries exactly one, of "
        "type agent_delegation; chains carrying several are left to a later revision. MUST be "
        "rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


def gen_reject_unknown_detail_type() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _tamper(_mint(leaf), 0, lambda p: _detail(p).__setitem__("type", "acme_site_policy"))
    return _vector(
        "DT_0's single detail is of a type this verifier does not implement ('acme_site_policy'), "
        "re-signed and the chain repaired. A verifier evaluates every detail or rejects the token; "
        "it classifies detail types when it parses, before step 1, so the root is covered too. "
        "MUST be rejected: malformed.",
        tokens, expect_reject_reason=R.MALFORMED)


# =========================================================================
# Section 5: the commitment is to a parent instance
# =========================================================================

def gen_reject_reissued_parent() -> dict:
    _r, _c, leaf = _base_chain()
    tokens = _mint(leaf)
    h_b64, p_b64, _ = tokens[1].split(".")
    reissued = json.loads(wire.b64url_decode(p_b64))
    reissued["jti"] = "chain:n1-reissued"
    reissued["iat"] = 10
    reissued["exp"] = 910
    tokens[1] = _resign(h_b64, reissued, _signer())        # the leaf's par_hash is NOT repaired
    return _vector(
        "The summarizer is re-issued (new jti, iat and exp, otherwise identical, validly signed) and "
        "presented with the formatter that was issued under the PREVIOUS instance. par_hash commits "
        "to a parent token instance, not a parent identity (Section 5): the formatter's commitment "
        "does not match the re-issued parent's signing input. MUST be rejected: par_hash_mismatch, "
        "by the same step-2 check that stops splicing. The formatter keeps verifying with the "
        "instance it was issued under (valid_chain.json).",
        tokens, expect_reject_reason=R.PAR_HASH_MISMATCH)


GENERATORS = {
    "valid_chain.json": gen_valid_chain,
    "valid_audience_array.json": gen_valid_audience_array,
    "valid_opaque_exact.json": gen_valid_opaque_exact,
    "valid_range_min_max.json": gen_valid_range_min_max,
    "valid_unknown_constraint_identical.json": gen_valid_unknown_constraint_identical,
    "reject_principal_altered.json": gen_reject_principal_altered,
    "reject_root_without_principal.json": gen_reject_root_without_principal,
    "reject_missing_client_id.json": gen_reject_missing_client_id,
    "reject_aud_null.json": gen_reject_aud_null,
    "reject_aud_empty_array.json": gen_reject_aud_empty_array,
    "reject_audience_mismatch.json": gen_reject_audience_mismatch,
    "reject_missing_cnf.json": gen_reject_missing_cnf,
    "reject_unsafe_integer.json": gen_reject_unsafe_integer,
    "reject_alg_not_accepted.json": gen_reject_alg_not_accepted,
    "reject_wildcard_over_opaque.json": gen_reject_wildcard_over_opaque,
    "reject_opaque_over_wildcard.json": gen_reject_opaque_over_wildcard,
    "reject_opaque_case_folded.json": gen_reject_opaque_case_folded,
    "reject_mixed_case_wildcard.json": gen_reject_mixed_case_wildcard,
    "reject_max_lifetime_widened.json": gen_reject_max_lifetime_widened,
    "reject_max_subtree_widened.json": gen_reject_max_subtree_widened,
    "reject_cross_type_lifetime_for_max.json": gen_reject_cross_type_lifetime_for_max,
    "reject_rank_order_mismatch.json": gen_reject_rank_order_mismatch,
    "reject_rank_without_order.json": gen_reject_rank_without_order,
    "reject_rank_outside_order.json": gen_reject_rank_outside_order,
    "reject_duplicate_key_type.json": gen_reject_duplicate_key_type,
    "reject_constraint_extra_member.json": gen_reject_constraint_extra_member,
    "reject_detail_extra_member.json": gen_reject_detail_extra_member,
    "reject_second_detail.json": gen_reject_second_detail,
    "reject_unknown_detail_type.json": gen_reject_unknown_detail_type,
    "reject_reissued_parent.json": gen_reject_reissued_parent,
}


def generate_all(out_dir: Path = VECTORS_DIR, package_dir: Path | None = PACKAGE_VECTORS_DIR) -> dict:
    """Write every vector to `out_dir` and, unless `package_dir` is None, to the packaged copy,
    from ONE serialisation each. Deterministic. Touches nothing outside these two directories:
    the -01 set in tests/vectors/ is byte-stable and has its own generator."""
    destinations = [out_dir] + ([package_dir] if package_dir is not None else [])
    for dest in destinations:
        dest.mkdir(parents=True, exist_ok=True)
        for stale in dest.glob("*.json"):
            if stale.name not in GENERATORS:
                stale.unlink()
    written = {}
    for filename, gen in GENERATORS.items():
        data = gen()
        text = json.dumps(data, indent=2, sort_keys=True) + "\n"
        for dest in destinations:
            (dest / filename).write_text(text)
        written[filename] = data
    return written


def score(data: dict) -> str:
    """Score one vector with this build's verifier, the way an independent implementation is
    asked to: the -02 profile, the verifier block's accepted algorithms and audience."""
    signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]), kid=data["signer"]["kid"])
    try:
        wire.load(data["tokens"], signer, now=data["now"], draft="02",
                  accepted_algs=data["verifier"]["accepted_algs"], audience=data["verifier"]["audience"])
        return "accept"
    except wire.WireError as e:
        return e.reason


def _self_check(written: dict) -> bool:
    ok = True
    for filename, data in sorted(written.items()):
        outcome = score(data)
        expected = data.get("expect") or data.get("expect_reject_reason")
        status = "OK" if outcome == expected else "MISMATCH"
        ok = ok and status == "OK"
        print(f"  self-check {filename}: expected={expected!r} got={outcome!r}  [{status}]")
    return ok


def main() -> int:
    written = generate_all()
    print(f"wrote {len(written)} vector file(s) to {VECTORS_DIR.relative_to(_ROOT)}/ "
          f"and {PACKAGE_VECTORS_DIR.relative_to(_ROOT)}/")
    print("\nself-checking against this build's attenu_guard.wire (draft=\"02\") ...")
    ok = _self_check(written)
    print("\nALL VECTORS SELF-CONSISTENT" if ok else "\nVECTOR SELF-CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
