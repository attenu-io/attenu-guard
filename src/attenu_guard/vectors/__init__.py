"""
attenu_guard.vectors — the Delegation Chain interop test vectors, shipped.

These are the interoperability artifact promised by
docs/draft-asor-wimse-agent-delegation-chain-01.md's "Reference Implementation
and Test Vectors" section: valid Delegation Chains and adversarial chains that
MUST each be rejected, every one naming the specific
reason it must be rejected FOR. They exist so an implementation written in
ANY language, from the draft alone, can score its own offline verifier against
a fixed, known-good/known-bad set of tokens.

They ship inside the installed package so that checking an independent
implementation needs `pip install attenu-guard` and nothing else — no clone, no
repository layout to know about:

    from attenu_guard import vectors

    for name, data in vectors.load_vectors().items():
        outcome = my_verifier(data["tokens"], data["signer"], data["now"])
        assert outcome == (data.get("expect") or data["expect_reject_reason"])

The files here are written by tests/vectors/generate.py, which is the single
writer for both this directory and tests/vectors/ — it serialises each vector
once and writes those same bytes to both, so neither is a stale copy of the
other. tests/test_wire.py asserts the two directories are byte-identical, so
they cannot diverge silently. Do not hand-edit anything in this directory.

`bundles/bundle_vectors_v1.json` is the second, bundle-level suite: whole
evidence bundles for `attenu_guard.evidence.verify_bundle` rather than token
chains for `wire.load()`. It is scored differently — a bundle verifier reports
a LIST of failures, so each rejecting case declares the minimal set of
{reason, seq, node} that MUST appear — and is written by
tests/vectors/generate_bundles.py, on the same single-writer discipline:

    from attenu_guard import vectors

    for case in vectors.load_bundle_vectors()["cases"]:
        report = my_verifier(case["bundle"], case["signer"])
        assert report.accepted == (case["expect"] == "accept")
        for expected in case["expect_failures"]:
            assert expected in report.failures      # reason AND position

`envelopes/envelope_vectors_v1.json` is the third suite: the OBSERVER ENVELOPE
layer, a witness's Ed25519 signature over the identity of one committed ledger
entry, carried beside the ledger in a bundle's top-level `envelopes` array. It
is scored through the same `verify_bundle` call with two more arguments — the
trust set the case declares, and, for the one case that needs them, the envelope
bytes as received:

    from attenu_guard import vectors

    for case in vectors.load_envelope_vectors()["cases"]:
        report = my_verifier(case["bundle"], case["signer"], case["witness_keys"])
        assert report.accepted == (case["expect"] == "accept")
        assert report.states == case["expect_states"]       # every entry, not only covered ones
        for expected in case["expect_failures"]:
            assert expected in report.failures              # reason AND position

`draft02/*.json` is the fourth suite: the Delegation Token vectors of
draft-asor-wimse-agent-delegation-chain-02, a second, separately named set (the twenty
-01 files above are byte-stable and do not conform to the -02). Each carries a
`verifier` block beside `signer`, because the -02's step 1 needs the verifier's
accepted-algorithm list and step 8 its audience, neither of which is in a token:

    from attenu_guard import vectors

    for name, data in vectors.load_vectors_02().items():
        outcome = my_verifier_02(data["tokens"], data["signer"], data["now"],
                                 data["verifier"]["accepted_algs"], data["verifier"]["audience"])
        assert outcome == (data.get("expect") or data["expect_reject_reason"])

Written by tests/vectors-02/generate_02.py on the same single-writer discipline.

tests/vectors/README.md documents the first three file formats and
tests/vectors-02/README.md the fourth, and how to use them from another implementation.
"""
from __future__ import annotations

import json
from importlib import resources

__all__ = ["VECTOR_NAMES", "read_vector_bytes", "load_vector", "load_vectors",
           "BUNDLE_VECTORS_PATH", "read_bundle_vectors_bytes", "load_bundle_vectors",
           "ENVELOPE_VECTORS_PATH", "read_envelope_vectors_bytes", "load_envelope_vectors",
           "VECTOR_NAMES_02", "read_vector_bytes_02", "load_vector_02", "load_vectors_02"]

#: Every shipped vector, valid chain first. Kept explicit rather than globbed so
#: a file that fails to make it into a wheel is a failure, not a shorter list.
VECTOR_NAMES = (
    "valid_chain.json",
    "reject_widened_scope.json",
    "reject_exceeded_ceiling.json",
    "reject_spliced_parent.json",
    "reject_depth_exceeded.json",
    "reject_nonmonotonic_exp.json",
    "reject_bad_signature.json",
    "reject_wildcard_widening.json",
    "reject_wildcard_boundary.json",
    "reject_bare_wildcard.json",
    "reject_nonterminal_wildcard.json",
    "valid_jcs_integral_float.json",
    "valid_jcs_exponent_form.json",
    "valid_jcs_non_ascii.json",
    "valid_jcs_utf16_key_order.json",
    "valid_jcs_big_integer.json",
    "valid_jcs_unmarked_header.json",
    "reject_non_finite.json",
    "reject_duplicate_member.json",
    "reject_unsafe_integer.json",
)


def read_vector_bytes(name: str) -> bytes:
    """The raw bytes of one vector file, read from the installed package.

    Goes through `importlib.resources`, so it works the same whether the package
    is an editable checkout, an installed wheel, or a zipimport."""
    if name not in VECTOR_NAMES:
        raise KeyError(f"unknown vector {name!r}; expected one of {list(VECTOR_NAMES)}")
    return (resources.files(__name__) / name).read_bytes()


def load_vector(name: str) -> dict:
    """One vector, parsed. See tests/vectors/README.md for the file format:
    `signer` (alg/kid/secret_hex), `now`, `tokens` (root-first), and exactly one
    of `expect` ("accept") or `expect_reject_reason`."""
    return json.loads(read_vector_bytes(name))


def load_vectors() -> dict[str, dict]:
    """Every vector, parsed, keyed by filename, in `VECTOR_NAMES` order."""
    return {name: load_vector(name) for name in VECTOR_NAMES}


#: The bundle-level vectors, as (subdirectory, filename) inside this package. Kept as parts
#: rather than a "bundles/..." string because `importlib.resources` traverses one name at a
#: time on every supported Python (multi-argument joinpath is 3.11+).
BUNDLE_VECTORS_PATH = ("bundles", "bundle_vectors_v1.json")


def read_bundle_vectors_bytes() -> bytes:
    """The raw bytes of the bundle-level vector file, read from the installed package."""
    target = resources.files(__name__)
    for part in BUNDLE_VECTORS_PATH:
        target = target / part
    return target.read_bytes()


def load_bundle_vectors() -> dict:
    """The bundle-level vectors, parsed: `{"version", "revision", "description", "cases": [...]}`.

    Cases are appended to this file, never inserted, changed or removed, so `version` is the
    compatibility contract and does not move; `revision` is the additive counter that does, and
    is what a conformance report should name. Iterate `cases`; do not assume a length.

    Each case is `{"name", "description", "signer", "bundle", "expect", "expect_failures"}`.
    `expect` is "accept" or "reject"; `expect_failures` is the MINIMAL set of
    `{"reason", "seq", "node"}` a conformant verifier MUST report for that bundle (empty for an
    accepting case). A verifier MAY report more failures than the minimal set — one broken
    record often makes a second check unsatisfiable — but never fewer, and never at a different
    position. See tests/vectors/README.md."""
    return json.loads(read_bundle_vectors_bytes())


#: The observer-envelope vectors, as (subdirectory, filename) inside this package — same
#: traversal discipline as BUNDLE_VECTORS_PATH, one name at a time.
ENVELOPE_VECTORS_PATH = ("envelopes", "envelope_vectors_v1.json")


def read_envelope_vectors_bytes() -> bytes:
    """The raw bytes of the observer-envelope vector file, read from the installed package."""
    target = resources.files(__name__)
    for part in ENVELOPE_VECTORS_PATH:
        target = target / part
    return target.read_bytes()


def load_envelope_vectors() -> dict:
    """The observer-envelope vectors, parsed: `{"version", "revision", "description", "cases"}`.

    Same append-only discipline as the bundle file: `version` is the compatibility contract and
    does not move, `revision` is the additive counter that does. Iterate `cases`; do not assume
    a length.

    Each case is `{"name", "description", "signer", "witness_keys", "bundle", "expect",
    "expect_states", "expect_failures"}`, with `canonical_hex` on the JCS-reorder case and
    `raw_hex` on the non-canonical one.

    `signer` verifies the bundle's anchor and is null on the one case that carries no anchor.
    `witness_keys` is the trust set: `[{"kid", "alg", "public_key_hex"}]`, where
    `public_key_hex` is a raw 32-byte Ed25519 public key in lowercase hex and `alg` is `EdDSA`.
    `expect_states` maps EVERY entry's seq (as a string) to `witness-signed` or
    `process-asserted`, so an accepting case asserts a state and not merely the absence of a
    failure. `expect_failures` is the MINIMAL set of `{"reason", "seq", "node"}` a conformant
    verifier MUST report. It MAY report more, never fewer, never at a different position — and
    two further rules bind where an extra may land: an envelope failure lands only on the hop
    that envelope covers, never on a hop coverage skipped, and no chain-level integrity failure
    is ever raised because an envelope failed. See tests/vectors/README.md."""
    return json.loads(read_envelope_vectors_bytes())


#: The -02 set (draft-asor-wimse-agent-delegation-chain-02), under `draft02/`. Explicit, like
#: VECTOR_NAMES, so a file missing from a wheel is a failure rather than a shorter list.
VECTOR_NAMES_02 = (
    "valid_chain.json",
    "valid_audience_array.json",
    "valid_opaque_exact.json",
    "valid_range_min_max.json",
    "valid_unknown_constraint_identical.json",
    "reject_principal_altered.json",
    "reject_root_without_principal.json",
    "reject_missing_client_id.json",
    "reject_aud_null.json",
    "reject_aud_empty_array.json",
    "reject_audience_mismatch.json",
    "reject_missing_cnf.json",
    "reject_cnf_without_confirmation.json",
    "reject_unsafe_integer.json",
    "reject_alg_not_accepted.json",
    "reject_wildcard_over_opaque.json",
    "reject_opaque_over_wildcard.json",
    "reject_opaque_case_folded.json",
    "reject_mixed_case_wildcard.json",
    "reject_newline_scope.json",
    "reject_max_lifetime_widened.json",
    "reject_max_subtree_widened.json",
    "reject_cross_type_lifetime_for_max.json",
    "reject_child_exp_exceeds_parent.json",
    "reject_child_raises_del_max_depth.json",
    "reject_rank_order_mismatch.json",
    "reject_rank_without_order.json",
    "reject_rank_outside_order.json",
    "reject_duplicate_key_type.json",
    "reject_constraint_extra_member.json",
    "reject_detail_extra_member.json",
    "reject_second_detail.json",
    "reject_unknown_detail_type.json",
    "reject_altered_sub_and_par_hash.json",
    "reject_reissued_parent.json",
)


def read_vector_bytes_02(name: str) -> bytes:
    """The raw bytes of one -02 vector file, read from the installed package."""
    if name not in VECTOR_NAMES_02:
        raise KeyError(f"unknown -02 vector {name!r}; expected one of {list(VECTOR_NAMES_02)}")
    return (resources.files(__name__) / "draft02" / name).read_bytes()


def load_vector_02(name: str) -> dict:
    """One -02 vector, parsed: `draft` ("02"), `signer`, `verifier` (`accepted_algs`,
    `audience`), `now`, `tokens`, and exactly one of `expect` or `expect_reject_reason`.
    See tests/vectors-02/README.md."""
    return json.loads(read_vector_bytes_02(name))


def load_vectors_02() -> dict:
    """Every -02 vector, parsed, keyed by filename, in `VECTOR_NAMES_02` order."""
    return {name: load_vector_02(name) for name in VECTOR_NAMES_02}
