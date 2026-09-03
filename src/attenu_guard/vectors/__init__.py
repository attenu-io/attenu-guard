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

tests/vectors/README.md documents both file formats and how to use them from
another implementation.
"""
from __future__ import annotations

import json
from importlib import resources

__all__ = ["VECTOR_NAMES", "read_vector_bytes", "load_vector", "load_vectors",
           "BUNDLE_VECTORS_PATH", "read_bundle_vectors_bytes", "load_bundle_vectors"]

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
