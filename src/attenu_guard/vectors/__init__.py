"""
attenu_guard.vectors — the Delegation Chain interop test vectors, shipped.

These are the interoperability artifact promised by
docs/draft-asor-wimse-agent-delegation-chain-00.md's "Reference Implementation
and Test Vectors" section: one Delegation Chain that MUST verify and seven
adversarial chains that MUST each be rejected, every one naming the specific
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

tests/vectors/README.md documents the file format and how to use a vector from
another implementation.
"""
from __future__ import annotations

import json
from importlib import resources

__all__ = ["VECTOR_NAMES", "read_vector_bytes", "load_vector", "load_vectors"]

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
