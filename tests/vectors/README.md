# Delegation Token offline-verification test vectors

This directory holds the interoperability artifact promised by
`docs/draft-asor-wimse-agent-delegation-chain-01.md`'s "Reference
Implementation and Test Vectors" section: a Delegation Chain that MUST
verify, and a set of adversarial chains that MUST each be rejected, each for
a specific, declared reason. They exist so an **independent implementation**
— in any language, following only the Internet-Draft — can check its own
offline verifier against a fixed, known-good/known-bad set of tokens without
needing this repository's Python or any of its code.

## Getting them without cloning this repository

They ship inside the installed package, so scoring your own verifier needs
nothing but `pip install attenu-guard`:

```python
from attenu_guard import vectors

for name, data in vectors.load_vectors().items():
    outcome = my_verifier(data["tokens"], data["signer"], data["now"])
    assert outcome == (data.get("expect") or data["expect_reject_reason"])
```

`vectors.VECTOR_NAMES` lists the 19 vectors; `vectors.read_vector_bytes(name)` gives
you the raw JSON if you would rather parse it yourself. The copies here and the
packaged ones are byte-identical — `generate.py` writes both from one
serialisation, and `tests/test_wire.py` fails if they ever differ.

## Regenerating

Regenerate with (stdlib-only, no network, no installs):

```
python3 tests/vectors/generate.py
```

That writes this directory AND `src/attenu_guard/vectors/`. Never hand-edit
either copy.

This is deterministic: nothing here ever calls a real clock or a random
number generator (see `wire.py`'s module docstring on determinism), so
running it twice produces byte-identical files. `generate.py` also
self-checks every vector it writes against this build's own
`attenu_guard.wire.load()` before exiting 0, so a vector can never drift
from what this reference implementation actually does.

`tests/test_wire.py` regenerates and loads these same files as part of the
main test run (`python3 tests/test_wire.py`), so they are self-checking on
every CI run, not just a static fixture that can go stale.

## Files

- `valid_chain.json` — a valid, 3-hop, strictly-attenuating chain
  (orchestrator -> summarizer -> formatter — the same story as
  `examples/poisoned_summarizer.py`). `"expect": "accept"`. A conformant
  verifier MUST accept it.
- `reject_widened_scope.json` — the leaf's scopes were widened past its
  parent's. `"expect_reject_reason": "not_narrower"`.
- `reject_exceeded_ceiling.json` — the leaf's `max_rows` ceiling was loosened
  past its parent's. `"expect_reject_reason": "not_narrower"`.
- `reject_spliced_parent.json` — a real, validly-issued child token is paired
  with a different, broader, honestly-signed root it was never actually
  delegated under (a chain-splicing attempt).
  `"expect_reject_reason": "par_hash_mismatch"`.
- `reject_depth_exceeded.json` — the root's `del_max_depth` was tampered
  down below the chain's actual length (every other invariant, including
  every downstream `par_hash`, was repaired so this vector isolates the
  depth check specifically). `"expect_reject_reason": "depth_invalid"`.
- `reject_nonmonotonic_exp.json` — the leaf's `iat`/`exp` were both shifted
  forward (simulating a much-later minting time), so its ttl/duration still
  satisfies subsumption but its *absolute* `exp` exceeds its parent's.
  `"expect_reject_reason": "expired"`.
- `reject_bad_signature.json` — one byte of the leaf token's signature was
  flipped. `"expect_reject_reason": "signature_invalid"`.
- `reject_wildcard_widening.json` — the leaf's scopes were replaced with the
  wildcard `crm.*` while its parent holds only the concrete `crm.read`, so the
  leaf claims strictly more than its parent ever held. The inverse of the
  legitimate direction in `valid_chain.json` (a concrete `crm.read` under a
  `crm.*` parent): wildcards narrow downward only.
  `"expect_reject_reason": "not_narrower"`.
- `reject_wildcard_boundary.json` — the leaf's scopes were replaced with
  `crmx.read` under a root holding the wildcard `crm.*`. The claim shares the
  wildcard's letters but not its segment boundary: `crm.*` covers `crm.`
  followed by anything, so a verifier that strips the `.*` and tests
  `startswith("crm")` wrongly accepts a neighbouring namespace.
  `"expect_reject_reason": "not_narrower"`.
- `reject_bare_wildcard.json` — the leaf carries the bare scope `*`. It is not
  universal authority; it is invalid scope syntax.
  `"expect_reject_reason": "malformed"`.
- `reject_nonterminal_wildcard.json` — the leaf carries `crm.*.read`. A wildcard
  is valid only as the complete final segment, so this is malformed rather than
  a glob. `"expect_reject_reason": "malformed"`.
- `valid_jcs_integral_float.json` — pins `100.0` to the JCS bytes `100`.
- `valid_jcs_exponent_form.json` — pins ECMAScript/JCS decimal form at `1e-6`
  and `1e16`.
- `valid_jcs_non_ascii.json` — pins raw UTF-8 for a non-ASCII subject.
- `valid_jcs_utf16_key_order.json` — pins UTF-16 code-unit member ordering.
- `valid_jcs_big_integer.json` — pins the binary64 form of a Python integer
  outside the safe-integer range.
- `reject_non_finite.json` — carries `NaN`, which is not JSON or JCS.
  `"expect_reject_reason": "non_finite"`.
- `reject_duplicate_member.json` — carries a duplicate object member name.
  `"expect_reject_reason": "duplicate_member"`.
- `valid_jcs_unmarked_header.json` — omits the informational `c14n` marker while
  retaining canonical JCS header and payload bytes. `"expect": "accept"`.

## File format

Every file is one JSON object:

```jsonc
{
  "description": "prose explaining what this vector is and why",
  "signer": {"alg": "HS256", "kid": "interop-v1", "secret_hex": "..."},
  "now": 0,                          // pass this as load()'s `now`
  "tokens": ["<jwt>", "<jwt>", ...], // root-first: [DT_0, DT_1, ..., DT_n]

  // exactly one of the next two keys is present:
  "expect": "accept",                          // valid_chain.json only
  "expect_reject_reason": "not_narrower"        // every reject_*.json
}
```

Each entry in `tokens` is a compact, three-part `header.payload.signature`
Delegation Token exactly as defined by the draft's Token Format section:
`base64url(JSON header) + "." + base64url(JSON payload) + "." +
base64url(signature)`, base64url with no `=` padding (RFC 7515 §2). Decode
any part with standard base64url decoding (re-pad to a multiple of 4 bytes
first if your library requires it).

Producers SHOULD emit `"c14n":"JCS"` in the protected header as an informational
label. The decoded protected header and payload bytes MUST already be RFC 8785
JCS; a verifier enforces those bytes regardless of whether the label is present.

To check a vector against your own implementation: verify each token's JWS
signature with HMAC-SHA256 over the ASCII bytes of
`base64url(header) + "." + base64url(payload)`, using the raw bytes of
`secret_hex` (hex-decoded) as the HMAC key — then run the Offline
Verification Algorithm from the draft's "Offline Verification Algorithm"
section against the decoded tokens and `now`, and confirm your verifier's
outcome matches `expect`/`expect_reject_reason`.

## Why HS256 for interop vectors carrying a published secret

`signer.secret_hex` is deliberately public — it is printed in this
directory's own JSON files. HMAC is symmetric (see
`attenu_guard.wire.HS256TestSigner`'s docstring): anyone who can verify
a token with this secret can also forge one with it. That is fine here and
does not undermine the vectors' purpose: these vectors exist to pin down the
wire **format** (exact claim shapes, base64url encoding, the `par_hash`
byte-commitment) and the offline verification **algorithm** (the sequence
of checks and their order), which are signature-algorithm-agnostic — not to
demonstrate a production trust boundary. `HS256TestSigner` needs no
third-party install, which keeps these vectors runnable with bare `python3`
everywhere. The draft's actual production requirement is Ed25519
(`attenu_guard.wire.Ed25519Signer`, public-key, offline-verifiable
without sharing a secret) — swapping the signer under test does not change
anything about the claim shapes or the verification algorithm these vectors
pin down, so a from-scratch implementation targeting production use should
still implement Ed25519 per the draft, and MAY use these HS256 vectors
purely to validate its claim-parsing and verification-algorithm logic.
