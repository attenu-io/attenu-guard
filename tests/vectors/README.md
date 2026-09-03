# Offline-verification test vectors

This directory holds two suites, for the two things an independent
implementation has to get right:

- **Delegation Token vectors** (`*.json` here) — token chains for the wire
  format and its offline verification algorithm. Documented first, below.
- **Evidence bundle vectors** (`bundles/bundle_vectors_v1.json`) — whole
  evidence bundles for the ledger verifier: hash-chain integrity against a
  signed anchor, monotonicity, containment, and the schema-v2 execution-binding
  rules. Documented in "Evidence bundle vectors", below.

## Delegation Token offline-verification test vectors

This suite is the interoperability artifact promised by
`docs/draft-asor-wimse-agent-delegation-chain-01.md`'s "Reference
Implementation and Test Vectors" section: a Delegation Chain that MUST
verify, and a set of adversarial chains that MUST each be rejected, each for
a specific, declared reason. They exist so an **independent implementation**
— in any language, following only the Internet-Draft — can check its own
offline verifier against a fixed, known-good/known-bad set of tokens without
needing this repository's Python or any of its code.

### Getting them without cloning this repository

They ship inside the installed package, so scoring your own verifier needs
nothing but `pip install attenu-guard`:

```python
from attenu_guard import vectors

for name, data in vectors.load_vectors().items():
    outcome = my_verifier(data["tokens"], data["signer"], data["now"])
    assert outcome == (data.get("expect") or data["expect_reject_reason"])
```

`vectors.VECTOR_NAMES` lists the 20 vectors; `vectors.read_vector_bytes(name)` gives
you the raw JSON if you would rather parse it yourself. The copies here and the
packaged ones are byte-identical — `generate.py` writes both from one
serialisation, and `tests/test_wire.py` fails if they ever differ.

### Regenerating

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

### Files

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
- `valid_jcs_big_integer.json` — pins the binary64 form of the largest safe
  integer, `2**53 - 1`: the last value a double still represents exactly.
- `reject_non_finite.json` — carries `NaN`, which is not JSON or JCS.
  `"expect_reject_reason": "non_finite"`.
- `reject_duplicate_member.json` — carries a duplicate object member name.
  `"expect_reject_reason": "duplicate_member"`.
- `reject_unsafe_integer.json` — carries an integer one magnitude past the safe
  range (`2**53`), which collides with its neighbours once rendered through
  binary64. The inverse of `valid_jcs_big_integer.json`.
  `"expect_reject_reason": "malformed"`.
- `valid_jcs_unmarked_header.json` — omits the informational `c14n` marker while
  retaining canonical JCS header and payload bytes. `"expect": "accept"`.

### File format

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

## Evidence bundle vectors

`bundles/bundle_vectors_v1.json` is the bundle-level suite: whole evidence
bundles for `attenu_guard.evidence.verify_bundle`, the check an auditor runs
on a published ledger with no engine, no service and no vendor in the loop.
The token vectors above pin what a delegation token means; these pin what the
LEDGER of a run has to satisfy — the hash chain reproduces and matches a
signed anchor, every delegation is a subset of its parent, every allowed scope
was inside the acting node's authority, and (schema v2) every tool call binds
to exactly one correctly-ordered outcome on the same node, with the arguments
that were authorized.

### File format

One JSON object holding every case:

```jsonc
{
  "version": "bundle_vectors_v1",         // compatibility contract; does not move
  "revision": "bundle_vectors_v1.1",      // additive counter; moves when a case is appended
  "description": "what this file is and how it is scored",
  "cases": [
    {
      "name": "reject_params_mismatch",
      "description": "prose explaining the one change and why it must be rejected",
      "signer": {"alg": "HS256", "kid": "bundle-interop-v1", "secret_hex": "..."},
      "bundle": { "v": 2, "chain_id": "vectors", "entries": [...], "anchor": {...}, ... },
      "expect": "reject",                       // or "accept"
      "expect_failures": [                       // [] for an accepting case
        {"reason": "params_mismatch", "seq": 3, "node": "vectors:n0"}
      ]
    }
  ]
}
```

`bundle` is exactly what `attenu_guard.evidence.export_bundle()` produces and
what `verify_bundle()` takes: the full ledger (`entries`, hash-chained,
root-first) plus the signed `anchor` over its head. `reason` is a stable token,
the text before the first colon in this build's own failure message — with two
historical exceptions that name a node there instead (`unreadable_authority`,
`unreadable_granted`) and so state their reason explicitly; neither occurs in
these vectors.

### Scoring is different here

A bundle verifier reports a LIST of failures, not one reject reason, so each
rejecting case declares `expect_failures`: the **minimal set** of
`{reason, seq, node}` that MUST appear.

- A conformant verifier MAY report **more** than the minimal set. One broken
  record often makes a second check unsatisfiable — a re-used `call_id`
  necessarily orphans somebody's outcome — and reporting that consequence is
  correct, not a failure to match.
- It may never report **fewer**, and never at a **different position**.
  `seq` is the offending entry's own `seq` field and `node` its `node`; both
  are `null` when the failure is chain-level, with nothing single to point at.
- Every rejecting bundle is derived from `valid_bundle_v2` by exactly **one**
  change, so each case isolates one rule. Unless a case says otherwise, the
  chain was re-hashed and a fresh anchor signed over it after the change, so
  integrity is NOT what fails.
- Cases are **appended, never inserted, changed or removed**: a case's name,
  position and declared minimal set are stable for life. So `version` is the
  compatibility contract and stays `bundle_vectors_v1` — an implementation that
  scored the file before still scores it — while `revision` moves with each
  addition, which is what a report should name (`bundle_vectors_v1.1`, twelve
  cases). Iterate `cases`; do not assume a length.

Score yourself with nothing but `pip install attenu-guard`:

```python
from attenu_guard import vectors

for case in vectors.load_bundle_vectors()["cases"]:
    report = my_verifier(case["bundle"], case["signer"])       # your implementation
    assert report.accepted == (case["expect"] == "accept"), case["name"]
    for expected in case["expect_failures"]:                    # reason AND position
        assert expected in report.failures, (case["name"], expected)
```

`vectors.read_bundle_vectors_bytes()` gives you the raw JSON if you would
rather parse it yourself. This repository's own verifier returns the same
information as `verify_bundle(bundle, signer)["failure_details"]`, a list of
`{"reason", "seq", "node", "call_id", "detail"}` that is the structured twin
of the human-readable `failures` list.

### Cases

- `valid_bundle_v2` — a complete, honest chain: an orchestrator delegates to a
  strictly narrower summarizer, each node makes one authorized call that is
  observed to completion with matching argument commitments, one over-reach is
  denied, both nodes finalize. `"expect": "accept"`, no failures. Every case
  below is this bundle with one thing changed.
- `reject_params_mismatch` — the outcome reports an `invoked_params_hash` that
  is not the `authorized_params_hash` its allow committed to: the arguments
  that ran were not the arguments that were authorized. Required:
  `params_mismatch` on the outcome entry.
- `reject_outcome_without_allow` — an outcome whose `call_id` no allow ever
  issued. Required: `outcome_without_allow` on the outcome entry.
- `reject_outcome_before_allow` — an allow and its outcome transposed, so the
  call finishes before it was authorized. Required: `outcome_before_allow` on
  the outcome entry, at its new position.
- `reject_duplicate_outcome` — one `call_id` reporting a terminal state twice.
  Required: `duplicate_outcome` on the second one.
- `reject_duplicate_call_id` — one `call_id` on two allows, which makes the
  allow -> outcome binding ambiguous by construction. Required:
  `duplicate_call_id` on the second sighting. This build additionally reports
  the outcome that is consequently orphaned; that is permitted, not required.
- `reject_rehashed_chain` — one entry edited and every later hash recomputed,
  so the ledger is perfectly self-consistent and only the ORIGINAL signed
  anchor still commits to the head it used to have. This is the rewrite a hash
  chain alone cannot catch. The failure is chain-level: this build reports
  `integrity(anchor)` with `seq` and `node` null, and an implementation that
  names its own equivalent unpositioned integrity failure is conformant.
- `reject_tampered_entry` — the same edit with nothing re-hashed. The stored
  hash no longer covers the entry's contents, so the chain check fails AT that
  entry. Required: `integrity`, positioned on it. This build additionally
  reports `integrity(anchor)` for the same mismatch, because the anchor check
  re-walks the chain before comparing heads; that is the one finding seen
  twice, permitted, not required. (Found by the first independent run.)
- `reject_widened_scope` — the `spawn` grants the child a scope its parent does
  not hold (`{crm.read}` becomes `{crm.read, pay.transfer}` under a parent
  holding `{crm.*, mail.send}`). Authority growing across a handoff is the one
  thing this library exists to make impossible, and a bundle is where an
  auditor catches it after the fact. Required: `monotonicity`, positioned on
  the **spawn that granted too much**, with the child as its node — not on any
  later action, because the spawn is where the authority was created.
  (Asked for by the first two independent runs; added in revision v1.1.)
- `reject_uncontained_allow` — an `allow` authorizes a scope outside what the
  acting node was granted (`crm.export` on a node holding `{crm.read}`). The
  chain root does hold `crm.*` and could have delegated it, so this is the
  acting node over-reaching against its own recorded grant, which is why
  containment is checked separately from monotonicity; the same bundle still
  carries the honest deny of that scope on that node, so the ledger
  contradicts itself in a way a reader can see. Required: `containment`,
  positioned on the allow. (Asked for by the first two independent runs; added
  in revision v1.1.)

- `reject_increased_ttl` — the `spawn` grants a ttl of 7200 under a parent
  holding 3600, so the child outlives the authority it was cut from. No scope
  is added: the grant is still exactly `{crm.read}`. Required:
  `monotonicity` on the spawn. (Added in revision v1.1.)
- `reject_loosened_ceiling` — the `spawn` raises the child's `max_rows` to
  250000 under a parent bounded at 100000, so the child may read more per call
  than the node that delegated to it. No scope is added and the ttl is
  untouched. Required: `monotonicity` on the spawn. (Added in revision v1.1.)

None of the four v1.1 cases has a permitted extra: each fails exactly one
check and reports exactly one failure.

Attenuation is a lattice relation over three dimensions, not a scope list, so
the last two cases add no scope at all. A verifier that compares scope sets
alone accepts both and reports nothing. Two further widenings fail the same
relation by omission rather than by growth, and a verifier should reject them
too, though neither has a vector: a child that omits a ceiling its parent holds
is unbounded on that dimension, and a child with no ttl under a parent that has
one never expires. Both were accepted by attenu-guard through 0.11.0, whose
monotonicity check was gated on a literal, non-wildcard-aware scope difference;
the gate is gone and the relation alone now decides.

### Permitted extras, and where implementations legitimately differ

Two cases have drawn different extras from different implementations. Both
differences are declared implementation choices inside the minimal-set rule,
not defects, and neither changes what is required.

On `reject_duplicate_call_id`, the required failure is `duplicate_call_id` at
seq 4. Which further failures follow depends on how an implementation binds an
outcome to an allow when one `call_id` names two of them. This build binds each
outcome to the **last** allow bearing that `call_id`, so the summarizer's
outcome at seq 6 still binds to its own allow at seq 4 and the only consequence
is the orchestrator's now-unclaimed outcome, reported as `outcome_without_allow`
at seq 3. Two code-independent implementations bound to the **first sighting**
instead and reported the same three downstream consequences as each other: the
orphan at seq 3, and a node mismatch and a params mismatch at seq 6, because
under that rule the summarizer's outcome binds back to the orchestrator's allow
on a different node with a different argument commitment. All of these remain
MAY under minimal-set scoring — one, three or none, at the implementation's
discretion, as long as `duplicate_call_id` at seq 4 is reported.

On `reject_tampered_entry`, the required failure is `integrity` positioned at
seq 3, and whether `integrity(anchor)` also appears is the stored-head versus
recomputed-head choice: this build re-walks the chain inside its anchor check
and so reports the anchor failure too, while an implementation that verifies
the anchor's signature and compares its `head` against the ledger's **stored**
head reports only the positioned failure, because in this case nothing was
re-hashed and the stored head is untouched. Both are conformant; the
`integrity(anchor)` extra is a MAY.

### Verifying a bundle from the file alone

Two hashes and one signature, all over RFC 8785 JCS bytes (the same
canonicalization the token vectors use):

- **Each entry's `hash`** is `SHA-256(prev_hash_ascii || JCS(entry without its
  "hash" member))`, lowercase hex, where `prev_hash_ascii` is the previous
  entry's `hash` as ASCII (not decoded from hex), and the first entry's
  `prev_hash` is 64 `0` characters. Walk the ledger from the start: `seq` must
  equal the position, `prev_hash` must equal the previous entry's `hash`.
- **The anchor** commits to the head: `hex(HMAC-SHA256(secret, JCS(anchor
  without its "kid", "sig" and "verified" members)))` must equal `sig`, and the
  anchor's `seq`/`head` must equal the last entry's `seq`/`hash`. The anchor's
  own `"verified"` field is the producer's claim about itself, never evidence —
  re-check the signature.
- **`signer`** is `{"alg": "HS256", "kid", "secret_hex"}`, the same shape as
  the token vectors; hex-decode `secret_hex` for the HMAC key.

Everything else a verifier needs is in the ledger: `authority` on the `root`
entry and `granted` on each `spawn` give the node authorities to compare for
monotonicity and containment, and the `call_id`/`capture`/`adapter`/
`authorized_params_hash` on allows and `call_id`/`body_state`/
`invoked_params_hash` on outcomes give the execution binding.

### Regenerating

```
python3 tests/vectors/generate_bundles.py
```

That writes `bundles/` here AND `src/attenu_guard/vectors/bundles/` from one
serialisation, so the two are byte-identical by construction. Never hand-edit
either copy. Deterministic: the two values a real chain draws from the OS
CSPRNG (the chain's `params_salt` and every `call_id`) come from a fixed
counter-derived stream during generation, and nothing else in the ledger is
time- or randomness-dependent, so running it twice produces identical bytes.
The generator self-checks every case against this build's own
`verify_bundle()` before exiting 0, and `tests/test_bundle_vectors.py`
regenerates and re-scores the whole file on every test run.

### Independent runs

Runs of this file by verifiers that share no code with this repository, pinned so a reader can
re-run them. Each carries the claim boundary its author stated, and nothing wider.

- **@safal207, 2026-09-02** — a standalone, stdlib-only Python verifier (no `attenu_guard`
  import; the fixture read as raw bytes) scored the released `bundle_vectors_v1.json` at
  attenu-guard `v0.11.0` / attenu-guard-ts `v0.6.0`: 8 of 8 cases conformant, every required
  `{reason, seq, node}` at its declared position, two diagnostic differences inside the
  minimal-set rule. Proof tree, verifier and machine-readable report:
  `safal207/ContractGraph-QA` at commit `052aa3d` (his corrected proof tree; the earlier `61dc428` carried a report not produced by the pinned verifier, which he replaced), `proofs/attenu-guard-v0.11.0-independent`.
  Stated boundary: the released corpus only; no claim of general verifier completeness,
  runtime correctness, production security or certification.
- **Xuebin Ma (@XuebinMa), agent-guard, 2026-09-02** — a Rust verifier
  (`crates/guard-verify/src/attenu/` in `XuebinMa/agent-guard`, pinned at commit
  `7c96469bafb609af8d071de8e71b18806546c0cd`), written from this README and the per-case
  descriptions, by the author's account without reading either reference implementation:
  8 of 8 cases conformant. How it was checked from this side: the vendored fixture is the
  same git blob as ours at `v0.11.0`; the nine Rust files in the crate contain no reference
  to `attenu_guard`, `evidence.py`, `evidence.ts`, `audit.py` or `verifyBundle`; the run was
  not reproduced here, but the repository's `Rust Tests (Workspace)` check is green on that
  commit and its test command covers both the fixture-pin test and the scoring test. His
  extras on `reject_duplicate_call_id` match the previous entry's, position for position.

## Why HS256 for interop vectors carrying a published secret

`signer.secret_hex` is deliberately public — it is printed in this
directory's own JSON files. The same reasoning covers the evidence bundles'
anchor signer. HMAC is symmetric (see
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
