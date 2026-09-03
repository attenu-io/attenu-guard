# Offline-verification test vectors

This directory holds three suites, for the three things an independent
implementation has to get right:

- **Delegation Token vectors** (`*.json` here) — token chains for the wire
  format and its offline verification algorithm. Documented first, below.
- **Evidence bundle vectors** (`bundles/bundle_vectors_v1.json`) — whole
  evidence bundles for the ledger verifier: hash-chain integrity against a
  signed anchor, monotonicity, containment, and the schema-v2 execution-binding
  rules. Documented in "Evidence bundle vectors", below.
- **Observer envelope vectors** (`envelopes/envelope_vectors_v1.json`) — the
  same bundles carrying a witness's signature over the identity of a ledger
  entry, for the one question the other two cannot answer: was this delegation
  event signed by something outside the process that wrote it? Documented in
  "Observer envelope vectors", below.

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
  "revision": "bundle_vectors_v1.2",      // additive counter; moves when a case is appended
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
- Every rejecting bundle is derived from an accepting case by exactly **one**
  change, so each case isolates one rule: from `valid_bundle_v2`, unless its
  description names `valid_bundle_v2_literal`. Unless a case says otherwise, the
  chain was re-hashed and a fresh anchor signed over it after the change, so
  integrity is NOT what fails.
- Cases are **appended, never inserted, changed or removed**: a case's name,
  position and declared minimal set are stable for life. So `version` is the
  compatibility contract and stays `bundle_vectors_v1` — an implementation that
  scored the file before still scores it — while `revision` moves with each
  addition, which is what a report should name (`bundle_vectors_v1.2`,
  seventeen cases). Iterate `cases`; do not assume a length.

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

### Reason vocabulary

The agreement an implementer cannot derive from prose is the set of names below. A verifier
that detects a violation at the right `{seq, node}` but reports it under a name of its own
scores that case as a failure to reproduce, which is what the third independent run found
(9 of 17 before adopting these names, 17 of 17 after). The per-case `Required:` lines are
instances of this table; the table is the contract.

**This vocabulary is closed.** Every reason the released verifier can report is in it, and
every row names a reason the verifier can report; `tests/test_bundle_vectors.py` asserts both
directions against the source, so a check cannot ship without a row and a row cannot outlive
its check. A token that is not here is one the contract has no opinion about. So, for an
implementation that checks a rule the corpus does not name yet: report it under a token of your
own, mark it as outside the contract, and say so in the thread where the corpus is discussed;
the next revision adds the row, the token, and a case that exercises it, and your token is
renamed to match. Inventing is expected; inventing silently is the failure mode. The same
holds for the seven envelope reasons in the observer-envelope section: they are the whole of
envelope v1's set, and a v2 declares its own.

| reason | what it means | positioned on |
|---|---|---|
| `integrity` | an entry's hash chain does not verify (a rehashed, reordered, or altered entry) | the first entry that fails |
| `integrity(anchor)` | the signed anchor does not verify against the bundle head | chain level, no `{seq, node}` |
| `monotonicity` | a spawned node's authority is not a subset of its parent's on some dimension (scopes, ttl, a ceiling, an omitted ceiling); the message names the dimension | the spawn entry of that node |
| `containment` | an `allow` names a node the bundle never spawned, or a scope outside that node's authority | the allow entry |
| `chain_id_mismatch` | an entry, or the anchor, names a different chain than the bundle | the foreign entry; chain level for the anchor |
| `missing_root` | the bundle has zero or more than one root event | chain level |
| `unsupported_version` | the bundle's `v` is not one this verifier supports | chain level |
| `anchor_version_mismatch` | the anchor's `v` differs from the bundle's | chain level |
| `root_version_mismatch` | the root entry's `v` differs from the bundle's | the root entry |
| `mixed_entry_versions` | some entry declares a `v` other than the bundle's | the first such entry |
| `expected_head_mismatch` | the bundle head differs from an independently retained head the verifier was given | chain level |
| `expected_anchor_mismatch` | the bundle's `(seq, head, chain_id, v)` differs from an independently retained anchor | chain level |
| `unreadable_authority` | a `root` entry's `authority` cannot be read back as an authority | that root entry |
| `unreadable_granted` | a `spawn` entry's `granted` cannot be read back as an authority | that spawn entry |

`unreadable_authority` and `unreadable_granted` are the two historical exceptions to the
"reason is the text before the first colon" rule: their message names the node there instead,
so a verifier states those two reasons explicitly rather than parsing them out.

Execution binding is checked on `schema_version=2` chains only; on a v1 bundle these cannot
occur and the report says `"not applicable"`. Every failure in the binding loop is about a
PAIR and is positioned on the **outcome**: the allow was a complete, valid record when it was
written, and it is the outcome that fails to bind to it.

| reason | what it means | positioned on |
|---|---|---|
| `v2_field_on_v1` | an entry on a `schema_version=1` chain carries a v2-only field | that entry |
| `invalid_root` | a `root` record does not satisfy the v2 record schema | that entry |
| `invalid_kill` | a `kill` record does not satisfy it | that entry |
| `invalid_allow` | an `allow` record does not satisfy it | that entry |
| `invalid_deny` | a `deny` record does not satisfy it | that entry |
| `invalid_outcome` | an `outcome` record does not satisfy it | that entry |
| `duplicate_call_id` | one `call_id` on two `allow`/`deny` records, which makes the binding ambiguous by construction | the **second** sighting |
| `duplicate_outcome` | one `call_id` reporting a terminal state twice | the second outcome |
| `outcome_without_allow` | an outcome whose `call_id` no allow in this chain ever issued | the outcome |
| `cross_ref` | an allow and its outcome sit on different nodes | the outcome |
| `outcome_before_allow` | the outcome's `seq` is not after its allow's | the outcome |
| `params_mismatch` | `authorized_params_hash` != `invoked_params_hash`: the arguments that ran were not the arguments authorized | the outcome |

The observer-envelope reasons complete the vocabulary. Each is positioned on the entry the
envelope covers, found by the subject's `seq` — never on a hop coverage skipped. The
observer-envelope section below is their full treatment.

| reason | what it means | positioned on |
|---|---|---|
| `envelope_unknown_version` | a `v` or `typ` this verifier does not know | the covered entry |
| `envelope_unknown_member` | a member added anywhere in the envelope at `v: 1` | the covered entry |
| `envelope_subject_mismatch` | a subject missing a member its `event` requires, a `seq` or `event` that is not an integer or a string, an `event` v1 has no subject for, an `entry_hash` disagreeing with the hash recomputed for that `seq`, or a locator disagreeing with the entry `seq` found | the covered entry, or nowhere when `seq` names no entry |
| `envelope_duplicate_subject` | a second envelope over an entry an earlier envelope in the same array already named | the covered entry |
| `envelope_non_canonical` | the bytes as received are not JCS of what they parse to, or the envelope holds a value JCS cannot represent at all | the covered entry |
| `envelope_unknown_witness` | `witness.kid` names a key that is not in `witness_keys`, is not a string, or an `alg` other than EdDSA | the covered entry |
| `envelope_bad_signature` | the signature does not verify under the key `witness.kid` names, or `sig` is not a hex string | the covered entry |

`tests/test_bundle_vectors.py` asserts that this vocabulary and the reasons `evidence.py` can
actually report are the same set, so a new check cannot be added without a row here.

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

- `valid_bundle_v2_literal` — `valid_bundle_v2` with one difference: the
  root holds `{crm.read, mail.send}` instead of `{crm.*, mail.send}`, so the
  child's `{crm.read}` is a **literal** subset of its parent's scopes, with no
  wildcard in play. Every check MUST pass. It is the base for the four rows
  below, and exists for one reason, stated after them. (Added in revision
  v1.2.)
- `reject_increased_ttl_literal` — `reject_increased_ttl`, derived from
  `valid_bundle_v2_literal` instead: ttl 7200 under a parent holding 3600,
  scopes a literal subset. Required: `monotonicity` on the spawn. (Added in
  revision v1.2.)
- `reject_loosened_ceiling_literal` — `reject_loosened_ceiling`, derived from
  `valid_bundle_v2_literal` instead: `max_rows` 250000 under a parent bounded
  at 100000, scopes a literal subset. Required: `monotonicity` on the spawn.
  (Added in revision v1.2.)
- `reject_null_ttl_literal` — the `spawn` grants the child no ttl at all
  (`ttl` null) under a parent holding 3600: a child that never expires under a
  parent that does. The ttl dimension failing by omission rather than by
  growth. Derived from `valid_bundle_v2_literal`. Required: `monotonicity` on
  the spawn. (Added in revision v1.2.)
- `reject_omitted_ceiling_literal` — the `spawn` grants the child no ceilings
  (`constraints` empty) under a parent bounded at `max_rows` 100000: a child
  unbounded on a dimension its parent bounds. The ceiling dimension failing by
  omission. Derived from `valid_bundle_v2_literal`. Required: `monotonicity`
  on the spawn. (Added in revision v1.2.)

None of the four v1.1 cases or the four v1.2 rejecting cases has a permitted
extra: each fails exactly one check and reports exactly one failure.

Attenuation is a lattice relation over three dimensions, not a scope list, so
the v1.1 ttl and ceiling cases add no scope at all. A verifier that compares
scope sets alone, wildcard-aware, accepts both and reports nothing. But a
verifier that compares scope lists **literally** and skips ttl and ceilings
rejects both anyway, for a scope reason at the declared position, because
`crm.read` is not literally in `{crm.*, mail.send}`: it passes the two rows
without ever checking the dimension they are about. attenu-guard through
0.11.0 was exactly that verifier, its monotonicity check gated on a literal,
non-wildcard-aware scope difference, and it scores both v1.1 rows as
conformant. The gate is gone and the relation alone now decides, but the rows
did not discriminate it, which is what revision v1.2 fixes. The four
`_literal` rows derive from a base whose child scopes are a plain subset of
the parent's, so a literal comparison finds nothing and only a ttl or ceiling
check can produce the required failure. attenu-guard 0.11.0 accepts all four
and 0.12.1 rejects each one, naming the dimension. Two of them are the
omission modes the previous revision described without a vector: a child that
omits a ceiling its parent holds, and a child with no ttl under a parent that
has one.

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
- **@safal207, 2026-09-03** — the same stdlib-only verifier, re-pinned to the released
  `bundle_vectors_v1.json` at attenu-guard `v0.12.0` (revision `bundle_vectors_v1.1`, twelve
  cases): 12 of 12 conformant. Proof tree `safal207/ContractGraph-QA` at commit `2a3623d`,
  `proofs/attenu-guard-v0.12.0-independent`; the fixture, verifier and report hashes he
  published match the files in that tree and the fixture matches ours byte for byte (checked
  from this side). He also ran the exact `v0.11.0` verifier against v1.1 and reported what
  the note above says: it rejects `reject_increased_ttl` and `reject_loosened_ceiling` at the
  required position for a scope reason, so those two rows do not discriminate it. Stated
  boundary: corpus conformance for the released fixtures, not regression discrimination.
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
- **Xuebin Ma (@XuebinMa), agent-guard, 2026-09-03** — the same Rust verifier against
  revision `bundle_vectors_v1.2` (seventeen cases), fixture `bundle_vectors_v1.json` at
  attenu-guard `v0.12.1`, 146,765 bytes, sha256
  `54311d68c8342c01ce233f4b1aea251125a4f3323fd9776c01843d3b2f5700ea`, verifier pinned at
  commit `a29f894698121672f87855b38a06f63c73291743`; reproduce with
  `cargo run -p guard-verify -- attenu-vectors --vectors crates/guard-verify/fixtures/attenu/bundle_vectors_v1.json`.
  **First run 9 of 17, then 17 of 17 after one change.** All eight failures were the same
  thing: the violation was detected and positioned correctly (right `seq`, right `node`) but
  reported as `not_narrower` where the corpus requires `monotonicity`, and as
  `scope_not_authorized` where it requires `containment`. The four v1.2 discrimination rows
  (longer ttl, looser ceiling, omitted ceiling, null ttl, each on a literal-subset scope set)
  were all rejected at seq 1 before any change. He reported the first number on purpose, as
  the one worth having; it is why the reason-vocabulary table above exists. Stated boundary,
  his words: "independent reproduction of the released corpus at that pinned boundary. Not
  verifier completeness, not runtime correctness, not certification." Source: crewAIInc/crewAI#5888.

## Observer envelope vectors

`envelopes/envelope_vectors_v1.json` is the third suite, and the narrowest.
The token vectors pin what a delegation token means; the bundle vectors pin
what the ledger of a run has to satisfy; these pin the one question neither
can answer — **was this delegation event signed by something outside the
process that wrote it?**

An **observer envelope** is a witness's Ed25519 signature over the **identity**
of one committed ledger entry, never over its contents, which the entry's own
`hash` already covers. Envelopes travel beside the ledger in the bundle's
top-level `envelopes` array. No entry changes, so a bundle without them stays
valid exactly as it is today.

An envelope is **never required**. An absent one is the status quo and changes
nothing; every entry of a bundle without them reports `process-asserted`. A
**present** one has to verify: a broken envelope lands in the same failure list
as the chain-level checks and the bundle rejects.

Per entry — the entry, not the node, because a node carries several entries and
an `allow` never creates a node of its own — a verifier reports one of two
states:

- **`witness-signed`**: an envelope exists whose `subject` matches the entry
  recomputed from the bundle, and whose signature verifies under the trusted key
  its `witness.kid` names. A signature that verifies under some *other* trusted
  key is not witness-signed. The state says where the signature came from and
  nothing about authority: the witness is whoever holds that key, and nothing in
  the envelope makes that the delegation parent.
- **`process-asserted`**: no envelope, or one that does not verify. This covers
  two facts a bundle does not separate — a hop nobody undertook to cover, and a
  hop a witness undertook to cover and never did. v1 takes the weaker reading
  and stops there.

`observed.result` never changes the state. A verifying envelope is
witness-signed whatever the witness concluded, and the report line prints the
two together, in the same form for all three results: `witness-signed
(matched)`, `witness-signed (not_matched)`, `witness-signed (indeterminate)`. A
process-asserted entry gets no result.

**`witness.alg` is part of the contract, not a negotiation.** v1 defines
`EdDSA` and no other algorithm, so an envelope naming anything else is
`envelope_unknown_witness` — whatever the trust-set row it is compared with
happens to say. A verifier that only compares the two algs accepts `"none"` the
moment both sides say it; one that ignores the alg hands `"HS256"` to its
Ed25519 verifier and reports a signature failure, naming the wrong cause on an
envelope whose signature was never the problem.

**A bundle is attacker-supplied, so a verifier reports and never raises.** Every
envelope member is an untrusted JSON value of any type. A `seq` that is not an
integer, an `event` or a `witness.kid` that is not a string, a `sig` that is not
a hex string, and a value JCS cannot represent are each a reason in the table
above, never an exception out of the verifier. `witness_keys` is the one
envelope input that is NOT attacker-supplied — the deployment chose those keys —
so a malformed row there raises, naming its `kid`, rather than being folded into
a finding about the bundle.

**One entry, at most one envelope.** A second envelope naming a `subject.seq` an
earlier envelope in the same array already named is `envelope_duplicate_subject`
at the covered entry, and that entry reports **`process-asserted`**. Two
observations of one event contradict each other by construction: whoever appends
the second would otherwise decide what the first said, and the same bundle in
the other array order would score differently. The first envelope's result is
still what that witness said; it is the entry that stops being witness-signed.
The rule is per entry, so envelopes over two different hops are the ordinary
sparse case, not a duplicate. An entry is claimed as soon as `subject.seq` finds
it, before the rest of the envelope is judged, so a second envelope cannot
escape the rule by being defective in some other way as well.

Why the file exists before any implementation of it: the third independent run of the bundle
corpus scored 9 of 17 with every check right and every reason name wrong, and its author drew
the conclusion for us. "An implementation working from prose will get the checks right and the
names arbitrary, every time, and nothing local will ever flag it. That seems to me the strongest
available argument for the order you are using on the envelope: vectors posted before anything
is implemented." (Xuebin Ma, @XuebinMa, agent-guard, crewAIInc/crewAI#5888, quoted with his
permission.) The envelope corpus was posted as text, reviewed by three implementers, and built
from that text; the two rows past sixteen came from reviewing the reference verifier against it.

### File format

One JSON object holding every case, in the same shape as the bundle file, with
two fields on every case that the bundle file does not have:

```jsonc
{
  "version": "envelope_vectors_v1",        // compatibility contract; does not move
  "revision": "envelope_vectors_v1.1",     // additive counter; moves when a case is appended
  "description": "what this file is and how it is scored",
  "cases": [
    {
      "name": "reject_locator_mismatch",
      "description": "prose explaining the one change and why it must be rejected",
      "signer": {"alg": "HS256", "kid": "bundle-interop-v1", "secret_hex": "..."},
      "witness_keys": [                      // the Ed25519 keys a verifier trusts for this case
        {"kid": "witness-interop-v1", "alg": "EdDSA", "public_key_hex": "..."}
      ],
      "bundle": { "v": 2, "entries": [...], "anchor": {...}, "envelopes": [...] },
      "expect": "reject",                    // or "accept"
      "expect_states": {                     // EVERY entry, not only the covered ones
        "0": "process-asserted", "1": "process-asserted", "…": "…"
      },
      "expect_failures": [
        {"reason": "envelope_subject_mismatch", "seq": 1, "node": "vectors:n1"}
      ]
    }
  ]
}
```

`bundle` is what `export_bundle()` produces, with the envelopes inside it,
where the contract puts them — so a two-argument scoring call still reaches
them. `signer` verifies the anchor and is **null** on the one case that carries
no anchor. `witness_keys` is the trust set: `public_key_hex` is the raw 32-byte
Ed25519 public key in lowercase hex and `alg` is `EdDSA`, the JOSE identifier
both implementations use for Ed25519. Carrying the keys in the file is what
makes `reject_bad_signature` and `reject_unknown_witness` checkable from the
file alone. `expect_states` covers **every** entry in the chain, so an
accepting case asserts a state and not merely the absence of a failure.

Two more fields appear on one case each:

- **`canonical_hex`** on `valid_jcs_reorder`: the exact JCS bytes the signature
  covers, the envelope without its `sig` member. Those are the **bytes**, not a
  digest over them. Score that row on both halves — it accepts, *and* the bytes
  the verifier canonicalized equal `canonical_hex`. Accepting while producing
  different bytes fails the row.
- **`raw_hex`** on `reject_non_canonical`: the envelope bytes **as received**,
  for that case's single envelope. `envelope_non_canonical` is the one failure a
  verifier cannot raise from a parsed object, because formatting and escaping do
  not survive a parse.

### The envelope

```jsonc
{
  "v": 1,
  "typ": "delegation-event-observation",
  "subject": {"chain_id": "…", "node": "…", "seq": 1, "entry_hash": "…", "event": "spawn"},
  "observed": {"result": "matched", "at": "2026-09-01T11:00:00Z", "method": "…"},
  "witness": {"kid": "…", "alg": "EdDSA"},
  "sig": "…"
}
```

`sig` is over `JCS(envelope minus its "sig" member)`, lowercase hex over the raw
signature bytes — the same canonicalization the ledger has signed with since
0.7.0, and the same hex convention as `entry_hash` and the anchor's own `sig`.

v1 defines two subject member sets, keyed by `event`: `spawn` carries
`chain_id`, `node`, `seq`, `entry_hash`, `event`; `allow` carries those five
plus `call_id`. v1 defines **no** subject for any other event.

`entry_hash` is the **binding member** — the only subject member that is
evidence of *which* entry the witness signed, because the hash covers
`prev_hash` and with it everything before the entry in the chain. The rest are
**locators**, whose job is to find the entry without hashing every entry. A
verifier finds the entry at `seq`, recomputes its hash from the bundle, and
compares; the locators are then checked against **that same entry**, and one
that disagrees is the same failure at the same position. `seq` is the lookup
key, so there is nothing to compare it against.

`observed.result` is a closed vocabulary of three. `matched` means the witness
saw the event and it agrees with what it independently observed.
**`not_matched` requires evidence that contradicts the event** — the witness
looked, and what it saw disagrees. **`indeterminate` is the residual state**: it
holds whenever the witness cannot settle the question in either direction,
including when there was nothing to go on. Thin or absent evidence is
`indeterminate`, never `not_matched`. `method` is free text naming how the
witness observed; the signature covers it, and no verifier decision turns on it.

The version commits the exact signed member set of the **whole** envelope, the
subject included, so a member added anywhere is a new version and the digest
cannot widen silently. A different `typ` is a different contract.

### The seven named failures

Every reported failure carries `{reason, seq, node}`, and every failed envelope
is reported on its own.

| reason | what it is |
|---|---|
| `envelope_unknown_version` | a `v` or `typ` this build does not know |
| `envelope_unknown_member` | a member added anywhere in the envelope at `v: 1` |
| `envelope_subject_mismatch` | a subject missing a member its `event` requires, a `seq` that is not an integer or an `event` that is not a string, an `event` v1 has no subject for, an `entry_hash` that disagrees with the hash recomputed for that `seq`, or a locator that disagrees with the entry `seq` found |
| `envelope_duplicate_subject` | a second envelope over an entry an earlier envelope in the same array already named |
| `envelope_non_canonical` | the bytes as received are not JCS of what they parse to, or the envelope holds a value JCS cannot represent at all |
| `envelope_unknown_witness` | `witness.kid` names a key that is not in `witness_keys`, is not a string, or an `alg` other than EdDSA |
| `envelope_bad_signature` | the signature does not verify under the key `witness.kid` names, or `sig` is not a hex string |

### Scoring, and the two rules on where a failure may land

The minimal-set rule is carried over from the bundle file unchanged. Each
rejecting case declares `expect_failures`: the **minimal set** of
`{reason, seq, node}` that MUST appear.

- A conformant verifier MAY report **more** than the minimal set.
- It may never report **fewer**, and never at a **different position**.
- Cases are **appended, never inserted, changed or removed**, so `version` is
  the compatibility contract and stays `envelope_vectors_v1` while `revision`
  moves with each addition. Iterate `cases`; do not assume a length.
- Unless a row says otherwise, the envelope is **re-signed by the witness after
  the change**, so `envelope_bad_signature` is not what fails.
  `reject_bad_signature` is the only row where it is.

Two rules from envelope v0.1 say where the permitted extras may **not** land.
Both bind scoring:

> An envelope failure lands only on the hop that envelope covers, never on a hop
> coverage skipped. In row 6 the envelope failure is at M, never at N, because
> no envelope covers N.

> A verifier never raises a chain-level integrity failure, `integrity(anchor)`
> or the equivalent it names, because an envelope failed. That failure comes
> from a real anchor mismatch and from nothing else. In row 12 the anchor is
> fresh and in row 14 there is none, so nothing at chain level fails in either.
> In rows 6 and 13 the anchor is the original over a rehashed chain, which is
> what makes `integrity(anchor)` assertable.

Score yourself with nothing but `pip install attenu-guard`:

```python
from attenu_guard import vectors

for case in vectors.load_envelope_vectors()["cases"]:
    report = my_verifier(case["bundle"], case["signer"], case["witness_keys"])
    assert report.accepted == (case["expect"] == "accept"), case["name"]
    assert report.states == case["expect_states"], case["name"]     # every entry
    for expected in case["expect_failures"]:                        # reason AND position
        assert expected in report.failures, (case["name"], expected)
```

`vectors.read_envelope_vectors_bytes()` gives you the raw JSON. This
repository's own verifier returns the same information as
`verify_bundle(bundle, signer, witness_keys=...)`, whose report carries
`failure_details` as before plus an `envelopes` summary with `states`,
`results` and `lines`.

### Cases

Every case runs on the **same nine-entry ledger** as `valid_bundle_v2` in the
bundle file — imported by the generator, not restated, so the two files cannot
describe different chains. Envelope-eligible entries are therefore the `spawn`
at seq 1 (`vectors:n1`) and the `allow`s at seq 2 (`vectors:n0`) and seq 4
(`vectors:n1`).

- `valid_spawn_envelope` — one honest envelope over the `spawn` at seq 1. Every
  check passes; seq 1 reports `witness-signed (matched)`, every other entry
  `process-asserted`. The rejecting rows below are this case with one change,
  unless their description names another.
- `valid_allow_envelope` — the same over the `allow` at seq 2, whose subject
  carries `call_id` alongside the five members a spawn subject carries.
- `valid_jcs_reorder` — the positive control for canonicalization: the same
  envelope as `valid_spawn_envelope`, same subject and same signature, with its
  members written in a different **source** order at every level. It accepts,
  and the row carries `canonical_hex`. **Every other object in this file is
  written with its members sorted; this envelope is the one deliberate
  exception, because a writer that sorted it would delete what the case tests.**
- `absent_envelope` — no top-level `envelopes` member at all: every bundle
  written before this contract existed. It verifies exactly as it does today
  and every entry reports `process-asserted`.
- `indeterminate_result` — a witness that looked and could not decide. It is
  carried and reported, and it is not a failure: seq 1 reports
  `witness-signed (indeterminate)`.
- `reject_rehashed_chain_sparse` — the `ts` at seq 1 restated and every later
  hash recomputed, with the **original** anchor. Coverage **skips** the mutated
  entry: the only envelope is over seq 2, the next covered hop, whose hash moved
  with the rehash. Required: `integrity(anchor)` at chain level, and
  `envelope_subject_mismatch` at seq 2. Position is only ever as fine as
  coverage.
- `reject_subject_mismatch` — the subject's `entry_hash` altered by one nibble,
  envelope re-signed. Required: `envelope_subject_mismatch` at the covered
  entry.
- `reject_bad_signature` — signed by a different key that **is** in
  `witness_keys`, while `witness.kid` still names the first, so only the
  signature is wrong. Required: `envelope_bad_signature`. The only row where it
  is what fails.
- `reject_unknown_version` — `v: 2`, re-signed, everything else untouched. The
  signature is valid, which is the point: a verifier that checks the signature
  first still has to refuse. Required: `envelope_unknown_version`.
- `reject_non_canonical` — the same object serialized non-canonically (the
  `typ` value's leading character written as a `\u0064` escape) and signed over
  **those** bytes, carried in `raw_hex`. Required: `envelope_non_canonical`. A
  verifier that recomputes the signing preimage also gets
  `envelope_bad_signature` here and may report it; that is an extra, and the
  required failure does not depend on whether a deployment kept the bytes.
- `reject_member_without_bump` — a member added to the subject with no version
  bump, re-signed. Required: `envelope_unknown_member`. Note the direction: a
  member **added** is `envelope_unknown_member`, a subject **missing** a member
  its event requires is `envelope_subject_mismatch`.
- `reject_masked_bundle_mutation` — the covered entry's `ts` mutated on the
  bundle side after the envelope was signed, chain re-hashed, **fresh** anchor.
  The envelope still verifies and the entry no longer matches it. Required:
  `envelope_subject_mismatch`, and that is the whole minimal set — nothing at
  chain level fails, and nothing may be reported there.
- `reject_rehashed_chain_anchored` — `reject_rehashed_chain_sparse` with the
  mutated entry **covered**. The two rows differ only in whether it carries an
  envelope. Required: `integrity(anchor)` and `envelope_subject_mismatch` at
  seq 1. This build also reports the mismatch at seq 2, whose hash moved with
  the same rehash; that is an extra on a covered hop.
- `reject_rehashed_chain_unanchored` — the same mutation with **no anchor** and
  `"signer": null`, so no bundle-level anchor check runs. Required:
  `envelope_subject_mismatch` at seq 1, and it is the only check that fails.
  **This is the row that fails only if the envelope check exists.**
- `reject_unknown_witness` — signed by a key whose `kid` is not in
  `witness_keys`. The signature is genuine; there is simply no reason to trust
  it. Required: `envelope_unknown_witness`.
- `reject_locator_mismatch` — the ledger and `entry_hash` untouched,
  `subject.node` the only change and set to **another node in the same chain**,
  so a verifier that looks the entry up by node lands on a real entry that is
  the wrong one. Re-signed. Required: `envelope_subject_mismatch` at the
  **found** entry's `{seq, node}` — the entry `seq` locates, not the node the
  subject names. This pins the position rule for a disagreeing locator on its
  own, since `reject_subject_mismatch` only exercises the hash. (Proposed by
  @safal207 on A2A #1575; appended after row 15, so nothing above it moved.)
- `reject_duplicate_subject` — **two** envelopes over the same entry, the
  `spawn` at seq 1. Both are honest on their own: the first is
  `valid_spawn_envelope`'s, saying `matched`; the second is signed by
  `witness-interop-v1-b`, the second key the trust set carries, over the same
  subject, saying `not_matched`. Nothing is malformed and both signatures
  verify, which is the point — a verifier that keeps one state per entry and
  overwrites it reports whichever envelope it read last, so the same bundle in
  the other order scores differently. Required: `envelope_duplicate_subject` at
  the covered entry, and seq 1 MUST report `process-asserted`. (Appended at
  revision `envelope_vectors_v1.1`, after row 16.)
- `reject_unknown_alg` — `witness.alg` set to `"none"` and the envelope
  **re-signed with the witness's real key**, so the signature is genuine and the
  `kid` is one the trust set carries. Required: `envelope_unknown_witness` at
  the covered entry, and seq 1 MUST report `process-asserted`. The row
  discriminates two verifiers a signature check alone would pass: one that
  compares the envelope's `alg` with the trust-set row's and accepts when both
  say `"none"`, and one that ignores `alg` and reports
  `envelope_bad_signature` — the right verdict for the wrong reason.
  (Appended at revision `envelope_vectors_v1.1`, after row 17.)

### Known limits of envelope v1, stated rather than fixed

- **An envelope is outside the anchor.** The bundle anchor signs the ledger head, not the
  `envelopes` array, so an array stripped in transit is indistinguishable from a bundle that
  never carried one: the verifier reports every entry `process-asserted` and raises nothing.
  That is the v0/v0.1 design (an absent envelope is the status quo), and it is the open
  question for a v2: anchor coverage, or an envelope count in the anchor.
- **The strict leak check does not read envelope text.** `export_bundle(strict=True)` vets the
  ledger entries; `observed.method`, `observed.at` and `witness.kid` are free text a witness
  wrote and pass through unvetted. Keep them free of anything you would not put in a ledger.
- **Canonicality is checked only where the received bytes are supplied**, and the report does
  not yet say per envelope whether that check ran. A `witness-signed` entry whose bytes were
  never supplied was not canonicality-checked; a later revision adds a per-envelope field.

### Regenerating

```
python3 tests/vectors/generate_envelopes.py
```

That writes `envelopes/` here AND `src/attenu_guard/vectors/envelopes/` from one
serialisation, so the two are byte-identical by construction. Never hand-edit
either copy. Deterministic: the chain's two CSPRNG draws are fixed by the bundle
generator, the three witness keys are derived from fixed seed strings, and
**Ed25519 signing is itself deterministic** (RFC 8032 derives the nonce from the
key and the message, never from a CSPRNG), so the signatures are the same bytes
whether `cryptography` is installed or the stdlib implementation in
`attenu_guard._ed25519` produced them. The generator self-checks every case
against this build's own `verify_bundle()` before exiting 0, and
`tests/test_envelope_vectors.py` regenerates and re-scores the whole file on
every test run.

### Why Ed25519 here, and HS256 for the anchors

The bundle anchors keep the published-secret HS256 signer for the reason given
at the end of this file. The envelopes cannot: the contract fixes
`witness.alg` at `EdDSA` and defines no other value, and a symmetric secret
printed in the file would make `reject_bad_signature` and
`reject_unknown_witness` unscoreable, since anyone reading the file could mint
either. Ed25519 is asymmetric, so the file carries only public keys and a
scorer still cannot forge an envelope. To keep the corpus runnable and
regenerable with bare `python3`, `attenu_guard._ed25519` implements RFC 8032 in
the standard library; `attenu_guard.evidence` prefers `cryptography` when it is
installed, and `tests/test_ed25519.py` pins both against the RFC's own test
vectors and against each other.

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
