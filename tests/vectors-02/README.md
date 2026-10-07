# Offline-verification test vectors for draft -02

This directory holds the Delegation Token vectors for
`docs/draft-asor-wimse-agent-delegation-chain-02.md`: chains that MUST verify and adversarial
chains that MUST be rejected, each naming the outcome of the draft's Table 2 it must produce.
They are the second, separately named set the draft's "Reference Implementation and Test
Vectors" appendix describes. The twenty -01 vectors in `tests/vectors/` are byte-stable and
untouched: they do not conform to the -02 (no `cnf`, no `client_id`, `aud` null), and under
the -02 profile every one of them is `malformed`, which is itself asserted by
`tests/test_wire_02.py`.

## Scoring

Score every file under the -02 rules, with the `verifier` block beside the `signer` block:

```python
from attenu_guard import vectors, wire

for name, data in vectors.load_vectors_02().items():
    signer = wire.HS256TestSigner(bytes.fromhex(data["signer"]["secret_hex"]), kid=data["signer"]["kid"])
    try:
        wire.load(data["tokens"], signer, now=data["now"], draft="02",
                  accepted_algs=data["verifier"]["accepted_algs"],
                  audience=data["verifier"]["audience"])
        outcome = "accept"
    except wire.WireError as e:
        outcome = e.reason
    assert outcome == (data.get("expect") or data["expect_reject_reason"]), name
```

An independent implementation substitutes its own verifier for `wire.load`. The vectors
ship inside the installed package (`vectors.VECTOR_NAMES_02`, `vectors.read_vector_bytes_02`),
so scoring needs `pip install attenu-guard` and nothing else.

**What a run of these files scores.** Steps 1 to 5 and 8 of the -02's Section 6, under the
HS256 single-signer public-test-key profile the `signer` block declares, plus the parse-time
rules of Sections 3, 4 and 4.4. Step 6 (holder binding) and step 7 (status list) are not
scored: every token carries a `cnf` claim whose `jkt` is a deterministic stand-in (the
base64url SHA-256 of the agent id), present and shaped as the -02 requires (a `cnf` carries
`jkt`, `jwk` or `x5t#S256`), with no key behind it. Step 8 is scored for its audience half
only; no vector carries an action.

## File format

```jsonc
{
  "description": "prose explaining the vector and the rule it pins",
  "draft": "02",
  "signer":   {"alg": "HS256", "kid": "interop-02", "secret_hex": "..."},
  "verifier": {"accepted_algs": ["HS256"], "audience": "https://crm.example.com"},
  "now": 0,
  "tokens": ["<jwt>", "<jwt>", ...],      // root-first: [DT_0, DT_1, ..., DT_n]

  // exactly one of:
  "expect": "accept",
  "expect_reject_reason": "not_narrower"
}
```

`verifier.accepted_algs` is the verifier's local list for step 1: a token whose `alg` is off
the list is `signature_invalid` even where its signature verifies. `verifier.audience` is
the Enforcement Point's own identifier for step 8: `DT_n`'s `aud` (a string, or a non-empty
array of strings) must name it, or the outcome is `audience_mismatch`. Both are inputs the
tokens cannot carry, which is why they are declared per vector.

The outcome names are the -02's Table 2, and only those this set can produce:
`malformed`, `signature_invalid`, `par_hash_mismatch`, `principal_altered`, `not_narrower`,
`audience_mismatch`. Each `reject_*` file isolates one rule: where a mutation touches a
token other than the leaf, every later `par_hash` is repaired and every token re-signed, so
the declared reason is the only thing wrong.

## Files

Accepting:

- `valid_chain.json`: the canonical 3-hop chain under the -02: Principal in `sub`, Acting Agent
  in `client_id`, string `aud`, `cnf` on every token; an opaque provider scope (`User.Read`) at
  two hops; a lifetime call bound (`max_calls`/`max_lifetime`); a per-action `max` and a
  per-subtree bound on one key (`max_spend`); an egress rank carrying its `order`.
- `valid_audience_array.json`: `aud` as an array that includes the verifier's audience.
- `valid_opaque_exact.json`: opaque scopes narrow by byte identity (Kieran Sweeney).
- `valid_range_min_max.json`: `min` and `max` on one key form a range; one constraint per
  (key, type).
- `valid_unknown_constraint_identical.json`: an unimplemented constraint type, carried
  identically by parent and child, is not malformed; it fails closed at step 8.

Section 3, claims (all `malformed` unless named): `reject_principal_altered.json`
(`principal_altered`), `reject_root_without_principal.json`, `reject_missing_client_id.json`,
`reject_aud_null.json`, `reject_aud_empty_array.json`, `reject_audience_mismatch.json`
(`audience_mismatch`, scored at a different audience), `reject_missing_cnf.json`,
`reject_cnf_without_confirmation.json` (an object with no `jkt`, `jwk` or `x5t#S256`),
`reject_unsafe_integer.json` (2^53).

Section 6 step 1: `reject_alg_not_accepted.json` (`signature_invalid`, scored under
`["EdDSA"]`).

Section 4.1, scope grammar: `reject_wildcard_over_opaque.json` and
`reject_opaque_over_wildcard.json` (`not_narrower`, Kieran Sweeney), `reject_opaque_case_folded.json`
(`not_narrower`), `reject_mixed_case_wildcard.json` and `reject_newline_scope.json` (`malformed`;
the second catches a grammar check that lets a trailing line feed through).

Sections 4.2 and 4.3, constraints: `reject_max_lifetime_widened.json`,
`reject_max_subtree_widened.json`, `reject_cross_type_lifetime_for_max.json`,
`reject_rank_order_mismatch.json`, `reject_child_raises_del_max_depth.json` (rule 5, per hop)
(all `not_narrower`); `reject_child_exp_exceeds_parent.json` (`expired`: rule 4 is step 5,
never a step-4 outcome, so a verifier comparing derived lifetimes at step 4 is wrong);
`reject_rank_without_order.json`,
`reject_rank_outside_order.json`, `reject_duplicate_key_type.json`,
`reject_constraint_extra_member.json` (all `malformed`).

Sections 4 and 4.4, the detail: `reject_detail_extra_member.json`, `reject_second_detail.json`,
`reject_unknown_detail_type.json` (all `malformed`; the last mutates DT_0, so a verifier that
classifies detail types only after the signature check still reports `malformed`).

Section 5, the commitment: `reject_reissued_parent.json` (`par_hash_mismatch`): a child
presented with a re-issued parent rather than the instance it commits to;
`reject_altered_sub_and_par_hash.json` (`par_hash_mismatch`): step 2 is named before the
step-3 principal check when both fail.

Step 8 and running totals: no vector carries an action, so the audience-must-be-supplied rule
and the cumulative-constraint denial are exercised by `tests/test_wire_02.py` and
`tests/test_draft02_review_fixes.py` rather than by this set. The running total a cumulative
constraint is measured over never comes from the request context; the reference verifier
takes it through a separate `totals` parameter (`VerifiedChain.permits(scope, ctx, audience=...,
totals=...)`), which may name only the total fields of the cumulative constraints the leaf
holds, and drops exactly those fields from the context it was given (an ordinary constraint
keyed like `order_total` keeps reading its own field). Two library restrictions under the
-02 profile, which the draft does not impose because it reserves no key names: a per-action
`max` on a `max_calls` key is refused as malformed (a cap on a count caps nothing; a count
bound is `max_lifetime` or `max_subtree`), and the guard's own call meter is the only source
of a `max_calls` total in-process.

## Regenerating

```
python3 tests/vectors-02/generate_02.py
```

Writes this directory and `src/attenu_guard/vectors/draft02/` from one serialisation per
file, self-checks every vector against this build's `wire.load(draft="02")`, and touches
nothing in `tests/vectors/`. Deterministic: no clock, no randomness. Never hand-edit either
copy; `tests/test_vectors_02.py` regenerates and compares on every run.

## Credits

`valid_opaque_exact`, `reject_wildcard_over_opaque` and `reject_opaque_over_wildcard` are
Kieran Sweeney's proposed cases from the WIMSE list thread on the -02 scope grammar
(cred-ninja/protocol commit 06e2957, `proposed-vectors/`), re-minted in this set's claim
layout and signed with this set's key; the scope values and declared outcomes are his.
`reject_reissued_parent` pins the answer to Jijie Wei's question on the same list about
what `par_hash` commits to when a parent is re-issued.
