# The auditor's walkthrough — verify a run you did not produce

*You have a bundle someone exported from an agent run. You do not have Attenu, an account, or a network. You have
the verifier and, optionally, the public half of the key that anchored the ledger. This takes about a minute.*

```bash
pipx run attenu-guard verify clean.bundle.json --hs256-key 73616d706c652d6b6579
```

```
integrity=True monotonicity=True containment=True anchor=verified nodes=3 actions_checked=2
OK
```

Three things were just checked, from the file alone:

1. **Integrity** — every entry's hash chains to the previous one, and the signed anchor matches the head. Nothing
   was inserted, removed, or rewritten after the fact.
2. **Monotonicity** — every delegated agent's authority is a subset of its parent's (`child ⊆ parent`), all the way
   down the chain. Nobody was handed more than the agent that delegated to them held.
3. **Containment** — every *allowed* action fell inside the acting agent's authority at the time. The denials are
   on the record too; here one is a row ceiling, one is a scope the reader never held.

## The two ways it fails — and they are different

```bash
pipx run attenu-guard verify tampered.bundle.json --hs256-key 73616d706c652d6b6579
#   integrity=False … anchor=FAILED  — a denial was rewritten into an allow after the fact
pipx run attenu-guard verify widened.bundle.json --hs256-key 73616d706c652d6b6579
#   integrity=True monotonicity=False … anchor=verified — a correctly signed ledger in which a child was
#   granted more than its parent: what an insider holding the key could write, and the invariant still catches it
```

The first is a **rewrite** (someone changed the record). The second is **a record of a wrong grant** — the ledger is
honest and the delegation was not. Both are findings; they point at different people.

## Without the key

```bash
pipx run attenu-guard verify clean.bundle.json
#   integrity=True monotonicity=True containment=True anchor=not checked
```

Chain, subset and containment are still checked; the anchor is not. "OK" then means *consistent* — a consistent
full rewrite by someone holding the signing key cannot be excluded without the key. Ask the operator for the public
half (`.attenu/product.json` → `anchor_pub` in an Attenu-managed app; `--pubkey <hex>` for Ed25519, or the KMS
public key for ES256).

## If the bundle carries observer envelopes

```bash
pipx run attenu-guard verify witnessed.bundle.json --witness-keys witness_keys.json
```

An envelope is a witness's signature over the identity of one ledger entry, carried in the bundle's top-level
`envelopes` array. Whose signature counts is yours to decide, so the keys come from you and never from the bundle:
`witness_keys.json` is `[{"kid": "…", "alg": "EdDSA", "public_key_hex": "…"}]`. Without the flag every envelope
fails `envelope_unknown_witness` — an unknown key is not a trusted one — and the output names the flag to pass.

## What the bundle is

`export_bundle` output: the hash-chained entries, a signed anchor over the head, a redaction report (prompts and
argument values never leave — names, scope classes, quantity buckets and salted hashes do), and a note. The schema is
[`schema/agent-audit.schema.json`](../../schema/agent-audit.schema.json). Regenerate the samples with
`python examples/verify/make_samples.py` (deterministic; the verifier key is the test signer's — production anchors
are Ed25519, product-local by default, or a KMS-held P-256 key).
