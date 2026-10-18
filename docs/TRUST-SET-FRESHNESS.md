# Trust-set freshness: a `not_after` for the whole `witness_keys` set

Design note for [#35](https://github.com/attenu-io/attenu-guard/issues/35). Status: implemented
in this repository and in attenu-guard-ts, unreleased.

## The gap

Since 0.19.0 (TypeScript 0.13.0) a `witness_keys` row may carry `not_after`. Two gaps remain,
as #35 states them:

1. The reader's clock decides. A wrong or manipulated clock accepts an expired row.
2. Nothing says the set itself is current. A stale copy is accepted until its rows expire, and a
   row without `not_after` never does.

This note closes the second gap. The first one stays open, and the threat model says so.

## The design

A trust set may be given as a document instead of a bare array:

```json
{
  "witness_keys": [
    {"kid": "witness-a", "alg": "EdDSA", "public_key_hex": "...", "not_after": "2027-01-01T00:00:00Z"},
    {"kid": "witness-b", "alg": "EdDSA", "public_key_hex": "..."}
  ],
  "not_after": "2026-11-01T00:00:00Z"
}
```

- **`not_after` on the document** is the set's own validity, in the row grammar: an RFC 3339
  date-time in UTC, written with `Z`. It is optional. A document without it means what the bare
  array means.
- **At or after the set's `not_after`, no row is trusted.** Every envelope then fails the
  existing `envelope_unknown_witness`. For a key the set held, the message says the trust set
  expired and when: `...: the trust set expired at not_after='2026-11-01T00:00:00Z'`. A row
  whose own `not_after` has also passed keeps its own message, `the key expired at`, and an
  envelope naming a kid the set never held gets the plain message. No new reason is added, so
  no vector and no reason table changes.
- **Every row gets an upper bound.** A row is trusted until the earlier of its own `not_after`
  and the set's. A row without `not_after` is no longer trusted forever once it sits in a
  document that has one.
- **The document is read whole.** Its members are `witness_keys` and `not_after` and nothing
  else. Any other member is refused, so a misspelled `notAfter` cannot leave a set that never
  expires. A `not_after` that is not in the grammar, `null` included, is refused. The rows are
  checked exactly as before. "Whole" is per member, not per byte: a JSON object that names a
  member twice reaches the reader with one value, the last, in both the Python and the
  TypeScript JSON parsers, so a trust file that writes `not_after` twice is read by its second
  one.
- **The same comparison as a row.** The set's `not_after` is compared with the verification time
  the rows use: the caller's `now` when given, and the reader's own UTC clock otherwise.

Where it is accepted:

| Surface | Python | TypeScript |
|---|---|---|
| Library | `verify_bundle(..., witness_keys=document)`, `verify_envelopes(...)` | `verifyBundle(..., { witnessKeys: document })`, `verifyEnvelopes(...)` |
| CLI | `--witness-keys FILE`, the file holding the document | the same |

A mapping is read as a document when it has a `witness_keys` member. The `{kid: key}` mapping
form therefore cannot name a kid `witness_keys`. The CLI reads a JSON object as a vector case
when it has both `bundle` and `witness_keys` members, as before, and takes that case's
`witness_keys`. Any other object with `witness_keys` is a trust-set document, read whole by the
library. An object with both `bundle` and `not_after` is refused: read as a vector case, the
set's expiry would be dropped. A vector case is not read whole: a misspelled `notAfter` on a
vector case is ignored and the case still verifies. "Read whole" applies to the document form
only.

## What it does not do

- **It does not fix the clock.** The set's `not_after` protects against staleness for a reader
  whose clock is right. A reader whose clock is behind, or held by an adversary, still accepts an
  expired set. `docs/THREAT-MODEL.md` says so.
- **It is not signed.** The proposal in #35 was a signed, short-lived statement over the set's
  digest, after TUF's timestamp role. A signature protects a set that reaches the reader over a
  channel the curator does not control. It needs a key the reader trusts in turn, and #35 left
  that key, and how the reader learns it, open. Today the trust set is the reader's own
  configuration, the one envelope input the verifier documents as not attacker-supplied. An unsigned
  expiry answers the stale copy of that configuration. A signed statement can wrap this same
  document later, when trust sets are distributed rather than configured.
- **Older readers ignore it.** A CLI before this change reads any object with a `witness_keys`
  member as a vector case and takes the array, so it trusts a document's rows without the set's
  expiry. The libraries before this change read a document passed as a mapping as `{kid: key}`
  and refuse it, so a library caller fails closed. Upgrade the reader before relying on the
  set's `not_after`.
