# Threat model (attenu-guard)

*The adversarial threat model — attacker tiers, defended attacks, and documented limitations —
lives in [`RED-TEAM.md`](RED-TEAM.md). This page states one boundary that document assumes
rather than proves: what the evidence ledger itself attests to.*

## What the evidence does not prove

The hash-chained ledger (`attenu_guard.audit`) and the offline-verifiable bundle it exports
(`attenu_guard.evidence`) record that a call was authorized and that the delegation completed
its lifecycle — an allow/deny per checked scope, a `done` event when a node's work finishes.
That is an authorization and lifecycle record, not an execution record.

An `allow` entry means the call was permitted before it ran; it is not proof the tool ran, and
it does not bind the tool's return value or side effects. `done` says a node was not cut short,
not that every action it took is on the ledger. A call path that bypasses the interception
point — the underlying function called directly, or a framework hook an adapter does not
cover — leaves the ledger silent, and silence is not itself flagged: `verify_bundle` checks
that what the bundle contains is internally consistent (hash chain, monotonicity, containment),
not that the bundle is complete.

Place enforcement where the interception point actually sits (`docs/INTEGRATIONS.md` has each
framework's hook); read the ledger as an authorization record, not an execution trace.

### Witness signatures

An observer envelope is a witness's signature over one ledger entry. The signature covers the
entry's hash and chain position plus what the witness-key holder observed (result, time, method).
It does not attest that the action was permitted. An entry reported `witness-signed` can still
fail containment or monotonicity: a process that appends an allow outside its node's authority,
in chain order, gets it signed by a witness that signs what it receives in chain order, and
containment is the check that catches it. `attenu-guard verify --entries` prints each entry's
envelope state next to the checks that failed on it.

A witness in the subject's own trust domain protects nothing beyond that domain. Place the
witness, and its key, where the process it observes cannot reach them.

Which witness keys count is the verifier's decision, made in `witness_keys`. A row there may
carry `not_after` (RFC 3339, UTC); from that time on the key is not trusted and its envelopes
fail `envelope_unknown_witness`. A row without `not_after` is trusted until it is removed.
