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
