# Denial contract (delegation-guard)

*What an agent, an adapter, and a ledger reader can rely on when a call is denied. Companion to the strike
policy (`StrikePolicy`).*

## The `Decision`

`Guard.check(scope, ...)` never raises; it returns a `Decision` that is falsy on denial and carries a
machine-readable, ordered list of `Reason`s. Every reason has a stable `code` (a `ReasonCode` constant):

| code | meaning |
|---|---|
| `scope_not_granted` | the node's authority does not cover the requested scope |
| `ceiling_exceeded` | a held ceiling (rows/spend/calls/egress) would be breached |
| `REVOKED` | the node or an ancestor is revoked (includes a strike-policy revocation) |
| `NO_AUTHORITY` | the principal holds no authority in this chain (adapter-level) |
| `TTL_EXPIRED` | the node's authority has expired |

Every allow **and** every deny is appended to the hash-chained audit log, so a denial is always
independently verifiable after the fact.

## What an adapter MUST do on a denial

1. **Block before the tool body runs** — the denial is a pre-condition, not a post-hoc log line.
2. **Return a machine-readable reason to the model** — the denied agent is told *what* it may not do and
   that it should not retry, so it can adapt or report instead of looping. (Adapters render the `Decision`
   into their framework's tool-error shape; the `ReasonCode` is preserved.)
3. **Never fail open.** A bug in the adapter, an unparseable argument, or an undeclared tool/agent all deny.

## Strike policy (optional, per installation)

When a `StrikePolicy` is attached, N denials of the same scope (default 3) cascade-revoke the offending
node and emit one `kill` event with `reason="strike_policy"`. This is "what happens when it keeps
getting blocked": the node is cut off and the parent sees why. Off by default; `enabled`, `n`, `mode`
(`same_scope`|`total`) are per-installation config.

## What the parent sees

A child's denials and any strike revocation are on the same chain ledger the parent's Guard owns, so a
parent (or an operator UI) can read them. Where a framework collapses a sub-agent's transcript, the
adapter surfaces the child's denial to the parent explicitly (adapter-specific; tracked per framework).
