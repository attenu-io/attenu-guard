# Denial contract (attenu-guard)

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

### `disposition` — *why* the scope was absent (held is not over-reach)

A `deny` entry — and the denial an adapter hands back to the model — carries a `disposition`
(`Disposition` constants), stated by the authority source and recorded by the shim, never derived by it:

| disposition | meaning | what it tells a human |
|---|---|---|
| `held_pending_grant` | a known tool in your policy pack whose scope awaits an explicit operator grant | **Held — waiting for your approval** |
| `withheld_tier2` | resolvable to a scope in your policy pack that needs one manual approval | grant it, or leave it held |
| `unresolved` | no authority is known for this tool at all (no policy / not in your policy pack) | declare it |
| `out_of_authority` | resolved and grantable, but not held by **this** node | **we stopped something** — real over-reach |

A plain `scope_not_granted` deny the caller did not explain records `out_of_authority` (the shim's own truth);
unknown values are refused before anything reaches the ledger; `allow` entries never carry it. An undeclared
tool is put on the ledger by every policy-map adapter as `unresolved` via `Guard.record_denial` — never only
in the adapter's memory. The Decisions queue of a console is `evidence.denials(bundle)`, a fold over exactly
these fields.

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

## The A2A receiving hop

`GuardedAgentExecutor` (`attenu_guard.adapters.a2a`) gates every inbound task before `inner.execute`
runs. After the chain itself is read and verified offline (a missing or invalid chain is refused
first), three more gates can still refuse the served `Guard`:

| gate | condition | error | disposition |
|---|---|---|---|
| `revocation_check=` | the deployment's own status-list/revocation feed returns a reason for the verified leaf | `revoked` | `out_of_authority` |
| `authority_for(agent_id, task)` | returns `None` — no permissions defined for what this agent's task needs | `no_authority` | `unresolved` |
| `authority_for(agent_id, task)` | returns an authority the verified leaf cannot meet — `Guard.delegate` raises `AuthorityError` rather than serve a widened `Guard` | `no_authority` | `out_of_authority` |

Every refusal reaches the caller as the executor's own denial message (same shape as any other
deny, `extension` field set) before `inner.execute` runs, and lands on the ledger through the same
`Guard`/`AuditLog` path as a denial inside the remote agent's own tools.

## What the parent sees

A child's denials and any strike revocation are on the same chain ledger the parent's Guard owns, so a
parent (or an operator UI) can read them. Where a framework collapses a sub-agent's transcript, the
adapter surfaces the child's denial to the parent explicitly (adapter-specific; tracked per framework).
