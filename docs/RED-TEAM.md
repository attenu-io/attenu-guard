# Red-Team Report & Threat Model — attenu-guard authorization protocol

*Adversarial assessment of the attenu-guard v0.1 authorization protocol.
Reproduce with `python tests/red_team.py` (exit code = number of unresolved
findings; currently 0). This is a living document — every new attack idea
becomes a case in `tests/red_team.py`, and the harness runs in CI as a gate.*

## What we are protecting

One property, stated in authorization terms and nothing softer:

> **A delegated agent can never obtain authority outside what its parent
> granted, that authority is bounded in scope, magnitude, and time, and a
> revoked delegation authorizes nothing — enforced, not advised.**

An attacker "wins" if a child ends up able to do something outside its parent's
grant (**escalation**), a revoked/expired node still acts (**containment /
time**), a declared control silently does nothing (**unenforced**), or the
record can be altered undetected (**integrity**). We also treat refusing a
*legitimately*-granted action as a defect (**false-deny**) — for an
authorization product, false denials break the workflows we exist to enable.

## Threat model — who the attacker is, per tier

The library has an **in-process tier** (this repo) and a **production
data-plane** (the commercial Attenu plane). They have different trust boundaries,
and honesty about the difference is the whole point of this document.

| | In-process library (OSS) | Production data-plane |
|---|---|---|
| Authority representation | Python object + per-chain HMAC seal | signed, offline-verifiable grant (Biscuit-class) |
| Trusts | its own process | nothing on the hot path; verifies signatures |
| In-scope attacker | a hostile *agent* / malicious delegation request / poisoned tool input; accidental or unsophisticated in-process mutation | + a compromised same-process component; + a malicious enforcement node |
| Out of scope | a same-process adversary that reads process memory | (folded in-scope via signatures) |

The in-process tier's job is to make **child ⊆ parent** true and enforced for
honest infrastructure running dishonest *agents*. That is exactly the OWASP
ASI07/ASI08 threat (a delegated or hijacked agent abusing inherited authority),
and it is what the harness below hammers.

## The two boxes

- **Black-box** — attacks that use only the public API (`spawn` / `check` /
  `kill`). This is the realistic in-band threat: what a hostile agent or a
  poisoned delegation request can attempt. No privileged access.
- **White-box** — attacks that use internal knowledge or same-process access:
  mutating node state, hand-constructing `Authority` objects to probe the order
  relation, re-sealing forged authority. This is a correctness audit of the
  proof machinery plus the same-process boundary.

## Results (v0.1, after the first red-team pass)

16 attacks · **14 defended · 0 unresolved · 2 documented limitations.**

### Defended — the protocol holds

Escalation is refused across every vector tried: requesting broader scopes or a
wildcard the parent never held, requesting a higher numeric ceiling, asking for
`egress: any` under a parent `egress: none`, and scope prefix look-alikes
(`crm.readsecrets` vs `crm.read`) all reduce to the attenuated meet and are
denied at `check()`. Containment holds: a root `kill()` silences the whole
subtree, a revoked node cannot mint fresh children, killing one subtree leaves
unrelated siblings running (blast radius is scoped, not global), and a recursive
delegation "depth bomb" hits the depth ceiling. Time is enforced: an expired-TTL
grant stops authorizing. The order relation `≤` is sound for custom ceilings.
Custom ceilings are both attenuated and enforceable. A wildcard granted by both
parent and request survives the meet (no false-deny). Audit tampering (mutation,
reorder, insertion, deletion) breaks offline verification.

### Findings fixed in this pass

Four were genuine protocol bugs, now closed and each guarded by a red-team case
that fails the build if it regresses:

1. **TTL was carried but never gated** (`unenforced`, black-box). `check()` had
   no expiry logic, so a `ttl=1s` grant authorized forever. *Fixed:* an
   injectable clock, per-node `issued_at`, and an expiry gate in `check()` and
   at delegation time.
2. **The `≤` order relation was unsound for custom ceilings** (`escalation`,
   white-box). A child unbounded on a ceiling key outside the built-in registry
   was judged `≤` a parent that bounded it — the relation the whole attenuation
   proof rests on could bless an escalating child. *Fixed:* any ceiling
   present-and-bounded on the parent but absent on the child now makes `≤`
   false, for every key.
3. **Custom ceilings were attenuated but inert** (`unenforced`, white-box).
   `check()` could only enforce `max_rows`/`max_spend`. *Fixed:* a generic
   `amounts=` path enforces any numeric ceiling (per-call and chain-aggregate).
4. **Wildcard pruning caused false denials** (`false-deny`, white-box). The meet
   dropped a wildcard when a concrete member was also present, so a child
   granted `crm.*` by both sides could be silently reduced to `crm.read`. *Fixed:*
   pruning now removes only redundant scopes a broader wildcard already covers,
   never the broadest grant.

### Documented limitations — by design for the in-process tier

Two attacks are *not* code bugs; they are properties of enforcing in a shared
process, mitigated (not eliminated) here and fully addressed by the production
data-plane. We label them honestly rather than pretend a fix.

- **Declared-quantity trust** (`unenforced`, black-box). Aggregate budgets are
  enforced against the number the caller supplies; an agent that omits the row
  count reads unmetered, because the in-process library cannot observe the true
  size. *Mitigations:* (a) `strict_metering=True` fails closed when a call
  flagged `metered=True` accesses a metered resource without declaring the
  quantity — framework adapters flag consuming calls; (b) the production
  data-plane measures at the gateway, which the agent does not control. The
  honest rule: **place enforcement where the real quantity is observable.**
- **Same-process re-seal** (`escalation`, white-box). The integrity seal catches
  naive mutation of node authority, but a component running in the same process
  can read the per-chain secret and re-seal a forged authority. This is out of
  scope for the library tier by definition. *Mitigation:* the production
  data-plane replaces the shared HMAC secret with signed, offline-verifiable
  grants, so a forged authority is detectable without any shared secret.

## How to extend this

Add an attack as a function returning `("DEFENDED" | "BROKEN" | "LIMITATION",
evidence)` and register it in `BLACK` or `WHITE` in `tests/red_team.py`. A
`BROKEN` result fails CI. New attack ideas welcome via the process in
[SECURITY.md](../SECURITY.md) — including the standing **Break-Our-Plane** pledge
for a commercial layer above the library.
