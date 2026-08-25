# Controls mapping — what attenu-guard does for named controls, and what it does not

*This maps mechanisms to controls other people wrote. It is not a certification and not a coverage claim; every row
names the test that pins it. Where a control is broader than the mechanism, the "not covered" column says so.*

## OWASP Top 10 for Agentic Applications (2026)

| Control | Mechanism in attenu-guard | Pinned by | Not covered |
|---|---|---|---|
| **ASI03 — Identity and Privilege Abuse**, incl. *un-scoped privilege inheritance* (a high-privilege agent delegating without least-privilege scoping) | A delegated agent holds `meet(parent, requested)` — scopes, limits and expiry can only narrow (`Authority.meet`, `Guard.delegate`); an over-broad request is met down, never granted; an agent absent from the roster holds nothing | `tests/run_properties.py` (child ⊆ parent over random trees), `tests/test_core_v02.py::TestMeetNeverWidens`, every `examples/integrations/*/*/` gate's `test_authority_is_monotonic_down_the_chain` | Credential-level scoping across a network boundary (the process's ambient credentials are the same for every agent — roadmap: credential-backed attenuation); identity *proofing* of agents |
| **ASI07 — Insecure Inter-Agent Communication** | Authority is a structural object on every handoff, not a message the receiver trusts; prompt text never changes a decision; the wire format signs each hop and links it to its parent (`wire.serialize_chain` / `wire.load`) so a receiving service can verify the chain offline | `tests/test_wire.py`, `tests/vectors/`, `examples/integrations/mcp/server_verifier/` gate (spliced and forged chains refused) | Confidentiality of agent messages; transport security (that is the framework's / MCP's) |
| **ASI08 — Cascading Failures** | Hard chain ceilings (depth, fan-out), per-node metered ceilings (calls, rows, spend), `Guard.revoke()` of a whole subtree in one call, `StrikePolicy` after repeated denials, fail-closed on unknown tools and on an unwritable ledger | `tests/test_core_v02.py` (ceilings, revocation, strikes), `examples/integrations/omnigent/policy_handler/` gate (depth ceiling), every gate's `test_bypass_*` | Failures outside the guarded process; resource exhaustion at the model provider |
| **ASI01 — Agent Goal Hijack** (partial) | A hijacked goal cannot widen what the process may do: decisions come from declared structure, never from prompt or tool text (`Permissions come from declared structure`) | every gate's `test_injection_*`; `tests/red_team.py` | Detecting that the goal was hijacked (that is detection, which this library does not do) |
| **ASI10 — Rogue Agents** (partial) | An agent that deviates is bounded by its authority and can be revoked by principal (`Guard.revoke_agent`) | `tests/test_core_v02.py::TestPrincipalRevocationAndDelegationDryRun` | Behavioural detection of rogue intent |

## Agent Baseline (v1.0-draft, 2026-07-30)

| Control | Mechanism | Pinned by | Not covered |
|---|---|---|---|
| **AUT-03 — Delegation attenuation** (class ENFORCEMENT): "prevents a downstream agent from receiving more authority than its caller holds, preserves the originating context and records each delegation hop" | `Guard.delegate` enforces child ⊆ parent; the audit log records every `spawn`, `allow`, `deny`, `kill` with node, agent and authority; the evidence bundle preserves the chain and verifies offline (`evidence.export_bundle` / `verify_bundle`) | `tests/run_properties.py`, `tests/test_wire.py`, every gate's `test_bypass_tampered_bundle_*` | Originating *user* context beyond what the app declares (the guard records the task string the app provides; it does not authenticate the human) |

## What this library deliberately does not do

Decide the policy for you (see [`attenu-derive`](https://github.com/attenu-io/attenu-derive)) · content or intent
detection · sandboxing of the process (a direct call around the framework runs — every example's trust boundary says
so) · credential issuance. Enforcement claims hold inside the stated trust boundary of each adapter and nowhere else.
