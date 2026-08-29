# attenu-guard × A2A (Agent2Agent protocol)

Tested against **`a2a-sdk` 1.1.2** (Apache-2.0) and the A2A specification of August 2026, on Python 3.12+.

A2A is a protocol rather than a framework: the calling agent and the remote agent are separate
processes, each with its own framework, its own tools and its own ledger. So the delegation moment is
the **hop** — `message:send` — and this adapter is two halves that meet on the wire.

## What A2A already settles

A2A's transport security is careful. Every agent authenticates the caller (§7), the Agent Card declares
security schemes, credentials for in-task authorization are meant to travel out of band, and §7.6.3 warns
that in-band credentials passing through a chain of agents are exposed to each agent in it. That is the
right foundation, and this recipe stands on it.

## What this adapter adds

A2A §7.6.4, "In-Task Authorization Scope", says where the boundary is:

> The A2A protocol does not define the scope, representation, validity, or revocation semantics of the
> authorization decision or credential obtained in response to this state. <!-- lint:allow -->

and:

> If an implementation requires authorization for specific operations, it is responsible for defining how
> the authorized operation is identified and how that authorization is checked before the operation is
> performed. <!-- lint:allow -->

That is what this supplies, through A2A's own **extension** mechanism (§4.6) rather than beside it:

1. **The caller grants less than it holds, and says so on the wire.** `parent.delegate(...)` mints the
   child, and the resulting Delegation Chain — signed JWT-shaped tokens,
   [`attenu_guard.wire`](../../../src/attenu_guard/wire.py) — rides on the outgoing message under
   `https://attenu.io/a2a/delegation-chain/v1`.
2. **The remote agent verifies it offline and narrows again.** Signatures, the parent-hash byte
   commitment at every hop, chain depth, child ⊆ parent at every hop, expiry — no authorization server in
   the path. The served permissions are the meet of the verified leaf and what the remote deployment
   decided this task needs, so neither side can widen the other.
3. **Every tool call is checked before its body**, in the remote process, and the refusal is on a
   hash-chained ledger.
4. **The record verifies afterwards** — the caller's ledger, the remote agent's ledger, and the tokens
   that bind them, from those inputs alone.

## What it hooks

| step | A2A API |
|---|---|
| attach the chain to an outgoing hop | `ClientCallInterceptor.before(BeforeArgs)` (`a2a/client/interceptors.py:46`), run for every call by `BaseClient._intercept_before` (`a2a/client/base_client.py:460`) — the same seam `AuthInterceptor` uses for bearer tokens |
| carry it | `Message.extensions` + `Message.metadata[<uri>]` (spec §4.6.2), plus the `A2A-Extensions` request header (§4.6.1) via `ClientCallContext.service_parameters` |
| read it, gate the remote agent | `AgentExecutor.execute(context, event_queue)` (`a2a/server/agent_execution/agent_executor.py:15`) — the boundary every binding funnels an inbound task through, reached from `DefaultRequestHandlerV2.on_message_send` (`a2a/server/request_handlers/default_request_handler_v2.py:240`) |
| check before a tool body | `guarded_tool(fn, scope=…)` on the remote agent's tools, reading the request's `Guard` from a `ContextVar` |
| declare the extension | `agent_extension()` → `AgentCard.capabilities.extensions` (§4.6.1), `required=True` |

Both hook points are public ABCs. Nothing is monkeypatched and nothing private is touched.

## Run it

```bash
pip install "a2a-sdk>=1.1" attenu-guard
python examples/integrations/a2a/demo.py

# the same story over real HTTP (Starlette + uvicorn, still no API key):
pip install "a2a-sdk[http-server]" uvicorn
RUN_LIVE=1 python examples/integrations/a2a/live_smoke.py
```

`demo.py` runs both agents in one process over `InProcessTransport`, an implementation of the SDK's
public `ClientTransport` ABC (`a2a/client/transports/base.py:28`) that hands the request to the server's
request handler instead of to a socket. Everything either side does is what it does over the wire.
`live_smoke.py` removes that caveat: it boots a Starlette A2A server, resolves the Agent Card over HTTP
and posts JSON-RPC. Point it elsewhere with `A2A_AGENT_URL=…` to exercise the client half against
someone else's agent.

## What you'll see

An orchestrator holding `{crm.read, crm.export, mail.send}` (100 000 rows, egress "any") sends a
summarising task to a remote summariser and grants it `{crm.read}` (5 000 rows, no egress, 15 minutes).
The remote deployment narrows again to 2 000 rows. The remote agent has been poisoned:

* it reads 1 800 CRM rows — **ALLOW**;
* it tries to export to `s3://attacker-bucket/…` — **DENY** (`scope_not_granted`), before the body, in
  the remote process; the control run with no guard exports;
* a 4 200-row read the *caller's* grant would have permitted — **DENY** (`ceiling_exceeded`), because the
  remote end narrowed further;
* a forged chain, a spliced chain, a widened chain, an expired chain and a missing chain are each refused
  at the boundary, before the remote agent's logic starts;
* the client half refuses to send a hop for which no permissions resolved;
* both ledgers and the tokens verify offline, and `attenu-guard verify` re-checks the remote ledger from
  the file.

Ends with `RESULT: OK`, exit `0`.

## Trust boundary

The check lives at the A2A boundary, inside the remote agent's process, before the agent's own logic
runs — and again before each tool body. Inside that boundary: a denied hop never reaches
`inner.execute`; a denied tool never runs its body; a chain that will not verify is a refusal, and so is
any exception raised while deciding; a tool reached by a path that did not pass through
`GuardedAgentExecutor` raises rather than running.

Outside it: a direct call to the underlying Python function inside the remote process, any other route to
the resource behind a tool, and anything the remote agent does that is not a guarded tool. Transport
security, agent authentication and per-hop credentials stay A2A's — this sits on top of them, not
instead of them.

**Extension negotiation is a declaration, not enforcement.** A server that does not know the extension
ignores it (§4.6.3) and is unguarded; that is why a guarded deployment declares it `required=True` and
why the guard, not the card, is what refuses.

## Revocation across the hop

Not solved here, and the shape of the gap is worth stating. `wire.load` does not consult a Token Status
List (that step of the offline verification algorithm is out of scope for the wire format), so a token
revoked in the caller's process after it was minted keeps verifying until it expires. What is enforced:
an **expired** chain is refused, and `revocation_check=` is the seam where a deployment plugs its own
status list or revocation feed — it runs before anything is minted. Keep TTLs short. Cross-process
revocation propagation is tracked as separate work.

## What verifies from where

Two processes, two ledgers, one token chain between them — so be exact about what each proves:

| input | what it proves |
|---|---|
| the **caller's** bundle | the caller's own chain, root → the child it minted for the remote agent, and that the child ⊆ the caller |
| the **remote agent's** bundle | its served node ⊆ the permissions it was handed, plus every allow and deny its tools produced |
| the **tokens** | they bind the two: the remote ledger's continuation root holds the leaf token's permissions exactly, under the leaf's subject, and its `chain_id` is derived from that leaf token's bytes |

`verify_hop(tokens, signer, client_bundle=…, server_bundle=…)` checks all three from those inputs alone.
Neither bundle on its own proves the hop, and a bundle that is not supplied is reported `"not checked"`,
never as passing. Two hops whose leaf tokens are byte-identical land in the same ledger id — give chains
distinct `chain_id`s if you need to tell such hops apart.

## Evidence manifest

| Claim | Pinned to | Test |
|---|---|---|
| Both hook points are public and shaped as the adapter binds to them | `a2a-sdk==1.1.2` | `test_compat_a2a_hook_points_are_public_and_unchanged` |
| Interceptors run before the transport sees the request | `BaseClient._execute_with_interceptors` | `test_compat_interceptors_are_run_before_the_transport` |
| The remote agent is served a strict subset of the caller's permissions | this recipe | `test_remote_agent_is_served_a_strict_subset_of_the_callers_permissions` |
| A denied tool body did not run; the unguarded control's did | side-effect oracle | `test_the_allowed_read_runs_and_the_export_body_never_does`, `test_the_unguarded_control_does_export` |
| Forged / spliced / widened / expired / absent chains are all refused before the agent's logic | this recipe | `test_a_bad_chain_is_refused_before_the_remote_agents_logic_starts`, `test_a_spliced_chain_is_refused` |
| A bug while deciding denies rather than serving | this recipe | `test_a_deciding_bug_denies_rather_than_serving` |
| Both ledgers plus the tokens verify offline; each tamper fails | `evidence.verify_bundle`, `verify_hop` | `test_both_ledgers_and_the_tokens_verify_offline_together`, `test_verify_hop_catches_*`, `test_a_tampered_server_ledger_fails` |

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03, ASI07, ASI08 ·
[`docs/DENIAL-CONTRACT.md`](../../../docs/DENIAL-CONTRACT.md) ·
[`docs/THREAT-MODEL.md`](../../../docs/THREAT-MODEL.md) · the Delegation Token wire format in
[`docs/`](../../../docs/draft-asor-wimse-agent-delegation-chain-01.md).

## What remains A2A's

The transport, agent authentication, the Agent Card, the task lifecycle, and the eventual standard
answer to §7.6.4. If A2A defines a field for delegated authority, this adapter reads it from there
instead of from the extension slot; the verification does not change.
