# What an MCP server can check today

*An MCP server (Python SDK, `FastMCP`) that verifies a delegation chain before it runs a tool. Offline, in-memory
transport, no API key. Verified against `mcp` 1.28.1 and the MCP roadmap post of 2026-08-22, on 2026-08-25.*

## What MCP built well

MCP's authorization (spec 2026-07-28) is careful about the confused deputy: resource indicators and protected-resource
metadata are MUSTs, servers must accept only tokens meant for them and must never pass a token through. Every hop
gets its own audience-bound token. That is the right foundation, and this recipe stands on it.

## What this recipe shows

1. **The request carries no agent authority today.** `CallToolRequestParams` has `name`, `arguments`, `meta`, `task`
   — nothing that says which agent is calling on whose behalf with how much of it. The roadmap post (2026-08-22)
   names it: "more and more of the callers are agents … delegating narrower authority to sub-agents" — with no
   spec text yet. The test next to this file pins that and names the day it changes.
2. **A server can already check a chain.** The client puts attenu-guard Delegation Tokens (root → calling agent)
   in `_meta` — out-of-band of the tool arguments, where the roadmap places agent identity. The server loads the
   chain offline (signatures, parent hashes, depth, child ⊆ parent at every hop), checks the *leaf* authority
   against the tool's scope and request context, records the decision on a hash-chained ledger, and only then
   runs the body. The reader's chain cannot export; a spliced chain fails; no chain is a deny.
3. **The record verifies offline** — the server's ledger, and the client's own bundle, with no service involved.

```bash
pip install 'attenu-guard' mcp
python examples/integrations/mcp/server_verifier/demo.py
# RUN_LIVE=1 python examples/integrations/mcp/server_verifier/live_smoke.py   # the same server over stdio
```

Expected: the control server runs the export · the guarded server allows the exporter, denies the reader, refuses
the spliced chain and the missing chain, allows the reader's read · tool bodies that ran = the two allowed calls ·
ledger verifies · `RESULT: OK`. Exit `3` = the SDK now carries an authority field (premise changed).

## Trust boundary

The check lives at the MCP boundary, inside the server, before the tool body. It does not see a direct Python call
to the underlying function (the test proves it runs), or any other route to the resource behind the tool. Inside
the boundary: a denied call never runs its body; a tool the server does not declare does not exist; retries stay
denied and each attempt is on the ledger; if the ledger cannot be written the body does not run.

## Evidence manifest

| Claim | Pinned to | Test |
|---|---|---|
| No agent-authority field in the tool-call request | `mcp==1.28.1`, `CallToolRequestParams.model_fields`; roadmap post 2026-08-22 | `test_semantic_request_carries_no_agent_authority` |
| Allowed / denied / spliced / missing chain behave as stated; side-effect oracle | this recipe | `test_side_effect_oracle_*`, `test_bypass_*` |
| Ledger verifies; tampered ledger fails | `AuditLog.verify` | `test_bypass_tampered_ledger_fails` |

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03, ASI07, ASI08 · Agent Baseline AUT-03 ·
[`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md) · the Delegation Token wire format in
[`docs/`](../../../../docs/draft-asor-wimse-agent-delegation-chain-00.md).

## What remains MCP's

The transport, the per-hop OAuth model, and the eventual standard field for agent identity and authority — when it
lands, this server reads it from there instead of `_meta`; the verification does not change.
