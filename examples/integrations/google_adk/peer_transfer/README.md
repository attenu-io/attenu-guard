# ADK peer transfer, contained

*An [ADK](https://google.github.io/adk-docs/) recipe: three `LlmAgent`s, one `disallow_transfer_to_peers=True` flag,
one plugin. Runs offline with a scripted model — no API key. Verified against **google-adk 2.7.1** on 2026-08-25.*

## What ADK does

Since 2.7.1, ADK enforces `disallow_transfer_to_peers` at transfer time on the `flows/llm_flows` path
(issue [#3850](https://github.com/google/adk-python/issues/3850), fix
[`fa18d26a`](https://github.com/google/adk-python/commit/fa18d26a): `_get_agent_to_run` raises
`ValueError('Transfer to sibling agent … is disallowed.')`). That is real enforcement, and the right place for it.

## What this recipe shows

1. **The 2.x workflow path does not run that check.** `google/adk/workflow/utils/_transfer_utils.py` resolves the
   sibling case (`# Case 3: SIBLING`) without reading the flag; the fix touched `flows/llm_flows` only. With a
   scripted model, an analyst that may not transfer to peers transfers to `exporter`, and the exporter's export
   tool *body runs*. The test next to this file pins that behaviour and names the day it stops.
2. **Even when transfer is legitimate, authority passes whole.** ADK decides *who* may transfer; nothing narrows
   *what the peer may do*. `DelegationGuardPlugin` gives each agent `meet(parent, requested)` — the exporter reached
   via the analyst holds only what the analyst holds — so the export is denied **before the tool body runs**. The
   sink the tool writes into is empty; in the unguarded run it is not.
3. **The record verifies offline.** The hash-chained audit log verifies with no service; a signed evidence bundle
   verifies integrity, child ⊆ parent and containment from the bundle alone.

```bash
pip install 'attenu-guard[google-adk]'
python examples/integrations/google_adk/peer_transfer/demo.py
# RUN_LIVE=1 GOOGLE_API_KEY=... python examples/integrations/google_adk/peer_transfer/live_smoke.py
```

Expected: `[1]` the transfer goes through and the export body runs · `[2]` the transfer still goes through, the
export is `authority_denied`, side effects `[]`, `exporter ⊆ analyst ⊆ root` · `[3]` chain and bundle verify · `RESULT: OK`.
Exit code `3` means ADK now enforces the flag on this path too — the premise of step 1 changed; steps 2–3 still hold.

## Trust boundary (read this before relying on it)

The plugin mediates ADK's tool dispatch (`before_tool_callback`) and agent transfers. It does **not** see a direct
Python call around ADK (`crm_export("…")` from your own code runs — the test proves it), other processes, or the
credentials the process itself holds. Inside that boundary: a denied call never executes its body; an undeclared
tool is denied by default; retries stay denied and each attempt is on the ledger; if the audit log cannot be written
the call does not proceed; a missing plugin makes `require_guard` refuse to run the app.

## Evidence manifest

| Claim | Pinned to | Test |
|---|---|---|
| 2.x path lets the peer transfer through | `google-adk==2.7.1`, `workflow/utils/_transfer_utils.py` sibling case; upstream fix `fa18d26a` in `flows/llm_flows/base_llm_flow.py` only | `test_semantic_2x_path_still_transfers_to_a_peer` |
| Export denied before the body runs (side-effect oracle) | this recipe | `test_side_effect_oracle_denied_export_left_no_trace` |
| exporter ⊆ analyst ⊆ root | `Guard.is_narrower_than` | `test_authority_is_monotonic_down_the_chain` |
| Undeclared tool denied by default · retries stay denied · guard absent refuses to run · audit-write failure fails closed · direct call is outside the boundary · tampered bundle fails | this recipe | `test_bypass_*` |

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03 (un-scoped privilege inheritance), ASI07, ASI08 ·
Agent Baseline AUT-03 (delegation attenuation) · [`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md).

## What remains ADK's

Transfer routing, the per-path flag enforcement, the plugin hooks this recipe stands on, and the fix for the
workflow path — a minimal repro against `_transfer_utils.py` is filed on #3850 alongside this recipe.
