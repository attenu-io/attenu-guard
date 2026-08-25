# One policy, every capability

*An [Agents SDK](https://openai.github.io/openai-agents-python/) recipe: three agents, one
`Authority` per agent, and every capability gate reading it. Runs offline with
`agents.testing.ScriptedModel` — no API key, no network. Verified against
**openai-agents 0.22.0** on 2026-08-25.*

## What the SDK built

The SDK already ships every gate this pattern needs, and each one is in the right place:

| Gate | API | What it decides |
|---|---|---|
| Function-tool visibility | [`FunctionTool.is_enabled`](https://openai.github.io/openai-agents-python/tools/) | whether the model sees a local tool this turn |
| MCP tool visibility | [`tool_filter`](https://openai.github.io/openai-agents-python/mcp/) (`ToolFilterContext`) | whether the model sees a server's tool this turn |
| Delegation visibility | [`Handoff.is_enabled`](https://openai.github.io/openai-agents-python/handoffs/) | whether a handoff is offered this turn |
| Invocation | [`FunctionTool.tool_input_guardrails`](https://openai.github.io/openai-agents-python/ref/tool/) | whether a specific call, with its arguments, runs at all |

Handoffs also carry [`input_filter`](https://openai.github.io/openai-agents-python/handoffs/),
because by default *"the new agent takes over the conversation, and gets to see the entire
previous conversation history"*. And the effective tool and handoff list for every model call
is already recorded on the agent span, as the maintainers confirmed when closing
[#4626](https://github.com/openai/openai-agents-python/issues/4626) — the SDK's observability
is not the thing this recipe adds.

Issue [#4618](https://github.com/openai/openai-agents-python/issues/4618) (opened 2026-08-24,
closed as a docs request 2026-08-25) asks for what to do with all of them at once:

> The Agents SDK now has several useful mechanisms for controlling what an agent can see at
> runtime: `FunctionTool.is_enabled`; `Handoff.is_enabled`; MCP `tool_filter`; tool guardrails / <!-- lint:allow -->
> approvals for execution-time checks; handoff input filtering. … I think there is an
> opportunity to document a single production pattern for using them together when capability
> availability comes from the same runtime policy.

It also states the distinction this recipe is built around:

> visibility filtering is not itself a security boundary … argument/resource-level
> authorization belongs at invocation time.

## What this recipe shows

1. **One policy, read by all four gates.** Each agent holds one `Authority` — a scope set and
   ceilings. `FunctionTool.is_enabled`, the MCP `tool_filter` and `Handoff.is_enabled` all ask
   it the same question, and the invocation check asks it again with the call's arguments. The
   policy is 40 lines and the wiring is a callback per gate.
2. **A handoff narrows.** `billing` is granted `meet(triage, request)`, so it may refund at
   most USD 50 where triage may spend USD 500. The relation holds by construction:
   `billing.authority.is_narrower_than(triage.authority)`.
3. **Escalation by routing is refused structurally.** `sre` requests `infra.deploy`, which
   triage does not hold. The recipe's `Handoff.is_enabled` compares the two sides, so
   `transfer_to_sre` never reaches the model at all and the refusal is on the ledger. The SDK
   applies no relation of its own here: `check_handoff_enabled` in
   `agents/run_internal/turn_preparation.py::get_handoffs` calls
   `is_enabled(context_wrapper, agent)` with the *sending* agent and names the receiver only by
   `Handoff.agent_name` — enough for an application to compute the relation, and left to the
   application to do so.
4. **Visibility is not the boundary, and the recipe does not pretend otherwise.** `kb_export`
   *is* visible to triage — triage holds `kb.*` — and the call is still denied, because the
   egress ceiling binds on an argument no visibility gate can see. A second run with every
   visibility gate switched off denies exactly the same calls
   (`test_bypass_visibility_off_still_denies_at_invocation`).
5. **The receiver is handed only history it may hold.** An `input_filter` drops the tool
   traffic whose scope the receiver does not hold; the SDK's own routing items stay.
6. **The record verifies offline.** The hash-chained ledger verifies with no service running,
   and a signed evidence bundle verifies integrity, child-subset-of-parent and containment
   from the bundle alone. This is a check a third party can run without us and without the
   model vendor — a different job from a trace, not a replacement for one.

The MCP server in the recipe is an in-memory `MCPServer` subclass so the demo needs no
subprocess. It applies the same `ToolFilterCallable` you would pass to
`MCPServerStdio(tool_filter=…)`, called the same way the shipped servers call it.

## Run it

```bash
pip install 'attenu-guard[openai-agents]'
python examples/integrations/openai_agents/one_policy/demo.py
python -m pytest -q tests/integrations/test_openai_agents_one_policy.py     # 19 tests
# RUN_LIVE=1 OPENAI_API_KEY=... python examples/integrations/openai_agents/one_policy/live_smoke.py
```

Expected: `[1]` the plain SDK offers the `sre` handoff and the USD 250 credit body runs ·
`[2]` the `sre` handoff is never offered, `billing ⊆ triage`, the USD 42 credit runs, the
USD 250 credit and the export are denied with empty side-effect sinks · `[3]` the chain and
the signed bundle verify · `RESULT: OK`.

Exit codes: `0` every expectation held · `1` an expectation failed · `3` the premise of step 1
changed — the SDK now relates the two sides of a handoff itself, or no longer passes the
sending agent to `Handoff.is_enabled`. Steps 2–6 still hold in that case.

## Trust boundary (read this before relying on it)

The recipe mediates the SDK's own dispatch: `Runner.run`'s tool-invocation path
(`FunctionTool.tool_input_guardrails`, which runs before the tool body and before
`RunHooks.on_tool_start`), handoff resolution, and the tool lists the SDK assembles per turn.

It does **not** see a direct Python call around the SDK — `issue_credit_impl(sink, 250.0)`
from your own code runs, and `test_bypass_direct_python_call_is_outside_the_boundary` proves
it so nobody mistakes mediation for a sandbox. It also does not see other processes, or the
credentials the process itself holds.

Inside that boundary: a denied call never executes its body; a tool with no declared scope is
checked against a scope nobody holds, so it is denied by default; retries stay denied and each
attempt is on the ledger; if the ledger cannot be written the call does not proceed; and
`require_guard()` refuses to start a run whose policy or checks are not wired.

## Evidence manifest

Verified against `openai-agents==0.22.0` (released 2026-08-19) on 2026-08-25, Python 3.12.
The same tests pass on `0.21.1`.

| Claim | Pinned to | Test |
|---|---|---|
| The SDK offers a handoff to a receiver more capable than the sender | `openai-agents==0.22.0`, `agents/run_internal/turn_preparation.py::get_handoffs` | `test_semantic_sdk_offers_a_handoff_to_a_more_capable_agent` |
| `Handoff.is_enabled` is handed the **sending** agent, so an application can compute the relation | same path, `check_handoff_enabled` | `test_semantic_handoff_is_enabled_receives_the_sending_agent` |
| The receiver is handed the prior conversation by default | `Handoff.input_filter` default `None` | `test_semantic_handoff_forwards_the_prior_conversation_by_default` |
| The four gate APIs exist and have the shape the recipe uses | `FunctionTool`, `Handoff`, `agents.mcp.ToolFilterContext`, `agents.mcp.MCPServer` | `test_compat_the_four_primitives_exist` |
| The denied credit left no trace (side-effect oracle) | this recipe | `test_side_effect_oracle_denied_credit_left_no_trace` |
| The denied MCP export left no trace, though the tool was visible | this recipe | `test_side_effect_oracle_denied_mcp_export_left_no_trace` |
| `billing ⊆ triage`, refund ceiling USD 50 | `Guard.is_narrower_than` | `test_authority_is_monotonic_down_the_chain` |
| Escalation by routing refused and recorded | this recipe | `test_escalation_by_routing_is_refused_and_recorded` |
| Only history the receiver may hold is forwarded | `Handoff.input_filter` | `test_narrowed_history_is_what_the_receiver_is_handed` |
| The model "decides" the over-limit credit and is denied | this recipe | `test_injection_the_model_decides_the_over_limit_credit_and_is_denied` |
| Undeclared alternate tool denied · visibility off changes nothing · retries stay denied · policy absent refuses to run · ledger-write failure fails closed · direct call is outside the boundary · tampered bundle fails, clean bundle passes | this recipe | `test_bypass_*` |

Re-run this table the week the recipe is published; a semantic failure names the premise that
changed.

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03 (un-scoped privilege inheritance),
ASI07, ASI08 · Agent Baseline AUT-03 (delegation attenuation) ·
[`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md) ·
[`docs/INTEGRATIONS.md`](../../../../docs/INTEGRATIONS.md).

## What remains the SDK's

Routing, the four gates themselves, the handoff and MCP machinery, tracing and the agent span,
approvals, and the decision about which capability belongs to which agent. This recipe adds
two things on top: the relation between the two sides of a handoff, and a record of every
decision that a third party can check offline. Both are ordinary application code against
public APIs — which is what #4618 asked for.
