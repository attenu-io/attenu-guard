# The subagent middleware, with authority attached

*A [LangChain](https://docs.langchain.com/oss/python/langchain/agents) recipe: one supervisor, two
subagents-as-tools, one extra middleware. Runs offline with a scripted model — no API key.
Verified against **langchain 1.3.17 · langchain-core 1.6.0 · langgraph 1.2.11 · deepagents 0.7.6**
on 2026-08-25.*

## What LangChain does

[Middleware](https://docs.langchain.com/oss/python/langchain/middleware) is the right seam, and
`wrap_tool_call` is the right hook: it hands you the `ToolCallRequest` and the handler, and not
calling the handler short-circuits the tool. Every gate below is built on that documented parameter —
no monkeypatching.

The [multi-agent guide](https://docs.langchain.com/oss/python/langchain/multi-agent) names five
patterns — Subagents, Handoffs, Skills, Router, Custom workflow — and is explicit about the axis it
optimises: *"At the center of multi-agent design is context engineering — deciding what information
each agent sees."* For the subagents pattern, *"a main agent coordinates subagents as tools"*, and
[Deep Agents](https://docs.langchain.com/oss/python/deepagents/subagents) ships that harness today:
each subagent spec carries its own `model`, `tools`, `system_prompt` and `middleware`. Deep Agents
also ships [filesystem permissions](https://docs.langchain.com/oss/python/deepagents/permissions) —
declarative path rules on the built-in file tools, with first-match-wins ordering.

## What this recipe shows

1. **Core has no subagent middleware yet — and the harness relates a subagent's tools to nothing.**
   Issue [#33879](https://github.com/langchain-ai/langchain/issues/33879), filed by a LangChain
   maintainer on 2025-11-07 and open today, asks to *"Add subagent middleware — inspired by deepagents
   sub agent middleware, which should be able to use this more general middleware… Got a good start
   here, but now out of date"* (PR #33484, closed unmerged; PR #39019 open as a draft). Meanwhile a
   subagent's tools come from its own spec: `deepagents/middleware/subagents.py` compiles each spec
   with `create_sub_agent(spec)` and never compares its tool list with the parent's. In the run below,
   a supervisor holding only `write_brief` spawns a `writer` whose spec also lists `web_search`, and
   the writer's search body *runs*. The test next to this file pins that and names the day it stops.
   The same shape is stated for the permission rules Deep Agents does ship: *"Subagents inherit the
   parent agent's permissions by default… This replaces the parent's rules entirely."*
2. **One more middleware makes the handoff narrow instead of replace.** `GuardedDelegation` gates
   `wrap_tool_call` on the supervisor and on each subagent spec. When the supervisor calls
   `task(description, subagent_type)`, the child is minted as `meet(supervisor, requested)` — so the
   `researcher`, which asks for `web.*`, `admin.export`, 10,000 rows and a 9,999-second lifetime, is
   granted `web.search`, 50 rows, 3,600 seconds and nothing else. The `writer` holds `brief.write`
   only, so its `web.search` is denied **before the tool body runs**. The sink the tool writes into
   stays empty for that call; in the unguarded run it does not.
3. **The record verifies with nothing else running.** Deep Agents collapses a subagent's transcript
   into a single `ToolMessage` for the supervisor, so a subagent's blocked calls do not appear in the
   parent's messages — the hash-chained audit log is where they surface. It verifies offline, and a
   signed evidence bundle verifies integrity, child ⊆ parent and containment from the bundle alone.

```bash
pip install 'attenu-guard[deepagents]'
python examples/integrations/langgraph/subagent_middleware/demo.py
# RUN_LIVE=1 ANTHROPIC_API_KEY=... python examples/integrations/langgraph/subagent_middleware/live_smoke.py
```

Expected: `[1]` the writer's `web_search` body runs · `[2]` `researcher GRANTED ['web.search'], 50 rows`,
one `ALLOW web_search`, one `DENY web_search (scope_not_granted)`, one `ALLOW write_brief`, and the
attacker's query in no tool body · `[3]` chain and bundle verify · `RESULT: OK`.
Exit codes: `0` every expectation held · `1` an expectation failed · `3` the upstream premise changed
(core now ships a subagent middleware, or a subagent's tools are now bounded by the parent's — see the
freshness rows below; step 2 and step 3 still hold either way).

## Trust boundary (read this before relying on it)

The middleware mediates LangChain's tool dispatch — `AgentMiddleware.wrap_tool_call` /
`awrap_tool_call`, and the delegation tool (`task`) as the point where a child is minted. It does
**not** see a direct Python call around the framework (`web_search.invoke({...})` from your own code
runs — a test proves it), other processes, or the credentials the process itself holds.

A subagent runs its own agent loop, so the middleware has to be installed on the subagent spec as
well as on the supervisor. A spec without it is a hole, not a narrowing — `require_guard()` refuses to
build such a tree, and a test proves the hole is real when that check is skipped.

Inside the boundary: a denied call never executes its body; a tool with no declared authority is
denied by default; retries stay denied and every attempt is on the ledger; if the audit log cannot be
written the call does not proceed; a child is never minted wider than its parent.

## Evidence manifest

| Claim | Pinned to | Test |
|---|---|---|
| Core ships no subagent middleware | `langchain==1.3.17`, `langchain/agents/middleware/`; issue #33879 open (PR #33484 closed unmerged, PR #39019 draft) | `test_semantic_core_still_has_no_subagent_middleware` |
| A subagent's tools are not bounded by the parent's | `deepagents==0.7.6`, `deepagents/middleware/subagents.py :: _build_task_tool._compile_spec -> create_sub_agent(spec)` | `test_semantic_subagent_tools_are_not_constrained_to_the_parents` |
| The hook and the delegation tool we key on are unchanged | `AgentMiddleware.wrap_tool_call`; `task(description, subagent_type)` | `test_compat_subagent_middleware_exposes_the_task_tool_we_hook`, `test_compat_guard_middleware_is_an_agent_middleware` |
| Denied search left no trace (side-effect oracle) | this recipe | `test_side_effect_oracle_denied_search_left_no_trace` |
| researcher ⊆ supervisor, writer ⊆ supervisor | `Guard.is_narrower_than` | `test_authority_is_monotonic_down_the_chain` |
| An over-broad request is met down, not granted | `Guard.delegate` | `test_over_broad_request_is_met_down_not_granted` |
| The model "decides" to obey a planted note and is denied | this recipe | `test_injection_scripted_model_obeys_the_planted_note_and_is_denied` |
| Undeclared tool denied by default · retries stay denied, each on the ledger · guard absent refuses to run · an ungated subagent spec refuses to run, and really is a hole · audit-write failure fails closed · direct call is outside the boundary · tampered bundle fails, clean one passes | this recipe | `test_bypass_*` |

Re-run the whole file before publication:
`python -m pytest -q tests/integrations/test_langgraph_subagent_middleware.py`

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03 (un-scoped privilege inheritance), ASI07,
ASI08 · Agent Baseline AUT-03 (delegation attenuation) ·
[`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md) ·
[`docs/INTEGRATIONS.md`](../../../../docs/INTEGRATIONS.md).

## What remains LangChain's

The agent loop, the middleware seam this recipe stands on, the subagent harness and its task tool, the
filesystem permission rules, tracing, and the design of the general subagent middleware #33879 asks
for. This recipe is one answer to the narrow question of what a subagent may do relative to its
parent; it is offered as a reference implementation on that issue, not as a replacement for it.
