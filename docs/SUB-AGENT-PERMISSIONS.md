# Does a sub-agent inherit its parent's permissions?

*Updated 2026-08-26. Every framework claim below is verified against released code and pinned by a test in this repository that fails the day the behaviour changes — see [`INTEGRATIONS.md`](INTEGRATIONS.md).*

**Short answer: in the agent frameworks we audited, no.** A sub-agent gets whatever list the developer (or the model) hands it. None of the five frameworks below computes the sub-agent's permissions as a subset of the parent's, none carries a ceiling down the chain, and none writes a record of what was denied. `attenu-guard` adds exactly that: at every handoff the child's authority is computed as the *meet* of what the parent holds and what the task asks for, enforced in your process on every tool call, and logged in a hash-chained audit trail you verify offline.

## What happens at a handoff today, framework by framework

| Framework (version tested) | What the sub-agent receives at a handoff | In the framework's own words |
|---|---|---|
| OpenAI Agents SDK 0.21 | The entire conversation; the receiving agent offers the model its own full tool list. `is_enabled` decides whether a handoff is *offered*, not what the target may do. | *"the new agent sees the entire conversation history"* (`Handoff.input_filter=None` default); `is_enabled` *"cannot authorize based on argument values"* |
| LangChain `deepagents` 0.7 | A sub-agent's `tools` and `permissions` **replace** the parent's — a child can be granted what its parent is denied. | *"When specified, overrides the inherited tools entirely"*; permissions *"replace the parent's permissions entirely"* |
| Google ADK 2.7.1 | By default an agent may transfer to its parent, siblings or children — a lateral transfer, not a narrowing. `disallow_transfer_to_peers` was bypassable on the 2.x workflow path ([adk-python #3850](https://github.com/google/adk-python/issues/3850)). | *"by default, an agent can transfer to its parent, siblings, or children"* |
| CrewAI 1.15 | A delegated coworker runs with its **own full tool list**; the tool-hook dispatcher swallows exceptions and runs the tool unless you raise its one blessed exception (fail-open). | Feature request *"Allow delegation to specific agents only"* ([crewAI #2917](https://github.com/crewAIInc/crewAI/issues/2917)) closed as not planned |
| AutoGen 0.7 | `Handoff` carries target, description and message only; the receiver offers the model its own full tool list. | — |
| Claude Code (hooks) | Narrows subagents natively through `PreToolUse`; what is missing is the *record* — see [the Claude Code recipe](../examples/integrations/claude_code/hooks_receipt/README.md). | Reported gaps: *"Sub-agents bypass permission deny rules"* ([claude-code #25000](https://github.com/anthropics/claude-code/issues/25000)) |

Two identity systems make the same choice from the other direction: Microsoft Entra's parent→child construct has two settings, *all allowed* or *none*, and MCP's scope flow is accumulation-biased (step-up unions). Neither can express *child ⊆ parent*.

## Why "give the child a list" is not "child ⊆ parent"

Every framework lets you hand a child a list. That solves the easy case — the developer remembers to write a narrower list — and fails the three that matter:

1. **Replace, not intersect.** If the child's list *replaces* the parent's, a sub-agent can hold `mail.send` while its parent never did. Nothing checks the relation between the two lists.
2. **Nothing survives the next hop.** A list is a snapshot at one handoff. At depth three, the grandchild's list has no relation to the root's, and there is no ceiling on depth, fan-out or aggregate spend.
3. **Over-constraint is as real as over-reach.** The opposite failure — a delegated agent that inherits every *deny* and cannot do its job — shows up in the same issue trackers ([opencode #26700](https://github.com/anomalyco/opencode/issues/26700)). The hard part is computing the subset *correctly*, not just denying more. An early rule of ours blocked 82.6% of a real workload for exactly that reason; the corrected rule (a parent holds what its delegation subtree needs) brought the benign-block rate to 0 across 3,970 calls in shadow mode.

## How attenu-guard computes and enforces it

```python
from attenu_guard import Authority, Guard, RowLimit, EgressRank

# The orchestrator holds broad authority.
orchestrator = Guard.issue("orchestrator", Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

# It delegates a narrow task. The child gets the *meet* of what the parent
# held and what the task needs — computed and enforced, not suggested.
summarizer = orchestrator.delegate("summarizer", Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
    task="summarize Q3 pipeline")

decision = summarizer.check("crm.read", context={"rows": 4_200})   # Decision(allowed=True)
summarizer.enforce("crm.export", context={"egress": "any"})        # raises AuthorityDenied
```

- **`Guard.delegate()`** returns a child whose authority is the meet of the parent's and the request's — scopes intersect, ceilings take the tighter bound, TTL the shorter. A request for more than the parent holds comes back narrowed, not granted. `would_delegate()` is the dry run.
- **`check()` / `enforce()`** run before the tool body on every call, in your process; unknown ceiling types fail closed.
- **Chain invariants** — depth, fan-out and aggregate budget ceilings — hold across every hop, and **`revoke()`** on any node denies every descendant immediately.
- **The audit log** is hash-chained and Ed25519-signed; `attenu-guard verify bundle.json` checks integrity, *child ⊆ parent* and containment from the file alone — no account, no network, no vendor present. The [auditor's walkthrough](../examples/verify/README.md) has three sample bundles (clean, tampered, widened).
- **Adapters** for LangGraph / deepagents, CrewAI, Google ADK, OpenAI Agents SDK, Claude Agent SDK, Pydantic AI, AutoGen, smolagents, AWS Strands, LlamaIndex, Semantic Kernel, Agno, Haystack, CAMEL-AI, Microsoft Agent Framework and AG2 hook each framework's public API — no monkeypatching — and treat the framework's own delegation call as the moment the child is minted. See [`INTEGRATIONS.md`](INTEGRATIONS.md).

## What has been measured

- **8,783 / 8,783** adversarial over-reach attempts denied; **43,128** prompt-injection variants, **0** widened a permission set — both run as CI gates ([red-team report](RED-TEAM.md)).
- **0 benign blocks** across the 21 evaluation scenarios on our own sample applications after a one-time setup pass; enforcement is structural, so Haiku and Sonnet give the same outcome.
- Enforced **live** across a real delegation chain: an analyst sub-agent holding `{web.fetch}` ⊂ its coordinator was denied `web.search` mid-run, and the ledger anchored across the chain.

## What this does not do

It does not decide for you what a task *should* be allowed to do — that is the job of the operator, or of [`attenu-derive`](https://github.com/attenu-io/attenu-derive), which computes each task's permission set from the application itself. It is not a content filter and does not inspect prompts; an injected instruction that asks for more than the sub-agent holds is denied because the permission is absent, not because the text was recognised. Standards context: [STANDARDS-ALIGNMENT.md](STANDARDS-ALIGNMENT.md) (OAuth token exchange, WIMSE, Agent Baseline AUT-03 "delegation attenuation").
