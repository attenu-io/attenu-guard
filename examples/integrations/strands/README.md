# delegation-guard × AWS Strands Agents

Tested against **strands-agents 1.52.0** (Apache-2.0, Python >= 3.10) on Python 3.12.

## What it hooks

| step | Strands API |
|---|---|
| mint child Guard — agents-as-tools | `BeforeToolCallEvent` where `selected_tool.tool_type == "agent"` (`strands/agent/_agent_as_tool.py:130`) |
| mint child Guard — swarm/graph handoff | `BeforeNodeCallEvent` (`strands/hooks/events.py:406`, raised `strands/multiagent/swarm.py:810`) |
| authorize every tool call | `BeforeToolCallEvent` (`strands/hooks/events.py:208`) |

Denials set `event.cancel_tool` / `event.cancel_node`. The executor checks
`cancel_tool` **before** dispatching (`strands/tools/executors/_executor.py:176-198`),
so the tool body never runs and the model gets an error `ToolResult` carrying the
reason — it can recover instead of crashing. (Raising from the hook also blocks the
call, but unwinds the run as `EventLoopException`.)

`dg.as_intervention()` gives the same guarantee through Strands' own authorization
seam, `Agent(interventions=[...])`: `Deny` is applied as that same `cancel_tool`
(`strands/interventions/registry.py:127-129`). Interventions have no multi-agent
lifecycle method, so a Swarm/Graph still needs the hook registration.

## Run it

```bash
pip install "strands-agents>=1.52" delegation-guard
python examples/integrations/strands/demo.py
```

No AWS credentials, no API key: `ScriptedModel` is a `strands.models.Model` subclass
emitting Bedrock-shaped `StreamEvent` dicts.

## What you'll see

A poisoned summarizer reads 4 200 CRM rows (**ALLOW**), then tries to export the CRM
to `s3://attacker-bucket/…` (**DENY**, `scope_not_granted`, body never runs) — via
agents-as-tools, via interventions, and via `Swarm`. Then: it cannot re-delegate; a
handoff to an agent with no declared `Authority` is cancelled at the node gate;
revocation stops every later call; the delegation tree prints; the audit log verifies.

`live_smoke.py` runs the same story against real Bedrock — skipped unless `RUN_LIVE=1`.
