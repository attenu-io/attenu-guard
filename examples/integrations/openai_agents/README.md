# delegation-guard × OpenAI Agents SDK

Tested against **openai-agents 0.21.1** (MIT, requires Python ≥ 3.10) on Python 3.12.

## What it hooks

| Moment | SDK API | File |
|---|---|---|
| Handoff (mint the child's `Guard`) | `RunHooks.on_handoff(context, from_agent, to_agent)` | `agents/lifecycle.py:59`, invoked at `agents/run_internal/turn_resolution.py:614` |
| Handoff, without `hooks=` | `handoff(agent, on_handoff=...)` | `agents/handoffs/__init__.py:334` |
| Agents-as-tools (mint before the nested run) | the agent-tool's own `tool_input_guardrails` | `agents/agent.py:576` |
| **Every tool call** (`guard.check` before the body) | `FunctionTool.tool_input_guardrails` | `agents/tool.py:480`, executed at `agents/run_internal/tool_execution.py:2012` |

`tool_input_guardrails` is the only pre-tool hook that can stop a call: it runs
*before* `RunHooks.on_tool_start` (line 2023), and `on_tool_start` returns `None`
so it can observe but never deny. On a denial the adapter returns
`ToolGuardrailFunctionOutput.reject_content(...)`, so the tool body is skipped and
the model is told why; pass `on_denied="raise"` to halt the run instead.

## Run it

```bash
python examples/integrations/openai_agents/demo.py            # no API key, no network
python -m pytest tests/integrations/test_openai_agents.py     # 15 tests
```

## What you'll see

An orchestrator (`{crm.*, mail.send}`, 100k rows, egress `any`) hands off to a
summarizer granted `{crm.read}`, 5k rows, egress `none`. **Both agents are handed
the identical tool objects**, so a shorter tool list is not the defence. The
summarizer's legitimate read runs; a 60k-row read is denied for
`ceiling_exceeded` inside an *allowed* scope; the poisoned `crm_export` is denied
for `scope_not_granted` before its body runs; after `registry.revoke("summarizer")`
everything is denied `revoked`. The run still reaches a final answer, and the
hash-chained ledger verifies — `dg view <path>` renders it.

The SDK forwards the **entire** conversation to a handoff target by default
(`Handoff.input_filter` is `None` and `RunConfig.nest_handoff_history` is `False`,
`agents/run_config.py:342`), so the poisoned instruction is in the child's context
either way — which is exactly why the child needs its own attenuated authority.
