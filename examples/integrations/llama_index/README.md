# attenu-guard × LlamaIndex agents

Enforced authority attenuation for `AgentWorkflow` handoffs. Tested against
**llama-index-core 0.14.23** (Python 3.12; the framework needs >=3.9).

## What it hooks

| # | Moment | Hook (public API) |
|---|--------|-------------------|
| 1 | **Delegation** — agent A hands off to agent B | `GuardedAgentWorkflow.get_tools()` wraps the framework-injected `handoff` tool and mints B's Guard with `guard_of(A).delegate(B, grants[B], task=reason)`. A structural refusal also clears `next_agent`, so control never reaches an agent with no authority. |
| 2 | **Tool invocation** | `guarded_tool(fn, scope=..., context=...)` returns a `FunctionTool` whose wrapper declares `ctx: Context`. LlamaIndex injects the live Context into such tools, so `guard.check(...)` runs **before** the wrapped body. |

On denial the wrapper raises `AuthorityDenied`; `AgentWorkflow._call_tool`
turns any tool exception into `ToolOutput(is_error=True, exception=exc)`, so the
model sees a recoverable tool error while callers keep the structured
`Decision` on `tool_output.exception.decision`. **The tool body never runs.**

Guards are live handles, so they cannot live in `ctx.store` (it deep-copies on
write and JSON-serializes between `.run()` calls). The store holds only a run
token; the Guards hang off a process-local registry keyed by it.

## Run it

```bash
python examples/integrations/llama_index/demo.py     # no API key needed
```

You will see: the orchestrator hand off to a summarizer with `{crm.read}` /
5 000 rows / egress `none`; `crm_query(4200)` run; the poisoned
`crm_export(...)` **denied** with `scope_not_granted` + `ceiling_exceeded`; every
call after `revoke()` denied with `revoked`; a greedy handoff request met down
to the parent's authority and refused at the point of use; a handoff to an
ungranted agent refused outright; then `AuditLog.verify() -> True` and the
delegation graph.

Tests: `python -m pytest -q tests/integrations/test_llama_index.py`.
The offline model is `llama_index.core.llms.MockFunctionCallingLLM` with a
scripted `response_generator` emitting `ToolCallBlock`s.
`live_smoke.py` runs the same story against a real LLM (`RUN_LIVE=1`).
