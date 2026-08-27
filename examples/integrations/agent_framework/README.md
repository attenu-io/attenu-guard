# attenu-guard × Microsoft Agent Framework

Enforced authority attenuation for
[Microsoft Agent Framework](https://github.com/microsoft/agent-framework) — the AutoGen
and Semantic Kernel successor. Tested against **`agent-framework` 1.15.0** (core 1.15.0)
on Python 3.12.

```bash
pip install 'attenu-guard[agent-framework]'
```

## What it hooks

| Hook point | Adapter piece | Why there |
|---|---|---|
| **Tool invocation** | `DelegationGuard(FunctionMiddleware)` | The tool body is reachable only through `final_wrapper` in `FunctionMiddlewarePipeline.execute` (`_middleware.py:1126-1163`), which only the innermost `call_next()` reaches. Returning without awaiting `call_next()` provably stops the body; `context.result` is what the model gets instead. |
| **Delegation** — agent-as-tool | `ToolPolicy(delegates_to=..., grant=...)` | `Agent.as_tool()` returns an ordinary `FunctionTool` (`_agents.py:718`) whose body starts the sub-agent at `self.run(...)` (`_agents.py:694`), so the same gate covers it. The child `Guard` is minted after the check passes, before the sub-agent starts. |
| **Delegation** — handoff orchestration | the same, keyed on `handoff_tool_name(target)` | Each handoff edge is a `handoff_to_<target_id>` `FunctionTool` (`agent_framework_orchestrations/_handoff.py:124-126`, `:335-350`). Its own `_AutoHandoffMiddleware` is *appended* (`_handoff.py:269`), so a guard registered on the agent runs first and can refuse the transfer. |

One registration covers both dispatch paths: the non-streaming (`_tools.py:3174`) and
streaming (`_tools.py:3337`) function-calling loops share the same
`execute_function_calls` partial, built once over the same pipeline
(`_tools.py:3628-3634`).

**Middleware does not propagate into sub-agents.** `as_tool` runs the *child* object's
own middleware list; workflow participants (`_workflows/_agent_executor.py:425`, `:481`)
likewise run whatever their own `Agent` carries. Install a `DelegationGuard` on every
agent in the graph — `guarded_agent()` is the one-liner, and an agent nobody delegated
to holds no `Guard`, so every tool it tries is denied.

## Run it

```bash
python examples/integrations/agent_framework/demo.py      # no API key needed
pytest tests/integrations/test_agent_framework.py
```

Agent Framework ships no test double, so both files define a 30-line
`ScriptedChatClient`. It composes `FunctionInvocationLayer` and `ChatMiddlewareLayer`
over `BaseChatClient` the way the real providers do
(`agent_framework_openai/_chat_client.py:3430-3434`) — those layers carry the
function-calling loop and the middleware pipeline, so a bare `BaseChatClient` never
invokes a tool at all (`_agents.py:870-875` only logs a warning).

## What you'll see

The demo runs the same poisoned-summarizer script twice. **Without** the guard, Agent
Framework executes `crm_export` and `send_mail` — a sub-agent keeps its own tool list
and the framework enforces nothing about its authority relative to the parent. **With**
the guard, only `crm_query` runs; the export and mail are denied before their bodies
execute, with reason code `scope_not_granted`. Then it shows the child is provably
narrower than the parent, that a greedy request is met down, that revocation cascades,
and that the hash-chained audit log verifies offline.

Denials come back as a `function_result` the model can react to. Pass
`on_deny="failure"` to raise `MiddlewareFailure` instead — the loop's documented
fail-closed escape (`_middleware.py:85`): the batch is cancelled, no further tool call
starts, and the error reaches the caller of `Agent.run`. Note that an *ordinary*
exception is not a denial here: `_tools.py:1642-1643` turns it into a tool-error result
and the loop keeps going, so the adapter never raises one.

## Trust boundary

The gate runs in your process, inside the function-invocation loop, before
`FunctionTool.invoke`. It decides nothing on its own — you write the `Grant` for each
delegation and the `ToolPolicy` for each tool; attenu-guard enforces that a child's
authority is a subset of its parent's, applies the ceilings, and records every allow and
deny in a hash-chained log that verifies without the library present.

Three things this seam cannot see, by construction:

- **Hosted / service-side tools** (hosted web search, code interpreter, hosted MCP)
  arrive as `informational_only` function calls and are filtered out before the seam
  (`_tools.py:1654-1655`); they execute at the model provider. Do not attach them to a
  guarded agent.
- **`Agent.as_mcp_server()`** invokes the agent tool directly (`_agents.py:1745`),
  bypassing the function pipeline. Guard the exposed agent's own tools instead of
  relying on the delegation gate.
- **Middleware ordering is trust ordering** — client-level function middleware runs
  outside agent-level (`_tools.py:3165`), so anything registered ahead of the guard can
  substitute a result before the check runs. `guarded_agent()` places the guard first in
  the agent's own list.

File and line references are against `agent-framework` 1.15.0 and will drift.
