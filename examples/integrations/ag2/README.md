# attenu-guard × AG2

Enforced authority attenuation for [AG2](https://github.com/ag2ai/ag2), the AutoGen
fork. Tested against **`ag2` 1.0.2** on Python 3.12.

```bash
pip install 'attenu-guard[ag2]'
```

AG2 1.0 is a rewrite: the package is `ag2` (not `autogen`), an agent is `ag2.Agent`, and
every hook is an `ag2.middleware.BaseMiddleware` subclass. This is a different
integration from [`../autogen/`](../autogen/), which targets Microsoft's
`autogen-agentchat` 0.7.

## What it hooks

| Hook point | Adapter piece | Why there |
|---|---|---|
| **Tool invocation** | `DelegationGuard(BaseMiddleware).on_tool_execution` | `FunctionTool.register` folds the agent's middleware around the tool object (`ag2/tools/final/function_tool.py:120-124`) and the subscriber sends the return value straight on (`:127-128`). The body is `FunctionTool.__call__` (`:132-145`), reachable only through `call_next` — so returning a `ToolResultEvent` instead provably stops it, and that event *is* what the model sees. |
| **Delegation** — agent-as-tool | `ToolPolicy(delegates_to=..., grant=...)` on `task_<agent>` | `Agent.as_tool()` builds a `@tool`-decorated `task_<agent-name>` function (`ag2/tools/subagents/subagent_tool.py:45-68`) whose body calls `run_task` → `agent.ask(...)` (`run_task.py:138-148`). The same gate covers it; the child `Guard` is minted after the check passes. |
| **Delegation** — auto-spawned subtask | `guarded_tools(...)` / `guard_tool_hook(...)` | `tasks=TaskConfig(...)` injects `run_subtask` (`ag2/agent.py:1673-1706`) and constructs the child `Agent` inside AG2 (`:1463-1469`) with **no** `middleware=` — `TaskConfig` has no such field. Per-tool middleware travels with the deep-copied tool object into that child (`function_tool.py:110-111`), where the agent-level hook cannot reach. |

`GuardRegistry` keys guards by agent name, and the gate reads the live agent from the
context (`ag2/agent.py:1491`), so the parent of a delegation is the agent whose turn
issued the delegating call — not "the last agent to speak".

**Agent middleware does not propagate into sub-agents.** `run_task` copies the parent's
dependencies and variables to the child (`run_task.py:141`, `:147`) but not its
middleware. Give every agent you construct its own guard (`guarded_agent()` is the
one-liner), and add `guarded_tools(...)` when an agent uses `tasks=TaskConfig(...)`. An
agent nobody delegated to holds no `Guard`, so every tool it tries is denied.

## Run it

```bash
python examples/integrations/ag2/demo.py      # no API key needed
pytest tests/integrations/test_ag2.py
```

The offline model is `ag2.testing.TestConfig` — AG2's own shipped test double, replaying
scripted `ToolCallEvent`s.

## What you'll see

The demo runs the same poisoned-summarizer script twice. **Without** the guard, AG2
executes `crm_export` and `send_mail` — a sub-agent keeps its own tool list and the
framework enforces nothing about its authority relative to the parent. **With** the
guard, only `crm_query` runs; the export and mail are denied before their bodies
execute, with reason code `scope_not_granted`. Then it shows the child is provably
narrower than the parent, that a greedy request is met down, that revocation cascades,
and that the hash-chained audit log verifies offline.

Denials come back as a `ToolResultEvent` the model can react to; `on_deny="error"`
returns a `ToolErrorEvent` instead. Raising is deliberately not offered:
`_execute_call` converts every exception into a `ToolErrorEvent`
(`ag2/tools/executor.py:116-122`), so a raise cannot stop the run — it would only look
like a tool failure, with the formatted traceback going to the model.

## Trust boundary

The gate runs in your process, inside AG2's tool-execution chain, before
`FunctionTool.__call__`. It decides nothing on its own — you write the `Grant` for each
delegation and the `ToolPolicy` for each tool; attenu-guard enforces that a child's
authority is a subset of its parent's, applies the ceilings, and records every allow and
deny in a hash-chained log that verifies without the library present.

Three things this seam cannot see, by construction:

- **Provider-side builtin tools** — `WebSearchTool`, `CodeExecutionTool`, `ShellTool`,
  `MCPServerTool`, `MemoryTool`, `SkillsTool` and friends register a no-op subscriber
  and ignore the `middleware` argument entirely (e.g.
  `ag2/tools/builtin/web_search.py:78-90`); they execute at the model provider. Do not
  attach them to a guarded agent.
- **`ToolResult(final=True)`** from any tool in a parallel batch makes the executor
  return early (`ag2/tools/executor.py:68-89`), discarding sibling results including a
  denial message. The denied body still never ran; only the message is lost.
- **Cross-process fan-out** over `ag2.network` is arbitrated at the hub
  (`ag2/network/hub/arbiter.py:245-324`), outside this adapter.

File and line references are against `ag2` 1.0.2 and will drift.
