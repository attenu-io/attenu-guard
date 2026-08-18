# delegation-guard × LangGraph / LangChain / deepagents

`delegation_guard.adapters.langchain` is a ~200-line adapter you can paste into your own project.

## What it hooks

| Hook point | API | Purpose |
|---|---|---|
| Tool invocation | `ToolNode(tools, wrap_tool_call=guarded.wrap_tool_call)` | `Guard.check()` runs before the tool body; not calling the handler short-circuits the call |
| Tool invocation | `create_agent(..., middleware=[guarded.middleware()])` — `AgentMiddleware.wrap_tool_call` | same gate inside the LangChain 1.x agent loop |
| Child creation | the same hook, filtered on the delegation tool (`task` in deepagents) | mints the child with `parent.delegate(...)` and installs it as the active `Guard` (a `ContextVar`) for the sub-agent's run |
| Graph nodes | `delegation_guard.adapters.langgraph.guard_node` (shipped) | for hand-written nodes; raises `AuthorityDenied` out of `graph.invoke()` |

No monkeypatching: every hook is a documented framework parameter.

## Run it

```bash
pip install -e '.' langgraph langchain deepagents
python examples/integrations/langgraph/demo.py            # LangGraph + create_agent
python examples/integrations/langgraph/deepagents_demo.py # real sub-agent spawning
```

Both use a scripted offline chat model — **no API key, no network**.
`live_smoke.py` runs the same story against a real model; it is env-gated
(`RUN_LIVE=1` + `ANTHROPIC_API_KEY`) and never runs in CI.

## What you'll see

An orchestrator holding `{crm.*, fs.*, mail.send}` / `RowLimit(100_000)` /
`EgressRank("any")` delegates to a summarizer holding only `{crm.read, fs.read}` /
`RowLimit(5_000)` / `EgressRank("none")`. The summarizer's `crm_query(rows=4200)`
executes; its poisoned `crm_export(...)` and `write_file(...)` are **denied before
the tool body runs** (proved by a side-effect list that stays empty); spawning an
undeclared sub-agent is refused; `revoke()` cascades; `AuditLog.verify()` returns
`True` and flips to `False` if one entry is edited.

## Versions tested

`langgraph` 1.2.11 · `langgraph-prebuilt` 1.1.0 · `langchain` 1.3.15 ·
`langchain-core` 1.5.6 · `deepagents` 0.7.6 · Python 3.12 · delegation-guard 0.2.0.

Tests: `tests/integrations/test_langgraph.py`, `tests/integrations/test_deepagents.py`.
