# attenu-guard x CAMEL-AI

Tested against **camel-ai 0.2.90** (Apache-2.0), Python 3.14. No changes to CAMEL
or to `attenu_guard` — the adapter is `attenu_guard.adapters.camel`, one module you
can also paste into your own project.

## What it hooks

| Hook point | CAMEL API | Adapter |
|---|---|---|
| Tool invocation | `FunctionTool` — the single object every call goes through: `ChatAgent._execute_tool` calls `tool(**args)` (`chat_agent.py:4048`) → `FunctionTool.__call__` (`function_tool.py:613`); `_aexecute_tool` tries `tool.func.async_call` then `tool.async_call` (`chat_agent.py:4093-4099`) → `FunctionTool.async_call` (`function_tool.py:700`); the streaming twins repeat both (`chat_agent.py:5031`, `5165-5172`) | `GuardedFunctionTool` / `guard_tools(...)` / `guard_toolkit(...)` runs `guard.check(scope, context=...)` before the inner tool's body, on **both** `__call__` and `async_call` |
| Delegation / handoff | `AgentToolkit.agent_run_subagent` (`agent_toolkit.py:286`) → `_create_subagent` (`agent_toolkit.py:161`) → `_resolve_child_tools` (`agent_toolkit.py:149`) → `ChatAgent._clone_tools` (`chat_agent.py:6183`) | `GuardedAgentToolkit` mints a fresh child Guard with `parent.delegate(...)` on every handoff and builds the sub-agent from tools bound to **that** Guard |

CAMEL fires no callback at handoff time, so the delegation call itself is the hook.
Subclassing `FunctionTool` and `AgentToolkit` are CAMEL's own extension mechanisms —
no monkeypatching — and the model-facing JSON schema is copied verbatim from the
inner tool, so the wrapper is invisible upstream.

The Workforce path has the same shape: `Workforce._post_task`
(`societies/workforce/workforce.py:4071`) hands a task to a worker over the task
channel, and the worker runs it with whatever tools its author gave the `ChatAgent`
(`SingleAgentWorker.__init__`, `single_agent_worker.py:234`). The task is
per-assignment; the authority is fixed at construction. `Worker._process_task`
(`worker.py:63`, called from `worker.py:133`) is the extension point there.

## Run it

```bash
pip install "camel-ai==0.2.90" "mcp<2" attenu-guard
python examples/integrations/camel/demo.py          # offline, no API key
pytest -q tests/integrations/test_camel.py          # 25 tests, offline
```

`camel-ai 0.2.90` needs `mcp<2`; with `mcp` 2.x installed, `camel.toolkits` fails to
import (`cannot import name 'FastMCP' from 'mcp.server'`) before any of this is
reached.

## What you'll see

1. **Baseline** — stock CAMEL: the parent delegates "summarise the CRM" and
   `AgentToolkit` builds the sub-agent from a clone of the parent's *whole* toolset
   (`crm_query`, `crm_export`, and `agent_run_subagent` itself). The sub-agent
   exports the CRM. The task is narrow; the authority is not.
2. **Guarded** — same run, same scripted model: `crm_query(rows=4200)` is allowed,
   `crm_export(...)` is **denied before the tool body runs** (proved by a
   side-effect ledger), and the run still completes — CAMEL records the denial as
   the tool's result (`chat_agent.py:4059`), so the model reads it and can adapt.
3. **Attenuation** — a delegation asking for `iam.admin`, 10M rows and a 24h TTL is
   met down to the parent's `crm.*` / 100k / 3600.
4. **Revocation** — `root.revoke(child_node_id)` denies every later tool call.
5. **Evidence** — the delegation graph, plus a hash-chained audit log where
   rewriting the denial to hide the export makes `AuditLog.verify` return False.

The LLM is a scripted `camel.models.BaseModelBackend` returning fixed
`ChatCompletion`s, so everything runs offline. One backend instance is shared by the
parent and its sub-agent (CAMEL builds the child with
`parent.model_backend.models`), and `agent_run_subagent(wait=True)` runs the child to
completion before the parent's next turn, so a single ordered script is consumed
deterministically.

## Wiring it into your own agents

```python
from attenu_guard import Authority, EgressRank, Guard, RowLimit
from attenu_guard.adapters.camel import GuardedAgentToolkit, GuardRef, guard_toolkit

CRM_SCOPES  = {"crm_query": "crm.read", "crm_export": "crm.export"}
CONTEXT_FNS = {"crm_query":  lambda rows: {"rows": rows},
               "crm_export": lambda destination: {"egress": "any"}}

def child_tools(ref):                      # built fresh per delegation
    return guard_toolkit(ref, CrmToolkit(), CRM_SCOPES, context_fns=CONTEXT_FNS)

root = Guard.issue("orchestrator",
                   Authority(scopes={"crm.*", "mail.send"},
                             ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
                   task="Q3 board report")

toolkit = GuardedAgentToolkit(
    parent_guard=root,
    authority=Authority(scopes={"crm.read"},
                        ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
    child_tools=child_tools)

parent = ChatAgent(
    system_message="You orchestrate the Q3 board report.",
    model=model,
    tools=[*guard_toolkit(GuardRef(root), CrmToolkit(), CRM_SCOPES,
                          context_fns=CONTEXT_FNS),
           *toolkit.get_tools()],
    toolkits_to_register_agent=[toolkit])
```

Three details worth knowing:

- **`guard_toolkit` refuses an unpriced tool.** A toolkit that grows a method in a
  later release cannot arrive unguarded — you get a `ValueError` naming it. Pass
  `on_unmapped="allow"` when that is what you want.
- **The sub-agent is not given the delegation toolkit.** It cannot delegate onward
  under a Guard nobody minted for it. To allow a grandchild, hand the child its own
  `GuardedAgentToolkit` from inside `child_tools`, rooted at the Guard in the
  `GuardRef` it is passed. The chain's `max_depth` bounds how far that can go.
- **`func` never carries an `async_call`.** `ChatAgent._aexecute_tool` checks
  `tool.func.async_call` *first* (`chat_agent.py:4093`), which would otherwise reach
  around an `async_call` override for a `FunctionTool` wrapping an MCP tool.
  `GuardedFunctionTool` normalises that away; `test_camel.py` pins it.

## The cookbook

`cookbook.mdx` in this directory is the same story in CAMEL's cookbook format
(front-matter + narrated code cells), ready to drop into `docs/cookbooks/` in the
`camel-ai/camel` repository. `docs/cookbooks/multi_agent_society/` is the matching
subdirectory: the piece is about one agent handing work to another.
