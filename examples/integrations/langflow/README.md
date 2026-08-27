# attenu-guard x Langflow

A custom Langflow component that checks every tool call against the authority its
agent holds, before the tool runs — and, when two of them are chained, narrows a
downstream agent to a subset of the upstream one.

Tested against **lfx 1.11.5** / **langchain-core 1.5** (Langflow's component base),
Python 3.14. Nothing in Langflow is modified.

## The component

`attenu_guard_component.py` defines `AttenuGuardToolsComponent` (display name
**Attenu Guard Tools**).

**Inputs**

| Port / field | What it is |
|---|---|
| **Tools** (`Tool`, list) | The tools this agent may use. Each comes back wrapped. |
| **Parent Authority** (`AttenuGuard`) | The **Guard** output of the delegating agent's component. Connected, this agent's authority becomes the meet of what it asks for and what the parent holds. Leave empty for the first agent in the chain. |
| **Agent ID** | The name recorded for this agent in the audit log. |
| **Task** | What this agent was asked to do; recorded on the delegation entry. |
| **Authority** | JSON: `{"scopes": ["crm.read"], "ceilings": {"max_rows": 5000, "egress": "none"}, "ttl": 900}`. Ceiling keys are `max_rows`, `max_spend`, `egress`, `max_calls`. |
| **Tool Scopes** | JSON map of tool name to the scope that tool consumes: `{"crm_query": "crm.read"}`. |
| **On Denied** (advanced) | `raise` — the run stops with the denial. `return` — the model reads the denial as the tool's output and can adapt. |
| **On Unmapped** (advanced) | `deny` — a tool with no scope in **Tool Scopes** is an error. `allow` — it passes through unwrapped. |

**Outputs**

| Port | What it is |
|---|---|
| **Guarded Tools** | The tool list, for an Agent component's `tools` port. |
| **Guard** | This agent's Guard, for a downstream component's **Parent Authority** port. That edge *is* the delegation. |
| **Evidence** | `Data` carrying the delegation graph, the hash-chained audit log, every allow/deny decision, and the result of re-verifying the log. |

## Hook point

Langflow tools are LangChain `BaseTool`s, and `BaseTool.invoke` → `run` → `_run` is
the single funnel every tool call goes through, whichever agent component drives it.
`guard_langchain_tool` builds a `langchain_core.tools.StructuredTool` whose function
runs `guard.check(scope, context=...)` and only then calls `inner.invoke(...)`,
mirroring the inner tool's `name`, `description` and `args_schema` so the model sees
an identical tool. That is LangChain's own composition API — no monkeypatching.

The Guard is resolved on each invocation rather than captured when the flow is built,
so a Guard revoked after the flow started is seen by the very next call.

## Add it to Langflow

Langflow discovers custom components under the directory named by the
`LANGFLOW_COMPONENTS_PATH` environment variable, organised as
`<base>/<category>/<component>.py` with an `__init__.py` in the category folder:

```
custom_components/            # LANGFLOW_COMPONENTS_PATH points here
└── attenu/
    ├── __init__.py
    └── attenu_guard_component.py
```

```bash
pip install attenu-guard
mkdir -p custom_components/attenu && touch custom_components/attenu/__init__.py
cp examples/integrations/langflow/attenu_guard_component.py custom_components/attenu/
LANGFLOW_COMPONENTS_PATH=$(pwd)/custom_components langflow run
```

Under Docker, mount the directory and set the same variable:

```bash
docker run -d --name langflow -p 7860:7860 \
  -v ./custom_components:/app/custom_components \
  -e LANGFLOW_COMPONENTS_PATH=/app/custom_components \
  langflowai/langflow:latest
```

**Attenu Guard Tools** then appears in the visual editor under the `attenu` category.

## Wiring a flow

```
[CRM tools] ──▶ Tools ┐
                      ├─▶ Attenu Guard Tools (orchestrator) ──▶ Guarded Tools ──▶ Agent
                      │                                    └──▶ Guard ──┐
[CRM tools] ──▶ Tools ┤                                                 │
                      ├─▶ Attenu Guard Tools (summariser) ◀── Parent Authority
                      │                     └──▶ Guarded Tools ──▶ Agent (sub)
                      └──▶ Evidence ──▶ (inspect)
```

The orchestrator's component holds `{"scopes": ["crm.*"], "ceilings": {"max_rows":
100000, "egress": "any"}, "ttl": 3600}`. The summariser's asks for `{"scopes":
["crm.read"], "ceilings": {"max_rows": 5000, "egress": "none"}, "ttl": 900}`. With the
**Guard** → **Parent Authority** edge in place, the summariser's agent can read the
CRM and cannot export it — and if someone edits its Authority field to ask for
`iam.admin` and ten million rows, it still gets `crm.*` and 100k, because the child's
authority is the meet of the request and the parent's.

## What you'll see

* `crm_query(rows=10)` runs.
* `crm_export(destination=...)` is denied **before the tool body runs** — there is no
  partial effect to undo. With **On Denied** = `return`, the agent reads the reason
  and can carry on.
* A read of 50,000 rows is denied by the `max_rows` ceiling even though `crm.read` is
  held.
* A tool added to the flow without a scope in **Tool Scopes** raises `UnpricedToolError`
  rather than arriving unguarded.
* The **Evidence** output re-verifies the audit log; rewriting one entry to hide a
  denial makes that verification fail.

## Tests

```bash
pip install attenu-guard lfx           # or the full langflow
pytest -q tests/integrations/test_langflow.py     # 25 tests, offline
```

The suite is split: the parsing and tool-wrapping half needs only `langchain-core`
and runs with Langflow absent; the component half is skipped when neither `lfx` nor
`langflow` is importable. Assertions read a side-effect ledger, so what is checked is
that a denied tool's body never ran — not that a log line was written.

## Contributing it upstream

Langflow's own guidance (`docs/docs/Contributing/contributing-components.mdx`) is for
components that ship *inside* Langflow, under `src/lfx/src/lfx/components/<category>/`
with a matching `__init__.py` entry, tests built on a `ComponentTestBase` class, and a
docs page. This file follows the same class shape — `Component` subclass,
`display_name` / `description` / `icon` / `name`, an `inputs` list, an `outputs` list
whose `method` names resolve on the class — so it can be moved there when it is
proposed for inclusion. Two of Langflow's stated rules matter for that move and are
already honoured: the class name and `name` attribute are the component's identity and
must not change afterwards, and fields and outputs are deprecated rather than removed.
