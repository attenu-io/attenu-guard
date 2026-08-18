# delegation-guard x CrewAI

Enforced authority attenuation across CrewAI agent delegation, via CrewAI's own
global tool hooks. Tested against **crewai 1.15.16** (Python 3.12; CrewAI needs
>=3.10, delegation-guard supports 3.9+).

## What it hooks

| # | Moment | CrewAI API (site-packages paths) |
|---|--------|----------------------------------|
| 1 | **Child creation** | The `Delegate work to coworker` / `Ask question to coworker` tool call (`crewai/tools/agent_tools/delegate_work_tool.py`, injected at `crewai/crew.py:1746`). The bridge mints the coworker's Guard with `parent.delegate(...)` before `BaseAgentTool._execute` runs the coworker (`crewai/tools/agent_tools/base_agent_tools.py:110-120`). |
| 2 | **Tool invocation** | `crewai.hooks.register_before_tool_call_hook` (`crewai/hooks/tool_hooks.py:208`), dispatched at `InterceptionPoint.PRE_TOOL_CALL` on every path — `crewai/utilities/tool_utils.py:123` (ReAct), `crewai/agents/crew_agent_executor.py:962` (native function calling) — always before the tool body. |

Denials become `crewai.hooks.HookAborted`, **not** `AuthorityDenied`: CrewAI's
dispatcher swallows every other exception fail-open
(`crewai/hooks/dispatch.py:264`), so a raised `AuthorityDenied` would be
silently ignored and the tool would run. A paired `after_tool_call` hook
replaces CrewAI's generic "Tool execution blocked by hook." with the
delegation-guard reason, so the model learns *why* and can adapt.

Everything fails closed: unknown agent, unknown tool, unconfigured coworker,
and any internal bridge error all deny.

## Run it

```bash
python examples/integrations/crewai/demo.py                     # offline, no API key
python -m pytest -q tests/integrations/test_crewai.py           # 17 tests, offline
RUN_LIVE=1 OPENAI_API_KEY=... python examples/integrations/crewai/live_smoke.py
```

## What you'll see

The orchestrator (`crm.*`, `RowLimit(100_000)`, `EgressRank("any")`) delegates
to a summarizer (`crm.read`, `RowLimit(5_000)`, `EgressRank("none")`).

1. `crm_query(rows=4200)` — in scope, under ceiling → **the tool body runs**.
2. `crm_export(...)` — poisoned step → **denied before the body runs**
   (`scope_not_granted` + `ceiling_exceeded` on egress).
3. With `revoke_on_deny=True`, the subtree is revoked, so the *next*
   `crm_query` — legal a moment earlier — is denied `revoked`.
4. The delegation graph and hash-chained audit log print; `AuditLog.verify` → `True`.
5. A **baseline** section re-runs the identical crew with the bridge
   uninstalled: the export succeeds. CrewAI applies no authority attenuation
   of its own — delegation is a prompt-mediated tool call and the coworker
   runs with its own full tool list.
