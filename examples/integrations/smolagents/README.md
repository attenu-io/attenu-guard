# delegation-guard x smolagents

Tested against **smolagents 1.26.0** (Apache-2.0), Python 3.12. No changes to
smolagents or to `delegation_guard` — the adapter is `dg_smolagents.py`, ~120
lines of logic you can paste into your own project.

## What it hooks

| Hook point | smolagents API | Adapter |
|---|---|---|
| Tool invocation | `Tool.forward` — the single funnel for **both** `ToolCallingAgent.execute_tool_call` (`agents.py:1453`) and `CodeAgent`'s sandbox callables (`agents.py:492` → `LocalPythonExecutor.send_tools`, `local_python_executor.py:1763`) | `GuardedTool` / `guard_tools(...)` runs `guard.check(scope, context=...)` before the inner tool's body |
| Delegation / handoff | `managed_agents=[...]`; a managed agent is duck-typed as a callable tool (`_setup_managed_agents`, `agents.py:369`) and invoked via `MultiStepAgent.__call__` (`agents.py:868`) | `DelegatedAgent` proxy mints a fresh child Guard with `parent.delegate(...)` on every handoff and binds it into the sub-agent's tools |

smolagents has **no** pre-execution callback: `step_callbacks` fire in
`_finalize_step` (`agents.py:620`), *after* a step has already run, so they
cannot authorize anything. Subclassing `Tool` and substituting the managed
agent are the framework's own extension points — no monkeypatching.

## Run it

```bash
pip install "smolagents==1.26.0" delegation-guard
python examples/integrations/smolagents/demo.py          # offline, no API key
pytest -q tests/integrations/test_smolagents.py          # 17 tests, offline
```

## What you'll see

1. **Baseline** — stock smolagents: the manager holds *no* export tool, yet its
   sub-agent exports the CRM anyway. Nothing in the framework relates a child's
   powers to its parent's; the `managed_agent.task` prompt template is advice.
2. **Guarded** — same run, same scripted model: `crm_query(rows=4200)` is
   allowed, `crm_export(...)` is **denied before the tool body runs** (proved by
   a side-effect ledger), and the run still completes — the denial reaches the
   model as an `AgentToolExecutionError` observation it can react to.
3. **Attenuation** — a delegation asking for `iam.admin`, 10M rows and a 24h TTL
   is met down to the parent's `crm.*` / 100k / 3600.
4. **Revocation** — `root.revoke(child_node_id)` denies every later tool call.
5. **Evidence** — the delegation graph, plus a hash-chained audit log where
   rewriting the denial to hide the breach makes `AuditLog.verify` return False.

The LLM is a scripted `smolagents.models.Model` subclass returning fixed
`ChatMessage`s, so everything runs offline. `live_smoke.py` runs the same story
against a real model, gated on `RUN_LIVE=1`.
