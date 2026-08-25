# attenu-guard × Google ADK

Tested against **google-adk 2.7.1** (Apache-2.0, requires Python ≥ 3.10) on Python 3.12.

## What it hooks

One `BasePlugin` (`attenu_guard.adapters.google_adk.DelegationGuardPlugin`), registered once on the `App`:

| attenu-guard step | ADK hook | where it runs |
| --- | --- | --- |
| mint the child `Guard` (`parent.delegate(...)`) | `before_agent_callback` | `google/adk/agents/base_agent.py:483` |
| `guard.check()` before the tool body | `before_tool_callback` | `google/adk/flows/llm_flows/functions.py:603`, ahead of the call at `:627` |

`before_agent_callback` is used for delegation because it is the only hook that fires for
all three ADK primitives — `transfer_to_agent`, `AgentTool`, and 2.x `mode='task'` sub-agents.
A denial is returned to the model as the tool result (`{"error": "authority_denied", ...}`),
which is exactly what ADK's `before_tool_callback` contract expects; pass `raise_on_deny=True`
for a hard stop instead.

## Run it

```bash
pip install "google-adk==2.7.1" attenu-guard
python examples/integrations/google_adk/demo.py          # no API key needed
pytest tests/integrations/test_google_adk.py
```

## What you'll see

An `orchestrator` ({crm.\*, mail.send}, 100k rows, egress `any`) transfers to a `summarizer`
delegated only {crm.read}, 5k rows, egress `none`. `crm_query(rows=4200)` runs; the poisoned
`crm_export` is **denied before its body executes** (proved by a side-effect list); `revoke()`
takes the whole subtree dark; the hash-chained audit log verifies at the end.

> **Note.** ADK's own `disallow_transfer_to_peers` is *not* enforced in code on 2.7.1's default
> execution path — `google/adk/workflow/utils/_transfer_utils.py:26-92` routes transfers with no
> `disallow_transfer_*` check at all (the only code check,
> `base_llm_flow.py:1444-1461`, sits on the legacy flow and is not reached on the default path). This plugin attenuates the peer's authority anyway, because the guard
> chain follows the *runtime* hand-off rather than the static `sub_agents` tree.
