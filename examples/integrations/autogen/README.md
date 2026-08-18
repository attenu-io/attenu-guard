# delegation-guard × AutoGen

Enforced authority attenuation for [AutoGen](https://github.com/microsoft/autogen)
(`autogen-agentchat`) multi-agent teams. Tested against **0.7.5** on Python 3.12.

## What it hooks

| Hook point | Adapter piece | Why there |
|---|---|---|
| **Delegation** — `Swarm` handoff | `GuardedHandoff(Handoff)` | AutoGen runs handoff tools *outside* the workbench (`_assistant_agent.py:1561-1574`), so a guarded workbench never sees them. Overriding `Handoff.handoff_tool` mints the child `Guard` when `transfer_to_<target>` fires. |
| **Delegation** — agents-as-tools | `ToolPolicy(delegates_to=..., grant=...)` | `AgentTool`/`TeamTool` are ordinary tools, so the workbench gate covers them. |
| **Tool invocation** | `GuardedWorkbench(StaticStreamWorkbench)` | Every non-handoff tool call routes through the agent's `Workbench` (`_assistant_agent.py:1576-1613`). `guard.check()` runs before `super()`, so a denied body never executes. |

Both `call_tool` **and** `call_tool_stream` are overridden — `AssistantAgent` takes
the streaming path whenever the workbench is a `StaticStreamWorkbench`
(`_assistant_agent.py:1580`), so guarding only `call_tool` would leave the real
path open.

## Run it

```bash
python examples/integrations/autogen/demo.py      # no API key needed
pytest tests/integrations/test_autogen.py
```

## What you'll see

The demo runs the same poisoned-summarizer script twice. **Without** the guard,
AutoGen executes `crm_export` and `send_mail` — a handoff target keeps its full
tool list and the framework enforces nothing about its authority relative to the
parent. **With** the guard, only `crm_query` runs; the export and mail are denied
before their bodies execute, with reason code `scope_not_granted`. Then it shows
the child is provably narrower than the parent, that a greedy request is met down,
that revocation cascades, and that the hash-chained audit log verifies offline.

Denials come back as `ToolResult(is_error=True)` so the model can react; pass
`on_deny="raise"` for a hard `AuthorityDenied` stop.
