# attenu-guard x Pydantic AI

Enforced authority attenuation for Pydantic AI's **agent delegation** pattern.
Tested against **pydantic-ai-slim 2.31.1** (MIT, requires Python >= 3.10).

## What it hooks

| Hook point | API used |
|---|---|
| Child creation | `GuardedDeps.delegate(...)`, called inside the delegating tool; the child `Guard` rides down as the sub-run's `deps` (`RunContext.deps`). Pydantic AI has no callback at the delegation site, so this is a construction-site integration. |
| Tool invocation | `DelegationGuard.wrap_tool_execute` — an `AbstractCapability` registered via `Agent(capabilities=[...])`. Since 0.10.0 this is the only hook it overrides (`get_ordering()` pins it `position="innermost"`); `ToolManager._run_execute_hooks` calls it (`tool_manager.py:463`) as the only path to `toolset.call_tool` (`tool_manager.py:1003`), so the tool body provably cannot run on a denial. One registration covers function tools, every toolset, and MCP. |
| Tool invocation (alt) | `GuardedToolset`, a `WrapperToolset` that checks inside `call_tool`. Use it to guard exactly one toolset instead of the whole agent. |

Both hooks share `authorize_tool_call(...)`, which never returns on a denial.

## Run it

```bash
python examples/integrations/pydantic_ai/demo.py     # offline, no API key
pytest tests/integrations/test_pydantic_ai.py
```

## What you'll see

An orchestrator (`crm.*`, `mail.send`, 100 000 rows, egress `any`) delegates to a
summarizer (`crm.read`, 5 000 rows, egress `none`, ttl 900) whose model has been
poisoned. Then: `crm_query(4200)` runs; `crm_export(...)` is **denied before its
body** (`ops.exported_to` stays `None`); a delegation asking for more is met down;
revoking the sub-agent denies even the tool it was allowed; the hash-chained audit
log verifies and carries the deny with reason `scope_not_granted`.

`on_denial="raise"` (default) aborts the run with `AuthorityDenied`;
`on_denial="tool_failed"` hands the model a `ToolFailed` result it can adapt to —
the body never runs either way. Unmapped tools and a missing `Guard` fail closed.
