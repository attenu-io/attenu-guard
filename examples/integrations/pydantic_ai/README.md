# attenu-guard x Pydantic AI

Enforced authority attenuation for Pydantic AI's **agent delegation** pattern.
Tested against **pydantic-ai-slim 2.31.1** (the pinned CI version), re-verified against
**2.37.0** and **2.39.0** (MIT, requires Python >= 3.10).

## What it hooks

| Hook point | API used |
|---|---|
| Child creation | `GuardedDeps.delegate(...)`, called inside the delegating tool; the child `Guard` rides down as the sub-run's `deps` (`RunContext.deps`). Pydantic AI has no callback at the delegation site, so this is a construction-site integration. |
| **Tool invocation — start here** | `GuardedToolsetCapability`, an `AbstractCapability` registered via `Agent(capabilities=[...])` that overrides no execution hook and contributes one `GuardedToolset` over the agent's composed toolset. `get_ordering()` declares `position="innermost", wrapped_by=[AbstractCapability]`, and `CombinedCapability.get_wrapper_toolset` applies contributed wrappers over `reversed(...)`, so chain-last is toolset-**innermost**: the guard's `self.wrapped.call_tool` is the call that reaches the tool, in every list order. One registration covers function tools, every toolset, and MCP. |
| Tool invocation (alt) | `DelegationGuard.wrap_tool_execute` — the hook-layer capability. Same coverage, plus the built-in `search_tools` discovery call, and a denial still stops the body cold. The limit: pydantic-ai runs the whole hook chain **above** the whole toolset chain, so a wrapper toolset another capability contributes sits between this hook and the tool, and the recorded outcome is that wrapper's rather than the body's. |
| Tool invocation (one toolset) | `GuardedToolset`, a `WrapperToolset` that checks inside `call_tool`. Build one yourself to guard exactly one toolset (say a single MCP server) instead of the whole agent. |

All three share `authorize_tool_call(...)`, which never returns on a denial. Register exactly
one of them per agent: each is a complete authorization path, and two means `guard.check()`
runs twice for the same call. All the combinations are refused at agent construction. Two
attenu-guard **capabilities** are refused by pydantic-ai itself, as `Circular ordering
constraints among capabilities` — each declares `wrapped_by=[AbstractCapability]` to hold the
innermost slot, so the sorter rejects the pair before the adapter can name them. If you see
that error on an attenu-guard agent, you registered two authorizers.

### Where the toolset guard sits

Verified on 2.31.1 by reading the composed chain from inside the guard:

```
ToolSearchToolset          <- outside; serves `search_tools` itself, never delegates it inward
  A, B, ...                <- any wrapper toolsets other capabilities contribute
    GuardedToolset         <- the guard, innermost
      PreparedToolset      <- overrides `get_tools` only, never `call_tool`
        CombinedToolset    <- routes the call to the toolset that owns the tool
          FunctionToolset  <- runs the tool body
```

**Why the ordering is exact.** `position="innermost"` on its own is a *tier*: among
capabilities in it, list order is preserved and the one listed **last** wins the slot, so the
guarantee would depend on where you typed this capability. `wrapped_by=[AbstractCapability]`
adds an edge to every sibling at once (a type ref is matched with `issubclass`, self-edge
skipped), so the sorter settles it last however you list it. Probed on 2.31.1 against a sibling
`innermost` wrapper toolset in both orders, and against one injected per-run — the guard is
innermost every time. There is no "list it last" rule to remember.

pydantic-ai's `CapabilityOrdering` gains an `exclusive_execution` flag on the branch of
[pydantic/pydantic-ai#8067](https://github.com/pydantic/pydantic-ai/pull/8067); no released
version has it (checked against 2.31.1, 2.37.0 and 2.39.0). `get_ordering()` feature-detects it
and sets it as soon as it ships. It is a better diagnostic rather than a fix: the edge already
holds the slot today.

**Durable execution composes today.** Temporal, DBOS and Prefect claim `innermost` too, but
they swap *leaf* toolsets for durable ones rather than wrapping the composed toolset, so the
durable wrapper lands inside this guard whichever order the two are applied in. When
`exclusive_execution` ships, both capabilities set it and pydantic-ai refuses the pair: from
then on an agent runs a durable engine or this capability, not both.

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

`demo.py` runs on `GuardedToolsetCapability`; pass `guard=DelegationGuard` to
`build_scenario(...)` to run the same story through the hook layer. The export is denied
before its body either way — the shapes differ in where the record is taken, not in what is
decided.
