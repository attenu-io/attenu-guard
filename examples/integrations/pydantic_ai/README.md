# attenu-guard x Pydantic AI

Enforced authority attenuation for Pydantic AI's **agent delegation** pattern.
Tested against **pydantic-ai-slim 2.31.1**, the version CI pins, and re-verified against
**2.39.0**, the latest release (MIT, requires Python >= 3.10). Line citations in the adapter are
as of 2.37.0; behaviour is stated against the version it was probed on.

## What it hooks

| Hook point | API used |
|---|---|
| Child creation | `GuardedDeps.delegate(...)`, called inside the delegating tool; the child `Guard` rides down as the sub-run's `deps` (`RunContext.deps`). Pydantic AI has no callback at the delegation site, so this is a construction-site integration. |
| **Tool invocation — start here** | `GuardedToolsetCapability`, an `AbstractCapability` registered via `Agent(capabilities=[...])` that overrides no execution hook and contributes one `GuardedToolset` over the agent's composed toolset. `get_ordering()` declares `position="innermost", wrapped_by=[AbstractCapability]`, and `CombinedCapability.get_wrapper_toolset` applies contributed wrappers over `reversed(...)`, so chain-last is toolset-**innermost**: the guard's `self.wrapped.call_tool` is the call that reaches the tool, in every list order. One registration covers function tools, every toolset, and MCP. |
| Tool invocation (alt) | `DelegationGuard.wrap_tool_execute` — the hook-layer capability. Same coverage, plus the built-in `search_tools` discovery call, and a denial still stops the body cold. The limit: pydantic-ai runs the whole hook chain **above** the whole toolset chain, so a wrapper toolset another capability contributes sits between this hook and the tool, and the recorded outcome is that wrapper's rather than the body's. |
| Tool invocation (one toolset) | `GuardedToolset`, a `WrapperToolset` that checks inside `call_tool`. Build one yourself to guard exactly one toolset (say a single MCP server) instead of the whole agent. |

All three run the same authorization core, and neither entry point returns on a denial. On a
`schema_version=2` chain that is `_authorize_v2(...)`, which passes `capture`/`adapter`/
`authorized_params` to `guard.check(...)` and binds the tool body's outcome to the decision; on
a v1 chain it is `authorize_tool_call(...)`, which authorizes and records nothing further.
Register exactly one entry point per agent: each is a complete authorization path, and two
means `guard.check()` runs twice for the same call.

What is refused at agent construction, and by whom:

| Combination | Refused by |
|---|---|
| Two attenu-guard **capabilities** (`GuardedToolsetCapability` beside `DelegationGuard`, or two of either) | pydantic-ai's sorter, as `Circular ordering constraints among capabilities` — each declares `wrapped_by=[AbstractCapability]` to hold the innermost slot, so the pair cycles before the adapter can name them. **If you see that error on an attenu-guard agent, you registered two authorizers.** |
| An agent-wide capability plus a `GuardedToolset` you built and listed in `toolsets=[...]` | the adapter's `for_agent()`, naming both. The walk follows `.wrapped` chains and `.toolsets` branches, so one nested inside a `CombinedToolset` is caught too |

**Not detected:** a `GuardedToolset` constructed inside a tool call and never listed in
`toolsets=[...]`. Nothing at construction time can see it, so don't do that.

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

**Known limit: durable execution.** Temporal, DBOS and Prefect claim `innermost` too, but they
never wrap the composed toolset — they swap the *leaf* toolsets for durable ones, and a
`WrapperToolset` rebuilds itself around the visited result, so the swap descends **through**
this guard. Both orders give the same tree, `Guard(Durable(FunctionToolset))`. Beside a durable
engine the guarantee this capability exists for does not hold: the durable toolset sits between
the guard and the tool body, and the recorded outcome encloses the durable dispatch rather than
the body. The policy lookup, `guard.check()` and the ledger write run outside that durable
toolset boundary, in the same context as the rest of the capability chain. What a given engine
does with that context was **not measured** — no worker was run for this work, and the tests use
a leaf-rewriting proxy — so nothing here claims anything about journalling or replay.

**There is no configuration in this release that places the guard inside the durable unit.** No
ordering does it, and neither does handing the engine a `GuardedToolset` of your own: the swap
descends through that wrapper the same way. Reaching inside would mean participating in the
registered leaf, a different primitive from anything `CapabilityOrdering` offers —
[pydantic/pydantic-ai#8127](https://github.com/pydantic/pydantic-ai/issues/8127).

pydantic-ai's maintainer says both halves in that comment: the guard is outside the durable unit
in every configuration, and refusing the pair outright is "arguably correct", since this
capability requires that nothing sit between it and the tool body and beside a durable engine
something always does. This release adds no refusal anyway, because it cannot detect one
honestly: a durability capability is recognisable only by its module, which would name the three
first-party engines and silently miss any other leaf rewriter.

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

`demo.py` runs on `GuardedToolsetCapability`. To run the same story through the hook layer,
import `DelegationGuard` from `attenu_guard.adapters.pydantic_ai` and pass it as
`build_scenario(..., guard=DelegationGuard)` — the example itself does not import it. The export is denied
before its body either way — the shapes differ in where the record is taken, not in what is
decided.
