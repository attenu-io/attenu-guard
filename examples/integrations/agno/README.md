# attenu-guard × Agno

Enforced authority attenuation for [Agno](https://github.com/agno-agi/agno) teams.
**Tested against `agno` 2.9.0 (Apache-2.0), Python 3.12.**

## What it hooks

Both hook points are Agno's own `tool_hooks` — no monkeypatching. A tool hook *wraps* the call
(`FunctionCall._build_nested_execution_chain`, `agno/tools/function.py:2020`), so a hook that
never calls `function_call(**arguments)` stops the tool body running at all. Agno designs for
this: it sanitises injected args before hooks run "so a hook used as an authorization gate
cannot read an identity the call will not actually execute with" (`agno/tools/function.py:2160`).

- **Delegation** — `Team(tool_hooks=[delegation_tool_hook(...)])` intercepts Agno's injected
  `delegate_task_to_member` tool (`agno/team/_default_tools.py:441`), minting the member's
  `Guard` via `parent.delegate(...)`.
- **Tool call** — `Agent(tool_hooks=[guarded_tool_hook(...)])` runs
  `guard.check(scope, context=..., tool=...)` before the tool body.

`team.tool_hooks` are **not** propagated to members (`agno/team/_init.py:487`), so every agent
carries its own hook. `tool_hooks` are not `pre_hooks`/`post_hooks` — those are guardrails
over the run *input* (`agno/guardrails/base.py:11`) and never see a tool call.

**Match the hook flavour to the callee.** Agno drops async hooks from the sync chain with only
a warning (`agno/tools/function.py:2081`) — an async-only gate *fails open* on `run()` — while
a sync hook on an async callee returns its coroutine un-awaited. Use the sync hooks for sync
tools (they work under `run` and `arun`), and `aguarded_tool_hook` / `adelegation_tool_hook`
for `async def` tools and for any Team driven by `arun`. All four are tested.

## Run it

    python examples/integrations/agno/demo.py          # offline, no API key
    python -m pytest tests/integrations/test_agno.py   # 23 tests, offline

Part 1 of the demo runs the attack **unguarded** — Agno hands the member a task *string* and it
exfiltrates the CRM. Part 2 runs it guarded: `crm_query(rows=4200)` executes, the poisoned
`crm_export` is denied before its body runs, a greedy delegation is met down to the parent's
ceiling, revocation cascades, and the audit log verifies. Denials raise `AuthorityDenied` → an
Agno tool error the model reads (default); `on_deny="stop"` raises `StopAgentRun` instead.
