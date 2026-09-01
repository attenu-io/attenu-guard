# attenu-guard x Claude Agent SDK

Tested against **claude-agent-sdk 0.2.139** (needs Python 3.10+; attenu-guard itself is 3.9+).

**Hook points.** `PreToolUse` on the `Agent`/`Task` tool authorizes the delegation itself
(`tool_input.subagent_type`); `SubagentStart` (`agent_id` + `agent_type`) mints the child's
attenuated `Guard`; `PreToolUse` on every tool call gates it, denying with
`permissionDecision: "deny"` before the tool body runs; `SubagentStop` cascade-revokes.
`ClaudeAgentOptions.can_use_tool` is wired too, but it never decides anything on its own — it
only replays the verdict `PreToolUse` already cached for that exact call (fails closed if none
is cached), so one physical tool call never produces two independent `guard.check()`s. `agent_id`
on `PreToolUse` is the correlation key that routes each call to the right `Guard`; it is absent
on the main thread, which is how the orchestrator's own calls are identified.

**Run it.**

```bash
python examples/integrations/claude_sdk/demo.py                    # offline, no key
pytest -q tests/integrations/test_claude_sdk.py                    # 29 tests, offline
RUN_LIVE=1 python examples/integrations/claude_sdk/live_smoke.py   # spends tokens
```

The live smoke needs no API key if Claude Code is installed and logged in here — the SDK shells
out to the Claude Code CLI and uses that session.

**What you'll see.** The summarizer reads 4,200 CRM rows (allowed), is then poisoned into
`crm_export` and `send_mail` — both denied before the body runs, proven by side-effect flags that
stay unset — and after a cascade revoke even its earlier read is denied. The hash-chained audit
log verifies and names each denial's reason code. `demo.py` replays the CLI's `PreToolUse`
contract rather than calling `query()`, because the SDK has no in-process test model (every model
turn happens inside the Claude Code subprocess). `live_smoke.py` runs the identical wiring against
the real CLI and deliberately puts `crm_export` in the subagent's `AgentDefinition.tools`
allowlist so attenu-guard is the only layer blocking it.

**vs. the SDK's own restrictions.** `AgentDefinition.tools` is a real, code-enforced per-subagent
allowlist — an omitted tool "isn't in the subagent's session at all". attenu-guard adds what a
name list cannot express: typed quantity ceilings checked against each call's arguments, a provable
child ⊆ parent relation across the chain, TTLs, mid-run cascade revocation, and a tamper-evident
audit log. `build_registry()` derives the SDK allowlist from the same `AgentGrant` declarations so
the two layers cannot drift.

## Live-verified (2026-08-18)

Both variants ran against a real Claude Code session on macOS (no API key — the SDK
used the logged-in CLI), Sonnet, `max_budget_usd=1.0`:

- `RUN_LIVE=1 python examples/integrations/claude_sdk/live_smoke.py` — real subagent
  spawn; hooks fired with a populated `agent_id`; the summarizer's `crm_query` was
  authorized under **its** guard; `SubagentStop` cascade-revoked it; audit verified
  (5 events). The model itself refused the injected exfil instruction, so no deny fired —
  which is the honest outcome of relying on prompt injection against a good model.
- `RUN_LIVE=1 DG_LIVE_OVERREACH=1 …` — the **parent** legitimately over-asks (summarize
  *and* export to an "approved" bucket). `crm_export` is in the summarizer's framework
  allowlist, so only its attenuated Authority stands in the way: the `PreToolUse` hook
  denied it (`scope_not_granted`; egress `ceiling_exceeded`), the tool body never ran, the
  model reported the block and did not try to route around it; audit verified (6 events).
