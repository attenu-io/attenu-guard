# Claude Code hooks, with a receipt

*A [Claude Code](https://code.claude.com/docs/en/hooks) recipe: one `PreToolUse` hook, two subagents, one
hash-chained ledger you can hand to a reviewer. Runs offline — no Claude Code binary, no API key.
Verified against the Claude Code docs on **2026-08-25**.*

## What Claude Code already does

Subagent narrowing is native, and it is good. From the
[subagents documentation](https://code.claude.com/docs/en/sub-agents):

- **`tools`** in a subagent's frontmatter is an allowlist — "If `tools` is specified, the subagent receives
  **only** those tools." Omit it and the subagent inherits every tool available to subagents.
- **`disallowedTools`** is a denylist that removes tools from the inherited or specified list. With both set,
  "`disallowedTools` is applied first… then `tools` is resolved against the remaining pool", and a tool in
  both is removed. MCP patterns (`mcp__<server>`, `mcp__<server>__*`, `mcp__*`) work in either field.
- **`Agent(worker, researcher)`** in `tools` restricts which subagents may be spawned.
- **`mcpServers`** scopes MCP servers to a single subagent — inline definitions connect when the subagent
  starts and disconnect when it finishes.
- **Hooks run inside subagents.** `PreToolUse` and `PostToolUse` from
  [`settings.json`](https://code.claude.com/docs/en/settings) "apply to all tool calls everywhere",
  and `SubagentStart` / `SubagentStop` target specific agent types.
- **`permissionMode`** inherits the parent's mode when unset. The docs state the precedence only in the loose direction: "If the parent uses `bypassPermissions` or `acceptEdits`, this takes precedence and can't be overridden", and under auto mode the child's frontmatter mode is ignored. No sentence says a stricter parent clamps a looser child (docs read 2026-09-02).

That machinery decides first. A call Claude Code refuses never reaches a tool body, whatever this recipe
does. What follows is a second, independent check that produces a record.

## What this recipe adds

1. **Derived.** Every permission set here is computed from the project's declared structure — the
   `.claude/agents/*.md` frontmatter and the `permissions` block in `.claude/settings.json` — and turned
   into an `Authority`. Each subagent's is `meet(session, derived)`, so it can never exceed the session's.
   Nobody writes a tool list twice, and the two cannot drift apart, because there is only one.
2. **Recorded.** Every `PreToolUse` decision, allow or deny, lands in a hash-chained ledger under the
   project's `.attenu/`. Each hook invocation is a fresh process, so the ledger is reloaded, re-verified
   and appended under an exclusive lock on every call. A chain that does not verify is not appended to.
3. **Verifiable.** At `SubagentStop` and `SessionEnd` the ledger is exported as a signed evidence bundle.
   A reviewer checks integrity, child-within-parent and containment with
   `attenu_guard.evidence.verify_bundle` — no Claude Code, no this project, no service.

Subagent transcripts already record what happened
([`<claude config dir>/projects/{project}/{sessionId}/subagents/agent-{agentId}.jsonl`](https://code.claude.com/docs/en/sub-agents)).
They are JSONL; the docs describe no chain, signature or anchor over them, so there is nothing for a third
party to check them against on its own. That is the gap this fills — not a criticism of what transcripts
are for.

## Install

Put `hook.py` in your project's `.claude/hooks/` directory and add the handler to
`.claude/settings.json` (the full block is in `settings.snippet.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/attenu_hook.py",
            "timeout": 10,
            "statusMessage": "attenu-guard: recording the decision..."
          }
        ]
      }
    ],
    "SubagentStop": [
      { "hooks": [{ "type": "command", "command": "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/attenu_hook.py" }] }
    ]
  }
}
```

No `matcher`: a handler without one runs for every tool call, which is what a fail-closed recorder needs —
a per-tool matcher would silently exempt any tool nobody remembered to list.

Your subagents need no changes at all. The two in `sample_project/.claude/agents/` are ordinary files:

```markdown
---
name: reviewer
description: Reviews code already in the repository. Reads and searches only; never edits, never runs commands, never reaches the network.
tools: Read, Grep, Glob
model: sonnet
---

You are a code reviewer. Read the files under review, search for related call sites,
and report what you find. You do not change files and you do not run commands.
```

## Run

```bash
pip install attenu-guard
python examples/integrations/claude_code/hooks_receipt/demo.py
python examples/integrations/claude_code/hooks_receipt/hook.py --derive .        # print the derivation
# RUN_LIVE=1 python examples/integrations/claude_code/hooks_receipt/live_smoke.py
```

The demo feeds `hook.py` the exact `PreToolUse` JSON Claude Code sends, one subprocess per call, and runs a
tool body only when the hook did not deny it. Expected output:

```
[1] derived from the project's declared structure — nothing written twice
    session root: ['agent.delegate.researcher', 'agent.delegate.reviewer', 'fs.glob', 'fs.grep', 'fs.read', 'net.fetch']
      researcher: ['fs.read', 'net.fetch']
      reviewer: ['fs.glob', 'fs.grep', 'fs.read']
[2] five tool calls through the hook (one subprocess each, JSON on stdin)
    reviewer    Read      allowed  within its derived permissions
    reviewer    Write     DENIED   Write needs fs.write, which is not in the permission set derived for subagent 'reviewer'
    reviewer    Bash      DENIED   Bash needs exec.bash, which is not in the permission set derived for subagent 'reviewer'
    reviewer    WebFetch  DENIED   WebFetch needs net.fetch, which is not in the permission set derived for subagent 'reviewer'
    researcher  WebFetch  allowed  within its derived permissions
    tool bodies that actually ran: ['Read', 'WebFetch']
[3] the unguarded control — the same five calls with no hook
    tool bodies that ran: ['Read', 'Write', 'Bash', 'WebFetch', 'WebFetch']
[4] evidence
    ledger verifies: True (8 events across 5 hook processes)
    signed bundle verifies offline: integrity=True monotonicity=True containment=True ok=True
RESULT: OK
```

Exit codes: `0` every expectation held · `1` an expectation failed · `3` the pinned hook contract changed
(see *Evidence manifest* below — the recipe, not the test, then needs attention).

The two `WebFetch` denials show the two kinds of refusal the ledger distinguishes.
`reviewer → WebFetch` is `out_of_authority`: the project declares that capability, just not for the
reviewer. `reviewer → Write` is `unresolved`: nothing in the project declares it at all, so it is denied by
default. A reviewer reading the ledger can act on the difference.

The hook returns `{}` on an allow, never `"permissionDecision": "allow"`. An explicit allow would skip
Claude Code's remaining permission machinery, which would make the hook widen your session instead of
recording it. `{}` is the documented "no decision; normal permission flow applies".

## Trust boundary (read this before relying on it)

The hook mediates Claude Code's own tool dispatch — the `PreToolUse` event, for the main thread and every
subagent. Inside that boundary: a denied call is refused before the tool body runs; an undeclared tool is
denied by default; a subagent type that is not in `.claude/agents` holds nothing; retries stay denied and
each attempt is on the ledger; parallel hook processes keep one valid chain; and if the ledger cannot be
written or does not verify, the call is denied rather than run unrecorded.

Outside that boundary, and stated plainly:

- **A command run by hand, or by another process, never reaches the hook.** A test in the gate proves such
  a call does run, so nobody mistakes mediation for a sandbox.
- **The real gate is the entry in `settings.json`,** which only Claude Code reads. `require_hook_installed()`
  refuses to proceed when that wiring is missing, but it cannot make Claude Code call a hook that is not
  configured. Managed settings are the place to make it non-optional for a team.
- **Argument-scoped permission rules stay Claude Code's.** `Bash(npm run lint)` read as a bare `Bash` grant
  would widen it; `Read(./.env)` read as a bare `Read` denial would narrow past what the operator wrote.
  Neither is guessed at — they are reported as unrepresented and left to Claude Code's own matcher, which
  still enforces them.
- **By default the hook enforces for subagents and records for the main thread.** The main session's
  permissions are the operator's own; set `enforce_main_thread` in `.attenu/config.json` to change that.
  `mode` is `observe`, `shadow` or `enforce`.
- **TTL is not enforced across hook processes** — each invocation is a new process, so the session is the
  lifetime. Revocation, not expiry, is the hard stop here.
- **The ledger is tamper-evident, not tamper-proof.** Someone who can write the file can delete it; what
  they cannot do is alter it and still have it verify. Anchor the head out of band if that matters.
- **The anchor key is project-local.** With `attenu-guard[crypto]` installed it is Ed25519 and a reviewer
  verifies with the public half alone (`.attenu/anchor.pub`); without it, HMAC, and verification needs the
  shared key. The bundle records which.

## Evidence manifest

| Claim | Pinned to | Test |
|---|---|---|
| The hook JSON contract — event names, stdin fields, return shape, exit codes | `contract.json`, transcribed from [hooks](https://code.claude.com/docs/en/hooks) / [sub-agents](https://code.claude.com/docs/en/sub-agents) / [settings](https://code.claude.com/docs/en/settings), 2026-08-25 | `test_compat_*` |
| Native subagent narrowing works as documented (all four rows of the resolution table, MCP patterns, `Agent(...)`) | sub-agents doc, 2026-08-25 | `test_semantic_native_subagent_narrowing_is_implemented_as_documented` |
| The story never claims a narrowing gap | the wording rule | `test_semantic_the_story_never_claims_a_narrowing_gap` |
| Permissions are written by the operator, not derived upstream | the documented frontmatter field list | `test_semantic_no_documented_field_derives_permissions` |
| Transcripts carry no integrity fields | sub-agents doc, 2026-08-25 | `test_semantic_transcripts_are_not_offered_as_verifiable_records` |
| `SubagentStart` JSON output is not a decision | hooks doc, 2026-08-25 | `test_semantic_subagent_start_output_is_never_used_as_a_decision` |
| Denied calls left no trace; the control shows the oracle sees every effect | this recipe | `test_side_effect_oracle_denied_calls_left_no_trace` |
| Every subagent's permission set is within the session's | `Authority.is_narrower_than` | `test_authority_is_monotonic_down_the_chain` |
| Derived from the files: edit the frontmatter, the permission set moves | this recipe | `test_derivation_comes_from_the_files_not_from_a_second_hand_written_list` |
| Undeclared tool · alternate write tool · undeclared subagent · retries · hook absent · ledger unwritable · tampered ledger · tampered bundle · direct call · session-id traversal · parallel processes · mid-session roster edit · shadow mode | this recipe | `test_bypass_*` (13) |
| Injected text never changes a decision (8 payloads × 2 calls, plus tool names and frontmatter) | this recipe | `test_injection_*` (4) |

Re-fetch the three doc sources on the week of publication and re-run the suite; a change in `contract.json`
is what tells us the recipe needs updating.

```bash
python -m pytest -q tests/integrations/test_claude_code_hooks_receipt.py
```

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03 (un-scoped privilege inheritance), ASI07, ASI08 ·
Agent Baseline AUT-03 (delegation attenuation) · [`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md) ·
[`docs/THREAT-MODEL.md`](../../../../docs/THREAT-MODEL.md).

## What remains Claude Code's

The tool allowlist and denylist and their resolution order; `Agent(name)` spawn restriction; MCP scoping;
permission modes and their inheritance; argument-scoped permission rules; workspace trust; managed settings;
the hook system this recipe stands on; and the transcripts. This recipe reads what those declare and writes
down what was decided. It replaces none of them.
