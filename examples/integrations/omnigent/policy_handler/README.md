# Omnigent counts how many; here is how much

*An [Omnigent](https://github.com/omnigent-ai/omnigent) recipe: one policy handler, registered the way every
Omnigent policy is registered, that gives each sub-agent an authority instead of a counter. Runs offline with a
scripted dispatch sequence — no API key, no harness. Verified against **omnigent 0.11.0** on 2026-08-28 (and 0.10.0 on 2026-08-25).*

## Three-minute repro

No API key, no harness, no account. From a clean shell:

```bash
git clone --depth 1 https://github.com/attenu-io/attenu-guard && cd attenu-guard
python3 -m venv .venv && . .venv/bin/activate && pip install -q 'attenu-guard[omnigent]'
python examples/integrations/omnigent/policy_handler/demo.py
attenu-guard verify attenu-omnigent-bundle.json --hs256-key 64656d6f2d6b6579   # step 4 again, Omnigent absent
```

What you will see: the same ten-step dispatch script run twice — once with no policy attached (all ten tool bodies
execute, including a depth-3 spawn, a second release and an undeclared `shell`), once through Omnigent's own
`FunctionPolicy` with this handler registered (four DENYs before the bodies run) — then the run's signed bundle
verified from the file alone. Measured at 20 s from a fresh clone on a laptop with a warm `pip` cache; allow a minute or two cold.

## What Omnigent does

Omnigent puts a decision point on every action. A policy is a Python callable registered from YAML
([`docs/POLICIES.md`](https://github.com/omnigent-ai/omnigent/blob/main/docs/POLICIES.md)), it returns
`ALLOW` / `ASK` / `DENY` or `None` to abstain, and composition is stated plainly: *"The engine evaluates them in
declaration order. A DENY from any policy short-circuits the rest."* Sub-agent dispatch has a named interception
point, `sys_session_send`, and two builtins already gate it — `spawn_bounds` caps dispatches per orchestrator turn,
`headless_subagent_purpose_guard` requires every dispatch to declare `args.purpose`. Evaluation fails closed on the
tool-call and request phases (`FAIL_CLOSED_PHASES` in `omnigent/policies/types.py`), and an exception inside a policy
becomes a DENY rather than a pass. That is a good decision layer, and this recipe plugs into it rather than beside it.

## What this recipe shows

Two of Omnigent's own open issues describe what the decision layer leaves to the operator. This handler answers both
inside their contract, and adds the record.

1. **A depth bound that is a property of the chain, not of a turn.** Issue
   [#5169](https://github.com/omnigent-ai/omnigent/issues/5169) (open, 2026-08-21): *"Nothing bounds how deep a
   sub-agent tree can go … It counts dispatches within a single orchestrator turn and denies past the cap, with a
   per-turn counter reset by the runner's `reset_turn` hook … That bounds one node's branching factor. It does not
   bound the tree, because each child gets its own turn and therefore its own fresh counter."* Here the ceiling lives
   on the delegation chain, which no turn boundary resets: a dispatch at depth 3 under `max_depth: 2` is DENIED in
   whichever turn or session it happens. Fan-out is counted the same way — for the life of the chain.
2. **Per-sub-agent scope, derived from what the spec already declares.** Issue
   [#2390](https://github.com/omnigent-ai/omnigent/issues/2390) (open, 2026-07-10): *"`sys_session_send` is the
   interception point for sub-agent dispatch (existing builtins like `spawn_bounds` and
   `headless_subagent_purpose_guard` already gate it), but there's no built-in policy for the specific, common case of
   per-user sub-agent access control."* That issue asks for a rule keyed on the human who triggered the dispatch. This
   handler answers a neighbouring question — one keyed on the **dispatching agent**: each sub-agent's authority is
   computed from the `tools` its own spec declares and is the *meet* with its parent's, so a child never holds more
   than the agent that dispatched it, and a tool absent from the declared scope map is held by nobody.
3. **A record that verifies with Omnigent absent.** A `PolicyResult` carries an action and a reason. Every ALLOW and
   DENY here is also appended to a hash-chained ledger, and `attenu-guard verify` — or
   `attenu_guard.evidence.verify_bundle` on a signed bundle — checks integrity, child-subset-of-parent and
   containment from the file alone, with no service and no network.

## Registering it

`handler.py` is an ordinary module: put it on `PYTHONPATH` as `attenu_omnigent.py` (or list its package under
`policy_modules:`), then register it in the server config or in each agent's spec. Full file, both placements and the
declared roster: [`policies.yaml`](policies.yaml).

```yaml
policies:
  attenu_delegation_guard:
    type: function
    function:
      path: attenu_omnigent.attenu_delegation_guard
      arguments:
        agent: orchestrator        # the roster entry whose session this instance runs in
        root: orchestrator
        chain_id: build-and-ship   # every instance sharing this key shares one chain
        max_depth: 2               # counted on the chain, not per turn
        max_fanout: 4
        audit_path: .omnigent/attenu-ledger.jsonl
        roster:
          orchestrator: {tools: [], subagents: [researcher, coder]}
          researcher:   {tools: [repo_read, web_fetch], subagents: []}
          coder:        {tools: [repo_read, repo_write], subagents: [deployer]}
          deployer:
            tools: [deploy_release]
            subagents: [smoke_tester]
            ceilings: [{max_calls: 1, applies_to: deploy.release}]
          smoke_tester: {tools: [repo_read], subagents: []}
        scopes:
          repo_read: repo.read
          repo_write: repo.write
          web_fetch: web.fetch
          deploy_release: deploy.release
```

Use `function: {path, arguments}`. `handler:` is accepted as an alias for a bare dotted path, but on this parser
path a sibling `factory_params:` is not read (`omnigent/spec/parser.py:3308`, `:3528`), so the factory would be
called with no arguments — pinned by `test_compat_policies_yaml_parses_with_omnigents_own_parser`.

## Running it

```bash
pip install 'attenu-guard[omnigent]'      # omnigent 0.11.0 at the time of writing
python examples/integrations/omnigent/policy_handler/demo.py
# RUN_LIVE=1 OMNIGENT_AGENT=path/to/agent.yaml python examples/integrations/omnigent/policy_handler/live_smoke.py
```

Expected:

```
[1] premise — Omnigent 0.11.0's own orchestration policies
    spawn_bounds('max_dispatches_per_turn', 'dispatch_tools') — a per-turn count, reset by the runner's reset_turn hook
    no orchestration policy factory takes a depth or nesting argument (issue #5169)
[2] the same script, no policy attached
    tool bodies that ran: 10/10 — including ['deploy_release', 'repo_read', 'repo_write', 'shell', 'sys_session_send']
[3] the same script through Omnigent's FunctionPolicy, handler registered
    ALLOW orchestrator -> researcher             (ok)
    ALLOW researcher: repo_read                  (ok)
    DENY  researcher: repo_write                 (ok)
    ALLOW orchestrator -> coder                  (ok)
    ALLOW coder: repo_write                      (ok)
    ALLOW coder -> deployer                      (ok)
    ALLOW deployer: deploy_release               (ok)
    DENY  deployer: deploy_release               (ok)
    DENY  deployer: shell                        (ok)
    DENY  deployer -> smoke_tester               (ok)
    denied bodies that ran anyway: [] (expected [])
    releases executed: 1 (expected 1)
    deployer ['deploy.release', 'repo.read'] subset of coder: True; researcher holds repo.write: False
[4] evidence
    hash chain verifies: True (11 events)
    signed bundle verifies offline: integrity=True monotonicity=True containment=True ok=True
    bundle written: attenu-omnigent-bundle.json — re-check it with Omnigent absent:
    attenu-guard verify attenu-omnigent-bundle.json --hs256-key 64656d6f2d6b6579
RESULT: OK
```

Exit codes: `0` every expectation held · `1` an expectation failed · `3` Omnigent now bounds delegation depth
itself — the premise of step 1 changed, and steps 2–4 still hold.

Everything that decides a call in step 3 is Omnigent's own code: `resolve_function_policy` imports the handler and
calls the factory with its arguments, `FunctionPolicy._build_event` builds the event dict, and
`FunctionPolicy.evaluate` dispatches on arity and coerces the returned dict into a `PolicyResult`. Only the
composition loop is the recipe's, and it mirrors `PolicyEngine.evaluate` in
`omnigent/runtime/policies/engine.py` — declaration order, first DENY short-circuits, an exception becomes a
fail-closed DENY (`_dispatch_policy`, same file). The real engine is not constructed here because it requires a
`ConversationStore`; the live variant runs against a real Omnigent session instead.

## Trust boundary (read this before relying on it)

The handler mediates what Omnigent hands its policies: `tool_call` phase events, including the `sys_session_send`
named dispatch. It does **not** see a direct Python call around Omnigent (`shell(command=…)` from your own code
runs — the test proves it), another process, a harness's own in-context sub-agent tool, or the credentials the
process already holds. The chain lives in one process, so the depth and fan-out ceilings bind the sessions that
share that process; across processes the chain would have to travel on the wire (`attenu_guard.wire`), which this
recipe does not do.

Inside that boundary: a denied call never executes its body; a tool with no declared scope is denied rather than
allowed by omission; retries stay denied and every attempt is on the ledger; if the ledger cannot be written the
call does not proceed; and a missing registration makes `require_guard` refuse to start. The ledger is
tamper-evident, not tamper-proof — whoever holds the signing key is stated in
[`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md).

## Evidence manifest

| Claim | Pinned to | Test |
|---|---|---|
| `spawn_bounds` is a per-turn width bound with no depth argument | `omnigent==0.11.0` (and 0.10.0), `omnigent/policies/builtins/orchestration.py` | `test_semantic_spawn_bounds_is_a_per_turn_width_bound` |
| No orchestration policy factory bounds delegation depth (#5169) | same module, every public factory's signature | `test_semantic_no_orchestration_policy_bounds_delegation_depth` |
| A decision is an action plus a reason, not a verifiable record | `omnigent/policies/types.py` `PolicyResult` fields | `test_semantic_policy_result_carries_no_verifiable_record` |
| Named dispatch carries the sub-agent in `agent` (#2390's interception point) | `omnigent/tools/builtins/spawn.py` `_build_sys_session_send_schema` | `test_semantic_dispatch_payload_names_the_subagent` |
| The handler loads with Omnigent absent | this recipe | `test_compat_handler_imports_with_omnigent_absent` |
| `policies.yaml` parses and keeps its factory arguments | `omnigent/spec/parser.py` `parse_default_policies` | `test_compat_policies_yaml_parses_with_omnigents_own_parser` |
| The factory resolves through Omnigent's own path | `omnigent/policies/function.py` `resolve_function_policy` | `test_compat_handler_resolves_through_omnigents_factory_path` |
| Denied calls left no trace (side-effect oracle, with a control run) | this recipe | `test_side_effect_oracle_denied_calls_left_no_trace`, `test_side_effect_oracle_control_run_executes_every_body` |
| deployer ⊆ coder ⊆ orchestrator, and no branch holds another's scopes | `Guard.is_narrower_than` | `test_authority_is_monotonic_down_the_chain` |
| A depth-3 dispatch is denied and recorded | `Chain.max_depth` | `test_depth_beyond_the_ceiling_is_denied_and_recorded` |
| Fan-out is bounded for the life of the chain; a repeat dispatch reuses the node | `Chain.max_fanout` | `test_fanout_beyond_the_ceiling_is_denied_and_recorded`, `test_repeat_dispatch_of_the_same_subagent_does_not_inflate_fanout` |
| Undeclared tool denied by default · retries stay denied · undeclared sub-agent denied · registration absent refuses to run · ledger-write failure fails closed · a direct Python call is outside the boundary · parallel dispatches stay siblings · a second instance cannot re-describe the chain · an agent outside the roster cannot be configured · tampered bundle fails, clean bundle passes | this recipe | `test_bypass_*` |
| Attacker text in the dispatch payload changes no decision | this recipe | `test_injection_the_scripted_orchestrator_decides_on_an_out_of_scope_call` |

Related: OWASP Top 10 for Agentic Applications 2026 — ASI03 (un-scoped privilege inheritance), ASI07, ASI08 ·
Agent Baseline AUT-03 (delegation attenuation) · [`docs/DENIAL-CONTRACT.md`](../../../../docs/DENIAL-CONTRACT.md).

## What remains Omnigent's

The decision points, the phases and their fail-closed set, composition and short-circuiting, the ASK path and its
approval UI, `spawn_bounds` and `headless_subagent_purpose_guard`, sandboxing, the harness abstraction, and the
choice of whether a depth bound belongs upstream at all — #5169 and #2390 are theirs to answer, and this recipe is
one working answer offered on those threads, not a replacement for one.
