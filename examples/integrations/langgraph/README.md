# Authority that narrows across a LangGraph node call

A recipe for `attenu_guard.adapters.langgraph` — the shipped node-wrapping
adapter, LangGraph 1.x's reference wiring for this library. An orchestrator
delegates a summarization job to a summarizer, the summarizer gets a Guard
that is strictly narrower than the orchestrator's, and a poisoned tool call
the summarizer was never delegated is denied before its body runs — with a
real execution-binding record proving the arguments authorized are the
arguments invoked, a revocation that cuts off a call that was legal a
moment earlier, and a signed, offline-verifiable evidence bundle at the end.

(LangChain 1.x's own agent-loop middleware, `attenu_guard.adapters.langchain`,
is a DIFFERENT module with its own recipe for the deepagents subagent-as-tool
pattern: see [`subagent_middleware/`](subagent_middleware/README.md). This
recipe is about `adapters.langgraph` specifically — one adapter, one recipe.)

Tested against **langgraph 1.2.11** (Python 3.12; langgraph itself needs
>=3.10, attenu-guard supports 3.9+).

## What this recipe teaches

- **Task-scoped delegation.** The orchestrator holds broad authority
  (`crm.*`, `mail.send`); `Guard.delegate(...)` mints the summarizer's Guard
  from an authority the orchestrator's own code declares — not from
  whatever a model asked for.
- **Monotonic narrowing.** The summarizer's Guard is checked to be strictly
  narrower than its parent's, and a caller that asks for MORE than its
  parent holds (`payments.transfer`, a 10,000,000-row ceiling) gets back
  exactly what its parent had — never more, however greedy the request.
- **Fail closed before the tool body runs.** `guard_node`/`add_guarded_node`
  wrap the `summarize` and `export` node functions; `export` is out of
  scope, and `AuthorityDenied` is raised — and propagates straight out of
  `graph.invoke()` — before `export`'s body ever executes.
- **Genuine execution-binding evidence, no attestation flag.**
  `attenu_guard.adapters.langgraph` is this library's reference wiring: on
  a `schema_version=2` chain, `guard_node` always binds a real
  `Capture.WRAPPER_SYNC` (or `WRAPPER_ASYNC`) outcome — there is no
  opt-in/opt-out mode to explain, unlike an adapter built on a framework's
  global hook. See [Trust boundary](#trust-boundary) for exactly what that
  capture does and does not prove.
- **A framework-agnostic wrapper.** `guard_node`'s decorated function is a
  plain Python callable — LangGraph is not required to exercise it. The
  revocation step in this recipe calls it directly, no graph involved.
- **Offline-verifiable evidence.** The audit log is exported as a signed
  bundle and checked back with the packaged `attenu-guard verify` command —
  a reviewer, or a regulator, needs only the public key, never this process
  or this repository.

## Prerequisites

- Python 3.10+ (langgraph's own floor; attenu-guard itself supports 3.9+)
- `langgraph==1.2.11` (`pip install langgraph==1.2.11`)
- No LLM API key for the offline run below — this recipe drives
  `attenu_guard.adapters.langgraph` directly, through plain LangGraph node
  functions; no chat model is invoked at all
- `cryptography` for the evidence-bundle step (`Ed25519Signer`) — install
  via attenu-guard's own `crypto` extra if it is not already present
  (`pip install 'attenu-guard[crypto]'`)
- A real application consuming attenu-guard from PyPI would pin
  `attenu-guard>=0.10,<0.11`; this recipe lives inside the attenu-guard repo
  itself and imports `src/` directly, so there is nothing to pin here

## Setup

From a checkout of this repository:

```bash
pip install -e '.[crypto]'
pip install langgraph==1.2.11
```

## Run

```bash
python examples/integrations/langgraph/demo.py                        # offline, no API key
python -m pytest -q tests/integrations/test_langgraph.py \
                    tests/integrations/test_deepagents.py \
                    tests/integrations/test_langgraph_subagent_middleware.py \
                    tests/integrations/test_langgraph_recipe_demo.py    # offline
```

`examples/integrations/langgraph/live_smoke.py` runs the same node-level
story against a real model; it is env-gated (`RUN_LIVE=1` +
`ANTHROPIC_API_KEY`) and never runs in CI.

## Expected output

Abridged; the run prints the full transcript, including the raw audit-log
lines inside section 6 (only their count is shown below).

```text
1. The authority the orchestrator holds
  orchestrator  Authority(scopes=['crm.*', 'mail.send'], ...)
  will delegate Authority(scopes=['crm.read'], ...)
  summarizer.is_narrower_than(orchestrator): True

2. What a greedy delegation request gets (met down, never up)
  requested  Authority(scopes=['crm.*', 'mail.send', 'payments.transfer'], ...)
  granted    Authority(scopes=['crm.*', 'mail.send'], ...)
  narrower than parent? True
  'payments.transfer' granted? False

3. Running the graph: crm_query allowed, crm_export denied before its body runs
    ok      node 'summarize' ran
    DENIED  node 'export'    denied: scope_not_granted ...

  node bodies that actually ran: ['summarize(rows=4200)']
  -> AuthorityDenied propagates straight out of graph.invoke(); the
     LangGraph run never reaches export's body.

4. Execution binding: genuine WRAPPER_SYNC, no attestation flag
  capture: wrapper_sync
  summarize() mutated its OWN argument in place, after the call was authorized:
    state['expected_rows'] became -1 inside the call (it was 4200 when authorized)
  authorized_params_hash == invoked_params_hash: True
  This is NOT a tautology: the snapshot is taken BEFORE the call, and re-used for
  BOTH hashes rather than re-read from the (now-mutated) argument afterward -- an
  adapter that instead re-read `state` post-call would commit a DIFFERENT
  invoked_params_hash here. It proves the ARGUMENTS authorized are the arguments
  invoked; it does not prove anything else about what summarize() did with them,
  and it says nothing about a call path that reaches crm_query without going
  through this node at all.

5. Revocation: a call that was legal a moment ago, denied
  before revoke: summarize({'expected_rows': 10}) allowed? True
    DENIED  denied: revoked: node has been revoked
  -> guard_node's wrapper is a plain callable: LangGraph was never required
     to exercise it, on this call or on the graph run above.

6. The ledger, checked without this process
    (9 raw audit-log lines printed here: seq 0-8, one per root/spawn/kill/
    allow/outcome/deny event)

  9 events, hash chain: True

  bundle: (fresh temp dir)/evidence-bundle.json
  verifying it with the packaged command:
    attenu-guard verify evidence-bundle.json --pubkey ...
integrity=True monotonicity=True containment=True anchor=verified nodes=3 actions_checked=1
OK
  reviewer view: 3 nodes

7. BASELINE: the same two node functions, no guard installed
  node bodies that actually ran: ['summarize(rows=4200)', 'export']

  CRM exported without a guard installed? True
  LangGraph itself carries no authority across a node call: a plain
  callable node runs whatever its body says, with no relation at all
  to what any other node in the graph is allowed to do.

RESULT: OK
```

The bundle path and the pubkey are different on every run (a fresh temp
directory and a fresh Ed25519 keypair each time); everything else is
deterministic.

`export` is absent from the list of node bodies that ran in section 3.

## Trust boundary

The adversary this addresses is the agent itself — a summarizer steered by
a poisoned tool response, a confused plan, or a bad system prompt into
asking for something outside its remit. The enforcement point is
`guard_node`/`add_guarded_node`'s own wrapper, invoked directly around
whichever node function it decorates, and holds:

- for any call to a wrapped node function — through `graph.invoke()`, or
  called directly as plain Python, as section 5 does. There is no separate
  "installed" state to lose: the wrapping IS the node.
- against permissions, not against content. The library takes no view on
  whether the export is a good idea; it holds the summarizer to what it
  was delegated.
- **The `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` execution binding shown in
  section 4 is this adapter's genuine, unconditional behavior on a
  `schema_version=2` chain — not an opt-in attestation.** Unlike an adapter
  built on a framework's own global hook (which cannot always prove it is
  the only thing registered on that hook, and so offers a narrower default
  plus an opt-in stronger mode), `guard_node` IS the call: it invokes the
  wrapped callable itself, synchronously or by awaiting it, and observes
  the outcome directly. There is no mode-split flag to set and no weaker
  default to fall back to here.
  **What `authorized_params_hash == invoked_params_hash` proves:** the
  arguments `Guard.check()` authorized are byte-for-byte the arguments the
  wrapped callable was actually invoked with — a callable that mutated its
  own inputs in place cannot make this adapter observe two different
  values for what was actually one call.
  **What it does NOT prove:** anything about what the callable's body did
  with those arguments once it ran, and nothing about a call path that
  reaches the same side effect (e.g. calling `crm_query`'s underlying
  client directly) without going through this wrapped node at all — that
  path is outside this adapter's reach, same as any other library boundary.

It does not defend against an attacker with code execution in the same
process, who can edit the tool policies and delegation authorities in this
recipe's own `demo.py` before they are loaded. Exported evidence is
verified against a public key, so a bundle altered after export fails
verification with the key alone.

Writing the delegated authorities is your job, deliberately: they are
declared inline in `demo.py`'s `main()`, a short, reviewable block, and the
wrapper enforces exactly what it says.

## Files

| Path | What it holds |
|---|---|
| `demo.py` | The offline recipe: the graph, the two guarded node functions, the execution-binding check, the evidence export and offline verification |
| `deepagents_demo.py` | A separate, real-multi-agent demo using `attenu_guard.adapters.langchain` (deepagents spawns actual sub-agents at runtime) — not part of this recipe's bar; see its own docstring |
| `subagent_middleware/` | The `adapters.langchain` recipe for LangChain 1.x's own agent-loop / deepagents subagent-as-tool pattern |
| `live_smoke.py` | Env-gated: the same node-level story against a real model (`RUN_LIVE=1`, costs money, not run by CI) |
| `../../../src/attenu_guard/adapters/langgraph.py` | The shipped adapter this recipe drives |
| `../../../tests/integrations/test_langgraph.py` | The adapter's own conformance suite (generic scenarios, not specific to this recipe) |
| `../../../tests/integrations/test_langgraph_recipe_demo.py` | Runnability plus the enforcement assertions for THIS recipe specifically — asserts `demo.main()` itself returns 0 |

Versions this was checked against: `langgraph` 1.2.11, `attenu-guard`
0.10.0, Python 3.12.

## License

This recipe is part of attenu-guard, licensed under the Apache License 2.0 —
see the repository's [`LICENSE`](../../../LICENSE) file for details.
