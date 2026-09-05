# The delegate contract, enforced

*A recipe for [anthropics/commerce-agents](https://github.com/anthropics/commerce-agents): one hook on
the executor's dispatch point that turns "a delegate cannot write, present, or invoke other delegates"
from a sentence into a decision, on a chain whose record verifies with the repo absent. Runs offline
with the repo's own scripted model client — no API key, no network.*

Every claim below about commerce-agents is stated against commit
[`fd4d592`](https://github.com/anthropics/commerce-agents/commit/fd4d59224ab96b43c6dc6888207c67b3bd5a24cf),
with the file and line it comes from. `tests/integrations/test_commerce_agents.py` re-checks each of
them against the installed package, so a claim that goes stale fails a test rather than sitting in
prose.

## Five-minute repro

commerce-agents is not on any package index — its own CI asserts that the seven names are
unregistered — so it installs from a clone:

```bash
git clone --depth 1 https://github.com/anthropics/commerce-agents.git
git clone --depth 1 https://github.com/attenu-io/attenu-guard.git
python3 -m venv .venv && . .venv/bin/activate
pip install -q -e ./commerce-agents/commerce-common \
               -e ./commerce-agents/merchant-agent/core \
               -e ./commerce-agents/merchant-agent/runtime-messages-api \
               -e ./attenu-guard
python attenu-guard/examples/integrations/commerce-agents/demo.py
attenu-guard verify ./attenu-commerce-bundle.json --hs256-key 64656d6f2d6b6579
```

The demo writes the bundle to the working directory, so run the last line from the same place (or
give it the path it printed). It is act 5 again, from the file alone, with nothing else installed.

```
integrity=True monotonicity=True containment=True anchor=verified nodes=4 actions_checked=8
OK
```

The tests need `pytest` and the same three editable installs:

```bash
python -m pytest -q attenu-guard/tests/integrations/test_commerce_agents.py
```

They skip, rather than fail, where commerce-agents is not importable — which is why this recipe is
not in attenu-guard's own CI matrix: every other integration installs its framework from PyPI, and
this one cannot.

## The contract, and what holds it today

`commerce-common/commerce_common/delegation.py:4-6` states it:

> A delegate receives a task brief and the session handles, never the conversation or the executor,
> and returns one schema-validated result; it cannot write, present, or invoke other delegates.

The first half is structural and holds: `DelegationContext` (`delegation.py:21-31`) carries the
backend, the config, the session and the state, and no executor. The second half is held by two
things that are not the dispatch point.

**The tool list.** `AnalysisRunner._build_tools` (`merchant-agent/runtime-messages-api/merchant_agent_runtime/analysis.py:117-139`)
puts only `ANALYSIS_READ_TOOLS` plus submit, progress and query on the delegate's surface, so its
model is never offered a write.

**A name test in the runner.** `AnalysisRunner._execute` (`analysis.py:348-375`) is a four-branch
ladder, in this order: the progress tool returns "Noted — continue the analysis." (`:355-360`); a
name in `ANALYSIS_READ_TOOLS` goes to `_read`, and therefore to an executor (`:361-362`); anything
that is not the SQL tool, or is the SQL tool where the backend does not support queries, comes back
as `Unknown tool in the analysis context` (`:363-364`); and what is left — the SQL tool on a backend
that supports it — goes to `_run_query`, and therefore straight to the backend, never through an
executor (`:365-375`). The third test is what keeps a write out, and it is a name check inside one
delegate's runner.

Both live inside the one delegate the repo ships. The executor that delegate builds does not share
them. `AnalysisRunner._read` (`analysis.py:332-339`) constructs an ordinary `MerchantToolExecutor`
with a scratch `MerchantSessionState`, and that object carries the full handler table — the five
`stage_*` tools, `apply_change` and `discard_change` (`merchant-agent/core/merchant_agent/executor.py:145-163`)
— plus the presentation components, which are a class attribute (`executor.py:93`) and are therefore
on every instance. Nothing at construction removes them. A second delegate whose author factors the
executor construction out of the turn loop, or passes the turn's delegate list along, gets writes,
presentation and nested delegation reachable through the same object.

Act 3 of the demo runs exactly that delegate with nothing installed. All three bodies execute:

```
    -- nothing installed --
      read    get_pending_changes        -> ran                [{"change_id": "chg-0001", "kind": "listing_update", "status": "staged", "summary": "R
      write   stage_price_update         -> ran                (fenced payload)
      present present_change_preview     -> ran                Displayed to the operator.
      nested  note_finding               -> ran                (fenced payload)
      side effects: staged=['chg-0002']  presented=['chg-0001']  peer_delegate_ran=True
```

`side effects` is the oracle, read from three places that are none of them the tool result.
`staged` is store-side: the difference in `ChangeLedger.pending()` across the call. `peer_delegate_ran`
is body-side: a flag the peer delegate's own `run` sets as its first statement. `presented` is
body-side too — `observing_presentation` swaps the component's `enrich` hook for one that records and
then calls the repo's own `enrich_change_preview`, and `run_presentation` awaits that hook
(`commerce_common/presentation.py:136`), so the id lands there only when the presentation body was
entered. The swap is restored afterwards and changes nothing else about the component.

## What this hook adds

| Question | commerce-agents today | With this hook |
|---|---|---|
| What may this delegate do? | Whatever its own runner routes onward | An `Authority` on a chain node, derived from the tools its surface declares |
| Can a delegate hold more than its caller? | Nothing compares them | No: `Guard.delegate` takes the meet, so child ⊆ parent by construction |
| Where is a refusal decided? | In each delegate's runner | On `BaseToolExecutor.dispatch`, before the body, for every delegate, through the `executor_class` seam |
| What is left afterwards? | Log lines | One hash-chained ledger; `attenu_guard.evidence.verify_bundle` checks integrity, monotonicity and containment from the file alone |
| Is the spending ceiling per-caller? | No: `max_campaign_budget` is one deployment number | Yes: a `SpendCap` per node, and a child's can be lower and never higher |

## The hook

`BaseToolExecutor.dispatch` (`commerce-common/commerce_common/execution.py:225-243`) is the one place
every tool call arrives. Two module docstrings say so between them: the executor frame's, that "the
Messages API runtime, the Agent SDK toolset, and the MCP server all call `execute`"
(`execution.py:4-8`), and the merchant executor module's, that those three "and the analysis
delegate's reads all execute through this class"
(`merchant-agent/core/merchant_agent/executor.py:4-8`; the class itself, at `:91`, carries no
docstring). `execute` (`execution.py:214-223`)
calls `self.dispatch`, and inside `dispatch` the presentation components, the presentation
extensions, the delegates and the handlers are each routed by name (`execution.py:236-243`) — so
replacing one instance attribute covers the whole surface on both entry points.

| Hook point | API used |
|---|---|
| **The deployment's executor — start here** | `guarded_executor_class(MerchantToolExecutor, policy, grants)` returns a subclass that authorizes in `dispatch`, and the repo already takes it: `executor_class` is documented as "the seam for a deployment's own `MerchantToolExecutor` subclass" (`merchant-agent/runtime-messages-api/merchant_agent_runtime/orchestrator.py:86-87`) and every consumption path accepts it. Nothing is patched. |
| One executor instance | `guard_executor(executor, guard, policy, grants)` replaces that instance's bound `dispatch`, for a call site that builds the executor directly. |
| Every executor, including ones out of reach | `install(policy, grants, root=...)` patches `BaseToolExecutor.dispatch`. This is a monkeypatch; see "Where the seam stops". |
| The delegation site | All three mint the child with `Guard.delegate` when a delegate name is dispatched, and bind it to a `contextvars` variable for the body's duration. |

The seam is not a convenience the repo happens to expose. Its own
`tests/test_consumption_paths.py::test_every_path_takes_a_deployments_own_executor_class` asserts
that the Messages API orchestrator, the Agent SDK toolset and the MCP server all take it, so a
guarded subclass is a supported deployment, not a workaround:

```python
Guarded = guarded_executor_class(MerchantToolExecutor, POLICY, GRANTS)
agent = MerchantAgent(backend=..., config=..., executor_class=Guarded)

root = Guard.issue("merchant-turn", OPERATOR_AUTHORITY, task="run the back office")
with authorize_as(root):
    async for event in agent.stream_turn(messages, session, state):
        ...
```

Only `dispatch` is overridden, so a deployment's own subclass — its `domain_error` mapping, its
wording — can be the base and keeps everything it defines.

That exact path is exercised, not just described: `test_the_real_orchestrator_takes_the_guarded_class`
runs a real `MerchantAgent` with `executor_class=Guarded` on the repo's own `FakeClient`, scripting a
search and then a price stage, and asserts both `ok` to the host, one change in the store and two
`allow` entries on the chain.

Register exactly one authorizer per executor: each is a complete authorization path, and two means
`check()` runs twice for the same call. Every guarded `dispatch` carries a mark, and each entry point
reads the dispatch a call would actually resolve before adding its own, so all four pairings are
refused with a message naming the class: `guard_executor` over an already-guarded instance **or over
an instance of a guarded class**; `guarded_executor_class` over a base that already authorizes,
including one whose `dispatch` is currently the installed hook; and `install` over a class that
already authorizes. A guarded class built *before* an `install()` is the one benign order and stays
allowed — it holds a direct reference to the dispatch it captured, so the later class patch is not in
its path; a test asserts one `allow` entry per call for it.

### Which guard authorizes a call

In order: the delegate body currently running, then the guard bound to the executor (`bind`, or
`guard_executor`), then the installed root. A dispatch that resolves to none of the three is held,
never allowed — an executor with no node is never a permissive one, which act 1 shows before it
opens the turn's scope. That first refusal is the one the demo prints but the bundle does not carry:
with no node bound there is nothing to record it on, so the screen shows six refusals and the ledger
five. The demo says so where it happens. `authorize_as(root)` is how a per-request chain gets to the head of that
order when the executor class was fixed at deployment time.

The first position is why `install()` reaches the shipped analysis delegate at all. The child guard
is bound around `await dispatch(...)` for the delegate call, so anything constructed inside that body
— including the `MerchantToolExecutor` the runner builds where no caller can reach it — authorizes as
the child. The binding is reset when the delegate returns, so the next tool call on the parent's
executor is the parent's again.

**Without `install()`, the shipped delegate's own reads are not on the ledger.** The `spawn` is: the
child is minted and recorded when `run_analysis` dispatches on the guarded turn executor. But the
executor the runner then builds is a plain `MerchantToolExecutor`, so its reads pass through
unguarded dispatch and nothing records them. A delegate whose runner uses the deployment's
`executor_class` — one you write — is enforced without `install()`.

### Deriving what a delegate holds

```python
grant = DelegateGrant.from_tools(
    "analysis",
    [t for t in ANALYSIS_READ_TOOLS if t != "get_campaign_performance"],
    POLICY, ttl=900)
```

The scopes come from the tools the delegate's own surface declares, mapped through the same policy
the executor authorizes against; the operator's decision is which of them to withhold.
`Guard.delegate` then takes the meet with the parent's authority, so a grant that asks for more than
the parent holds yields the parent's — the `spawn` entry records the request and the grant side by
side, and the offline verifier re-checks child ⊆ parent from those two fields.

That per-delegate narrowing has no equivalent upstream today. The only lever is
`MerchantAgentConfig.enable_campaigns`, and `config.absent_tools()`
(`merchant-agent/core/merchant_agent/config.py:202-220`) removes `get_campaign_performance` from the
operator's surface at the same time.

Act 2 runs the real `AnalysisRunner` against the repo's own `FakeCreateClient`:

```
      ANALYSIS_READ_TOOLS declares : ['get_business_snapshot', 'query_metrics', 'get_campaign_performance', 'search_listings']
      the operator grants          : ['listing.read', 'metrics.read']
      delegate run_analysis              -> ran                (fenced payload)
      node commerce-demo:n0 merchant-turn scopes=['campaign.*', 'change.*', 'delegate.*', 'inventory.*', 'listing.*', 'memory.*', 'metrics.*', 'order.*', 'present.*', 'pricing.*']
        node commerce-demo:n1 analysis   scopes=['listing.read', 'metrics.read']
      DENY  node=commerce-demo:n1 scope=campaign.read tool=get_campaign_performance reason=scope_not_granted disposition=out_of_authority
```

**One thing to know about a held call inside a delegate.** `AnalysisRunner._read` returns
`(outcome.result_text, outcome.is_error)` (`analysis.py:346`) and drops `ToolOutcome.blocked`, so a
held call reaches the delegate's model as an ordinary tool result rather than an error. The same is
true of the repo's own provenance and guardrail gates. The body still never ran and the denial is
still on the ledger; only the delegate's model sees it as prose.

### The three the contract forbids

Act 3, the same delegate, this time with `install()` active:

```
    -- attenu-guard installed --
      read    get_pending_changes        -> ran                [{"change_id": "chg-0001", "kind": "listing_update", "status": "staged", "summary": "R
      write   stage_price_update         -> HELD[authority]    That call is outside this agent's authority: denied: scope_not_granted requested=prici
      present present_change_preview     -> HELD[authority]    That call is outside this agent's authority: denied: scope_not_granted requested=prese
      nested  note_finding               -> HELD[authority]    That call is outside this agent's authority: denied: scope_not_granted requested=deleg
      side effects: staged=none  presented=none  peer_delegate_ran=False
```

A refusal is a `ToolOutcome.held("authority", ...)`, the repo's own shape for a gated call
(`commerce_common/streaming.py:156`), so a host that already renders `merchant_agent.gates`'
provenance and guardrail holds renders this one unchanged. It is not an exception: nothing in the
turn loop needs a new `except`.

### Ceilings

`MerchantAgentConfig.max_campaign_budget` (`config.py:57`, default 10,000) is checked by
`check_guardrails` when a change is staged and again before it is applied
(`merchant-agent/core/merchant_agent/changes.py:101-107`, `changes.py:151` and `changes.py:191`). It is one
number for the deployment, and a delegate holds the same config object, so a delegate that reaches
`stage_campaign` is measured against the operator's own limit.

Put it on the root node as a `SpendCap` and it becomes per-node. Act 4:

```
      config.max_campaign_budget = 10,000  (merchant_agent/config.py, checked at stage and again at apply)
      the draft asks for         = 5,000
      operator stage_campaign            -> ran                (fenced payload)
      drafter  stage_campaign            -> HELD[authority]    That call is outside this agent's authority: denied: ceiling_exceeded constraint=max_s
```

The store's own guardrail passes 5,000 for both. The chain holds it for a child capped at 2,000. A
child that asks for `SpendCap(50_000)` gets the parent's 10,000, because the meet takes the minimum.

### The record

```
      entries: 17   bundle: attenu-commerce-bundle.json
      verify_bundle -> ok=True  checks={'integrity': True, 'monotonicity': True, 'containment': True, 'anchor': 'verified', 'version': True, 'chain_id': True, 'root': True, 'expected_anchor': 'not checked', 'envelopes': 'not present'}

      the chain, read back from the file alone:
        commerce-demo:n0   merchant-turn     allows=5   denies=0  
        commerce-demo:n1   analysis          allows=1   denies=1    under commerce-demo:n0
        commerce-demo:n2   report            allows=2   denies=3    under commerce-demo:n0
        commerce-demo:n3   campaign-drafter  allows=0   denies=1    under commerce-demo:n0
```

`verify_bundle` is not a re-run of the guard: it reconstructs each node's authority from the `root`
and `spawn` entries and re-checks child ⊆ parent, then checks every `allow` against the authority its
node actually held. Monotonicity is a real check, not a formality — the demo ends by rebuilding the
same ledger with one child's grant widened by a scope the parent never held, re-hashing and
re-signing it, which is what an insider holding the key could produce:

```
        integrity=True  monotonicity=False  anchor=verified  ok=False
        monotonicity: commerce-demo:n1 not ⊆ parent commerce-demo:n0 (child scopes ['billing.refund', 'listing.read', 'metrics.read'] not held by parent)
```
## Where the seam stops

**commerce-agents does not take contributions.** Its README says so in the licence section
(`README.md:193`): *"This is a reference implementation; it is not maintained and does not accept
contributions."* Nothing below is a pull request or a proposal to anyone. It is the precise statement
of where the deployment's own seam ends, for a reader who vendors the packages, forks them, or is
building the same shape themselves.

`executor_class` is that seam, and it holds on every consumption path: the Messages API orchestrator
(`orchestrator.py:101`, used at `:165`), the Agent SDK toolset
(`merchant-agent/runtime-agent-sdk/merchant_agent_sdk/merchant_tools.py:77`, used at `:81`) and the
MCP server (`merchant-agent/managed-agents/merchant-mcp-server/merchant_mcp_server.py:96`, used at
`:129`). Upstream's own `test_every_path_takes_a_deployments_own_executor_class` holds all three to
it.

One consumption path does not carry it. `AnalysisRunner._read` names `MerchantToolExecutor` inside
the method (`analysis.py:333-339`) and keeps no reference outside it, so the deployment's executor
stops at the delegate's own reads. That is the whole reason `install()` exists in this recipe: a
monkeypatch is the only thing that reaches an instance nobody hands out.

It is one of exactly two non-test constructions of that class in the repo. The other is the demo web
host at `examples/demo_common/merchant.py:248`, which builds an executor for the portal's approval
buttons; that is an example site rather than a path the library offers, and a deployment that copies
it passes its own class the same way every other path does.

Carrying the same parameter one level further closes it. The patch below is verified, not sketched:
it applies to the clone at `fd4d592` with `git apply`, their own `test_analysis.py` stays at 31
passing with it applied, and with it applied `guarded_executor_class` alone enforces the shipped
delegate's reads — the child's `query_metrics` allowed and its `get_campaign_performance` denied,
with no `install()` anywhere.

```diff
--- a/merchant-agent/runtime-messages-api/merchant_agent_runtime/analysis.py
+++ b/merchant-agent/runtime-messages-api/merchant_agent_runtime/analysis.py
@@ -83,10 +83,15 @@ def present_analysis(result: BaseModel, context: DelegationContext) -> tuple[Any
 
 
 def build_analysis_delegate(
-    client: AsyncAnthropic, backend: MerchantBackend, config: MerchantAgentConfig
+    client: AsyncAnthropic,
+    backend: MerchantBackend,
+    config: MerchantAgentConfig,
+    executor_class: type[MerchantToolExecutor] = MerchantToolExecutor,
 ) -> DelegateExtension:
     definition = build_analysis_tool_definition()
-    runner = AnalysisRunner(client=client, backend=backend, config=config)
+    runner = AnalysisRunner(
+        client=client, backend=backend, config=config, executor_class=executor_class
+    )
     return DelegateExtension(
         name=ANALYSIS_TOOL,
         description=definition["description"],
@@ -105,11 +110,17 @@ class AnalysisRunner:
     """Builds the delegate's tool surface once per deployment and runs one loop per call."""
 
     def __init__(
-        self, *, client: AsyncAnthropic, backend: MerchantBackend, config: MerchantAgentConfig
+        self,
+        *,
+        client: AsyncAnthropic,
+        backend: MerchantBackend,
+        config: MerchantAgentConfig,
+        executor_class: type[MerchantToolExecutor] = MerchantToolExecutor,
     ) -> None:
         self._client = client
         self._backend = backend
         self._config = config
+        self._executor_class = executor_class
         self._system = build_analysis_system_prompt(config)
         self._sql_supported = backend_supports_analysis_query(backend)
         self._tools = self._build_tools()
@@ -330,7 +341,7 @@ class AnalysisRunner:
     ) -> tuple[str, bool]:
         # A scratch state keeps listing and campaign ids out of the session's gates.
         scratch = MerchantSessionState()
-        reads = MerchantToolExecutor(
+        reads = self._executor_class(
             backend=self._backend,
             config=self._config,
             skills=SkillRegistry([]),
--- a/merchant-agent/runtime-messages-api/merchant_agent_runtime/orchestrator.py
+++ b/merchant-agent/runtime-messages-api/merchant_agent_runtime/orchestrator.py
@@ -111,7 +111,11 @@ class MerchantAgent:
         self.extra_presentation_tools = tuple(extra_presentation_tools)
         self.extra_delegates = tuple(extra_delegates)
         built_in = (
-            [build_analysis_delegate(self.client, self.backend, self.config)]
+            [
+                build_analysis_delegate(
+                    self.client, self.backend, self.config, self.executor_class
+                )
+            ]
             if self.config.enable_analysis
             else []
         )
```

The `AnalysisRunner.__init__` hunk is not optional: upstream's signature is keyword-only
`client`/`backend`/`config` (`analysis.py:107-109`) and it never sets `self._executor_class`, so the
`_read` change alone raises `TypeError` at construction and `AttributeError` at the read.

Nothing here is only about authorization. Metering, tracing and a deployment's own error wording all
stop at the same line, because they all arrive through the same subclass.

Until a reader applies it, `install()` is the only way to guard an executor a delegate constructs
internally, and the tests cover both paths.
## What is not covered

- **The shopping agent has no delegates.** `shopping_agent`'s executor
  (`shopping-agent/core/shopping_agent/executor.py:115-128`) registers eleven handlers and no
  `DelegateExtension`; the delegate contract is exercised only on the merchant side today. The hook
  is on the shared base class, so it guards a shopping executor's tools the same way, but there is
  no delegation to attenuate there yet.
- **The hosted code-execution sandbox.** With `analysis_use_code_execution` on, the delegate's read
  tools carry `allowed_callers: [code_execution_20260120]` (`analysis.py:134-138`) and the sandbox
  calls them server-side. Those calls do not pass through `dispatch` in this process, so this hook
  does not see them. The demo turns the flag off, which is also what keeps it offline.
- **Anything outside the executor.** A delegate that calls `self._backend` directly, as
  `AnalysisRunner._run_query` does for SQL (`analysis.py:377-394`), bypasses `dispatch` and therefore
  this hook. Guarding that path means guarding the backend, which is a different recipe.
- **Execution binding.** This recipe runs a `schema_version=1` chain: every allow and deny is on the
  ledger, but no `call_id`, params commitment or `record_outcome`. So an `allow` means the call was
  authorized, not that the body ran — the repo's own `absent_tools` check (`execution.py:232-233`)
  and its provenance and guardrail gates all run *after* this hook. Measured, not inferred:
  `test_an_allow_means_authorized_not_executed` stages a price without a prior search through the
  real orchestrator, and the same turn produces one `allow` for `pricing.stage` on the chain and a
  `tool_result` carrying `status: "blocked"`, `reason: "provenance"` to the host, with nothing
  written to the store. attenu-guard's shipped adapters (`attenu_guard.adapters.*`) carry the v2
  wiring that closes that gap.
- **A role that overrides `dispatch`.** `install()` patches the base class. No executor in the repo
  overrides `dispatch` today (only `handlers`, `memory_subject` and `domain_error` are role hooks),
  but one that did would shadow the patch. `guarded_executor_class` over that subclass, or
  `guard_executor` on the instance, still works.

## Files

| File | What it is |
|---|---|
| `attenu_commerce.py` | The paste-in adapter. Imports nothing from commerce-agents at module load. |
| `demo.py` | Five acts, offline. Also carries the demo store, a `MerchantBackend` over the repo's own `ChangeLedger`. |
| `../../../tests/integrations/test_commerce_agents.py` | The gate: compatibility, the pinned upstream facts, the side-effect oracle, the fail-closed edges. |
