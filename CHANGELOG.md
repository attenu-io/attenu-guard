# Changelog

All notable changes to attenu-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Execution binding (`record_outcome`, 0.9.0) wired into six more adapters, on a
  `schema_version=2` chain (unchanged, byte-and-type identical to before, on `schema_version=1`),
  each choosing the most honest capture its framework's real hook surface supports:
  - `adapters.crewai`: `Capture.FRAMEWORK_POST_HOOK` -- the bridge never calls the tool body
    itself; the outcome is closed out from CrewAI's own `after_tool_call` post hook, which fires
    for every dispatch path including a blocked call. `BodyState.RAISED` is never reported: CrewAI's
    `ToolUsage.use`/`ause` catches every tool exception internally and turns it into a formatted
    string before the post hook ever runs, so a raise and an ordinary return are indistinguishable
    at the one hook point this adapter has.
  - `adapters.openai_agents`: `Capture.FRAMEWORK_POST_HOOK` via a second guardrail,
    `ToolOutputGuardrail`, added alongside the existing `ToolInputGuardrail`; the two correlate
    through the SDK's own `tool_call_id`. Same honesty limit as CrewAI: the SDK's default
    `failure_error_function` catches a tool's exception inside `on_invoke_tool`, before the output
    guardrail runs, so `BodyState.RAISED` is unreachable under default configuration; with
    `failure_error_function=None` the exception propagates past the output guardrail entirely and
    that call's outcome is simply never recorded (the hook structurally never fires for it).
    `guarded_agent_tool()`'s delegation-scope check and `guarded_handoff()`/`DelegationGuardHooks`
    mint via `Guard.delegate()`, not a tool body, so they stay the library's default `pre_hook_only`.
  - `adapters.google_adk`: `Capture.FRAMEWORK_POST_HOOK`, and the richest of the six -- ADK's
    `BasePlugin` offers a real error hook (`on_tool_error_callback`) alongside the success one
    (`after_tool_callback`), and does NOT swallow a tool's exception before it runs, so this is
    the one adapter of the six that genuinely observes and reports `BodyState.RAISED` (with
    `error_code`), no honesty caveat needed. The two hooks correlate their pending state with
    `_authorize()`'s `check()` via `id(tool_context)` -- ADK threads one `ToolContext` per call
    through before/after/error uniformly. Applies uniformly to both the tool check and the
    delegation-scope check (`delegation_scope=...`), since both go through `_authorize()` and
    both are real ADK tool calls with the same before/after/error lifecycle.
  - `adapters.pydantic_ai`: `Capture.WRAPPER_ASYNC` at BOTH hook points -- unlike the framework-post-hook
    adapters above, this one calls the tool body itself and awaits it, like `adapters.langgraph`'s
    reference wiring. `DelegationGuard` authorizes in `before_tool_execute` (unchanged shape on
    `schema_version=1`) and closes the outcome out in `AbstractCapability.wrap_tool_execute`,
    correlated by `id(call)` (the same `ToolCallPart` flows through both for one call).
    `GuardedToolset.call_tool` needs no such correlation -- it already calls
    `self.wrapped.call_tool(...)` directly, so authorization and capture live in one method. Both
    genuinely observe and report `BodyState.RAISED` (pydantic-ai does not swallow a tool's
    exception before either hook runs) and `BodyState.ABANDONED` on `asyncio.CancelledError`.
  - `adapters.haystack`: `Capture.WRAPPER_SYNC`/`Capture.WRAPPER_ASYNC` on hook 2
    (`guard_tool`/`guard_tools`) -- `_Guarded.invoke`/`invoke_async` call `super().invoke`/
    `invoke_async` themselves, exactly like `adapters.langgraph`'s reference wiring. Haystack's
    `Tool.invoke`/`invoke_async` re-raise the body's own exception as a `ToolInvocationError`
    with the original set as `__cause__`, which this adapter unwraps for an honest `error_code`
    (`_underlying_error_code`) rather than reporting `ToolInvocationError` itself, an artifact of
    Haystack's own plumbing. A delegation tool mints via `guard.delegate()`, never calls
    `guard.check()` for itself, so it never binds an outcome. Hook 3 (`AttenuationStrategy`) is
    NOT wrapped -- it can veto a pending call but never touches the tool body, which the
    framework calls afterward entirely outside the hook -- so its checks stay the library's
    default `pre_hook_only`, unchanged.

## [0.9.0] — 2026-08-31

### Fixed
- Integers beyond the RFC 8785 safe range (±(2**53-1)) are now rejected — at canonicalization, at
  `RowLimit`/`SpendCap`/`CallLimit` construction, and by `wire.load` (as `malformed`) — instead of
  silently colliding with a neighbouring integer once rendered through binary64. A tenth reject
  vector, `reject_unsafe_integer.json`, brings the interop suite to 20.
- `evidence.verify_bundle` and `AuditLog.verify_anchor` now check the bundle/anchor schema version
  and chain identity instead of ignoring them, so a bundle for the wrong version or the wrong chain
  no longer verifies.

### Added
- `AuditLog.append` now raises `CommittedAuditError` (carrying the committed `entry`) if persisting
  an entry fails after it was already committed to the in-memory chain — the file write or a sink
  raising no longer looks the same as nothing having been recorded. The entry stays committed;
  callers must not retry the call that produced it on the strength of this error alone.
- **Execution binding**, opt-in per chain via `Guard.issue(..., schema_version=2)` (schema version 1
  is unchanged and remains the default): `check()`/`record_denial()` now allocate a `call_id`
  (fail-closed, with meters restored, if the CSPRNG fails) and return it on `Decision.call_id`;
  `check()` gains `authorized_params`/`capture`/`adapter` and refuses further calls once the node
  is `complete()`d (`ReasonCode.NODE_FINALIZED`). `Guard.record_outcome(call_id, body_state, ...)`
  binds what a body-owning wrapper observed afterwards — `returned`/`raised`/`abandoned`/`deferred`,
  with `error_code` required exactly when raised. On a `schema_version=2` chain, `complete()`
  returns a bool-coercible `CompletionResult` and refuses while calls are pending; on
  `schema_version=1` it still returns a plain `bool`, byte-and-type identical to every release
  before 0.9.0. `revoke()`/`revoke_agent()` snapshot still-pending call_ids onto the `kill` entry
  as `pending_at_kill` — atomically, under one hold of the chain lock, together with the
  revocation itself and (in `check()`) with `complete()`'s own check-pending-then-append sequence
  — without clearing them, so a late `record_outcome()` after a kill is still accepted. Every
  pre-commit `check()`/`record_outcome()` failure (not only CSPRNG exhaustion) rolls back its
  meters/bookkeeping. Arguments are committed via `params_c14n_v1` (`attenu_guard.params`):
  `SHA-256(raw_salt || JCS(params))`, never the raw value — closing, for this profile only, the
  one gap the shared JCS canonicalizer leaves open for out-of-range integral floats, without
  changing that canonicalizer's own behaviour elsewhere. `evidence.verify_bundle` gains
  `execution_binding`: per-call observed/unobserved/unaccounted (an outcome counts as observed
  only once it is bound correctly — right node, right order), per-node
  finalized/in_progress/revoked_with_pending, an aggregate clean/incomplete/failed, and
  `params_coverage` (computed over every call, not only those with an outcome) as its own axis —
  `not applicable` for a schema-version-1 bundle. `verify_bundle` also rejects a rootless bundle
  and accepts an optional independently retained `expected_anchor`/`expected_head`, so a rewritten
  bundle whose own (self-consistent) anchor cannot be relied on is still caught. The LangGraph
  adapter (`adapters.langgraph`) is the reference wiring: `guard_node`/`DelegatedToolNode` call
  `record_outcome` on a `schema_version=2` guard, sync and async, from an immutable
  pre-invocation argument snapshot (a callable that mutates its own inputs cannot cause a false
  params mismatch), with generators/futures reported `deferred` and `asyncio.CancelledError`
  reported `abandoned`. Schema and verifier are event- and version-aware and strict: a v2 allow
  REQUIRES `capture`/`adapter` (`Guard.check()` supplies `pre_hook_only` plus a guard-attributed
  adapter when the caller passes neither — a bare `check()` IS itself pre_hook_only observation,
  never merely absent), `deny` FORBIDS every allow-only field, and a v1 entry FORBIDS every
  v2-only field (including `call_id` — v1 never allocates one); `tests/test_execution_binding.py`
  runs in CI. A language-neutral `params_c14n_v1` parity vector file
  (`tests/vectors/params_c14n/params_c14n_v1.json`, consumed by `tests/test_params_c14n_vectors.py`)
  covers its accepted/rejected numeric boundaries and salt handling; the TypeScript consumer of
  this same file is being built on `attenu-guard-ts` (`feat/090-execution-binding`) — parity
  between the two is a release gate for 0.9.0, not deferred work.

### Changed
- Behaviour change: constructing an `AuditLog` (or `Guard.issue`) with a `path`/`audit_path` that
  already names a non-empty file now raises `FileExistsError` instead of silently truncating it.
  Pass `overwrite=True` (`Guard.issue(..., audit_overwrite=True)`) to keep the old reset-on-open
  behaviour where that is what you want.

## [0.8.0] — 2026-08-29

### Changed
- Scope values now use one interoperable grammar: lowercase dot-separated
  segments, with `*` permitted only as the complete final segment after a dot.
  A terminal wildcard covers any depth below that segment boundary, but not the
  bare prefix or an adjacent namespace. Constructors and wire verification
  reject malformed scope syntax.

### Added
- `reject_bare_wildcard.json` and `reject_nonterminal_wildcard.json` bring the
  interop suite to 19 vectors and pin malformed wildcard forms to the
  `malformed` wire reason.

## [0.7.1] — 2026-08-29

### Changed
- `c14n` is informational; producers still emit it, while verifiers enforce RFC 8785 JCS from canonical bytes and hashes regardless of the label.

## [0.7.0] — 2026-08-29

### Changed — BREAKING
- **All signed and hash-linked artifacts now use RFC 8785 JCS exclusively.** Delegation
  tokens declare `"c14n":"JCS"`; their protected header and payload must already be
  canonical JCS bytes. Audit entries, integrity seals, anchors, and evidence bundles use
  the same canonicalizer and carry the same marker where the artifact has metadata.
  Duplicate object members, non-finite numbers, lone surrogates, unmarked tokens, and
  non-canonical encodings are rejected. The interop suite now contains 17 vectors,
  including all six known Python/ECMAScript divergence classes. There is no legacy or
  dual-format reader.

### Added
- **A ninth interop test vector, `reject_wildcard_boundary.json`** (`"expect_reject_reason":
  "not_narrower"`), shipped in both copies and in the installed package. The leaf claims
  `crmx.read` under a root holding the wildcard `crm.*` — a scope that shares the wildcard's
  letters but not its segment boundary. `crm.*` covers `crm.` followed by anything, so
  `crmx.read` is a different namespace and no ancestor grants it. It closes the half the eighth
  left open: `reject_wildcard_widening.json` pins the DIRECTION of the wildcard rule, and this
  pins its REACH. An independent verifier that implements the wildcard by stripping the `.*` and
  testing `startswith("crm")` accepts the neighbouring namespace — the sloppy-prefix bug an
  attacker uses to step sideways into the namespace next door — and so scored 8/8 while being
  exploitable; it now fails a vector instead of shipping. The reference implementation already
  rejected it (it strips only the `*` and keeps the dot); this is coverage, not a fix.

## [0.6.1] — 2026-08-29

### Added
- **An eighth interop test vector, `reject_wildcard_widening.json`** (`"expect_reject_reason":
  "not_narrower"`), shipped in both copies and in the installed package. The leaf's scopes are
  replaced with the wildcard `crm.*` while its parent holds only the concrete `crm.read`, so the
  leaf claims strictly more than any ancestor ever held. It pins down the direction of the
  wildcard rule, which the existing seven left implicit: `valid_chain.json` shows a concrete
  `crm.read` sitting legitimately under a `crm.*` parent, and this is that turned round. An
  independent verifier that tests only whether a parent scope and a child scope are
  wildcard-*compatible*, rather than which side is the broader one, accepts both directions and
  lets a leaf hand itself `crm.export` — it now fails a vector instead of shipping. The reference
  implementation already rejected it; this is coverage, not a fix.

## [0.6.0] — 2026-08-28

### Added
- **The interop test vectors ship inside the package** as `attenu_guard.vectors`
  (`VECTOR_NAMES`, `load_vector`, `load_vectors`, `read_vector_bytes`, read through
  `importlib.resources`). The Internet-Draft promises a chain that MUST verify and six that
  MUST each be rejected for a named reason, so that an implementation written in ANY language
  from the draft alone can score its own offline verifier; shipping them means doing that needs
  `pip install attenu-guard` and no clone. `tests/vectors/generate.py` is the single writer for
  both copies — it serialises each vector once and writes those bytes to `tests/vectors/` and
  `src/attenu_guard/vectors/` — and `tests/test_wire.py` asserts the two are byte-identical, so
  they cannot diverge. A CI step verifies they survive an install, not just a checkout.
- **A2A adapter** (`attenu_guard.adapters.a2a`, extra `a2a`, tested against `a2a-sdk` 1.1.2): carries the attenuated
  delegation chain across an Agent2Agent hop, so a remote agent in another process runs with permissions bounded by the
  calling agent's. Two halves on public seams — client side, a `DelegationInterceptor` (`ClientCallInterceptor.before`)
  mints the child with `parent.delegate(...)` and puts the signed Delegation Chain (`attenu_guard.wire`) on the outgoing
  message as an A2A **extension** (`Message.extensions` + `Message.metadata[<uri>]`, spec §4.6.2, with the
  `A2A-Extensions` header §4.6.1); server side, `GuardedAgentExecutor` wraps the deployment's `AgentExecutor.execute`,
  verifies the chain offline (`wire.load`: signatures, parent-hash linkage, depth, child ⊆ parent at every hop, expiry)
  and mints the served `Guard` from the verified leaf, narrowed again by what the remote task needs. A missing, forged,
  spliced, widened or expired chain — or any exception raised while deciding — refuses the request before the remote
  agent's own logic starts, returning the denial contract in the extension's metadata slot. `guarded_tool(fn, scope=…)`
  checks before each tool body; `require_guard()` refuses a tool reached outside the executor. `verify_hop(tokens,
  signer, client_bundle=…, server_bundle=…)` checks the caller's ledger, the remote ledger and the tokens that bind them
  from those inputs alone, and reports an unsupplied bundle as "not checked" rather than as passing. This answers A2A
  §7.6.4, which states that the protocol defines no scope, validity or revocation semantics for an in-task authorization
  decision. Cross-process revocation propagation remains open: an expired chain is refused and `revocation_check=` is the
  seam for a status list, both documented as limits. Example (offline demo plus a `live_smoke.py` verified over a real
  Starlette/uvicorn HTTP hop) and 35 offline tests; seventeenth entry in `docs/INTEGRATIONS.md`.

## [0.5.0] — 2026-08-27

### Added
- **Haystack adapter** (`attenu_guard.adapters.haystack`, extra `haystack`, tested against `haystack-ai` 3.1.0): guards deepset Haystack `Agent`s and pipelines through `Tool.invoke`/`invoke_async` (a subclass of each tool's own class, so `ComponentTool`/`AgentTool` identity and the `inputs_from_state`/`outputs_to_string` machinery are untouched), mints the child `Guard` at the `AgentTool` call, and offers Haystack's own `before_tool` `ConfirmationHook` as an alternative denial path. Denials raise a `ToolInvocationError` subclass, so the Agent's existing `raise_on_tool_invocation_failure` decides between "tell the model" and "stop the run". Parent tracking is a `ContextVar`, so parallel delegations in one model turn are siblings, not a chain. Example + 26 offline tests; 13th framework in `docs/INTEGRATIONS.md`.
- **Two new framework adapters, both AutoGen successors.** `attenu_guard.adapters.agent_framework` for **Microsoft Agent Framework** 1.15 (the AutoGen + Semantic Kernel successor) — `DelegationGuard(FunctionMiddleware)` gates every tool body through the one seam the framework's function-invocation loop can reach, and the same hook mints the child `Guard` at `Agent.as_tool()` and `handoff_to_<target>` calls; denials come back as a `function_result`, or as `MiddlewareFailure` (`on_deny="failure"`) for a fail-closed abort. `attenu_guard.adapters.ag2` for **AG2** 1.0 (the AutoGen fork, a rewrite around the `ag2` package) — `DelegationGuard(BaseMiddleware).on_tool_execution` gates the tool body and the `task_<agent>` delegation call, plus `guarded_tools()` / `guard_tool_hook()` for per-tool middleware, the only hook that reaches a child AG2 constructs itself from `tasks=TaskConfig(...)`. Install with `pip install 'attenu-guard[agent-framework]'` / `'attenu-guard[ag2]'`. Offline demos under `examples/integrations/{agent_framework,ag2}/` and 36 tests under `tests/integrations/`; matrix rows in `docs/INTEGRATIONS.md`.
- Supply chain: every release now carries SLSA build provenance (sigstore attestation via `actions/attest-build-provenance`); OpenSSF Scorecard runs weekly and on push; a `.pre-commit-hooks.yaml` exposes `attenu-guard verify` as a pre-commit hook for committed evidence bundles.

### Fixed
- Adapter docstrings still referred to the pre-rename paste-in module names (`dg_google_adk`, `dg_crewai`, `dg_smolagents`, `dg_llama_index`) and said "paste/copy this file"; they now name the packaged modules (`attenu_guard.adapters.<name>`) and the matching extras.

## [0.4.1] — 2026-08-26

### Fixed
- README: the install block still said "pre-publish… once published to PyPI"; the package has been on PyPI since 0.4.0. It now reads `pip install attenu-guard`.

### Changed
- Packaging: PyPI classifiers, `Documentation` / `Issues` / `Changelog` project URLs, and a summary aligned with the project description. No code changes.

## [0.4.0] — 2026-08-24

### Changed — BREAKING
- **Renamed: `delegation-guard` → `attenu-guard`.** Distribution `attenu-guard`, module `attenu_guard`, CLI `dg` → `attenu-guard`. Versions before 0.4.0 were published under the old name; nothing else in the API changed in the rename itself. Everything below was unreleased 0.3.0 work and ships here.


Driven by integration PoCs against twelve real agent frameworks
(`examples/integrations/`, `docs/INTEGRATIONS.md`): the library integrated
**unmodified** everywhere; what follows is what those integrations asked for.

### Fixed
- **Google ADK adapter: parallel delegations were chained, not fanned out.** When one
  model turn issued several `AgentTool` calls (ADK runs them concurrently), "parent =
  the last active agent" minted child 2 from child 1. The delegating agent is now
  recorded at the tool call and used as the parent when the child starts. Safe
  direction before (authority only shrank), wrong topology. Found by sampling.
- **Thread-safety under parallel tool calls.** Frameworks execute an agent's
  parallel tool calls on thread pools; concurrent `check()`s could interleave the
  audit hash-chain append (`verify()` then rejected the library's own log) and
  log out of sequence. The audit log, sequence clock and chain mutations are now
  serialised per chain; `ts`/`seq` advance atomically.
- **`strict_metering=True` failed open on a partial context.** Only an entirely
  empty context was refused; a context that declared some dimensions but omitted
  a held metered ceiling's field silently skipped that ceiling. Strictness is now
  per ceiling: a metered call must declare every metered dimension the node holds
  (`ceilings.ctx_field_of`, `ceilings.is_metered`; built-ins carry `ctx_field`).
- `tests/test_langgraph_adapter.py` asserted that langgraph was *not installed*
  (a statement about the machine, not the module); it now asserts the actual
  guarantee — importing the adapter does not import langgraph.

### Added
- **`deny` ledger entries carry a `disposition` — held is not over-reach.** `Guard.check(..., disposition=)` and
  `Guard.record_denial(..., disposition=)` accept a `Disposition` value (`held_pending_grant` · `withheld_tier2` ·
  `unresolved` · `out_of_authority`); a plain `scope_not_granted` deny the caller did not explain records
  `out_of_authority` (the shim's own truth); unknown values are refused before anything reaches the ledger; `allow`
  entries never carry it. `Disposition` is exported; `evidence.LEDGER_FIELDS` and `schema/agent-audit.schema.json`
  gained the field so a strict export still passes. Closes the threat model's "held pending curation must render
  distinct from denied" item at the ledger, where every UI reads it.
- **`evidence.denials(bundle)`** — deny events grouped by (node, tool, scope, disposition) with counts and first/last
  seq: the rows a Decisions queue renders, as a pure fold over the ledger; `delegation_graph` nodes gain
  `denials_by_disposition`.
- **Disposition contract across all 12 adapters** (`ToolPolicy` / `ToolAuthority` / `ScopeRequest` fields and the
  `guarded_tool` / `guard_node` / `GuardedTool` kwargs), passed to `Guard.check`; the ADK denial dict returned to the
  model carries `disposition`. **Undeclared tools now land on the ledger** as `unresolved` via
  `Guard.record_denial` in every policy-map adapter (previously only in the adapter's memory / an exception).
  `tests/test_adapters_contract.py` pins the contract stdlib-only in CI.
- **`delegation_guard.identity`** — a product has an identity before it has a key: `.attenu/product.json`
  discovery (`ATTENU_PRODUCT_DIR` or walk-up), per-process `boot_id()`, assigned `new_chain_id()`, and
  `ledger_path` / `spool_path` under the product dir.
- **`AuditLog(sinks=...)` + `sinks.SpoolSink`** — local-file sinks fed after the ledger write (never the network);
  the spool is a separate append-only file (a new AuditLog never truncates it), bounded, flushed per line,
  fsync'd every N + on `flush()`, resumable (`read_pending` / `ack`), and every line carries the ingest
  idempotency key (boot_id, chain_id, seq, hash). `Guard.issue(audit_sinks=)`.
- **`wire.Ed25519Verifier`** — public-key-only verification for consoles/auditors/ingest (cannot sign);
  `Ed25519Signer.private_bytes_raw()` / `from_private_bytes()` for key files.

- **`Guard.is_descendant_of(other)`**; the **Google ADK adapter treats `transfer_to_agent` back to an ancestor as a
  return**, not a delegation: no `agent.delegate.<ancestor>` check, the returning child is marked `done`, control
  moves up (found live on a 21-agent app where the planner transferred back to root and was denied).
- `evidence.delegation_graph` names a disposition-less deny by its reason (`revoked`, `ceiling_exceeded`).

### Changed
- Version 0.3.0 (ledger schema gains an optional `disposition` field on deny; wire and hash chain unchanged).
- `ReasonCode.NO_AUTHORITY` — the principal holds no Authority in this chain
  (adapter-level: undelegated agent, unmapped tool, unparseable args).
- `Guard.record_denial(reason, message, *, scope, tool, context)` — put an
  adapter-level refusal on the audit trail as a schema-conformant `deny` event.
- `Guard.agent_id`, `Guard.is_revoked`, `Guard.is_expired` (read-only).
- `Guard.revoke_agent(agent_id)` — principal-scoped, chain-wide revocation with a
  grow-only ban (`AuthorityError` reason `agent_banned` on any later `delegate()`),
  closing the re-delegation bypass found by the Strands/OpenAI-SDK integrations.
- `Guard.would_delegate(agent_id, request)` — pure dry-run of the delegation
  preconditions (`Chain.delegation_error`), no node, no fanout, no audit write.
- `AuditLog.__iter__` / `__len__`.
- **Framework adapters shipped in the package** as `delegation_guard.adapters.<name>`
  with per-framework extras (`pip install 'delegation-guard[crewai]'` …): `langchain`
  (LangGraph `ToolNode` / LangChain `create_agent` / deepagents), `openai_agents`,
  `google_adk`, `pydantic_ai`, `crewai`, `autogen`, `claude_sdk`, `smolagents`,
  `strands`, `llama_index`, `semantic_kernel`, `agno` — plus the existing
  `langgraph` node adapter. Each has an offline demo (`examples/integrations/`)
  and a test (`tests/integrations/`, 213 tests) using the framework's own mock
  model; CI matrix per framework. `docs/INTEGRATIONS.md` documents hooks,
  versions and what each framework enforces itself.
- **Scoped call ceilings**: `CallLimit(max, applies_to=<scope|pattern>)` — its own
  dimension (`max_calls[<scope>]`, ctx field `calls[<scope>]`), evaluated only for the
  matching scope; `Authority.permits` passes the requested scope to ceilings as the
  reserved `_scope` context key. **Auto-metering**: `Guard.check()` supplies `calls` /
  `calls[<pattern>]` per (node, pattern) when the caller does not, incrementing on allow —
  adapters need no counting logic; `would_allow()` reads the meter without consuming it.
  Unscoped `CallLimit` wire form is unchanged.
- **Observe-mode hooks on the LangChain, Google ADK and CrewAI adapters** (sampling):
  `GuardedDelegation(default_policy=, default_subagent_authority=)`,
  `DelegationGuardPlugin(default_tool_authority=, default_delegation=)` and
  `CrewAIGuardBridge(default_policy=, default_delegation_authority=)` generate the
  policy / Authority for an undeclared tool / sub-agent so the call is
  authorized-and-recorded on the audit log instead of denied. Deny stays the default
  without the hooks. The ADK plugin now records the `AgentTool` `request` as the
  child's task text on the spawn record (was `"delegated to <name>"`).

- **Bundle redaction guarantee (`evidence.redaction_report`, `export_bundle(strict=, context_allowlist=, redact_task=)`,
  `EvidenceLeakError`).** The exported bundle is customer data in transit, so custody is a test not a habit: a top-level
  `LEDGER_FIELDS` allow-list (an unknown field is where a raw argument would hide → `strict=True` raises), an optional
  caller `context_allowlist` (a raw tool-arg value under a non-feature context key is caught), and `redact_task=True`
  replaces free-text prompts with a length+hash marker before the anchor, so the transport carries no raw prompt yet
  still verifies. Nothing unvetted leaves the premises.
- **Offline evidence bundle + verifier (`delegation_guard.evidence`).** `export_bundle(audit_log, signer)`
  produces a self-contained bundle (the hash-chained ledger + a signed anchor); `verify_bundle(bundle, signer)`
  checks three invariants from the bundle ALONE, no engine: **integrity** (hash chain + anchor — a consistent
  full rewrite fails), **monotonicity** (every delegation child ⊆ parent), **containment** (every allowed
  action was within the acting node's authority). `delegation_graph(bundle)` renders the chain (nodes, agents,
  authorities, action counts, edges) for a reviewer or UI. This is the offline-verifiable audit trail: an
  auditor confirms the guarantees without trusting the engine that produced them.
- **Ledger anchoring (`AuditLog.anchor` / `verify_anchor` / `head`, ADR-14).** A signed external commitment to
  the chain head. `verify()` catches in-chain tampering; a consistent full rewrite (re-hash the whole log)
  reproduces its own hashes and passes `verify()` — but not `verify_anchor()`, because the out-of-band signed
  head hash is the fixed point it cannot reproduce. Uses the existing `wire` signers (Ed25519 in production).
- **`StrikePolicy` — revoke a node after repeated denials** (`Guard.issue(strikes=StrikePolicy(n=3, mode="same_scope"))`,
  off by default). N denials of the same scope (or N total) cascade-revoke the offending node; one `kill` event with
  `reason="strike_policy"`, `scope`, `strikes`, `mode` so the parent can see why. The policy propagates to every child
  in the chain. A denied agent that keeps probing the same wall is stopped, not left to keep probing.
- **`Guard.complete()` / `Guard.is_complete` — node lifecycle end** (`done` audit event, idempotent,
  informational: authority is unchanged, revocation stays the hard stop). The LangChain, Claude SDK,
  Google ADK and CrewAI adapters record it when a delegation returns to its caller, so a ledger reader
  can tell a sub-agent that finished from one that was cut short. Schema enum gains `done`.
- `Ceiling.describe()` on all built-ins, `ceilings.describe()` helper,
  `Authority.describe()`; `ReasonCode` constants for the structural
  `AuthorityError` reasons (`CHAIN_REVOKED`, `AGENT_BANNED`, `TTL_EXPIRED`,
  `MAX_DEPTH`, `MAX_FANOUT`, `CHAIN_CEILING`).
- `tools/render_demo_gif.py` regenerates `docs/assets/demo.gif` from `dg demo`.
- CI: actions bumped to v6; 6-hourly quickstart canary; per-framework pinned
  `integrations` job; weekly unpinned `integrations-latest` drift canary.

## [0.2.0] — 2026-08-17

The hardening release. A black- and white-box red-team pass drove real fixes,
the API moved to rich decisions, and the wire format plus offline verification
landed as the reference implementation of the Internet-Draft.

### Added
- **Wire format** (`delegation_guard.wire`): sign and serialize a delegation
  chain as JWS **Delegation Tokens** and verify child ⊆ parent **offline**, with
  no authorization server in the path. Ed25519 (via the optional `cryptography`
  extra) or a stdlib HS256 test signer. Interop test vectors live in
  `tests/vectors/` — one valid chain and six adversarial rejects.
- **Typed, extensible ceilings**: `RowLimit`, `SpendCap`, `CallLimit`,
  `EgressRank`, `Allow`, `Deny`, `Prefix`, plus `register_ceiling` for your own.
  Unknown ceiling types **fail closed**, never silently unbounded.
- **Rich `Decision`**: `check()` returns a bool-coercible `Decision` carrying
  machine-readable reason codes and `explain()`; `enforce()` raises on denial;
  `would_allow()` is a side-effect-free dry run.
- **Scenario harness**: declarative JSON/YAML authorization tests
  (`dg scenarios file.json`).
- **LangGraph adapter** under `delegation_guard.adapters.langgraph`.
- CLI: `dg demo | view | verify | scenarios`.

### Changed
- Public API is now `Guard.issue / delegate / revoke` and `Authority.meet /
  is_narrower_than`. The v0.1 `root / spawn / kill` names remain as deprecated
  aliases and emit `DeprecationWarning`.
- Package moved to a `src/` layout. The core is zero-dependency; optional extras
  are `crypto`, `yaml`, and `langgraph`.

### Fixed (from the red-team pass)
- TTL was never enforced. Added an injectable clock, per-node `issued_at`, and
  an expiry gate, so expired authority is denied.
- `is_narrower_than` was unsound for custom ceilings. Any ceiling present on the
  parent but absent on the child now makes the child *not* narrower.
- Custom ceilings could be inert. Generic quantity and rank constraints are now
  enforced at `check()` time.
- Wildcard scope pruning could false-deny. Only scopes strictly covered by a
  broader wildcard are pruned.

### Security
- A property suite (4,000 random delegation trees per invariant, zero deps) and
  a 17-attack red-team harness run in CI. Every genuine finding is fixed and
  pinned as a regression. See [`docs/RED-TEAM.md`](docs/RED-TEAM.md).

## [0.1.0]

- Initial release: `Authority` / `Guard` core, `meet` attenuation, chain depth /
  fanout / budget ceilings, cascade revocation, and a hash-chained audit log.

[0.8.0]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.8.0
[0.7.1]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.7.1
[0.7.0]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.7.0
[0.6.1]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.6.1
