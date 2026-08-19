# Changelog

All notable changes to delegation-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[0.2.0]: https://github.com/attenu-io/delegation-guard/releases/tag/v0.2.0
