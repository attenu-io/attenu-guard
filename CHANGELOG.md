# Changelog

All notable changes to delegation-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Driven by integration PoCs against twelve real agent frameworks
(`examples/integrations/`, `docs/INTEGRATIONS.md`): the library integrated
**unmodified** everywhere; what follows is what those integrations asked for.

### Fixed
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
- Integrations (examples + offline tests + CI matrix): LangGraph / LangChain
  `create_agent`, deepagents, OpenAI Agents SDK, Google ADK, Pydantic AI, CrewAI,
  AutoGen, Claude Agent SDK, smolagents, AWS Strands, LlamaIndex, Semantic
  Kernel, Agno. `docs/INTEGRATIONS.md` documents hooks, versions and what each
  framework enforces itself.
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
