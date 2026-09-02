# Changelog

One line per change. The long-form notes for each version (reasoning, review findings, migration detail) are in [`docs/release-notes/`](docs/release-notes/README.md).

Versions follow semantic versioning.

## [0.11.0] - 2026-09-02

### Added
- Bundle interop vectors (`tests/vectors/bundles/bundle_vectors_v1.json`), packaged as `attenu_guard.vectors.load_bundle_vectors()` — eight scoring cases
- `verify_bundle()` — `failure_details`, a structured dict per `failures` string (`reason`, `seq`, `node`, `call_id`, `detail`); `failures` unchanged

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.11.0.md

## [0.10.0] - 2026-08-31

### Fixed
- `Guard.check()`: a `PRE_HOOK_ONLY` allow wedged `complete()` forever — only `WRAPPER_SYNC`/`WRAPPER_ASYNC`/`FRAMEWORK_POST_HOOK` calls now register pending
- `adapters.langgraph` — `_snapshot_params` could alias live arguments; now routes through the shared `adapters._snapshot.freeze()` sanitizer
- `adapters.crewai`: outcome correlation was thread-local — now keyed FIFO by `id(ctx.tool_input)`; a third-party veto records `ABANDONED`
- `adapters.openai_agents`: execution binding is opt-in via `guarded_tool(..., registry=...)`, and `guard.check()` runs inside the tool's `on_invoke_tool`
- Adapter snapshots could share live call arguments — one `adapters._snapshot.freeze()` now rebuilds containers, handles cycles, and marks the rest `UNSUPPORTED`
- `adapters.google_adk`: a deferring tool was recorded `RETURNED` — `after_tool_callback` now checks `is_long_running`/`_defers_response` and records `DEFERRED`
- `adapters.haystack`: a `ToolPolicy` with both `scope` and `delegates_to` left its call pending forever — the outcome is now carried into the child scope
- `adapters.pydantic_ai`: capability ordering could leak or falsify outcomes — one `wrap_tool_execute` now does both, and `for_agent()` rejects conflicts
- `adapters.autogen`: closing a `call_tool_stream` early recorded no outcome — `GeneratorExit` now records `BodyState.ABANDONED` before re-raising
- `tools/render_demo_gif.py` uses `shutil.which("ffmpeg")` directly instead of a hardcoded fallback path; a machine-specific path in a demo comment removed

### Added
- Execution binding on `schema_version=2` chains for `adapters.crewai`, `openai_agents`, `google_adk`, `pydantic_ai`, `haystack` and `autogen`; v1 unchanged
- `adapters.langchain`: execution binding on `schema_version=2`, opt-in via `GuardedDelegation(..., strict_single_hook=True)`; default records no outcome
- `adapters.llama_index`: execution binding via `guarded_tool()`'s async wrapper (`Capture.WRAPPER_ASYNC`), snapshotting the model-supplied kwargs
- `adapters.smolagents`: execution binding from `GuardedTool.forward()`; generators, coroutines and futures record `DEFERRED`, not `RETURNED`
- `adapters.strands`: execution binding from `AfterToolCallEvent`, opt-in via `DelegationGuard(..., strict_single_hook=True)`; lost-outcome paths documented
- `adapters.camel`: execution binding from `GuardedFunctionTool.__call__`/`async_call`; the `camel` extra's stale `mcp<3` pin corrected to `mcp<2`
- `adapters.agno`: execution binding from `guarded_tool_hook`/`aguarded_tool_hook`, opt-in via `strict_single_hook=True`; default records no outcome
- Execution binding wired into `adapters.ag2` (the AutoGen fork): `Capture.WRAPPER_ASYNC` from `_Gate.run`, which awaits `call_next(event, context)` itself.
- `adapters.agent_framework`: execution binding from `DelegationGuard.process`, opt-in via `strict_single_hook=True`; the default records no outcome
- `adapters.a2a`: execution binding from `guarded_tool()`'s sync/async wrapper; its internal check calls `guard.check()` instead of `guard.enforce()`
- Execution binding wired into `adapters.claude_sdk` (Claude Agent SDK), OPT-IN via `DelegationGuardRegistry(..., strict_single_hook=True)`.
- `adapters.semantic_kernel`: execution binding from `_dg_tool_gate`, opt-in via `attach_guard(..., strict_single_hook=True)`; `protobuf` added to the extra

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.10.0.md

## [0.9.0] - 2026-08-31

### Fixed
- Integers outside the RFC 8785 safe range (±(2**53-1)) are now rejected at canonicalization, at `RowLimit`/`SpendCap`/`CallLimit` and by `wire.load`
- `evidence.verify_bundle` and `AuditLog.verify_anchor` now check schema version and chain identity, so a bundle for the wrong chain no longer verifies

### Added
- `AuditLog.append` raises `CommittedAuditError` (carrying the committed `entry`) when persistence fails after the entry was committed to the chain
- Execution binding, opt-in via `Guard.issue(..., schema_version=2)`: `Decision.call_id`, `Guard.record_outcome()`, and `verify_bundle`'s `execution_binding`

### Changed
- Behaviour change: an `AuditLog`/`Guard.issue` path naming a non-empty file raises `FileExistsError` instead of truncating; `overwrite=True` restores it

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.9.0.md

## [0.8.0] - 2026-08-29

### Changed
- Scope values now use one interoperable grammar: lowercase dot-separated segments, with `*` permitted only as the complete final segment after a dot.

### Added
- `reject_bare_wildcard.json` and `reject_nonterminal_wildcard.json` — interop suite at 19 vectors, pinning malformed wildcard forms to the `malformed` reason

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.8.0.md

## [0.7.1] - 2026-08-29

### Changed
- `c14n` is informational; producers still emit it, while verifiers enforce RFC 8785 JCS from canonical bytes and hashes regardless of the label.

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.7.1.md

## [0.7.0] - 2026-08-29

### Changed — BREAKING
- All signed and hash-linked artifacts use RFC 8785 JCS only: tokens declare `"c14n":"JCS"`, no legacy or dual-format reader; the interop suite is 17 vectors

### Added
- Ninth interop vector `reject_wildcard_boundary.json` — `crmx.read` under a `crm.*` root must be rejected `not_narrower`; pins the wildcard's segment boundary

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.7.0.md

## [0.6.1] - 2026-08-29

### Added
- Eighth interop vector `reject_wildcard_widening.json` — a leaf claiming `crm.*` under a `crm.read` parent must be rejected `not_narrower`

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.6.1.md

## [0.6.0] - 2026-08-28

### Added
- Interop vectors ship in the package as `attenu_guard.vectors` (`VECTOR_NAMES`, `load_vector`, `load_vectors`, `read_vector_bytes`)
- **A2A adapter** (`attenu_guard.adapters.a2a`, extra `a2a`) — carries the signed delegation chain across an Agent2Agent hop and verifies it offline server-side

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.6.0.md

## [0.5.0] - 2026-08-27

### Added
- **Haystack adapter** (`attenu_guard.adapters.haystack`, extra `haystack`) — guards `Agent`s and pipelines through `Tool.invoke`/`invoke_async`
- Microsoft Agent Framework and AG2 adapters (`adapters.agent_framework`, `adapters.ag2`; extras `agent-framework` and `ag2`) gate tool bodies and delegations
- Supply chain: SLSA build provenance on every release, weekly OpenSSF Scorecard, and `attenu-guard verify` as a pre-commit hook via `.pre-commit-hooks.yaml`

### Fixed
- Adapter docstrings named the pre-rename paste-in modules — they now name `attenu_guard.adapters.<name>` and the matching extras

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.5.0.md

## [0.4.1] - 2026-08-26

### Fixed
- README: the install block still said "pre-publish… once published to PyPI"; the package has been on PyPI since 0.4.0.

### Changed
- Packaging: PyPI classifiers, `Documentation` / `Issues` / `Changelog` project URLs, and a summary aligned with the project description.

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.4.1.md

## [0.4.0] - 2026-08-24

### Changed — BREAKING
- Renamed `delegation-guard` to `attenu-guard`: module `attenu_guard`, CLI `dg` becomes `attenu-guard`; the API itself is unchanged

### Fixed
- Google ADK adapter: parallel `AgentTool` calls were chained, not fanned out — the delegating agent is now recorded at the tool call and used as the parent
- Thread safety under parallel tool calls: the audit log, sequence clock and chain mutations are serialised per chain, so `ts`/`seq` advance atomically
- `strict_metering=True` failed open on a partial context — a metered call must now declare every metered dimension the node holds (`ceilings.ctx_field_of`)
- `tests/test_langgraph_adapter.py` asserted langgraph was not installed — it now asserts that importing the adapter does not import langgraph

### Added
- `deny` entries carry a `disposition` (`held_pending_grant`, `withheld_tier2`, `unresolved`, `out_of_authority`) via `Guard.check()`/`Guard.record_denial()`
- `evidence.denials(bundle)` — deny events grouped by (node, tool, scope, disposition) with counts, seq range; `delegation_graph` gains `denials_by_disposition`
- Disposition contract across all 12 adapters, passed to `Guard.check`; undeclared tools now land on the ledger as `unresolved` via `Guard.record_denial`
- `delegation_guard.identity` — `.attenu/product.json` discovery (`ATTENU_PRODUCT_DIR` or walk-up), `boot_id()`, `new_chain_id()`, `ledger_path`/`spool_path`
- `AuditLog(sinks=...)`/`Guard.issue(audit_sinks=)` + `sinks.SpoolSink` — append-only local-file sinks fed after the ledger write, never the network
- `wire.Ed25519Verifier` — public-key-only verification for consoles and auditors; `Ed25519Signer.private_bytes_raw()`/`from_private_bytes()` for key files
- `Guard.is_descendant_of(other)`; the Google ADK adapter treats `transfer_to_agent` back to an ancestor as a return, not a delegation
- `evidence.delegation_graph` names a disposition-less deny by its reason (`revoked`, `ceiling_exceeded`).

### Changed
- Version 0.3.0 (ledger schema gains an optional `disposition` field on deny; wire and hash chain unchanged).
- `ReasonCode.NO_AUTHORITY` — the principal holds no Authority in this chain (adapter-level: undelegated agent, unmapped tool, unparseable args).
- `Guard.record_denial(reason, message, *, scope, tool, context)` — put an adapter-level refusal on the audit trail as a schema-conformant `deny` event.
- `Guard.agent_id`, `Guard.is_revoked`, `Guard.is_expired` (read-only).
- `Guard.revoke_agent(agent_id)` — principal-scoped, chain-wide revocation with a grow-only ban (`AuthorityError` reason `agent_banned` on any later `delegate()`)
- `Guard.would_delegate(agent_id, request)` — pure dry-run of the delegation preconditions (`Chain.delegation_error`), no node, no fanout, no audit write.
- `AuditLog.__iter__` / `__len__`.
- Framework adapters ship in the package as `delegation_guard.adapters.<name>`, with per-framework extras (`pip install 'delegation-guard[crewai]'`)
- Scoped call ceilings: `CallLimit(max, applies_to=<scope|pattern>)`; `Guard.check()` auto-meters calls per node and pattern, `would_allow()` does not consume
- Observe-mode hooks (`default_policy=`, `default_delegation=`) on the LangChain, Google ADK and CrewAI adapters record undeclared tools instead of denying them
- Bundle redaction: `export_bundle(strict=, context_allowlist=, redact_task=)`, `evidence.redaction_report` and `EvidenceLeakError` keep raw values out
- Offline evidence bundle: `export_bundle()`/`verify_bundle()` in `delegation_guard.evidence` check integrity, monotonicity and containment from the bundle alone
- Ledger anchoring (`AuditLog.anchor`/`verify_anchor`/`head`, ADR-14) — a signed commitment to the chain head that a consistent full rewrite cannot reproduce
- `StrikePolicy` — `Guard.issue(strikes=StrikePolicy(n=3, mode="same_scope"))` cascade-revokes a node after N denials; one `kill` event, off by default
- `Guard.complete()`/`Guard.is_complete` — node lifecycle end, an idempotent `done` audit event; authority is unchanged and revocation stays the hard stop
- `Ceiling.describe()` on all built-ins, plus `ceilings.describe()` and `Authority.describe()`; `ReasonCode` constants for structural `AuthorityError` reasons
- `tools/render_demo_gif.py` regenerates `docs/assets/demo.gif` from `dg demo`.
- CI: actions bumped to v6; 6-hourly quickstart canary; per-framework pinned `integrations` job; weekly unpinned `integrations-latest` drift canary.

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.4.0.md

## [0.2.0] - 2026-08-17

### Added
- Wire format (`delegation_guard.wire`) — sign a delegation chain as JWS Delegation Tokens and verify child ⊆ parent offline, Ed25519 or a stdlib HS256 signer
- Typed ceilings: `RowLimit`, `SpendCap`, `CallLimit`, `EgressRank`, `Allow`, `Deny`, `Prefix`, plus `register_ceiling`; unknown ceiling types fail closed
- `check()` returns a bool-coercible `Decision` with reason codes and `explain()`; `enforce()` raises on denial; `would_allow()` is a side-effect-free dry run
- Scenario harness — declarative JSON/YAML authorization tests (`dg scenarios file.json`)
- LangGraph adapter under `delegation_guard.adapters.langgraph`
- CLI: `dg demo | view | verify | scenarios`.

### Changed
- Public API is now `Guard.issue / delegate / revoke` and `Authority.meet / is_narrower_than`.
- Package moved to a `src/` layout.

### Fixed (from the red-team pass)
- TTL was never enforced.
- `is_narrower_than` was unsound for custom ceilings.
- Custom ceilings could be inert.
- Wildcard scope pruning could false-deny.

### Security
- A property suite (4,000 random delegation trees per invariant) and a 17-attack red-team harness run in CI; findings pinned as regressions, `docs/RED-TEAM.md`

Full notes: https://github.com/attenu-io/attenu-guard/blob/main/docs/release-notes/v0.2.0.md

[0.8.0]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.8.0
[0.7.1]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.7.1
[0.7.0]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.7.0
[0.6.1]: https://github.com/attenu-io/attenu-guard/releases/tag/v0.6.1
