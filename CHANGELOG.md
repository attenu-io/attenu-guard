# Changelog

All notable changes to delegation-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
