# Changelog

One line per change. The long-form notes for each version (reasoning, review findings, migration detail) are in [`docs/release-notes/`](docs/release-notes/README.md).

Versions follow semantic versioning.

## [Unreleased]

### Fixed
- **A raising context function was still silent on a delegated child.** `smolagents` and `camel` resolve their Guard through a `GuardRef` (how `DelegatedAgent` wires every delegated child), and both handed that unresolved reference to the shared context helper — `record_denial` on a `GuardRef` is an `AttributeError`, so the refusal was lost exactly on the delegated node. Both call sites pass the resolved Guard now; the helper also resolves a reference it is handed anyway, and anything that is neither fails loudly rather than swallowing the record. A test asserts no adapter passes `self.<something>` to the helper
- **The body-refusal receipt was bound to the wrong Decision, so it only ever appeared on the un-gated path.** The receipt was looked up from `gate.decision`, which this adapter sets only in strict execution-binding mode; on a normally-authorized call there was no `call_id` to bind to, and `_record_inner_refusal` gave up silently. The passthrough path happened to keep its own Decision, which is why the one place the receipt did appear was the only place it was tested. The `guard.check()` Decision is now kept unconditionally. On the real AstrBot battery this is the difference between one `outcome` across thirty ledgers and the receipt appearing wherever a layer between the gate and the tool refuses — `direct` (main agent, observe), the `h17-alias-native` twin and `h18-omitted-tools` included
- **The body-refusal receipt was written on one path only.** The `_BodyWitness` that lets an `allow` say whether the tool body was actually reached was installed just on the re-nested `get_full_tool_set()` branch. It is now installed on every path this adapter guards a tool on — the eager sweep, `guard_tools()` and that branch — so wherever a layer ends up between this gate and the tool, the refusal is on the entry
- **The ADK 0.x callback fallback bound async callbacks, which fail OPEN there.** ADK 0.3.0 never awaits a callback result: `base_agent.py:261` puts the return straight into an `Event`, and `functions.py:156-160` does `function_response = agent.before_tool_callback(...)` then `if not function_response:` before calling the tool. A coroutine is truthy, so the first shipped version of `attach()` would have skipped every tool body, handed the coroutine back as the tool result, authorized nothing and recorded nothing — failing open on the audit trail while looking like it worked (probed on a real `google-adk==0.3.0`). Every hook's work is synchronous now (`_*_sync`), `attach()` binds plain functions on every version, and the plugin API's five async methods are thin wrappers over the same bodies. The test stub mimics 0.3.0 exactly — calls the callback, never awaits, treats a truthy return as "skip the body" — so a coroutine return fails the test
- **The Google ADK adapter could not attach to an ADK 0.x project at all.** It imported `google.adk.plugins.base_plugin.BasePlugin` (and its usage example named `google.adk.apps.App`), neither of which exists on `google-adk==0.3.0` — the version evo-ai pins — so the import failed and the shipped adapter was unusable there. The plugin import is optional now (`HAS_PLUGIN_API`), and `DelegationGuardPlugin.attach(agent)` binds the SAME four hooks to the per-agent `before_agent_callback` / `after_agent_callback` / `before_tool_callback` / `after_tool_callback` that ADK has carried since 0.x, walking `sub_agents` and every `AgentTool`-wrapped agent. Same hook points, same authorization, same ledger shape; the plugin path stays the default on 1.x and later. An existing callback is kept — the attribute becomes a list with this adapter's first — and `attach()` is idempotent per agent
- **An `exempt_tools` entry ran with no audit row of any kind** in the Google ADK adapter — the one path in it with the B1 shape. An exemption is the operator saying "do not authorize this", never "do not say it happened": such a call is now recorded as an `allow` marked `policy="unlisted"`, so a reader sees the exemption instead of a hole. `transfer_to_agent` and `AgentTool` calls stay unrecorded here on purpose — they are delegation, already on the same ledger as spawns, and recording them again would double-count the one event this library exists to get right
- **An `allow` whose body was refused by a framework layer nested inside the gate now says so.** With this adapter's gate outermost (the previous entry), AstrBot's `_PermissionGuardedTool` can still refuse without ever reaching the tool — so the call was correctly recorded, but an `allow` read on its own said it went through. A `_BodyWitness` sits innermost and observes the one unambiguous fact, whether the real body ran; when it did not, the entry gets an `outcome` (`body_state: returned` — a value did come back to the wrapper) whose `receipt` names the refusing layer and commits to the returned text by SHA-256 without logging it. Existing event, existing fields, no new vocabulary; `verify_bundle` reports the call as `observed` and still accepts
- **`guard_node` on an async function and a `schema_version=2` guard authorized nothing unless the caller awaited it.** The v2 branch put the check inside the coroutine body, so calling the node without awaiting created a coroutine and returned: no check, no ledger row, no `AuthorityDenied`, a denied scope indistinguishable from an allowed one. It now authorizes eagerly in a sync wrapper, exactly as the v1 branch always has, and closes the outcome out from inside the coroutine where the body actually runs — execution binding unchanged (`wrapper_async` capture, `authorized_params` committed before the body, real return/raise/cancel observed). Note the wrapper's shape is now sync on both versions, as v1 documents; a caller who never awaits leaves the call authorized and pending, which `complete()` reports honestly
- **A raising context function refused the call and wrote nothing, in every adapter.** Fixed once, in `adapters/_context.py`, and applied across a2a, ag2, agent_framework, agno, autogen, camel, claude_sdk, crewai, haystack, langchain, langgraph, llama_index, openai_agents, pydantic_ai, semantic_kernel and smolagents (openhands and astrbot already returned a denial in their own idiom). The refusal is a `deny` with the existing `no_authority` reason and `disposition=unresolved`, then `AuthorityDenied` carrying that decision — previously the operator's own exception propagated, so the call already aborted; now it leaves a record. A literal context mapping is passed through untouched. No new reason token, no vector change. A test asserts no adapter evaluates a context callable bare
- **`Guard` could not be copied.** `copy.deepcopy` of anything holding one raised `TypeError: cannot pickle 'itertools.count' object` (the chain's sequence counter; the audit log's `RLock` is the same class of problem), which crashed hosts that copy their tool objects — found on a minion-agent run. `__copy__`/`__deepcopy__` return `self`: a Guard is an identity, not a value, and a copy that forked the node, the counter or the hash chain would be a second authority writing a second history

### Added
- smolagents: `install(guard, agent, scopes, ...)` — the installer the other adapters have, in this adapter's idiom. `guard_tools()` wraps a list once; a tool added to `agent.tools` afterwards ran with no ledger entry at all (minion battery, H12). `install()` is re-runnable, takes a `scope_for` observe-mode hook, and with `allow_unlisted=True` records an undeclared tool as a passthrough (`policy="unlisted"`) instead of leaving it invisible
- smolagents: `DelegatedAgent` mirrors `inputs` and `output_type` as well as `name`/`description`. smolagents stamps all four in `_setup_managed_agents`, so swapping the proxy into an already-built `managed_agents` dict produced an agent-as-tool with no argument schema
- AstrBot: tools registered after `install()` are covered. `add_func()` appends a plugin's tool and the MCP paths rebuild `func_list` wholesale, both after the eager pass, so the tool ran un-gated and un-ledgered (battery H12, on both routes). The manager is now re-swept from `get_func()` and `get_full_tool_set()`, the two methods an agent gets its tools through; `uninstall()` removes it. Both H12 routes go from a tool body that ran to a denial on the ledger
- AstrBot: a `ToolPolicy` declared under the name an MCP server PUBLISHES now binds. AstrBot rewrites an MCP tool's name on the way in (`push.record` -> `push_record`, `MCPTool.__init__`) and keeps the original on `mcp_tool.name`, which is what goes back out on the wire; nothing inside AstrBot answers to the published name, so an operator who declared a rule under the only name they saw had it bind to nothing and the call ran as an unlisted passthrough. Either spelling binds now, the exposed name winning when both are declared, and the ledger entry's context carries the published name so the trail says what was called on the wire. Battery H17-alias goes from an un-gated allow that pushed to a denial
- AstrBot: a declared policy that matches no registered tool is reported at install time (`unbound_policies()`, surfaced through the new `on_unbound` hook; default a `logging` warning, not a ledger entry — nothing has happened on the chain yet). A rule that covers nothing is the failure an operator cannot see
- AstrBot: this adapter's gate is the OUTERMOST wrapper on both toolset branches. On the `Agent.tools is None` branch, `get_full_tool_set()` wrapped AstrBot's `_PermissionGuardedTool` around this adapter's tool, and that class returns an error string before delegating — so a call AstrBot refused never reached the ledger, the same blind spot open-swe had. The nesting is inverted on the objects the toolset hands out, so every call is recorded first and AstrBot's permission check runs as part of the body
- OpenHands: `GuardedDelegation.delegate_executor(inner)` makes the SDK's second delegation mechanism a spawn seam. `openhands.tools.delegate.DelegateExecutor` ships without a tool class (apps wire their own), and only the configured `delegation_tool` was treated as a delegation, so an app delegating this way minted no child node and the sub-agent's own tool calls were recorded on the PARENT's node (battery `h18-omitted-delegate`). `spawn` now mints one child per sub-agent id from the Authority declared for its agent TYPE, resolved through the SDK's registry so an omitted `agent_types` (which `_resolve_agent_type` turns into the literal `"default"`) finds `general-purpose`; an undeclared type is refused before the SDK creates anything. Each child is bound to ITS conversation rather than to a `ContextVar`, because `_delegate_tasks` runs each sub-agent in a plain `threading.Thread` and a thread inherits no context — the conversation is handed to the executor on every call, so the binding survives the thread boundary
- OpenHands: tools registered AFTER `install()` are covered. `install(*classes)` guarded the classes it was handed and nothing else, so a tool a sub-agent's own definition named — registered at run time, as the SDK's `register_tool()` API invites — ran un-gated and left NO ledger entry (OpenHands battery H12: the ledger showed root/spawn/done/done while the tool pushed). The adapter now arms the registration seam itself (the registry's `_REG` mapping wraps each incoming resolver) and restores it in `uninstall()`, so a late registration is gated and ledgered on the node that runs it. The battery's `h12-runtime-tool` case is now identical to its `-installed` twin, without the re-`install()` that twin needed
- OpenHands: the SDK's sub-agent aliases are resolved before minting. The gate keyed on the raw `subagent_type`, so `default` — the SDK's alias for `general-purpose` (`subagent/registry.py`) — missed a sub-agent the operator HAD declared: observe minted a child under the alias while `general-purpose` ran, enforce refused it. The name is now resolved through `get_agent_factory()`, the SDK's own registry, so a declared name covers its aliases; the spawn entry records the canonical name and keeps the requested alias in its task text. An absent selector is NOT resolved to the default — that would turn a refusal into a spawn
- Both adapters: a failing gate is recorded. When the operator's `ToolPolicy.context` callable raised, the body correctly never ran and nothing was written at all (OpenHands battery H14). It is now a `deny` with the existing `no_authority` reason — whose vocabulary already covers an adapter-level refusal upstream of scope and ceiling evaluation — and `disposition=unresolved`. No new reason token, so the closed vocabulary and every vector are untouched
- `Guard.record_passthrough(tool)`: an adapter running with `allow_unlisted=True` passed an undeclared tool straight through and left NOTHING on the audit trail (found on a real open-swe run — the tool ran, the ledger showed root/spawn/deny/done and no trace of it). The passthrough is now recorded as an `allow` marked `policy="unlisted"`, a new allow-only ledger field that says the call happened AND that the chain did not authorize it. `verify_bundle` counts those entries as `ungated` in its report instead of testing them for containment (they assert no authority to contain), so an un-gated call can never read as an authorized one and can never be silently absent either. Fixed in the langchain, openhands and astrbot adapters; `attenu-guard`'s fail-closed default (`allow_unlisted=False`) is unchanged
- `ReasonCode.DELEGATION_REFUSED` and a ledger entry for it: a delegation refused by the adapter before it reached the chain (the named sub-agent has no declared Authority) went back to the model as a tool error with no audit entry at all, so the refusal was visible in the transcript and nowhere else. It is now a `deny` with `disposition=unresolved`, routed through `Guard.record_denial()`. Same fix in the langchain, openhands and astrbot adapters
- Bundle vector `valid_bundle_v2_ungated_allow`, revision `bundle_vectors_v1.3` (eighteen cases): a valid bundle carrying one `policy="unlisted"` allow, so the rule is pinned by a case before anyone implements it from prose. It MUST accept — a verifier that runs a policy-marked allow through containment rejects an honest bundle, and one that drops it silently understates the run. Cases may now declare `expect_report`, named report counters a conformant verifier reproduces exactly (`actions_checked: 2`, `ungated: 1` here); it exists for a rule accept/reject cannot distinguish. The seventeen earlier rows are byte-identical and `version` stays `bundle_vectors_v1`

### Changed
- AstrBot `install()` documents the late-registration gap it does not close (battery H12, on the plugin `add_func` and stdio-MCP routes) and names the workaround: call `install()` again after registering. Closing it automatically was measured and held back — see the docstring
- `evidence.denials()` folds `spawn_denied` alongside `deny`: a delegation the chain refuses structurally (revoked/expired parent, depth/fanout overflow) is recorded once, by `Guard.delegate()`, and was invisible to an operator's Decisions queue because the fold read only `deny`. Rows gain `event` and `requested` (the sub-agent that was refused; None on an action deny), and a `spawn_denied` row is folded onto the parent node that asked. One decision, one entry — the adapters do not write a second
- README first sentence and the repository description say what the contract is: the caller declares the child's grant, the library bounds it by the parent's (the meet), so a child never holds more than its parent; "only what its task needs" and "strict subset" overstated it (equal authority is permitted, and task text does not narrow a grant)

## [0.15.0] - 2026-09-06

### Added
- Observer-envelope corpus revision `envelope_vectors_v1.2`, nineteen cases: `reject_duplicate_subject_defective_second` is `reject_duplicate_subject` with one hex nibble of the SECOND envelope's signature flipped. It is the only row that separates a verifier which claims the entry as soon as `subject.seq` finds it from one which judges the envelope first. Row 17 cannot — both envelopes are sound there, so both verifiers reach the duplicate rule and both reject. Break the second signature and they part: claiming first reports `envelope_duplicate_subject` and seq 1 falls back to `process-asserted`; judging first stops at the signature, never reaches the duplicate rule, counts no claim, and leaves seq 1 reporting `witness-signed` on the first envelope alone, telling a consumer the entry is witness-signed while two witnesses contradicted each other. Required set unchanged from row 17 (`envelope_duplicate_subject` at seq 1, seq 1 `process-asserted`); `envelope_bad_signature` at that seq is a permitted extra, as on `reject_non_canonical`, and reporting it INSTEAD is fewer than the minimal set. No new reason name. Rows 1 to 18 are byte-identical and `version` stays `envelope_vectors_v1`. Proposed by Xuebin Ma (@XuebinMa, agent-guard) on a2aproject/A2A#1575 after scoring revision v1.1 18 of 18. Both implementations already claim first, so this pins existing behaviour rather than changing it

## [0.14.1] - 2026-09-05

### Changed
- README: the first screen now opens with the definition, who it is for, the licence line (Apache-2.0, Python 3.9+, zero runtime dependencies, TypeScript port) and one snippet that prints on success; the live-enforcement sentence is narrowed to what `attenu-derive` docs/LIVE-ENFORCE.md and docs/A3-FRAMEWORKS.md show; framework and version labels agree with the matrix (18 entries, MCP as a recipe); package summary says 18

### Added
- `examples/integrations/commerce-agents/` — a recipe for `anthropics/commerce-agents`, whose delegate contract ("a delegate cannot write, present, or invoke other delegates") is stated in prose and held by each delegate author rather than at the shared dispatch point. `guarded_executor_class` arrives through `executor_class`, the seam the repo documents and every consumption path already takes; `install()` covers the one construction that ignores it, `AnalysisRunner._read`. Offline on the repo's own `FakeClient`/`FakeCreateClient`, so the real `MerchantAgent` and the real `AnalysisRunner` both run with no API key. Not in the `integrations` CI matrix: the packages are unregistered on every index by upstream's own design, so the test skips unless the repo is installed from a clone

### Fixed
- `attenu-guard verify <missing path>` printed a raw `FileNotFoundError` traceback; it now prints `cannot read <path>: <reason>` and exits 1, like every other usage error

## [0.14.0] - 2026-09-05

### Added
- `adapters.pydantic_ai.GuardedToolsetCapability` — the pydantic-ai integration's primary tool-invocation hook point, and now the one the shipped example runs on. An `AbstractCapability` that overrides no execution hook and contributes ONE `GuardedToolset` over the agent's composed toolset through `get_wrapper_toolset`. pydantic-ai runs the entire hook chain ABOVE the entire toolset chain (maintainer DouweM, pydantic/pydantic-ai#8007), so `DelegationGuard.wrap_tool_execute`'s `handler` is the composed toolset and any wrapper toolset another capability contributes runs INSIDE it: the denial still stops the tool body cold, but the outcome recorded is that wrapper's, not the body's. `CombinedCapability.get_wrapper_toolset` applies contributed wrappers over `reversed(self.capabilities)`, so chain-last is toolset-innermost, and `get_ordering()` puts the guard there in every list order — see the ordering bullet below for the tier and the `wrapped_by` edge that makes it exact. `PreparedToolset` (which overrides `get_tools` only) and `CombinedToolset` (which only routes) are all that remain below it
- `GuardedToolsetCapability.get_ordering()` declares `position="innermost", wrapped_by=[AbstractCapability]`. `innermost` alone is a TIER whose only tiebreak is list order, so a sibling claiming it and contributing a `call_tool`-overriding wrapper toolset would take the innermost slot whenever it was listed after this capability; the `wrapped_by` edge is matched by `issubclass` and so names every sibling at once, registered or injected per-run, and the sorter settles this capability last in every list order. Probed on 2.31.1 in both directions and for both per-run forms — there is no "list it last" rule. Nothing about the ordering is conditional on the installed pydantic-ai: both fields predate the `>=2.31` extra floor
- **Stated limit: beside a durable-execution engine the guarantee does not hold.** Temporal, DBOS and Prefect claim `innermost` too but never wrap the composed toolset: `get_wrapper_toolset` swaps the LEAF toolsets through `visit_and_replace`, and `WrapperToolset.visit_and_replace` rebuilds itself around the visited result, so the swap descends THROUGH this guard. Both orders give `Guard(Durable(FunctionToolset))`, measured with a leaf-rewriting proxy. The durable toolset therefore sits between the guard and the tool body, and the recorded outcome encloses the durable dispatch rather than the body. The policy lookup, `guard.check()` and the ledger write run outside that durable toolset boundary, in the same context as the rest of the capability chain; what a given engine does with that context was NOT measured — no worker was run and the tests use a leaf-rewriting proxy — so nothing is claimed about journalling or replay. No configuration in this release places the guard inside the durable unit: no ordering does it, and neither does handing the engine a `GuardedToolset` of your own, since the swap descends through that wrapper too. Reaching inside would mean participating in the registered leaf, a different primitive from anything `CapabilityOrdering` offers. The maintainer states both halves — the guard is outside in every configuration, and refusing the pair is "arguably correct" since the requirement cannot be met (DouweM, pydantic/pydantic-ai#8127, comment 5547131287). This release adds no refusal, because a durability capability is recognisable only by its module, which would name the three first-party engines and silently miss any other leaf rewriter; the limit is documented instead
- Two attenu-guard authorizers on one agent stay refused at construction, now by two different messengers. Either agent-wide authorizer over a `GuardedToolset` the caller built and listed in `toolsets=[...]` is refused by `for_agent()` with a message naming both. The CAPABILITY pairs — `GuardedToolsetCapability` beside a `DelegationGuard`, or two of either — cycle in `sort_capabilities` first, since both classes declare `wrapped_by=[AbstractCapability]`, and surface as pydantic-ai's `Circular ordering constraints among capabilities` before any `for_agent` runs. Both class docstrings, the example README and the adapter's two-authorizers message say that this error on an attenu-guard agent means two authorizers were registered
- The ledger's `allow` entries record WHICH hook point observed a call: a toolset-layer check writes `adapter.hook_path` of `...GuardedToolset.call_tool`, the hook layer keeps `...DelegationGuard.wrap_tool_execute`. The two enclose different things, so the record says which one it was. `deny` entries carry no adapter — `Guard.check` writes `capture`/`adapter` only when the decision allows, since a denied call had no execution to observe — which is unchanged core behaviour
- `GuardedToolset.label` — what the toolset calls itself in `UnmappedToolError` and `MissingGuardError`. It said `GuardedToolset` even when `GuardedToolsetCapability` had contributed it, so a fail-closed refusal pointed at an object the user never wrote; the capability now sets its own class name

### Fixed
- `adapters.pydantic_ai`: a hand-built `GuardedToolset` nested inside a `CombinedToolset` in `toolsets=[...]` escaped BOTH agent-wide authorizers' dual-instrumentation check and every tool call was then authorized twice — two `allow`/`outcome` pairs on the ledger for one body, and (with `metered=True`) the call counted twice against any `CallLimit`. The check followed `.wrapped` chains only; a toolset tree also BRANCHES through `CombinedToolset.toolsets`, and both are walked now. `AbstractToolset.apply` is not usable for this: `WrapperToolset.apply` forwards to `self.wrapped` without visiting the wrapper itself, so a top-level `GuardedToolset` would be missed

### Changed
- `adapters.pydantic_ai` module and `DelegationGuard` docstrings state the hook layer's limit in the maintainer's terms, live-probed on 2.31.1: sorted last among capabilities, `DelegationGuard` still runs outside every contributed wrapper toolset, and the trace with two of them is `guard:enter, A:enter, B:enter, TOOL BODY`. What only the hook layer sees is also stated — the built-in `search_tools` discovery call, which `ToolSearchToolset` (from the auto-injected `position="outermost"` `ToolSearch` capability) serves itself and never delegates inward, so a `DelegationGuard` agent with `defer_loading=True` tools must give `search_tools` a policy or it is refused as unmapped
- `adapters.pydantic_ai`: `DelegationGuard.for_agent()` no longer refuses a capability ordered INSIDE it that also wraps tool execution. The check now lives at one call site, the per-call re-read of `ctx.root_capability` in `wrap_tool_execute`, which reads the chain a run actually resolved and so covers the per-run `agent.run(..., capabilities=[...])` additions construction cannot see; the construction-time copy could only ever fire on a chain assembled past the sorter. `_find_execution_wrapper_nested_inside` and its message are unchanged, and `for_agent()` still refuses a second AUTHORIZER on the agent
- `examples/integrations/pydantic_ai/demo.py` runs on `GuardedToolsetCapability`; `build_scenario(..., guard=DelegationGuard)` runs the same story through the hook layer, and a test asserts the export is denied before its body either way

## [0.13.0] - 2026-09-03

### Added
- Observer envelopes (envelope v1) — a witness's Ed25519 signature over the IDENTITY of one committed ledger entry (`chain_id`, `node`, `seq`, `entry_hash`, `event`, and `call_id` on an allow), carried beside the ledger in a bundle's top-level `envelopes` array. `evidence.sign_envelope()`, `evidence.verify_envelopes()`, `evidence.envelope_subject()`, `evidence.envelope_signing_input()`, and `export_bundle(..., envelopes=...)`. The signature is over `JCS(envelope minus "sig")`, the same canonicalization the ledger has signed with since 0.7.0
- `verify_bundle()` — `witness_keys` (the trust set: `[{"kid", "alg", "public_key_hex"}]` or a `{kid: public_key}` mapping) and `envelope_bytes` (the envelope bytes as received, which only `envelope_non_canonical` needs). Per-entry state `witness-signed` / `process-asserted` in `report["envelopes"]`, with the report line `witness-signed (matched|not_matched|indeterminate)`; a process-asserted entry gets no result. `checks["envelopes"]` is `"not present"` on a bundle carrying none, which is every bundle written before this release
- Seven named envelope failures, in `evidence.ENVELOPE_FAILURES` and in the same `failures`/`failure_details` list as every other bundle failure: `envelope_unknown_version`, `envelope_unknown_member`, `envelope_subject_mismatch`, `envelope_duplicate_subject`, `envelope_non_canonical`, `envelope_unknown_witness`, `envelope_bad_signature`. An envelope is never required; a present one has to verify
- Observer-envelope interop vectors (`tests/vectors/envelopes/envelope_vectors_v1.json`), packaged as `attenu_guard.vectors.load_envelope_vectors()` — eighteen scoring cases, revision `envelope_vectors_v1.1`, on the same nine-entry ledger as `bundle_vectors_v1.json`. Every case carries `witness_keys` and `expect_states` (every entry, not only the covered ones); `valid_jcs_reorder` carries `canonical_hex`, `reject_non_canonical` carries `raw_hex`, `reject_rehashed_chain_unanchored` carries `"signer": null`
- `attenu_guard._ed25519` — RFC 8032 Ed25519, stdlib-only, so the envelope corpus is scorable and regenerable by a `pip install attenu-guard` that pulled in no dependencies. `evidence` prefers `cryptography` when it is installed; Ed25519 is deterministic, so both backends produce the same bytes, and CI regenerates the corpus under each and diffs the result
- `tests/vectors/README.md`: a **reason vocabulary** — every one of the 33 reason strings a verifier may report (ledger-level, execution binding, envelope), each with its meaning and its `{seq, node}` position rule, above the cases. The names are the contract and the per-case `Required:` lines are its instances; `tests/test_bundle_vectors.py` asserts the table and the reasons `evidence.py` can actually report are the same set, so neither can drift from the other. Asked for by the third independent run, which scored 9 of 17 before adopting the names and 17 of 17 after; that run's row is under *Independent runs*: Xuebin Ma (@XuebinMa), `agent-guard`, Rust, revision `bundle_vectors_v1.2` at `v0.12.1`, fixture and verifier pinned
- **One entry, at most one envelope.** A second envelope naming a `subject.seq` an earlier envelope in the same array already named is `envelope_duplicate_subject` at the covered entry, and that entry reports `process-asserted` rather than `witness-signed`. Without the rule the per-entry state was written once per envelope and the last one read won, so the same bundle in the other array order scored differently and anyone able to append an envelope could decide what an earlier witness said. The first envelope's result is still reported as what that witness said. Corpus row 17, `reject_duplicate_subject`, carries two valid envelopes over one entry from two trusted witnesses, `matched` then `not_matched`
- `attenu-guard verify --witness-keys FILE` — the trust set for a bundle's observer envelopes, as the vector file's `[{"kid", "alg", "public_key_hex"}]` array or a whole vector case. Without it every envelope in a bundle failed `envelope_unknown_witness` and the CLI could not verify a witness-signed bundle at all; the failure still stands when no file is given, and the output now names the flag
- `adapters.a2a.verify_hop(..., witness_keys=...)` — envelope trust for a hop check, plus `checks["envelopes"]`. With no trust set configured the hop is checked on a copy of each bundle WITHOUT its `envelopes` member and reported as `not evaluated (no witness_keys configured)`; before this, a peer refused every honest hop whose ledger carried an envelope, because the adapter scored it against an empty trust set
- **`witness.alg` is checked against the contract**, not against the trust-set row: v1 defines `EdDSA` and no other algorithm, so anything else is `envelope_unknown_witness`. `"alg": "none"` on both sides — in the envelope and in the row it was compared with — verified as witness-signed; `"HS256"` reached the Ed25519 verifier and was reported as `envelope_bad_signature`, the right verdict for the wrong reason. `witness_keys` rows declaring another alg are refused at construction. Corpus row 18, `reject_unknown_alg`, carries a genuinely signed envelope from a trusted kid whose `alg` says `"none"`
- **`verify_bundle()` reports on hostile bundle content and never raises.** Every envelope member is an untrusted JSON value of any type, and five values a JSON parser accepts crashed the scorer: an unhashable `subject.seq` or `subject.event` or `witness.kid` used as a lookup key (`TypeError: unhashable type`), a `sig` that is not a string reaching `bytes.fromhex` (`TypeError`, which the `except ValueError` around it does not catch), and a value JCS cannot represent — a non-finite number, an integer outside the binary64 safe range — reaching the canonicalizer at the signature step. Each is now a named reason at a defined position: `envelope_subject_mismatch` (`subject seq is not an integer`, `subject event is not a string`) positioned nowhere when the `seq` names no entry, `envelope_unknown_witness` (`witness kid is not a string`), `envelope_bad_signature` (`sig is not a hex string`) and `envelope_non_canonical`. `true` as a `subject.seq` also stopped finding the entry at seq 1, which it did because `hash(True) == hash(1)`
- Malformed caller inputs are refused rather than coerced: an `envelope_bytes` entry that is not hex or bytes reports `envelope_non_canonical` for that envelope instead of `bytes(n)` fabricating n zero bytes; a `witness_keys` row whose key is not 64 hex characters or 32 bytes, or whose `kid` is not a string, raises `ValueError` naming the kid at trust-set construction — `{kid: 32}` used to fabricate 32 zero bytes and downgrade a misconfiguration into a signature failure against that witness

### Changed
- `adapters.pydantic_ai` header: re-verified against pydantic-ai-slim 2.38.0
- `tests/test_bundle_vectors.py` reason-vocabulary anti-drift: the envelope reasons are now READ OUT of `_score_envelope`'s own body (every literal passed to its `report()` helper) and asserted equal to `evidence.ENVELOPE_FAILURES`, instead of being taken from that tuple. Taking them from the tuple made the check blind for envelopes in both directions — a reason the scorer could report with no row in the tuple and no row in the README passed
- `evidence.export_bundle(redact_task=True, envelopes=[...])` raises `ValueError`: redaction rewrites every entry hash, so envelopes signed over the unredacted ledger shipped bound to entries that no longer existed and failed `envelope_subject_mismatch`. Export the redacted bundle first, sign over ITS entries, then export again with those envelopes

## [0.12.1] - 2026-09-03

### Added
- Bundle interop vectors, revision `bundle_vectors_v1.2` — five appended cases: `valid_bundle_v2_literal` (the root holds `{crm.read, mail.send}`, so the child's scopes are a literal subset) and, derived from it, `reject_increased_ttl_literal`, `reject_loosened_ceiling_literal`, `reject_null_ttl_literal`, `reject_omitted_ceiling_literal`. The v1.1 ttl/ceiling rows are rejected by a verifier that compares scope lists literally and never checks ttl or ceilings (0.11.0 was one), for a scope reason at the declared position, so they never discriminated it; the four new rows can fail only on the dimension they are about. 0.11.0 accepts all four; this build rejects each. `version` stays `bundle_vectors_v1`; no case changed

## [0.12.0] - 2026-09-03

### Fixed
- `verify_bundle()` monotonicity: a delegation that widened only ttl or only a ceiling verified CLEAN whenever the child's scopes were literally a subset of the parent's — the check was gated on a literal, non-wildcard-aware scope difference, so `is_narrower_than` returning False was discarded. A child that outlived its parent, raised a ceiling, dropped a ceiling its parent held, or carried no ttl at all now fails, and the message names the dimension (`ttl 7200 > parent 3600`, `ceiling max_rows<=250 looser than parent max_rows<=100`). The scope-widening string is unchanged
- `adapters.pydantic_ai`: `DelegationGuard.get_ordering()` adds `wrapped_by=[AbstractCapability]`, so the sorter settles it LAST in every list order — `position="innermost"` alone is a tier whose only tiebreaker is list order, and a sibling innermost execution wrapper could land between it and the raw tool body
- `adapters.pydantic_ai`: the per-call re-read of `ctx.root_capability` is no longer load-bearing — the ordering is the guarantee; it and the construction-time check are belt-and-braces, narrowed to "anything ordered after DelegationGuard in the resolved chain that wraps execution", and a sibling innermost execution wrapper (registered, rebound or per-run-injected) is no longer refused

### Added
- Bundle interop vectors, revision `bundle_vectors_v1.1` — four appended cases: `reject_widened_scope` and `reject_uncontained_allow` (the delegation checks no rejecting case covered), `reject_increased_ttl` and `reject_loosened_ceiling` (the two dimensions the gate above hid); `version` stays `bundle_vectors_v1`
- `tests/vectors/README.md` — the permitted extras two independent runs reported on `reject_duplicate_call_id` (first-sighting vs last-sighting binding) and on `reject_tampered_entry` (stored-head vs recomputed-head), both conformant

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
