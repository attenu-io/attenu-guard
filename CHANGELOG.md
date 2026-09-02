# Changelog

All notable changes to attenu-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Bundle-level interop test vectors (`tests/vectors/bundles/bundle_vectors_v1.json`, shipped in
  the package as `attenu_guard.vectors.load_bundle_vectors()`).** The token vectors have always
  let an independent implementation score its own *token* verifier; there was no equivalent for
  the *bundle* verifier, which is where the offline-verifiability claim actually lands -- an
  auditor checks a published ledger with no engine, no service and no vendor in the loop. Eight
  cases, every one derived from a single valid schema-v2 bundle by exactly ONE change, so each
  isolates one rule: `valid_bundle_v2` (accept), `reject_params_mismatch`,
  `reject_outcome_without_allow`, `reject_outcome_before_allow`, `reject_duplicate_outcome`,
  `reject_duplicate_call_id`, `reject_rehashed_chain` (one entry edited and every later hash
  recomputed -- the rewrite a hash chain alone cannot catch, which only the signed anchor does)
  and `reject_tampered_entry` (the same edit with nothing re-hashed, which fails AT that entry).
  Written by `tests/vectors/generate_bundles.py` on the same single-writer, deterministic,
  stdlib-only discipline as `generate.py`: one serialisation written to both the repository copy
  and the packaged copy, byte-identical by construction, self-checked against this build's own
  `verify_bundle()` before the generator exits 0. Because a bundle verifier reports a LIST of
  failures rather than one reject reason, each rejecting case declares `expect_failures`: the
  MINIMAL set of `{reason, seq, node}` that MUST appear, at that exact position. A conformant
  verifier MAY report more (one broken record often makes a second check unsatisfiable) but never
  fewer and never elsewhere. Format, scoring rule and the byte-level recipe for re-checking an
  entry hash and an anchor signature: `tests/vectors/README.md`.
- **`verify_bundle()` reports `failure_details`, the structured twin of `failures`** (additive;
  `failures` is byte-identical to before, because other implementations parse those strings).
  One dict per string, same order, same count: `{"reason", "seq", "node", "call_id", "detail"}`,
  so a conformance suite can assert WHICH check failed and WHERE instead of matching prose.
  `reason` is the token before the colon in the message, except at the two historical sites whose
  message names a node there (`unreadable_authority`, `unreadable_granted`), which state their
  reason explicitly. Positions are the offending entry's own `seq`/`node`: the second sighting for
  a re-used `call_id`, the `outcome` entry for every allow/outcome binding failure, and null for a
  genuinely chain-level failure such as a signed anchor that no longer matches the ledger head.
  Every failure in `evidence.py` now goes through one collector, so a message cannot be added
  without its twin -- `tests/test_bundle_vectors.py` asserts the two lists stay in step at every
  failure site in the module (including the ones no vector exercises) and traps a direct append.
  The `execution_binding` sub-report's own shape is unchanged: the twins ride alongside it.

## [0.10.0] - 2026-08-31

### Fixed
- **`Guard.check()` (core, `guard.py`) — a `PRE_HOOK_ONLY` allow wedged `complete()` forever.**
  Codex review round 3, finding 1 (critical): `register_pending()` ran unconditionally for
  every v2 `allow`, in both the normal commit path and the `CommittedAuditError` path, with no
  regard for `capture`. A bare `check()` (or any explicit `capture=Capture.PRE_HOOK_ONLY`) is an
  honest promise of NO terminal observation -- nothing is ever going to call `record_outcome()`
  for it -- yet it was registered pending exactly like a `WRAPPER_SYNC`/`WRAPPER_ASYNC`/
  `FRAMEWORK_POST_HOOK` allow, so `complete()` refused forever for a node with only
  `PRE_HOOK_ONLY` calls. This is a defect in the shipped 0.9.0 execution-binding layer itself
  (unchanged before this fix), surfaced -- not caused -- by round 2/3's adapter mode-splits: the
  moment `adapters.crewai`/`adapters.google_adk` shipped a genuinely PRE_HOOK_ONLY default mode
  that real callers would use, this was reachable in ordinary use, not just in a synthetic test.
  The offline verifier already treated a missing `PRE_HOOK_ONLY` outcome as merely `unobserved`
  (`evidence.py`'s `_execution_binding`), so runtime and offline semantics disagreed. Fixed: a
  call is now registered pending only when its capture is one of `WRAPPER_SYNC`/`WRAPPER_ASYNC`/
  `FRAMEWORK_POST_HOOK` -- in both the normal path and the `CommittedAuditError` path. A bare/
  `PRE_HOOK_ONLY` allow never enters the pending set, so `complete()` finalizes immediately, and
  the verifier's `unobserved` classification for it now matches the runtime's own view.
- **`adapters.langgraph` — the SHIPPED, hand-written-node reference-wiring adapter still had an
  aliasing snapshot path, and its own regression test tested a different module.** Release-gate
  finding 1 (CRITICAL). Every OTHER Python adapter went through two rounds of adversarial review
  that closed this exact class of defect; `adapters.langgraph` was never touched by either batch
  (it predates them, as the original reference wiring) and still used raw `copy.deepcopy()` in
  `_snapshot_params`, falling back to the raw (live) dict on failure. A hostile `__deepcopy__`
  reproduced `snapshot["args"][0] is live`, and a later mutation of the live argument changed
  the "snapshot" -- the exact `authorized_params`/`invoked_params` integrity guarantee every
  other adapter's own `_freeze()` exists to hold. Separately, `tests/integrations/
  test_langgraph.py` -- despite its filename and its own module docstring's claim to cover "the
  SHIPPED adapter (`attenu_guard.adapters.langgraph`)" -- imported `attenu_guard.adapters.
  langchain` under an alias (`dg_langgraph`) that made every `GuardedDelegation`-based test in
  the file (the large majority of it) read as testing the shipped `langgraph` module when it was
  actually, correctly, testing `adapters.langchain`; only the NAME was wrong, but it meant this
  regression class had no test coverage anywhere. Fixed: `adapters.langgraph`'s
  `_snapshot_params` now routes through the same shared `attenu_guard.adapters._snapshot.
  freeze()` sanitizer every other adapter uses (see the consolidation entry below); the
  misleading alias in `test_langgraph.py` is renamed to `dg_langchain` with a comment explaining
  what it actually is; and `tests/test_langgraph_adapter.py` (the zero-dependency unit suite
  that genuinely imports `attenu_guard.adapters.langgraph` itself) gained a
  `TestSnapshotHardening` class: the never-aliases-a-custom-`__deepcopy__` regression test every
  other adapter's own test suite already has, a mutation-does-not-cause-a-params-mismatch test
  through the real `guard_node` wrapper, and a circular-container test pinning the shared
  sanitizer's `UNSUPPORTED` marker (see the consolidation entry's own corrections below).
- `adapters.crewai`: outcome correlation was keyed by a thread-local slot (one per OS thread,
  not per dispatch); two async tool calls interleaved on one thread (CrewAI's own async
  executor can do this) could let a later call's `before` hook overwrite an earlier call's still-
  pending outcome. Now keyed by `id(ctx.tool_input)`, the object CrewAI itself threads through
  the before/after hook contexts for one dispatch, held with a strong reference for that
  dispatch's whole span. Also: a THIRD-PARTY `before_tool_call` hook (not this bridge's own) that
  vetoes a call after this bridge already authorized it no longer gets recorded as a fabricated
  `BodyState.RETURNED` -- CrewAI's own literal "blocked by hook" result is recognized and the
  outcome is left unrecorded instead.
  **Round 2 correction (Codex review, finding 1):** three fresh defects. (a) `getattr(ctx,
  "tool_input", None) or {}` substituted a BRAND NEW `{}` literal on every FALSEY `tool_input`
  (a zero-argument tool call) -- CrewAI itself reuses the SAME `{}` object across its own before/
  after hooks even then, so the `or {}` broke correlation entirely for every zero-arg tool
  (allow, no outcome, `complete()==False`). Fixed: `getattr(ctx, "tool_input", {})`, no
  truthiness check, preserves identity on a present-but-falsey value. (b) Two dispatches CAN
  legitimately share one `tool_input` object identity (not just equal content -- e.g. CrewAI's
  own argument-parse caching for identical call text); a single dict slot per key let a second
  such dispatch overwrite the first's still-pending entry. Fixed: `self._pending[key]` is now a
  FIFO `collections.deque`, and `_before_tool_call` passes the EXACT `_Pending` object it just
  appended directly to `_authorize`/`_deny` (never re-looked-up by key), so there is no ambiguity
  for the write side; `_after_tool_call` pops FIFO for the read side, sound because two
  dispatches sharing one identity are semantically symmetric. (c) The third-party-veto path now
  records `BodyState.ABANDONED` (this bridge's own observation was cut short by something
  outside its control) instead of leaving the call unrecorded -- an honest, explicit record beats
  a silently missing one, though `error_code` is NOT attached (`Guard.record_outcome` only
  permits it together with `RAISED`).

  Most importantly, per the execution-binding spec's own governing principle -- an honest
  unobserved beats a promised outcome that can be lost -- `Capture.FRAMEWORK_POST_HOOK` is now
  OPT-IN, not automatic: `CrewAIGuardBridge(..., strict_single_hook=True)` is an explicit
  attestation that this bridge's hooks are the ONLY tool-call hooks registered in the process
  (required for the third-party-veto scenario above to even be a bounded risk rather than an
  open one). The DEFAULT (`strict_single_hook=False`) never passes `capture`/`authorized_params`
  to `guard.check()` at all -- a v2 chain's `allow` is the Guard's own default
  `Capture.PRE_HOOK_ONLY`, and no outcome is ever recorded by this bridge.
  **Round 3 correction (Codex review, finding 2):** round 2's fix (b) above -- the per-key FIFO
  `collections.deque` -- rested on a false theory: that two dispatches sharing one tool+args
  identity are "semantically symmetric", so pairing completions to entries in append order is
  as correct as any other pairing. Codex's reverse-completion repro disproved it: nothing
  guarantees two same-key dispatches COMPLETE in the order they were AUTHORIZED (e.g. a later-
  authorized call blocked near-instantly by an unrelated hook while an earlier one's real tool
  body is still running), and CrewAI gives this bridge no per-dispatch token to tell two
  completions on one key apart -- a wrong FIFO pairing silently cross-binds outcomes (the
  earlier call's `record_outcome` receiving the LATER call's actual result, and vice versa),
  each individually self-consistent and therefore undetectable by the offline verifier. Fixed:
  `self._pending` is a single-slot `dict[int, _Pending]` again, not a queue -- `_before_tool_
  call` now fails CLOSED on a second, concurrent dispatch that finds its key already occupied
  by a still-live entry, denying it outright via `HookAborted` without ever authorizing it or
  giving it a slot to collide with. A `collided` flag on the occupying entry additionally
  closes the one residual this leaves: CrewAI still runs POST_TOOL_CALL for the collision-
  denied call too, and if that fires before the first call's own real completion, it would
  find the first call's entry still resident -- since a collision-denied call can only ever
  itself produce a blocked-looking result, `_after_tool_call` now trusts a `collided` entry's
  completion when it does NOT look blocked (that shape can only be the first call's own real
  result) and leaves it unrecorded, rather than guessing, when it does.
  **Round 4 correction (Codex review, finding 1, critical):** the round-3 fix above still
  popped the slot from `self._pending` UNCONDITIONALLY, before ever classifying whether the
  completion was ambiguous. Exact repro Codex found: A authorized; B, sharing A's object,
  denied via `HookAborted`; B's OWN blocked after-hook (CrewAI still runs POST_TOOL_CALL for a
  call this bridge itself blocked) fires FIRST and pops A's still-live slot, recording nothing;
  A then returns normally, finds no slot, and its promised outcome is silently lost -- one
  `allow`, zero outcomes, `complete()` wedged, A permanently pending in the core Guard. Fixed:
  `_after_tool_call` now PEEKS the slot and classifies BEFORE ever touching `self._pending` --
  a blocked-looking completion on a `collided` entry is left exactly where it is (never popped)
  for a later, trustworthy (non-blocked) completion to consume; only a non-ambiguous completion
  is popped and recorded. The one gap this cannot close: if the surviving call's OWN completion
  is genuinely a third-party veto (a legitimate `ABANDONED`) AND its entry was ever collided,
  that specific combination now permanently leaves the call unrecorded rather than ever
  recording it wrong -- documented in the module docstring's "CORRELATION" as the least-bad
  failure mode available.
- `adapters.openai_agents`: rebuilt on genuine WRAPPER capture (`Capture.WRAPPER_ASYNC`, wrapping
  the tool's own `on_invoke_tool` directly) instead of a second, unreliable `ToolOutputGuardrail`
  that a later `tool_input_guardrails` entry could cause to never run at all (leaving an `allow`
  with no outcome ever recorded, and no way to tell that apart from one merely still in flight).
  Execution binding is now OPT-IN via `guarded_tool(..., registry=...)`: previously an output
  guardrail (and the schema-2 `capture` on `check()`) was attached unconditionally, which changed
  a `schema_version=1` tool's shape (`tool_output_guardrails`) even though behavior was
  unaffected -- a real regression against every adapter's "`schema_version=1` stays byte-and-
  type identical" guarantee. Omitting `registry=` (the default) now never touches the tool at
  all, on any chain.
  **Round 2 correction (Codex review, finding 2):** wrapping `on_invoke_tool` for CAPTURE was not
  enough -- authorization still ran in a SEPARATE `ToolInputGuardrail`, correlated with the
  wrapper via a `tool_call_id`-keyed map. Pinned openai-agents 0.22.0 runs ALL
  `tool_input_guardrails` before invoking anything and returns immediately if a LATER guardrail
  (not this adapter's own) rejects, so `on_invoke_tool` -- and this adapter's wrapper -- was
  never called at all for that dispatch, leaking the map entry (an `allow` with no outcome ever
  recorded). `guard.check()` now runs INSIDE `on_invoke_tool` itself, immediately before invoking
  the original body, in the v2 (`registry=`) path -- no separate guardrail, no correlation map of
  any kind. A denial there raises `AuthorityDenied(decision)` directly (`on_denied="raise"`) or
  returns the denial text as the tool's own output (`on_denied="reject"`, the default) --
  `on_invoke_tool`'s own documented return contract, not `ToolGuardrailFunctionOutput`. If
  authorization never runs at all (a third-party guardrail rejects first, or the SDK never
  invokes `on_invoke_tool` for some other reason), there is now no ledger entry whatsoever for
  that call, not an `allow` with a missing outcome. The v1 (no `registry=`) path is UNCHANGED --
  still the original `ToolInputGuardrail`-based `_authorize_v1`.
- All six new adapters (below): the "immutable snapshot" helper fell back to a shallow `dict(...)`
  copy whenever `copy.deepcopy` failed on any nested value, silently keeping shared references to
  the live, mutable call arguments -- exactly the false-substitution risk the snapshot exists to
  rule out. Replaced with `_freeze()`/`_snapshot_params()`: dicts and lists are always rebuilt
  fresh, recursively; a leaf that cannot itself be deep-copied is replaced by its `repr()` (a new,
  immutable string) rather than shared as-is. Never shares a mutable container.
  **Release-gate correction (Codex review):** "Never raises" (the claim on the line above, as it
  read before this correction) was false -- each of the (then 17) adapter-local `_freeze()`
  copies recursed into a `Mapping`/`(list, tuple, set, frozenset)` value with NO cycle guard at
  all, so a genuinely circular container (a dict containing itself, directly or through a nested
  structure) raised `RecursionError`. Reproduced directly before fixing. Fixed as part of the
  same release-gate pass that consolidated every adapter's own `_freeze()` into ONE shared
  `attenu_guard.adapters._snapshot.freeze()` (see that module's own doc comment): PATH-ACTIVE
  cycle tracking -- the set of container `id()`s on the CURRENT recursion path, passed as a new
  set at each recursive call rather than mutated in place -- reports a genuine cycle as
  `"<circular>"` instead of recursing forever, while correctly NOT flagging a DAG's repeated
  reference (the same container appearing twice as sibling values, not an ancestor of itself) as
  circular. `adapters.langgraph` -- the original, hand-written reference-wiring adapter,
  untouched by either earlier adversarial-review batch -- was migrated onto this same shared
  sanitizer in the same pass; it had been using raw `copy.deepcopy()` with a live-object
  aliasing fallback the whole time (see the separate CRITICAL finding below).
  **Round 2 correction (Codex review, finding 4):** that first fix still tried `copy.deepcopy(value)`
  wholesale before falling back to the rebuild -- but a mutable class can implement `__deepcopy__`
  to hand back `self` (or another object it still owns), so `deepcopy` *succeeding* was never proof
  the result was independent of the live object graph. `_freeze()` now never calls `copy.deepcopy`,
  or any copy protocol, on anything: containers (`dict`/`list`/`tuple`/`set`/`frozenset`) are
  always rebuilt from scratch as fresh builtins; only already-immutable leaf types
  (`str`/`int`/`float`/`bool`/`None`/`bytes`) are kept as-is; everything else becomes its `repr()`.
  **Re-gate correction (HIGH, symmetry with the TS adapter's own re-gate fix):** "everything else
  becomes its `repr()`" (the line above, as it read before this correction) was itself an
  attacker-controlled-code-execution defect, not a fix -- `repr(value)` invokes the value's own
  `__repr__`, unconditionally, BEFORE authorization is ever decided; reproduced directly: a
  hostile class's `__repr__` override genuinely executed during `freeze()`. Its own
  `except Exception:` fallback was no better: `f"<unrepresentable {type(value).__name__}>"` is a
  JSON-representable STRING, and a real dict value that happens to equal that exact literal
  freezes to itself unchanged (strings pass through verbatim) -- producing the IDENTICAL frozen
  shape, and therefore the identical `params_c14n_v1` commitment, as the exotic value it was
  meant to stand in for. Reproduced directly: `freeze({"arg": Explodes()})` (a class whose
  `__repr__` raises) and `freeze({"arg": "<unrepresentable Explodes>"})` (an ordinary string
  argument) produced the exact same output. Audited `"<circular>"` (the genuine-cycle sentinel
  above) for the identical collision class rather than leaving it unexamined -- it has the same
  problem. Fixed the same way the TS adapter's own `freeze()` was: anything whose EXACT type is
  not `None`/`str`/`int`/`float`/`bool` and not a `Mapping`/list-family container becomes
  `UNSUPPORTED`, a module-private sentinel OBJECT (never a string, so it cannot collide with any
  real call argument by construction) -- without calling `repr()`, `str()`, or any other
  protocol. `bytes` now routes to `UNSUPPORTED` too, deliberately: it was already outside the
  `params_c14n_v1` domain regardless (`canonical.dumps` has no `bytes` case, so it already raised
  `UnsupportedTypeError` for it), so this changes nothing about the final commit outcome, only
  stops the raw snapshot from retaining a live `bytes` reference for no purpose -- checked
  directly that no shipped adapter inspects the raw snapshot for anything besides handing it to
  `params.commit()`. The whole container walk now runs inside one `try`/`except`, degrading any
  reflection/iteration failure to `UNSUPPORTED` too, rather than letting an exception propagate
  out of a snapshot taken before authorization. A genuine cycle's own leaf value is `UNSUPPORTED`
  now as well, not `"<circular>"` -- the same collision class, the same fix. `UNSUPPORTED`
  anywhere in the frozen tree already degrades the whole `params_c14n_v1` commitment to
  `params_hash_reason: "unsupported"` via `canonical.dumps`'s own exact-type dispatch (no case
  for `UNSUPPORTED`'s type) -- no separate wiring needed; verified directly. Six adapter test
  suites (`autogen`, `crewai`, `google_adk`, `haystack`, `openai_agents`, `pydantic_ai`) had a
  test asserting the unclonable-leaf fallback was a `str` -- updated to assert it `is
  UNSUPPORTED` instead, the representation having deliberately changed; every adapter's own
  never-aliases-a-custom-`__deepcopy__` test (a DIFFERENT invariant, unaffected by this fix)
  still passes unchanged.
  **Final-check correction:** the "EXACT type" gate above originally read
  `isinstance(value, (str, int, float, bool))`, which -- despite the CHANGELOG text above already
  saying "EXACT type" -- was not actually one: `isinstance` admits a SUBCLASS of any of those
  too, and a subclass instance can carry its own mutable attributes. Reproduced directly:
  `freeze(boxed) is boxed` was `True` for a `str` subclass with a mutable list attribute --
  the fast path passed it through completely unchanged, aliasing the live object.
  `params.commit()`'s own disposition was never wrong either way (`canonical.dumps` already
  gates on EXACT type there, so a subclass already fell through to `UnsupportedTypeError`/
  `"unsupported"` downstream regardless), but the raw snapshot itself retained a live, mutable
  reference, violating the never-alias invariant every leaf here is supposed to hold. Fixed by
  actually matching `canonical.dumps`'s own domain: `type(value) in (str, int, float, bool)`.
  Tests added: a `str` subclass and `int`/`float` subclasses each become `UNSUPPORTED` (asserted
  by identity), never the live reference, with zero protocol calls (`__str__`/`__repr__`
  overrides on the subclass asserted uncalled); a plain-primitives-still-pass-through test
  pinning the fix did not become over-strict; and a wrapper-level test through the real
  `guard_node` asserting `params_hash_reason: "unsupported"` end to end.
- `adapters.google_adk`: `after_tool_callback` now checks `tool.is_long_running`/
  `tool._defers_response` -- the SAME flags ADK's own `functions.py` checks -- before deciding
  `RETURNED` vs `BodyState.DEFERRED`; a long-running/deferring tool's placeholder response was
  previously always recorded `RETURNED`. Pending-outcome insertion is now `.setdefault`-style
  (never silently overwrites a colliding, still-unconsumed key). Documents (module docstring,
  "HONESTY NOTES") three genuine, structural gaps in ADK's plugin/callback surface that this file
  cannot close without going outside documented hooks: a caller's own AGENT-level
  `before_tool_callback=` substituting a response (undetectable from `after_tool_callback`, and
  the one gap that CAN record a wrong `RETURNED` rather than merely leaving a call unobserved);
  `asyncio.CancelledError` (a `BaseException`, so neither the error nor after callback ever fires
  -- there is no hook to record `ABANDONED` from); and `PluginManager`'s stop-at-first-non-None
  dispatch, where an earlier-registered THIRD-PARTY plugin overriding the result prevents this
  plugin's own callback -- and so its outcome close-out -- from ever running. Its module
  docstring now also documents `duration_ms` as an observation window (`check()` to whichever
  callback fires), not a body-execution timer, matching `Guard.record_outcome`'s own contract.
  **Round 3 correction (Codex review, finding 3):** the three documented gaps above are real
  on pinned 2.7.1, and documenting them did not make `Capture.FRAMEWORK_POST_HOOK` an honest
  claim for every call -- the plugin still promised it unconditionally. Per the execution-
  binding spec's own governing principle -- an honest unobserved beats a promised outcome that
  can be lost -- `FRAMEWORK_POST_HOOK` is now OPT-IN, exactly like the round 2 fix already
  applied to `adapters.crewai`: `DelegationGuardPlugin(..., strict_single_hook=True)` is an
  explicit attestation that this plugin is registered first (or alone) for tool callbacks on
  the `App`/`Runner`, and that no agent in the tree substitutes a response via a canonical
  `before_tool_callback=`. The DEFAULT (`strict_single_hook=False`) never passes `capture`/
  `authorized_params` to `guard.check()` at all -- a v2 chain's `allow` is the Guard's own
  default `Capture.PRE_HOOK_ONLY`, and `_pending_outcomes` is never populated. Also fixed, in
  strict mode: the module docstring claimed the pending entry "holds a strong reference to
  `tool_context` for its whole span", but `_PendingOutcome` never actually stored the object --
  only `id(tool_context)` was kept, as the dict key, which nothing referenced the object back
  from. `_PendingOutcome` now carries a `tool_context: ToolContext` field so the pinned-alive
  claim is genuinely true, not merely asserted in a comment.
- `adapters.haystack`: a delegation `ToolPolicy` that declares BOTH a real `scope` and
  `delegates_to`/`grant` (unusual, but the dataclass allows it) calls `guard.check()` for itself
  first, exactly like any other guarded tool -- but `_ToolGuard.scope()` discarded that
  already-registered pending outcome when building the delegation's child scope, leaving the
  call_id pending forever and wedging `complete()`. Now carried through unchanged; the existing
  test only exercised `UNGUARDED` (`scope=None`) delegation, which never hit this branch.
- `adapters.pydantic_ai`: `DelegationGuard.before_tool_execute`/`wrap_tool_execute` correlation
  was ordering-dependent when other capabilities are also registered on the same agent --
  `CombinedCapability` composes `before_tool_execute` sequentially in the capabilities' LISTED
  order and `wrap_tool_execute` as nested middleware in that same order, so a capability
  positioned "after" `DelegationGuard` could raise once this one had already stashed a pending
  outcome (leaking it), or wrap the raw tool body such that DelegationGuard's own `wrap_tool_
  execute` was catching an INNER capability's failure and misreporting it as `BodyState.RAISED`
  for a body that never ran. `DelegationGuard.get_ordering()` now declares `position="innermost"`
  (pydantic-ai's own `CapabilityOrdering`, topologically sorted regardless of listed order):
  every OTHER capability's `before_tool_execute` now runs first (so if one raises, this one's own
  before_tool_execute -- and its pending-outcome stash -- never runs either, and nothing leaks),
  and the `handler` this capability's `wrap_tool_execute` receives is always the raw tool
  invocation, never another capability's own wrapping. The docstring also now explicitly warns
  against using both `DelegationGuard` and `GuardedToolset` on the same tool (two independent,
  complete authorization paths -- two `allow`/`outcome` pairs on the ledger for one body).
  **Round 2 correction (Codex review, finding 5):** `innermost` is a TIER, not a unique position
  -- pydantic-ai 2.31.1's sorter places every `innermost` capability after every non-innermost
  one, but preserves LISTED order among MULTIPLE `innermost` capabilities, so
  `[DelegationGuard, OtherInnermost]` left `DelegationGuard` authorizing first and wrapping
  around `OtherInnermost`'s own middleware -- reproducing both the leaked-pending-entry and the
  false-`RAISED` defects. Fixed structurally, not by ordering alone: authorization and outcome-
  recording collapsed into ONE operation, entirely inside `wrap_tool_execute` -- there is no
  `before_tool_execute` override, and no `_pending` map, at all any more. If some OTHER
  capability's `before_tool_execute` (or an outer `wrap_tool_execute`) raises before this one's
  own `wrap_tool_execute` is ever reached, `guard.check()` simply never ran either -- no allow,
  no leak, nothing false. The residual (a SECOND `innermost`-positioned capability whose own
  `wrap_tool_execute` raises before calling its own handler, which this one's `handler` would
  then be) is documented in the class docstring as a genuine limit of pydantic-ai's own ordering
  guarantee -- `wraps`/`wrapped_by` reference specific other capability types/instances this
  file cannot know in advance for an arbitrary caller-supplied capability. Also: `DelegationGuard`
  + `GuardedToolset` dual instrumentation is now REJECTED (not just documented) at AGENT
  CONSTRUCTION time via `DelegationGuard.for_agent()`, which walks `agent.toolsets` (unwrapping
  `WrapperToolset` chains) for a `GuardedToolset` instance -- undetectable only for a
  `GuardedToolset` built and used entirely dynamically, never listed in `agent.toolsets` at all.
  **Round 3 correction (Codex review, finding 3):** the SECOND-`innermost`-capability residual
  documented (not fixed) in round 2 above was real, and documenting it did not stop it: a live
  probe against pinned 2.31.1 confirmed a sibling `innermost` capability's own pre-handler
  failure gets misreported here as `BodyState.RAISED` for a body `DelegationGuard` never
  reached (the raw body's own side-effect sink stayed empty). `for_agent()` now ALSO rejects
  this combination at agent construction time, the same way it already rejects `DelegationGuard`
  + `GuardedToolset`: it walks `agent.root_capability.capabilities` (populated for every sibling
  by pydantic-ai's own two-phase `bind_capabilities_tier`, verified directly against pinned
  2.31.1) for any OTHER capability whose `get_ordering().position == "innermost"` AND that
  overrides `wrap_tool_execute` (the same `type(x).method is not Base.method` idiom pydantic-ai
  uses internally for its own `_has_wrap_node_run`), and raises `UserError` naming it -- for
  EITHER list order, since pinned 2.31.1's innermost tier has no ordering edges among its own
  members, only list order as a tiebreaker. Undetectable only for a capability added entirely
  dynamically, per-run (`for_run()`, never declared in the agent's own `capabilities=[...]`) --
  the same category of limit as the dynamic-`GuardedToolset` case, documented on `for_agent()`.
  **Round 4 correction (Codex review, finding 2, high):** the round-3 construction-time check
  is a fast path, not the guarantee it was treated as. Pinned pydantic-ai 2.31.1 binds the
  `innermost` tier through ONE list comprehension and does not update `agent.root_capability`
  until the WHOLE call returns, so a sibling whose own `for_agent()` REBINDS to a replacement
  that wraps execution (its originally-registered instance did not) is invisible to
  `for_agent()` -- a live probe confirmed construction succeeds in both list orders, and the
  adverse order still reaches the misreported-`RAISED` defect. There is also a public per-run
  bypass this hook cannot see at all: `agent.run(..., capabilities=[OtherInnermostWrapper()])`
  adds capabilities AFTER static `for_agent()` has already run; that repro likewise recorded a
  false `RAISED` with the raw body sink empty. Fixed: `wrap_tool_execute` now runs the SAME
  conflict check again, at the very start of every call, against the ACTUAL resolved
  `ctx.root_capability` (`RunContext.root_capability` -- pydantic-ai's own documented mechanism
  for validating per-run additions, confirmed by a live probe to reflect both adversarial cases
  correctly) -- BEFORE `_resolve()` or `guard.check()` ever run, so a rejection writes nothing
  to the ledger. `for_agent()`'s construction-time check stays as the friendly, early-failing
  fast path for the common case it CAN see; `wrap_tool_execute`'s runtime check is the real
  guarantee. One structural asymmetry surfaced while testing this: in the list order where the
  conflicting sibling is OUTER of `DelegationGuard` (not INNER, the shape the original defect
  needs), `DelegationGuard`'s own `wrap_tool_execute` -- and so its new runtime check -- never
  even runs, because the outer sibling raises before ever calling its own handler; the raw
  exception from the sibling propagates untouched instead of `DelegationGuard`'s `UserError`,
  but the ledger is still untouched either way, since `DelegationGuard`'s own code never ran.
- `adapters.autogen`: `GuardedWorkbench.call_tool_stream` recorded no outcome at all when a
  consumer closed the stream early (one event consumed, then `.aclose()`/GC) -- `GeneratorExit`,
  raised inside the generator at its suspended `yield`, is a `BaseException`, bypassing the
  `except Exception`/`else` split entirely, despite the call's `allow` advertising
  `Capture.WRAPPER_ASYNC` (a promise this adapter CAN keep here, since it does observe the
  closure). Added an `except GeneratorExit` arm recording `BodyState.ABANDONED` before
  re-raising (required by Python's own generator protocol). Also fixes the snapshot fallback
  (finding 7), matching the other five adapters.
- **Two machine-specific path leaks, release-gate finding 3.** `tools/render_demo_gif.py`'s
  ffmpeg discovery fell back to a hardcoded absolute path to a Homebrew-installed binary when
  `shutil.which("ffmpeg")` came up empty -- `shutil.which` already checks every directory on
  PATH, including a Homebrew bin dir when it is actually on PATH, so the hardcoded fallback only
  ever helped on one specific machine's non-PATH install while leaking that machine's own
  layout into the repo; removed, with `shutil.which`'s own result used directly (and its
  possible `None` handled explicitly, which the old code did not do either).
  `examples/integrations/claude_sdk/live_smoke.py` had a code comment naming the user's home
  directory's Claude settings path by its shorthand notation; reworded to describe the same
  SDK-isolation behavior (`setting_sources=[]`) without a path-shaped string. Semantic path
  fixtures used as test data elsewhere in the tree (`/tmp`, `/etc`, `/usr/bin`, `/opt/homebrew`)
  and file shebangs are unaffected -- they are not machine-specific leakage.

### Added
- Execution binding (`record_outcome`, 0.9.0) wired into six more adapters, on a
  `schema_version=2` chain (unchanged, byte-and-type identical to before, on `schema_version=1`),
  each choosing the most honest capture its framework's real hook surface supports:
  - `adapters.crewai`: `Capture.FRAMEWORK_POST_HOOK`, OPT-IN via `CrewAIGuardBridge(...,
    strict_single_hook=True)` (see the "Fixed" section's round 2 entry) -- the bridge never
    calls the tool body itself; in strict mode the outcome is closed out from CrewAI's own
    `after_tool_call` post hook, which fires for every dispatch path including a blocked call.
    `BodyState.RAISED` is never reported: CrewAI's `ToolUsage.use`/`ause` catches every tool
    exception internally and turns it into a formatted string before the post hook ever runs, so
    a raise and an ordinary return are indistinguishable at the one hook point this adapter has.
    `duration_ms` is an observation window (before-hook to after-hook), documented as such, not a
    body-only timer. The default (`strict_single_hook=False`) is `Capture.PRE_HOOK_ONLY` with no
    outcome ever recorded.
  - `adapters.openai_agents`: `Capture.WRAPPER_ASYNC`, OPT-IN via `guarded_tool(..., registry=...)`
    -- `registry.root_guard.schema_version` is checked once, at build time (a whole-chain property),
    to decide whether to replace the tool's `on_invoke_tool` with a wrapper that calls the original
    directly and observes completion itself, exactly like `adapters.langgraph`'s reference wiring.
    `BodyState.RAISED` (with `error_code`) is reached only when the wrapped tool's own
    `on_invoke_tool` genuinely lets the exception through (e.g. `failure_error_function=None`); the
    SDK's *default* `failure_error_function` still catches it first and returns an error string, so
    the honest result there is `RETURNED`, same as CrewAI. `BodyState.ABANDONED` on
    `asyncio.CancelledError` is reliably reached either way (cancellation is a `BaseException`, not
    caught by the SDK's own `except Exception`). A later `tool_input_guardrails` entry (not this
    adapter's own) rejecting the call after this one authorized it means `on_invoke_tool` -- ours or
    the original -- is simply never called, so nothing is fabricated for a body that never ran.
    `guarded_agent_tool()`'s delegation-scope check and `guarded_handoff()`/`DelegationGuardHooks`
    mint via `Guard.delegate()`, not a tool body, so they stay the library's default `pre_hook_only`.
  - `adapters.google_adk`: `Capture.FRAMEWORK_POST_HOOK`, OPT-IN via `DelegationGuardPlugin(...,
    strict_single_hook=True)` (see the "Fixed" section's round 3 entry) -- the plugin never
    calls the tool body itself; in strict mode the outcome is closed out from ADK's own
    `after_tool_callback`/`on_tool_error_callback`, and (unlike CrewAI and the OpenAI Agents
    SDK) ADK does NOT swallow a tool's exception before its error hook runs, so this is the one
    adapter of the six that genuinely observes and reports `BodyState.RAISED` (with
    `error_code`) for calls whose error hook fires. The two hooks correlate their pending state
    with `_authorize()`'s `check()` via `id(tool_context)`, and (strict mode) the pending entry
    itself holds a strong reference to that same `tool_context` object. Applies uniformly to
    both the tool check and the delegation-scope check (`delegation_scope=...`), since both go
    through `_authorize()` and both are real ADK tool calls with the same before/after/error
    lifecycle. The default (`strict_single_hook=False`) is `Capture.PRE_HOOK_ONLY` with no
    outcome ever recorded. See the "Fixed" section above for three documented, structural gaps
    in ADK's own callback surface that strict mode's observation still cannot guarantee around.
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
  - `adapters.autogen`: `Capture.WRAPPER_ASYNC` on `GuardedWorkbench.call_tool`/`call_tool_stream`,
    which call `super().call_tool(...)`/`super().call_tool_stream(...)` themselves, like the
    langgraph reference wiring. Unlike every other adapter, a delegation-marked tool
    (`policy.delegates_to`, the agents-as-tools pattern) STILL gets execution binding here: its
    body (the nested run) genuinely executes through this same call, unlike a `Swarm` handoff
    (`GuardedHandoff`), which AutoGen runs entirely outside the workbench and so never calls
    `guard.check()` at all. `BodyState.RAISED` is never reported: AutoGen's own
    `StaticWorkbench.call_tool`/`StaticStreamWorkbench.call_tool_stream` already catch every
    tool exception and return/yield a `ToolResult(is_error=True)` instead of letting it
    propagate, so a raise and an ordinary return are the same shape by the time this wrapper
    resumes -- every completed call is `BodyState.RETURNED`. `asyncio.CancelledError` is NOT
    caught by AutoGen's own `except Exception`, so it DOES propagate; `BodyState.ABANDONED` is
    genuinely reachable and is still re-raised.
- Execution binding (`record_outcome`, 0.9.0) wired into `adapters.langchain` (LangGraph 1.x /
  LangChain 1.x `create_agent` / deepagents), on a `schema_version=2` chain (unchanged, byte-
  and-type identical to before, on `schema_version=1`): `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC`
  from `GuardedDelegation.wrap_tool_call`/`awrap_tool_call` respectively -- both call the tool
  body (`handler(request)`) themselves, exactly like `adapters.langgraph`'s reference wiring.
  `authorized_params`/`invoked_params` are one immutable snapshot (`_freeze()`, never a copy
  protocol) taken before `handler` runs. `BodyState.RAISED`/`ABANDONED` (on
  `asyncio.CancelledError`, re-raised) are both genuinely observed on the async path; no shared,
  cross-call correlation state exists at all (unlike the hook-based adapters above), since the
  decision/snapshot travel through the call stack in a local `_Gate`, not a dict keyed by object
  identity -- so same-tool-concurrency and later-hook-block classes of defect are structurally
  inapplicable here. A delegation tool call (`task`) mints the child via `guard.delegate()`,
  which never calls `guard.check()` at all -- no `Decision`/`call_id` exists to bind an outcome
  to, so it is unaffected by any of this.
  **Round 2 correction (Codex review, batch 2, finding 1):** the original claim that
  `handler(request)` "genuinely observes completion... with no cross-hook honesty caveat" was
  wrong for the `create_agent(middleware=[...])` entry point. Verified directly against pinned
  `langchain.agents.factory._chain_tool_call_wrappers`: `ToolNode(wrap_tool_call=...)` accepts
  exactly ONE wrapper so `handler` IS genuinely the raw body on that path, but `create_agent`
  composes EVERY registered middleware's `wrap_tool_call` into one chain ("first = outermost"),
  and LangChain ships middleware (`tool_retry.py`, `tool_emulator.py`) explicitly designed to
  call the inner handler zero, one, or several times. `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` is
  now OPT-IN via `GuardedDelegation(..., strict_single_hook=True)`, an attestation that this
  adapter is the ONLY `wrap_tool_call`-implementing middleware in use (true by construction on
  the `ToolNode` path). The default (`strict_single_hook=False`) is `Capture.PRE_HOOK_ONLY` with
  no outcome ever recorded, safe regardless of what else is composed.
- Execution binding wired into `adapters.llama_index` (LlamaIndex `AgentWorkflow`/
  `FunctionAgent`), same terms: `Capture.WRAPPER_ASYNC` from `guarded_tool()`'s `_guarded()`
  wrapper, which `await`s the target itself. `authorized_params`/`invoked_params` are one
  `_freeze()` snapshot of the ORIGINAL model-supplied kwargs, taken before the framework's own
  `ctx` argument is injected and before the target runs. `BodyState.RAISED`/`ABANDONED` (on
  `asyncio.CancelledError`, re-raised) are both genuinely observed. The handoff tool
  (`_guarded_handoff`) mints the child via `parent.delegate(...)`, which never calls
  `guard.check()` -- unaffected, on any schema version, same as the delegation tool above.
- Execution binding wired into `adapters.smolagents`, same terms: `Capture.WRAPPER_SYNC` from
  `GuardedTool.forward()`, which calls the inner tool (`self.inner(*args, **kwargs)`) itself --
  smolagents only ever calls `forward` synchronously, so there is no async variant to wire.
  `_freeze()` snapshot of `{"args": [...], "kwargs": {...}}`, taken before the inner tool runs.
  `BodyState.RAISED` (with `error_code`) is genuinely observed -- smolagents does not swallow a
  tool's exception before `forward`'s own caller sees it. `DelegatedAgent.mint()` mints the
  child via `parent_guard.delegate(...)`, which never calls `guard.check()` -- unaffected.
  - **Round 2 correction (Codex review, batch 2, finding 5):** on a clean return, this adapter
    recorded `BodyState.RETURNED` unconditionally, without checking what the inner tool's own
    return value actually was. Wrong when the inner tool's own `forward()` implementation is a
    generator function (uses `yield`): pinned smolagents 1.26.0's `Tool.__call__` returns
    unknown result types unchanged, so calling a generator function returns a generator OBJECT
    immediately, with none of its body executed yet -- ordinary Python generator semantics,
    nothing smolagents-specific, and this wrapper has no way to know whether or when it will
    ever be iterated. Added the shared `_is_deferred_result`/`_body_state_for` pattern every
    other adapter in this package already uses for its own generator/streaming case (`return
    inspect.isgenerator(result) or inspect.isasyncgen(result)`, matching `adapters.haystack`/
    `pydantic_ai`'s simpler sync-appropriate form rather than the fuller async-Future-checking
    one, since smolagents genuinely has no async entry point here). `GuardedTool.forward()`'s
    final `record_outcome()` now reads `_body_state_for(result)` instead of a hardcoded
    `BodyState.RETURNED`. Test added: `test_v2_a_tool_returning_a_generator_records_a_deferred_
    outcome` -- a `StreamingCrmQuery` tool whose `forward()` is a generator function, driven
    directly through `GuardedTool` (the same direct-construction pattern
    `test_metered_passthrough_under_strict_metering` already uses); asserts the returned value
    is a live, unconsumed generator, the tool's own side effect has NOT happened yet, and the
    recorded `body_state` is `DEFERRED`, not `RETURNED`.
  - **Round 3 correction (a parallel adversarial review):** `_is_deferred_result()` checked
    `isgenerator()`/`isasyncgen()` but not a coroutine -- the same class of gap, just for a
    tool whose own `forward()` implementation is `async def` rather than a generator function.
    Calling it plainly (`self.inner(*args, **kwargs)`, no `await` anywhere in this synchronous
    wrapper) returns a coroutine object with none of its body run yet;
    `BodyState.RETURNED` would be exactly as much of a lie as in the generator case. Currently
    UNREACHABLE through pinned smolagents' own sync-tool contract (nothing in this adapter
    ever awaits the result, so a caller relying on this adapter alone would never see the gap
    trigger), but a caller-supplied `Tool` subclass is free to define an async `forward`
    regardless of what smolagents itself calls for -- closing it costs one line and removes the
    gap before it can ever surface, rather than leaving it live on an unstated assumption about
    what callers will or won't hand this adapter. Added `inspect.isawaitable(result)` to
    `_is_deferred_result()` -- a strict superset of `iscoroutine()` that also covers
    Future-like awaitables and generator-based coroutines with the one check; the "no async
    entry point" reasoning in the Round 2 bullet above justified skipping this check, which
    was too narrow -- the WRAPPER has no async entry point, but a tool's own implementation
    is not constrained by that. Test added:
    `test_v2_a_tool_returning_a_coroutine_records_a_deferred_outcome` -- an `AsyncCrmQuery`
    tool whose `forward()` is `async def`, driven the same way as the generator test; asserts
    the returned value is a live, un-awaited coroutine, the tool's own side effect has NOT
    happened yet, and the recorded `body_state` is `DEFERRED`.
  - **Round 4 correction (Codex re-pass on the batch):** `isawaitable()` (Round 3, above)
    covers coroutines and `asyncio.Future` (which implements `__await__`) but deliberately
    NOT `concurrent.futures.Future` -- a thread-pool future a sync `forward()` could hand
    back after merely SUBMITTING work, without waiting for it. Verified directly before
    writing the fix: `inspect.isawaitable(concurrent.futures.Future())` is `False` --
    confirming the gap was real, not assumed. Added an explicit
    `isinstance(result, (asyncio.Future, concurrent.futures.Future))` check alongside
    `isawaitable()` (the `asyncio.Future` half is redundant with `isawaitable()` but kept
    for parity with every other adapter's own "fuller" `_is_deferred_result()` form).
    `_is_deferred_result()` now covers the complete lazy-result family this package
    checks anywhere: generators, async generators, awaitables (coroutines included), and
    both Future families. Two tests added:
    `test_v2_a_tool_returning_an_asyncio_future_records_a_deferred_outcome` and
    `test_v2_a_tool_returning_a_concurrent_futures_future_records_a_deferred_outcome` --
    the latter asserts `not inspect.isawaitable(result)` first, so the test is only
    meaningful if `isawaitable()` genuinely misses the type it is meant to catch.
- Execution binding wired into `adapters.strands` (AWS Strands Agents), OPT-IN via
  `DelegationGuard(..., strict_single_hook=True)`: this adapter never calls the tool body
  itself, but pinned strands-agents 1.52.x's `AfterToolCallEvent` is an unusually good hook
  surface -- `HookRegistry.invoke_callbacks`/`_async` runs every registered callback
  unconditionally (unlike Google ADK's plugin manager, no other hook can prevent this one's
  own `after_tool_call` from running), and `tool_use["toolUseId"]` is a genuinely UNIQUE
  identifier per dispatch (not an object-identity collision risk CrewAI-style). `Capture.
  FRAMEWORK_POST_HOOK` closes out from `AfterToolCallEvent.exception`/`cancel_message` --
  `BodyState.ABANDONED` (no `error_code`) for a third-party veto after this adapter's own
  allow (this adapter's own denial never stashes a pending entry, so a later `cancel_message`
  can only mean that), `BodyState.RAISED` (with `error_code`) otherwise. The default
  (`strict_single_hook=False`) is `Capture.PRE_HOOK_ONLY` with no outcome ever recorded --
  despite the strong hook surface, still opt-in, because pinned 1.52.x's retry mechanism
  (`AfterToolCallEvent.retry`) genuinely can discard an already-recorded outcome, and a
  tool-originated interrupt skips `AfterToolCallEvent` entirely; both are documented as strict-
  mode residuals in the module docstring rather than silently promised away.
  - **Round 2 correction (Codex review, batch 2, finding 6):** "`HookRegistry.invoke_callbacks`/
    `_async` runs every registered callback unconditionally" was read, correctly, as claiming
    `AfterToolCallEvent` fires unconditionally, full stop -- verified against pinned 1.52.x
    source to be FALSE. That claim was only ever true on the axis the `AfterToolCallEvent`
    docstring quote actually describes (the tool BODY's own success/failure/cancellation); it
    says nothing about whether the event is DISPATCHED AT ALL, which depends on the BEFORE-hook
    phase completing without incident. Three lost-terminal paths exist, verified directly against
    `strands/tools/executors/_executor.py`'s `ToolExecutor.stream` and
    `strands/hooks/registry.py`'s `HookRegistry.invoke_callbacks_async`, each reproduced with a
    throwaway `HookProvider` sibling standalone before being written up: (1) a LATER-registered
    `before_tool_call` hook raises `InterruptException` -- `invoke_callbacks_async`'s
    per-callback loop catches only `InterruptException`, converting it into the returned
    `interrupts` list; `stream()` short-circuits to `ToolInterruptEvent` + `return` BEFORE its own
    inner `try:` that would call `_invoke_after_tool_call_hook` is ever entered, so this
    adapter's already-stashed pending entry is never popped -- reproduced directly (`agent(...)`
    returns normally, `Guard.complete()` reports `completed=False` with that call's `call_id`
    still pending), and UNLIKE the tool-originated-interrupt case, not reliably self-healing on
    resume either (`self._pending` is keyed by `toolUseId`; a fresh allow on retry OVERWRITES the
    same key, silently orphaning the first `call_id` forever). (2) An ORDINARY (non-`Interrupt
    Exception`) exception from a `before_tool_call` hook registered to run AFTER this adapter's
    own -- `invoke_callbacks_async`'s loop does not catch a plain exception at all, so it
    propagates out of `ToolExecutor.stream()` itself as an unhandled exception (that call is
    BEFORE `stream()`'s own inner `try`/`except`); reproduced directly: `agent(...)` raises
    `EventLoopException`, and the pending entry is wedged exactly as in (1). (3) The SAME
    exception from a hook registered to run BEFORE this adapter's own -- the per-callback loop
    stops at the first uncaught exception, so this adapter's own `before_tool_call`/
    `evaluate_tool_call` never runs for that call at all: no `guard.check()`, no allow/deny
    logged, no pending entry created; reproduced directly: fail-safe for authorization (the tool
    body does not run either, since the same exception aborts the whole dispatch before the
    tool-execution stage), but the attempt leaves NO record in this adapter's ledger at all, not
    even a denial. A fourth, narrower risk found during the same verification pass but not one
    of the three named: `AfterToolCallEvent` DOES use `should_reverse_callbacks = True`, so an
    ordinary exception from a sibling `after_tool_call` callback that runs EARLIER than this
    adapter's own (by virtue of being registered LATER) can wedge this adapter's own
    `after_tool_call` by the identical uncaught-exception mechanism, one hook-type over --
    documented, not given a separate test, since it is structurally identical to path (2).
    **Considered and rejected: whether strict mode should fail closed on a detectable
    interrupt.** It should not -- none of these three paths are an authorization gap
    (`guard.check()`'s `allow`/`deny` `Decision` is already correctly committed before any of
    this can happen; what is lost is only the later outcome-observation, an audit-completeness
    concern, not an enforcement bypass), and there is no hook this adapter can install to detect
    "a sibling before-hook is about to raise" ahead of time to act on. `Guard.complete()`/the
    offline verifier already surface a wedged `call_id` honestly as incomplete, never as a
    fabricated success -- the same posture already established for the tool-originated-interrupt
    case. Rewrote the module docstring's "EXECUTION BINDING" intro with this correction and all
    three paths; no code change was needed (the underlying `strict_single_hook` mechanism and
    `after_tool_call`'s own handling were already correct -- this was a documentation-accuracy
    finding, not a logic bug). Tests added in `tests/integrations/test_strands.py`:
    `test_v2_strict_mode_a_later_before_hook_interrupt_wedges_the_pending_entry`,
    `test_v2_strict_mode_a_later_before_hook_ordinary_exception_wedges_the_pending_entry`,
    `test_v2_strict_mode_an_earlier_before_hook_exception_means_this_adapter_never_ran` -- each
    reproduces its path with a throwaway sibling `HookProvider`, verified standalone before being
    written up as a permanent regression test.
- Execution binding wired into `adapters.camel` (CAMEL-AI), same terms as `adapters.langchain`/
  `llama_index`/`smolagents`: `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` from `GuardedFunctionTool.
  __call__`/`async_call`, which call the inner tool themselves. `_freeze()` snapshot of
  `{"args": [...], "kwargs": {...}}`, taken before the inner tool runs. `BodyState.RAISED`
  (with `error_code`) is genuinely observed on both paths; `asyncio.CancelledError` on the
  async path is `BodyState.ABANDONED`, still re-raised. `GuardedAgentToolkit.mint()` goes
  through `parent_guard.enforce(...)`, which never returns a `Decision`/`call_id` -- delegation
  is unaffected by any of this. **Also fixed**, unrelated to execution binding: the `camel`
  extra's `mcp<3` pin was stale -- camel-ai 0.2.90 imports `mcp.server.FastMCP`, renamed to
  `MCPServer` in mcp 2.x (mcp's own migration guide recommends `mcp<2`), so `pip install
  'attenu-guard[camel]'` was broken on a clean install; corrected to `mcp<2`.
- Execution binding wired into `adapters.agno`: `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` from
  `guarded_tool_hook`/`aguarded_tool_hook`, which call `function_call(**arguments)`/`await
  function_call(**arguments)` themselves. `_freeze()` snapshot of the model-supplied
  `arguments`, taken before `function_call` runs. `BodyState.RAISED` (with `error_code`) is
  genuinely observed on both paths when the attestation below holds; `asyncio.CancelledError`
  on the async path is `BodyState.ABANDONED`, still re-raised. `authorize()` (shared by both
  hook flavours) returns `(guard, call_id, snapshot)` instead of `None`, threading `capture=`
  through from each hook since they share one authorization function. `delegation_tool_hook`/
  `adelegation_tool_hook` mint via `parent.delegate(...)`, which never calls `guard.check()` --
  unaffected.
  **Round 2 correction (Codex review, batch 2, finding 1):** the original claim that a hook
  never calling `function_call` "prevents the body from running at all" was true but incomplete
  -- it did not establish that `function_call` genuinely IS the body when it IS called. Verified
  directly against pinned agno 2.9's `FunctionCall._build_nested_execution_chain`:
  `Agent(tool_hooks=[...])` is a list, folded into ONE nested chain, so `function_call` this
  hook receives can be ANOTHER listed hook's own wrapper, not the real entrypoint; AND, even
  when this hook is the only/innermost one, Agno's own `execute_entrypoint` can itself return a
  CACHED result (`cache_results=True`) without calling the real function at all -- not a
  sibling hook, baked into the same dispatch. `Capture.WRAPPER_SYNC`/`WRAPPER_ASYNC` is now
  OPT-IN via `guarded_tool_hook(..., strict_single_hook=True)` (and `aguarded_tool_hook`'s
  identical kwarg), an attestation that this hook is the ONLY entry in `tool_hooks=[...]` AND
  that none of the guarded tools declare `cache_results=True`. The default
  (`strict_single_hook=False`) is `Capture.PRE_HOOK_ONLY` with no outcome ever recorded, safe
  regardless of either.
- Execution binding wired into `adapters.ag2` (the AutoGen fork): `Capture.WRAPPER_ASYNC` from
  `_Gate.run`, which awaits `call_next(event, context)` itself. `_freeze()` snapshot of
  `event.serialized_arguments`, taken at authorization time before `call_next` runs.
  `BodyState.RAISED` is read from a genuinely honest, TYPED signal here: pinned ag2 1.0.2's
  `FunctionTool.__call__` catches every tool-body exception ITSELF and returns a
  `ToolErrorEvent` carrying the original `.error: Exception` -- it never lets the exception
  propagate as a raised Python exception through `call_next`'s own return (unlike CrewAI/
  AutoGen, which swallow the distinction into an indistinguishable string), so
  `isinstance(result, ToolErrorEvent)` + `type(result.error).__name__` is read straight off the
  framework's own typed result, not inferred. Documented honesty note: a `ToolErrorEvent` could,
  in principle, come from a different middleware ahead of this one in the chain rather than the
  tool body itself, though not in this module's own prescribed single-`DelegationGuard`-per-
  agent usage. `asyncio.CancelledError` on the wrapper's own `await` is `BodyState.ABANDONED`,
  still re-raised. AG2 has no separate delegation callback -- every hand-off IS a regular tool
  call authorized through this SAME path via its own `ToolPolicy(scope=...)`, so a delegation
  tool call gets exactly the same capture/outcome treatment as any other allowed call; only the
  internal `registry.delegate(...)` mint step (inside the same `authorize()` call, after the
  scope check passes) adds no second, separate check/outcome of its own.
  - **Round 2 correction (Codex review, batch 2, finding 1):** the claim above --
    `Capture.WRAPPER_ASYNC` as an unconditional, always-genuine observation -- was wrong.
    Pinned ag2 1.0.2's `FunctionTool.register()` folds an ORDERED LIST of middleware into ONE
    composed chain around the tool body, at TWO independent composition points: agent-level
    (`Agent(middleware=[...])`) and, separately, tool-level (`FunctionTool.with_middleware(...)`
    / `Toolkit(middleware=[...])`, reversed, so the LAST-listed hook ends up innermost).
    `ag2/middleware/builtin/` ships real stackable middleware (`llm_retry.py`,
    `token_limiter.py`, `approval.py`, `logging.py`, `metrics.py`, `telemetry.py`,
    `history_limiter.py`), so a sibling at either point is not hypothetical. Added
    `strict_single_hook: bool = False` to `_Gate`, `DelegationGuard`, `guard_middleware()`,
    `guard_tool_hook()` and `guarded_tools()`. Default: `Capture.PRE_HOOK_ONLY`, no
    `record_outcome()` ever, safe regardless of what any sibling at either composition point
    does. `strict_single_hook=True`: an explicit, scoped attestation that this gate is the sole
    middleware at ITS composition point, unlocking `Capture.WRAPPER_ASYNC` -- this package
    cannot verify the attestation itself (ag2 exposes no construction-time roster the way
    `pydantic-ai`'s `for_agent()` does for batch 1's equivalent detect-and-refuse pattern).
    Tests added, verified against ag2's OWN `_wrap_middleware` composition primitive (not a
    hand-rolled stand-in): default-mode-honest; both-order short-circuit (`guard_outer`
    records a false `RETURNED`, `sibling_outer` is never reached); guard-outer with a sibling
    retrying the real body underneath it (empirically confirmed first, per this project's own
    "verify, don't assume" discipline: the real body runs twice, this gate records exactly one
    honest `RETURNED` for the final attempt, silently under-reporting the retry).
  - **Round 3 correction (a parallel adversarial review):** the agent-level ordering claim
    just above -- "LAST-listed `on_tool_execution` ends up outermost" -- was backwards.
    That claim tested `FunctionTool.register()`'s own `_wrap_middleware` loop IN ISOLATION,
    against a hand-built list, never going through `agent.py`'s own turn setup at all; that
    setup REVERSES `Agent(middleware=[...])`'s user-facing list before it ever reaches
    `register()` (`~agent.py:1362-1366`: `for m in reversed(tuple(chain(self._middleware,
    additional_middleware))): middleware_instances.append(mw)`). The two reversals compose:
    at the USER-FACING `Agent(middleware=[...])` level, the FIRST-listed middleware ends up
    OUTERMOST, the LAST-listed innermost -- the opposite of the isolated-primitive test's
    conclusion, now confirmed end-to-end through a real `Agent` (`middleware=[A, B]`
    dispatches `A-enter, B-enter, body, B-exit, A-exit`). The tool-level claim (reversed, so
    the LAST-listed hook ends up innermost, via `FunctionTool.with_middleware(...)` /
    `Toolkit(middleware=[...])`) was independently re-verified and is correct as written --
    only the agent-level ordering direction was wrong. Safety is unaffected: the residual
    behaviors themselves (a false `RETURNED`, an under-reported retry, safety when inner)
    are properties of WHICH PHYSICAL POSITION in the composed chain a hook occupies, not of
    how a caller's list order maps to that position, and the existing finding-1 tests
    construct the composed chain directly via `_wrap_middleware` rather than asserting
    anything about `Agent(middleware=[...])`'s own list-order-to-position mapping -- so no
    finding-1 test or code-logic change was needed, only the module docstring's and this
    CHANGELOG entry's prose.
  - **Round 4 (Codex re-pass, low):** Codex required the end-to-end ordering claim itself be
    committed as a test, not asserted in prose alone against a probe run once and discarded.
    Added `test_agent_middleware_first_listed_is_outermost_end_to_end` in
    `tests/integrations/test_ag2.py`: a real `Agent`, a real `TestConfig`-scripted tool call,
    and two real `BaseMiddleware` subclasses (the factory shape `Agent(middleware=[...])`
    actually expects) recording their own entry/exit order -- asserts
    `["A-enter", "B-enter", "body", "B-exit", "A-exit"]` for `middleware=[A, B]`, turning the
    exact probe that produced the Round 3 correction into a permanent regression test.
- Execution binding wired into `adapters.agent_framework` (Microsoft Agent Framework):
  `Capture.WRAPPER_ASYNC` from `DelegationGuard.process`, which awaits `call_next()` itself.
  `_freeze()` snapshot of the tool call's arguments, taken at authorization time before
  `call_next()` runs. `BodyState.RAISED` is genuinely observed via a real raised Python
  exception -- verified directly against pinned 1.15.x source (`_tools.py`/`_middleware.py`)
  that a tool-body exception propagates all the way through `FunctionMiddlewarePipeline.
  execute`'s `final_wrapper` and every enclosing `middleware.process`'s own `call_next()`,
  including this one; the conversion into a tool-error result (cited in the module docstring's
  "DENIAL SHAPE") happens in an `except Exception` ABOVE the whole middleware pipeline, not
  inside it, so this adapter's own `try`/`except` around `await call_next()` sees the raise
  first, same shape as `adapters.langgraph`'s reference wiring (unlike `adapters.ag2`'s typed-
  event signal, or CrewAI/AutoGen's swallowed-into-a-string one). `asyncio.CancelledError` is
  `BodyState.ABANDONED`, still re-raised. Same as `adapters.ag2`: Agent Framework has no
  separate delegation callback -- every hand-off is a regular tool call authorized through this
  SAME path via its own `ToolPolicy(scope=...)`, so a delegation tool call gets exactly the same
  capture/outcome treatment as any other allowed call; only the internal
  `self._registry.delegate(...)` mint step adds no second, separate check/outcome of its own.
  - **Round 2 correction (Codex review, batch 2, finding 1):** the claim above --
    `Capture.WRAPPER_ASYNC` as an unconditional, always-genuine observation -- was wrong.
    Pinned 1.15.x's `FunctionMiddlewarePipeline.execute` (`_middleware.py:1126-1163`) is a
    genuinely composable chain (verified empirically against the framework's own pipeline:
    index 0 runs first and is outermost), and `Agent.middleware` (`_agents.py:468`) is a plain
    MUTABLE list attribute, not a fixed roster resolved once at construction -- a caller can
    append or insert into it any time after `Agent(...)` returns, and client-level function
    middleware (`_tools.py:3165`, already flagged in this module's own "KNOWN GAPS") is a
    separate, even-less-visible composition point this class cannot see at all. Added
    `strict_single_hook: bool = False` to `DelegationGuard` and `guarded_agent()`. Default:
    `Capture.PRE_HOOK_ONLY`, no `record_outcome()` ever, safe regardless of what else is on
    either middleware list, now or later. `strict_single_hook=True`: an explicit, scoped
    attestation that this guard is the ONLY function middleware that will ever run on this
    agent, for its entire lifetime -- unlocks `Capture.WRAPPER_ASYNC`. This package cannot
    verify the attestation itself (no construction-time roster to check the way `pydantic-ai`'s
    `for_agent()` offers for batch 1's equivalent detect-and-refuse pattern). Tests added,
    verified against the framework's OWN `FunctionMiddlewarePipeline` (not a hand-rolled
    stand-in): default-mode-honest; both-order short-circuit (`guard_outer` records a false
    `RETURNED`, `sibling_outer` is never reached); guard-outer with a sibling retrying the real
    body underneath it (empirically confirmed first, per this project's own "verify, don't
    assume" discipline: the real body runs twice, this guard records exactly one honest
    `RETURNED` for the final attempt, silently under-reporting the retry).
- Execution binding wired into `adapters.a2a` (the A2A protocol): `Capture.WRAPPER_SYNC`/
  `Capture.WRAPPER_ASYNC` from `guarded_tool()`'s sync/async wrapper, which calls `fn(*args,
  **kwargs)`/awaits it itself, same shape as `adapters.langgraph`'s reference wiring -- despite
  being grouped with the other hook-surface adapters up front, pinned-source inspection showed
  this is a genuine wrapper, not a hook, so no mode split was needed. `_freeze()` snapshot of
  `{"args": ..., "kwargs": ...}`, taken at authorization time before the call. `BodyState.RAISED`
  is a real raised Python exception (`fn` is called directly, nothing in this module's own path
  catches it first). `asyncio.CancelledError` on the async wrapper's own `await` is
  `BodyState.ABANDONED`, still re-raised. The separate delegation/hop machinery
  (`DelegationInterceptor`/`delegating_guard_for` client-side, `GuardedAgentExecutor` server-side)
  is a cross-process protocol boundary that never calls `guard.check()` and stays unaffected --
  verified directly, not assumed, after the ag2/agent_framework rounds' reminder that "delegation
  is unaffected" needs checking per framework, not inherited. `guarded_tool()`'s internal
  `_check()` now calls `guard.check()` directly (raising `AuthorityDenied(decision)` itself on a
  deny) instead of the old `guard.enforce()`, which discarded the `Decision` and its `call_id`;
  behaviourally identical on `schema_version=1`.
- Execution binding wired into `adapters.claude_sdk` (Claude Agent SDK), OPT-IN via
  `DelegationGuardRegistry(..., strict_single_hook=True)`. Unlike every other adapter in this
  batch, the tool body here runs inside the Claude Code CLI -- a separate, closed-source Node.js
  process on the other side of a JSON control channel -- so this is `Capture.FRAMEWORK_POST_HOOK`
  from a THIRD hook, not a wrapper: `PreToolUse` (`pre_tool_use`) authorizes and stashes a
  pending outcome keyed by `tool_use_id` (the SDK's own documented, wire-protocol-guaranteed
  unique-per-call correlation key -- verified against `ToolPermissionContext.tool_use_id`'s and
  `PreToolUseHookInput`/`PostToolUseHookInput`/`PostToolUseFailureHookInput`'s field docstrings in
  pinned claude-agent-sdk 0.2.148's `types.py`, no collision machinery needed, same shape as
  `adapters.strands`'s `toolUseId`); `PostToolUse`/`PostToolUseFailure` (newly registered by
  `hooks()`, strict mode only) close it out. `BodyState.RETURNED` from `PostToolUse`;
  `BodyState.RAISED` from `PostToolUseFailure`, with `error_code` set to the CLI's own free-text
  `error` string (single-lined) rather than a Python exception class name -- there usually is no
  Python exception object, since the tool ran across the process boundary, an explicitly
  documented deviation from every in-process adapter's convention; `PostToolUseFailure` with
  `is_interrupt` set is `BodyState.ABANDONED` instead (no `error_code`, per the contract). The
  delegation tool call (`Agent`/`Task`) gets the same treatment as any other tool: its own
  `PostToolUse` genuinely fires when the whole subagent run completes, a real body-completion
  signal. `can_use_tool` -- the SDK's second, independent permission gate on the SAME call
  `PreToolUse` already gated -- deliberately never participates in execution binding in either
  mode: only one `PostToolUse`/`PostToolUseFailure` can ever fire per `tool_use_id`, so binding
  both call sites would either double-count one call as two ledger entries or leave one `Decision`
  permanently orphaned in the pending set; binding only the primary enforcement point avoids both.
  Honesty note specific to this adapter: the "fires exactly once" guarantee is NOT independently
  verifiable from this package's Python source the way every other adapter's dispatch loop was --
  it rests on the SDK's own `TypedDict` field documentation across a process boundary to a
  closed-source CLI, not on anything this module can read or exercise offline; documented
  prominently in the module docstring rather than assumed. `duration_ms` is an observation window
  (`PreToolUse` hook seen to `PostToolUse`/`PostToolUseFailure` hook seen), not a body-only timer.
  - **Round 2 corrections (Codex review, batch 2, findings 2/3/4):** three related defects,
    each verified directly against pinned 0.2.139 before being fixed. **Finding 3:**
    `authorize()` used to compute `policy.context(tool_input)` TWICE per call -- once
    (frozen) for the `authorized_params` commitment, and again, independently, for
    `guard.check()`'s own `context=` argument -- so a non-pure `policy.context` (or
    `tool_input` mutated between the two calls by another concurrently-dispatched hook,
    which this module's own docstring already notes is possible) could commit something
    different from what was actually enforced; separately, `policy.context(tool_input)` is
    usually a narrow, policy-chosen PROJECTION, so any field of `tool_input` the policy did
    not extract was never committed at all -- contradicting `Guard.check`'s own contract that
    `authorized_params` "is the exact tool-call JSON object presented at authorization time."
    Fixed: `pre_tool_use` now freezes the COMPLETE, unmodified `tool_input` exactly ONCE,
    before this module's own `_tool_use_id` injection and before `policy.context()` ever
    runs; that frozen snapshot, not `policy.context(tool_input)`'s projection, is what gets
    committed, and `policy.context(tool_input)` itself is now computed exactly once, purely
    as the enforcement argument. **Finding 2:** the recommended strict configuration
    (`hooks=reg.hooks()` AND `can_use_tool=reg.can_use_tool`) ran `authorize()` TWICE for one
    physical tool call whenever `can_use_tool` fired -- `PreToolUse` wrote one
    `allow`/`Capture.FRAMEWORK_POST_HOOK` entry, `can_use_tool` wrote a SECOND, independent
    `allow`/`Capture.PRE_HOOK_ONLY` entry for the SAME call. Fixed: `pre_tool_use` now caches
    its own verdict for EVERY call (not only strict/bound ones), keyed by `(agent_id,
    tool_use_id)` -- the only two fields `ToolPermissionContext` exposes to `can_use_tool`;
    `can_use_tool` now only ever REPLAYS that cached verdict and never calls `authorize()`
    itself again, in any mode; a replay-miss (no `hooks=` wired alongside `can_use_tool`, a
    misconfiguration this module's own USAGE section never recommends) fails closed rather
    than silently allowing or resurrecting an independent decision path.
    - **Round-2-re-pass correction (Codex, medium):** that verdict cache
      (`_recent_verdicts`) grew without bound -- every `PreToolUse` with a `tool_use_id`
      inserts, only `can_use_tool` removes, and pinned 0.2.139's own `can_use_tool`
      docstring says it fires ONLY for the "ask" permission path, so an unclaimed entry is
      the COMMON case for any tool covered by `allowed_tools`/an allow rule (Codex repro:
      100 non-ask calls -> 100 resident entries). Not an authorization gap -- a call
      reaching `can_use_tool` already passed its own `PreToolUse` check, so a collision
      under memory pressure can only cause a safe FALSE denial, never an unauthorized
      allow -- but genuine unbounded resource growth over a long session. Fixed:
      `_recent_verdicts` is now an `OrderedDict` bounded by `max_recent_verdicts`
      (constructor parameter, default 2048, mirroring `SpoolSink.max_bytes`'s own
      bounded-with-a-counted-drop pattern in `sinks.py`) -- the OLDEST entry is evicted
      once the cache would exceed the cap, counted in `self.recent_verdicts_evicted`,
      never silently. Replay-miss fail-closed is UNCHANGED: an evicted entry is
      indistinguishable from one never cached, so `can_use_tool` denies it the same way.
      `post_tool_use`/`post_tool_use_failure` also pop the entry as a courtesy cleanup
      when they fire (proof the call already ran, so any lingering verdict for it is
      provably stale) -- reduces eviction pressure in strict mode specifically (the only
      mode those hooks are ever registered for), but does NOT replace the bound, since
      neither post hook firing is guaranteed. Tests added:
      `test_v2_recent_verdicts_cache_stays_bounded_under_sustained_non_ask_traffic` (50
      calls against a cap of 10 -> exactly 10 resident, 40 evicted, verified with a small
      explicit cap rather than the production default so the test is fast and
      deterministic); `test_v2_can_use_tool_fails_closed_on_an_evicted_verdict` (the
      evicted entry's own replay is denied, a SURVIVING entry still replays correctly);
      `test_v2_strict_post_tool_use_cleans_up_the_recent_verdicts_entry_too`. **Finding 4:**
    `ToolPermissionContext.tool_use_id`'s own docstring guarantees uniqueness only "within the
    assistant message" -- NOT globally, so concurrent messages or concurrently-running
    subagents CAN collide -- but `_pending_outcomes` was keyed by bare `tool_use_id` alone, so
    a collision would silently overwrite an unclaimed entry, orphaning its `call_id` forever.
    Fixed: `_pending_outcomes` is now keyed by `(session_id, agent_id, tool_use_id)` (all
    three available to `pre_tool_use`, `post_tool_use` AND `post_tool_use_failure` alike), and
    `authorize()` fails closed -- mirroring `adapters.crewai`'s own duplicate-live-key
    precedent -- on a `pre_tool_use` call whose key is already occupied by an unclaimed entry,
    before `guard.check()` ever runs for the new call, leaving the original entry untouched.
    This fail-closed treatment is deliberately NOT extended to the finding-2 verdict cache
    (`_recent_verdicts`, keyed by `(agent_id, tool_use_id)` only -- `can_use_tool` has no
    `session_id`): that cache has no reliable release signal (`can_use_tool` only fires for
    calls reaching the CLI's "ask" path, a minority in most configurations, so an unclaimed
    entry is the COMMON case, not evidence of a collision) -- treating every pre-existing
    entry there as a collision would misfire on ordinary usage, so it stays last-writer-wins,
    pop-on-read, documented as a residual. Tests added in `tests/integrations/test_claude_sdk.py`:
    `test_v2_strict_authorized_params_is_the_full_raw_tool_input_evaluated_once` (verified
    against the `params` module's own public `commit()`/`decode_salt()` -- the same path an
    offline verifier would use, not a private `Guard` internal); `test_v2_strict_authorize_
    fails_closed_on_a_duplicate_live_correlation_key`; `test_can_use_tool_fails_closed_when_
    no_pretooluse_verdict_was_cached`. Six pre-existing tests updated: two `can_use_tool` tests
    rewritten to drive `pre_tool_use` first (the replay-only design requires it), one corrected
    for a now-stale docstring claim ("cannot lazily mint a Guard" no longer applies once
    `can_use_tool` never mints anything itself), the `v2_post`/`v2_post_failure` test helpers
    given the `agent_id` their own payloads had always been missing (harmless before this
    round, since the old key was bare `tool_use_id`; load-bearing now).
- Execution binding wired into `adapters.semantic_kernel` (Microsoft Semantic Kernel):
  `Capture.WRAPPER_ASYNC` from `_dg_tool_gate`, which `await`s `next(context)` itself -- there is
  no sync entry point (`KernelFunction.invoke`/`invoke_stream` are both `async`), exactly like
  `adapters.langgraph`'s reference wiring. Verified against pinned semantic-kernel 1.44.1:
  `KernelFunction.invoke`'s own `try`/`except Exception as e: ...; raise e` around
  `await stack(function_context)` re-raises unchanged, and `KernelFunctionFromMethod.
  _invoke_internal` does not swallow its own exception either, so `BodyState.RAISED` (with
  `error_code`) is genuinely observed, not inferred. The SAME registered filter also gates
  `invoke_stream` (both share one `FilterTypes.FUNCTION_INVOCATION` stack); there,
  `_invoke_internal_stream` sets `context.result.value` to the raw generator/async-generator
  WITHOUT consuming it -- the actual iteration happens in `invoke_stream` itself, AFTER
  `next(context)` has already returned to this filter -- so `context.result.value` is inspected
  for generator-ness and reported `BodyState.DEFERRED`, never fabricated as `RETURNED`.
  `_freeze()` snapshot of the function's own raw `context.arguments`, taken immediately before
  `await next(context)` runs. `asyncio.CancelledError` on the filter's own `await` is
  `BodyState.ABANDONED`, still re-raised. The handoff gate never calls `guard.check()` at all --
  a handoff mints the target's Guard via `chain.delegate()` -> `Guard.delegate()`, not a scope
  check -- so it stays outside execution binding entirely, same as `adapters.langchain`/
  `llama_index`/`camel`, unlike `adapters.ag2`/`agent_framework` (whose delegation IS a priced
  call).
  - **Round 2 correction (Codex review, batch 2, finding 1):** the claim above --
    `Capture.WRAPPER_ASYNC` as an unconditional, always-genuine observation -- was wrong.
    Pinned `Kernel.add_filter`/`construct_call_stack`
    (`semantic_kernel/filters/kernel_filters_extension.py:36-51`, `:108-117`) fold EVERY
    `FilterTypes.FUNCTION_INVOCATION` filter registered on the SAME kernel into ONE composed
    chain, per kernel, not per filter -- verified by tracing `construct_call_stack`'s
    `stack.insert(0, ...)` loop by hand (matching `add_filter`'s own docstring: "the first
    filter added, will be the first to be executed"): the FIRST-added filter ends up
    OUTERMOST, the LAST-added ends up innermost, closest to the real tool body. `attach_guard`
    registers `_dg_tool_gate` via one `add_filter` call, but `kernel.add_filter` stays callable
    on the same kernel for its whole lifetime -- nothing stops a caller from registering
    another `FUNCTION_INVOCATION` filter on it before OR after `attach_guard` returns. Added
    `strict_single_hook: bool = False` to `attach_guard(...)`. Default: `Capture.PRE_HOOK_ONLY`,
    no `record_outcome()` ever, safe regardless of what other function-invocation filters are
    on this kernel, now or later. `strict_single_hook=True`: an explicit, scoped attestation
    that `_dg_tool_gate` is the ONLY such filter for the kernel's entire lifetime -- unlocks
    `Capture.WRAPPER_ASYNC`. This package cannot verify the attestation itself (no
    construction-time roster to check the way `pydantic-ai`'s `for_agent()` offers for batch
    1's equivalent detect-and-refuse pattern). Tests added, verified against the framework's
    OWN `Kernel.add_filter`/`construct_call_stack` (not a hand-rolled stand-in):
    default-mode-honest; both-order short-circuit (`guard_outer` records a false `RETURNED`,
    `sibling_outer` is never reached); guard-outer with a sibling retrying the real body
    underneath it (empirically confirmed first, per this project's own "verify, don't assume"
    discipline: the real body runs twice, this guard records exactly one honest `RETURNED` for
    the final attempt, silently under-reporting the retry).
  **Also fixed**, unrelated to execution binding: the `semantic-kernel` extra was missing
  `protobuf` -- `semantic_kernel/agents/runtime/core/serialization.py` does an unconditional
  `from google.protobuf import any_pb2`, reached lazily the moment `HandoffOrchestration` (or
  anything else under `semantic_kernel.agents.runtime`) is actually accessed -- a bare `import
  semantic_kernel.agents` alone does not trigger it, PEP 562 `__getattr__` lazy-loads the
  submodule. So `pip install 'attenu-guard[semantic-kernel]'` broke on a clean install the
  moment this adapter's own shipped demo/tests exercised `HandoffOrchestration`; added
  `protobuf` to the extra.
  - **Round 2 correction (Codex review, batch 2, finding 7):** the claim above -- "which
    semantic-kernel itself does not declare as a dependency" -- was stated as an unqualified,
    version-independent fact. It is wrong for `semantic-kernel==1.36.0` specifically: Codex
    checked that wheel's own `METADATA` and it DOES carry `Requires-Dist: protobuf` (re-verified
    here directly against the same wheel: `pip download semantic-kernel==1.36.0 --no-deps`, then
    `Requires-Dist: protobuf` is present, unconditioned, in its `METADATA`). What is actually
    true, checked directly rather than assumed: `semantic-kernel==1.44.1` -- what `>=1.36`
    resolves to today, and the version this test suite actually runs against -- does NOT declare
    `protobuf` in its `METADATA` (`pip show semantic-kernel` lists no `protobuf` under
    `Requires:`), yet still hard-imports `google.protobuf` in the module path above. Reproduced
    directly in the project's own `semantic-kernel` venv: `pip uninstall -y protobuf` makes
    `tests/integrations/test_semantic_kernel.py` fail collection with `ModuleNotFoundError: No
    module named 'google.protobuf'` (traced through
    `semantic_kernel/agents/orchestration/handoffs.py` ->
    `.../agent_actor_base.py` -> `.../orchestration_base.py` ->
    `.../runtime/core/base_agent.py` -> `.../runtime/core/core_runtime.py` ->
    `.../runtime/core/serialization.py`); `pip install protobuf` (no version pin needed) fixes it
    and the suite is 28/28 again. **The `protobuf` extra addition itself was correct and stays --
    only the stated REASON for it was wrong.** semantic-kernel's own declared dependency on
    protobuf is version-dependent (present in 1.36.0's metadata, absent in 1.44.1's), not a
    fixed framework property; this extra covers the gap for whatever version `>=1.36` actually
    resolves to.

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
