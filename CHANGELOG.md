# Changelog

All notable changes to attenu-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  immutable string) rather than shared as-is. Never raises, never shares a mutable container.
  **Round 2 correction (Codex review, finding 4):** that first fix still tried `copy.deepcopy(value)`
  wholesale before falling back to the rebuild -- but a mutable class can implement `__deepcopy__`
  to hand back `self` (or another object it still owns), so `deepcopy` *succeeding* was never proof
  the result was independent of the live object graph. `_freeze()` now never calls `copy.deepcopy`,
  or any copy protocol, on anything: containers (`dict`/`list`/`tuple`/`set`/`frozenset`) are
  always rebuilt from scratch as fresh builtins; only already-immutable leaf types
  (`str`/`int`/`float`/`bool`/`None`/`bytes`) are kept as-is; everything else becomes its `repr()`.
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
  body (`handler(request)`) themselves, exactly like `adapters.langgraph`'s reference wiring, so
  this is a genuine observation with no cross-hook honesty caveat. `authorized_params`/
  `invoked_params` are one immutable snapshot (`_freeze()`, never a copy protocol -- applying
  every lesson from the six adapters above from the start, not retrofitted after a Codex
  finding) taken before `handler` runs. `BodyState.RAISED`/`ABANDONED` (on
  `asyncio.CancelledError`, re-raised) are both genuinely observed on the async path; no shared,
  cross-call correlation state exists at all (unlike the hook-based adapters above), since the
  decision/snapshot travel through the call stack in a local `_Gate`, not a dict keyed by object
  identity -- so same-tool-concurrency and later-hook-block classes of defect are structurally
  inapplicable here, not merely tested-and-passing. A delegation tool call (`task`) mints the
  child via `guard.delegate()`, which never calls `guard.check()` at all -- no `Decision`/
  `call_id` exists to bind an outcome to, so it is unaffected by any of this.
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
