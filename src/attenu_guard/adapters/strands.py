"""
attenu-guard x AWS Strands Agents — a thin enforcement adapter.

Ships as `attenu_guard.adapters.strands` (`pip install 'attenu-guard[strands]'`). It uses `attenu_guard` unmodified and
only Strands' *public* hook API — no monkeypatching, no subclassing of Agent,
Swarm or Graph.

HOOK POINTS USED
----------------
1. Child creation / delegation
   a. `strands.hooks.BeforeToolCallEvent` where `event.selected_tool.tool_type
      == "agent"` — i.e. the "agents as tools" pattern (`Agent.as_tool()` ->
      `strands/agent/_agent_as_tool.py:28 _AgentAsTool`). The parent agent
      calling the sub-agent IS the delegation, so the child's `Guard` is minted
      there via `parent_guard.delegate(...)`.
   b. `strands.hooks.BeforeNodeCallEvent` (`strands/hooks/events.py:406`,
      raised at `strands/multiagent/swarm.py:810` and `graph.py:993`) — fires
      immediately before a swarm/graph node executes. The node that handed off
      is `swarm.state.node_history[-1]`, so the child Guard is minted from that
      node's Guard with the handoff message as the task.

2. Tool invocation
   `strands.hooks.BeforeToolCallEvent` (`strands/hooks/events.py:208`). Setting
   `event.cancel_tool = <str>` makes the executor skip the tool body entirely
   and hand the model an error ToolResult carrying that string
   (`strands/tools/executors/_executor.py:176-198`). That is a code-enforced
   gate, not a prompt: the function never runs.

USAGE
-----
Build a root `Guard`, describe (a) which scope+context each tool call needs and
(b) what authority each child may REQUEST, then register one
`DelegationGuard` on the parent agent, on every sub-agent, and — if you use one
— on the Swarm/Graph::

    dg = DelegationGuard(
        root_guard=Guard.issue("orchestrator", ORCH_AUTHORITY, task="root"),
        root_agent_name="orchestrator",
        scope_for=scope_map({
            "crm_query":  lambda i: ScopeRequest("crm.read",   {"rows": i["rows"]}),
            "crm_export": lambda i: ScopeRequest("crm.export", {"egress": "any"}),
            "summarizer": "agent.delegate",
        }),
        authority_for=lambda name, task: SUB_AGENT_AUTHORITY[name],
    )
    for agent in (orchestrator, summarizer):
        agent.hooks.add_hook(dg)      # or Agent(hooks=[dg], ...)
    swarm = Swarm([orchestrator, summarizer], hooks=[dg])   # if you use one

Prefer Strands' own authorization seam? `Agent(interventions=[dg.as_intervention()])`
gives the identical guarantee — `Deny` is applied as the same `cancel_tool` —
but interventions have no multi-agent lifecycle method, so a Swarm/Graph still
needs the hook registration above.

attenu-guard deliberately does NOT decide what authority a task needs — you
write `authority_for`. Whatever it returns is only ever an *input* to
`Authority.meet`, so a child can never come out wider than its parent.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`) -- TWO MODES
-----------------------------------------------------------------------------------------
This adapter never calls the tool body itself -- Strands does -- so it cannot observe
completion the way a wrapper that calls the body itself can. Strands' `AfterToolCallEvent`
(`strands/hooks/events.py`) is, on pinned strands-agents 1.52.x, an unusually GOOD hook for
this: ONCE DISPATCHED, it fires "regardless of whether the execution was successful or
resulted in an error" (its own docstring) -- a raised tool body, a returned result, and a
tool-body cancellation all reach it alike, and `HookRegistry.invoke_callbacks`/`_async`'s
per-callback loop is never short-circuited by another hook's RETURN VALUE (unlike Google
ADK's plugin manager) -- and `tool_use["toolUseId"]` is a genuinely UNIQUE identifier per
dispatch (`types/tools.py`'s own docstring), not an object identity CrewAI-style collision
risk.

ROUND 2 CORRECTION (Codex review, batch 2, finding 6): the paragraph above, as it read before
this correction, was read by a reviewer as claiming `AfterToolCallEvent` fires unconditionally,
full stop -- verified against pinned 1.52.x source to be FALSE. "Fires unconditionally" was
only ever true with respect to the TOOL BODY's own success/failure/cancellation (the axis the
docstring quote above actually describes); it says nothing about whether the event is DISPATCHED
AT ALL, which depends on the BEFORE-hook phase completing without incident. Three lost-terminal
paths exist, verified directly against `strands/tools/executors/_executor.py`'s
`ToolExecutor.stream` and `strands/hooks/registry.py`'s `HookRegistry.invoke_callbacks_async`,
each reproduced with a throwaway `HookProvider` sibling before being documented here:

  * A LATER-registered `before_tool_call` hook raises `InterruptException`. `stream()` calls
    `_invoke_before_tool_call_hook` -> `invoke_callbacks_async`, whose per-callback loop catches
    ONLY `InterruptException` (converting it into the returned `interrupts` list) -- back in
    `stream()`, `if interrupts: yield ToolInterruptEvent(...); return` fires BEFORE `stream()`'s
    own inner `try:` block that would eventually call `_invoke_after_tool_call_hook` is ever
    entered. If this adapter's own `before_tool_call` already ran (registered earlier in
    `BeforeToolCallEvent`'s registration-order iteration -- `should_reverse_callbacks` is
    `False` there) and allowed, `evaluate_tool_call` already stashed a pending entry in
    `self._pending`; `after_tool_call` never runs, so it is never popped -- a permanent wedge,
    reproduced directly (`agent(...)` returns normally, `Guard.complete()` reports
    `completed=False` with that call's `call_id` still pending). UNLIKE the tool-originated
    interrupt case above, this one is not reliably self-healing on resume either: `_pending` is
    keyed by `toolUseId`, and a fresh allow on retry OVERWRITES the same key, silently orphaning
    the FIRST `call_id` forever rather than closing it.
  * An ORDINARY (non-`InterruptException`) exception from a `before_tool_call` hook registered
    to run AFTER this adapter's own. `invoke_callbacks_async`'s per-callback loop does not catch
    a plain exception at all -- it propagates straight out of the loop, out of
    `_invoke_before_tool_call_hook`, and out of `ToolExecutor.stream()` itself as an unhandled
    exception (that call happens BEFORE `stream()`'s own inner `try`/`except`, so nothing in the
    tool-execution machinery, including this adapter's own exception handling, ever runs).
    Reproduced directly: `agent(...)` raises `EventLoopException` wrapping the sibling's
    original exception, and this adapter's pending entry for that call is wedged exactly as
    above -- `record_outcome()` never runs, `complete()` reports it pending forever.
  * The SAME exception, from a hook registered to run BEFORE this adapter's own. Since the
    per-callback loop stops at the first uncaught exception, this adapter's own
    `before_tool_call`/`evaluate_tool_call` is never invoked for that call AT ALL -- no
    `guard.check()`, no allow/deny logged, no pending entry created. Reproduced directly: this
    is the one case that is NOT a wedge in `self._pending` (there is nothing to wedge, since
    this adapter never got a chance to authorize the call), and the tool body does not run
    either (the same uncaught exception aborts the whole dispatch before the middleware/tool-
    execution stage is ever reached) -- fail-safe for authorization, but the attempt leaves NO
    record in this adapter's ledger at all, not even a denial.

None of these are something this adapter can code around within Strands' documented hook
surface: `HookRegistry` gives a registered `HookProvider` no priority/ordering control over
other callbacks beyond registration order itself, and there is no hook point between "a sibling
before-hook is about to raise" and the raise itself for this adapter to intervene from. A related,
narrower risk found during this same verification pass but not one of the three named above:
`AfterToolCallEvent` DOES use `should_reverse_callbacks = True`, so if THIS adapter's own
`after_tool_call` is registered earlier than a sibling's (making it run LAST among after-hooks),
an ordinary exception from that EARLIER-running sibling's own `after_tool_call` would, by the
same uncaught-exception mechanism, stop the after-hook loop before this adapter's own
`after_tool_call` runs -- the identical wedge, one hook-type over. Documented here for
completeness rather than given its own bullet, since it is structurally the same defect as the
second bullet above, just on the after-hook side of the same dispatch.

CONSIDERED AND REJECTED: whether strict mode should fail closed on a detectable interrupt.
It should not, for two reasons verified above rather than assumed. First, none of these three
paths are an AUTHORIZATION gap -- `guard.check()` already ran and its `allow`/`deny` `Decision`
is already correctly committed to the audit log before any of this can happen; what is lost is
only the LATER outcome-observation (did the body run, and how), which is an audit-COMPLETENESS
concern, not an enforcement bypass. Second, there is no hook this adapter can install to detect
"a sibling before-hook is about to raise" ahead of time, so a "fail closed" response would have
to happen AFTER the fact -- but by then the call has already either been authorized (paths 1-2)
or never reached this adapter at all (path 3), and Strands offers no mechanism to retroactively
undo either. `Guard.complete()`/the offline verifier already surface a wedged `call_id` honestly
as incomplete/`unaccounted`, never as a fabricated success -- the same "honest gap, not a lie"
posture this file's own governing principle establishes for the tool-originated-interrupt case
above. Building a bespoke sweep-and-close mechanism for this specific residual would trade one
documented, honestly-surfaced gap for an ad hoc one with its own unverified edge cases, for a
risk that is about completeness of the record, not about what was ever actually authorized.

Despite that strength, this adapter still ships with TWO modes, controlled by
`DelegationGuard(..., strict_single_hook=...)`, per this whole effort's governing principle --
an honest unobserved beats a promised outcome that can be lost -- because pinned 1.52.x's
retry mechanism (below) genuinely CAN lose an already-recorded outcome, on top of the three
before-hook paths just documented:

  * DEFAULT (`strict_single_hook=False`): every `guard.check()` call passes NO `capture`/
    `authorized_params` at all. On a v2 chain the Guard itself stamps its own default, honest
    `Capture.PRE_HOOK_ONLY`; this adapter never stashes a pending outcome and `after_tool_call`
    never calls `record_outcome()`.
  * STRICT (`strict_single_hook=True`): `evaluate_tool_call` passes `capture=Capture.
    FRAMEWORK_POST_HOOK` to `guard.check()` on every regular (non-delegation) allow, and stashes
    a pending outcome keyed by `tool_use["toolUseId"]`. `after_tool_call` closes it out from
    `AfterToolCallEvent.exception`/`cancel_message` (never dropped: this adapter's own denial
    never stashes a pending entry in the first place, so a later `cancel_message` there is
    always a THIRD-PARTY veto after this adapter's own allow -- `BodyState.ABANDONED`, `error_code`
    NOT attached per `Guard.record_outcome`'s own constraint). `duration_ms` is an OBSERVATION
    window (`check()`'s call to `after_tool_call`), not a body-only timer, matching `Guard.
    record_outcome`'s own documented contract.

HONESTY NOTES (strict mode) -- genuine, structural gaps in pinned 1.52.x's hook surface, not
bugs this file can code around without going outside documented hooks:

  * RETRY: "When `retry` is set to True by a hook callback, the tool executor will discard the
    current tool result and invoke the tool again" (`AfterToolCallEvent`'s own docstring).
    `AfterToolCallEvent` uses REVERSE registration order (`should_reverse_callbacks = True`), so
    whether this adapter's own `after_tool_call` sees a retry decision another hook makes on the
    SAME event depends entirely on relative registration order -- a hook registered AFTER this
    one runs BEFORE it (and so its `retry=True` IS visible here), while one registered BEFORE
    this one runs AFTER it (invisible here). If this adapter's own `record_outcome` already ran
    for what the executor then discards and retries, there is no way to un-record it (`Guard.
    record_outcome` permits exactly one outcome per `call_id`) or to correlate the retried
    attempt with a fresh one (the retry reuses the same `tool_use`, so the same `toolUseId` --
    there is nothing left to key a second pending entry on). This is a genuine, accepted
    residual of strict mode: the recorded outcome may describe a discarded attempt, not the
    attempt whose result the model actually sees.
  * TOOL-ORIGINATED INTERRUPTS: a `ToolInterruptEvent` yielded from a tool's own `stream()` (a
    human-in-the-loop pause raised BY the tool body, distinct from a middleware-level
    `InterruptException`) makes the executor return WITHOUT ever calling `AfterToolCallEvent` at
    all (`_executor.py`'s own comment: "a halted tool has no result, so the after-hook ... [is]
    intentionally skipped"). This adapter's pending entry for that `toolUseId` is simply never
    popped -- self-healing IF the run later resumes and the SAME tool use eventually completes
    (the entry is still there, keyed correctly, waiting), an honest gap (the offline verifier's
    `unobserved`/`unaccounted`, never a lie) if it never resumes at all.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from strands.hooks import (
    AfterToolCallEvent,
    BeforeNodeCallEvent,
    BeforeToolCallEvent,
    HookProvider,
    HookRegistry,
)
from strands.interventions import Deny, InterventionHandler, Proceed

from attenu_guard import Authority, AuthorityError, Guard, __version__
from attenu_guard.reasons import BodyState, Capture

__all__ = [
    "ScopeRequest",
    "ScopeResolver",
    "AuthorityResolver",
    "DelegationGuard",
    "scope_map",
]


# ---------------------------------------------------------------------------
# What a single tool call is asking for
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScopeRequest:
    """The authority one tool call needs: a scope plus the quantities the
    ceilings are measured against (e.g. `{"rows": 4200}`, `{"egress": "any"}`).
    """

    scope: str
    context: Mapping[str, Any] = field(default_factory=dict)
    metered: bool = False
    disposition: Optional[str] = None     # see attenu_guard.Disposition


# (tool_use) -> ScopeRequest, or None meaning "this tool needs no authority"
ScopeResolver = Callable[[Mapping[str, Any]], "ScopeRequest | None"]

# (child_agent_name, task) -> the Authority the child may REQUEST, or None to
# refuse the delegation outright.
AuthorityResolver = Callable[[str, str], "Authority | None"]


def scope_map(
    mapping: Mapping[str, "str | ScopeRequest | Callable[[Mapping[str, Any]], ScopeRequest | None]"],
    *,
    unmapped: str = "deny",
) -> ScopeResolver:
    """Build a `ScopeResolver` from a `{tool_name: ...}` table.

    A value may be a bare scope string, a ready-made `ScopeRequest`, or a
    callable taking the tool's parsed arguments and returning one.

    `unmapped="deny"` (the default) is what makes this fail CLOSED: a tool
    nobody wrote a rule for resolves to the synthetic scope `tool.<name>`,
    which no `Authority` grants — so attenu-guard denies it through its
    normal path and the refusal lands in the audit log with the reason code
    `scope_not_granted`, rather than being special-cased in adapter code.
    `unmapped="allow"` opts a deployment out of that.
    """
    if unmapped not in ("deny", "allow"):
        raise ValueError("unmapped must be 'deny' or 'allow'")

    def resolve(tool_use: Mapping[str, Any]) -> ScopeRequest | None:
        name = tool_use["name"]
        if name not in mapping:
            return None if unmapped == "allow" else ScopeRequest(f"tool.{name}")

        rule = mapping[name]
        if isinstance(rule, str):
            return ScopeRequest(rule)
        if isinstance(rule, ScopeRequest):
            return rule
        return rule(_tool_input(tool_use))

    return resolve


def _tool_input(tool_use: Mapping[str, Any]) -> Mapping[str, Any]:
    """Strands parses the model's tool arguments into `tool_use["input"]`; a
    provider that streams a bare string leaves it as one."""
    raw = tool_use.get("input")
    if isinstance(raw, Mapping):
        return raw
    return {"input": raw}


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


def _freeze(value: Any) -> Any:
    """A genuinely immutable, fully decoupled rebuild of `value` -- NEVER calls a copy protocol
    (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back itself (or
    another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is independent
    of the live object graph, so a "snapshot" built that way can silently change out from under
    the commitment when the tool body (or Strands itself) later mutates the original in place.
    Containers are always rebuilt from scratch as fresh builtins (dict/list, recursively); only
    already-immutable leaf types (`str`/`int`/`float`/`bool`/`None`/`bytes`) are kept as-is --
    sharing an immutable value carries no aliasing risk regardless of what protocol it does or
    does not implement. Everything else becomes its `repr()` -- a brand-new, independent string
    -- rather than being handed through any copy protocol that could return a live reference."""
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if isinstance(value, Mapping):
        return {k: _freeze(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_freeze(v) for v in value]
    try:
        return repr(value)
    except Exception:
        return f"<unrepresentable {type(value).__name__}>"


def _snapshot_params(tool_use: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    Strands invokes the tool body -- and reused as both `authorized_params` and `invoked_params`."""
    return _freeze(dict(_tool_input(tool_use)))


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.DelegationGuard.evaluate_tool_call",
}


@dataclass
class _PendingOutcome:
    """An allowed, v2 tool check (strict mode only) waiting on `after_tool_call` to close it
    out -- keyed by `tool_use["toolUseId"]` in `DelegationGuard._pending`, a genuinely unique
    identifier per dispatch (see the module docstring's "EXECUTION BINDING")."""

    guard: Guard
    call_id: str
    snapshot: Any
    started_at: float


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------

class DelegationGuard(HookProvider):
    """One object, registered on every Agent (and on the Swarm/Graph if you
    use one), that mints attenuated child Guards at delegation time and
    authorizes every tool call before its body runs.

    It is deliberately fail-closed: an agent with no Guard bound to it cannot
    call any tool, and a delegation whose `authority_for` returns None is
    refused.
    """

    def __init__(
        self,
        root_guard: Guard,
        root_agent: "Any | None" = None,
        *,
        root_agent_name: "str | None" = None,
        scope_for: ScopeResolver,
        authority_for: AuthorityResolver,
        on_decision: "Callable[[str, str, Any], None] | None" = None,
        strict_single_hook: bool = False,
    ) -> None:
        """
        strict_single_hook: execution-binding (0.9.0) mode switch -- see the module docstring's
                          "EXECUTION BINDING ... TWO MODES". `False` (default): every
                          `guard.check()` call is left to the Guard's own honest
                          `Capture.PRE_HOOK_ONLY` default; no outcome is ever recorded.
                          `True`: an explicit attestation that this adapter's own
                          `AfterToolCallEvent` callback is registered (it always is, via
                          `register_hooks` -- this flag is about accepting the documented retry/
                          tool-interrupt residuals, not about registration) -- restores
                          `Capture.FRAMEWORK_POST_HOOK` and real outcome recording. See the
                          HONESTY NOTES for what strict mode still cannot guarantee.
        """
        if root_agent is None and root_agent_name is None:
            raise ValueError("pass root_agent, or root_agent_name if it does not exist yet")

        self.root_guard = root_guard
        self.root_agent = root_agent
        self._scope_for = scope_for
        self._authority_for = authority_for
        self._on_decision = on_decision
        self._strict_single_hook = strict_single_hook

        root_name = root_agent_name or self._agent_name(root_agent)
        self._by_obj: dict[int, Guard] = {} if root_agent is None else {id(root_agent): root_guard}
        self._by_name: dict[str, Guard] = {root_name: root_guard}
        self._revoked_names: set[str] = set()
        # Execution binding (0.9.0, strict mode only): an allowed, v2 check() waiting on
        # after_tool_call to close it out -- keyed by tool_use["toolUseId"], a genuinely
        # unique identifier per dispatch (see the module docstring's "EXECUTION BINDING").
        self._pending: dict[str, _PendingOutcome] = {}

    # -- introspection ------------------------------------------------------

    def guard_for(self, agent: Any) -> "Guard | None":
        """The Guard bound to `agent` — by object identity, falling back to
        `agent.name`. The name fallback exists because Strands' `interventions=`
        is constructor-only: with agents-as-tools the parent does not exist yet
        when its sub-agent is built, so the guard can only be bound by name."""
        guard = self._by_obj.get(id(agent))
        if guard is None:
            guard = self._by_name.get(self._agent_name(agent))
            if guard is not None:
                self._by_obj[id(agent)] = guard
        return guard

    def guard_for_name(self, name: str) -> "Guard | None":
        return self._by_name.get(name)

    def revoke(self, name: str) -> list:
        """Cascade-revoke an agent's current Guard and refuse to re-mint one
        for that name.

        The second half is adapter policy, not library behaviour:
        `Guard.revoke()` revokes a chain NODE, but a framework that hands off
        to the same agent twice would simply mint a fresh node. Remembering
        the name is what makes revocation stick to the *principal*.
        """
        guard = self._by_name.get(name)
        if guard is None:
            raise KeyError(f"no Guard bound to agent {name!r}")
        self._revoked_names.add(name)
        return guard.revoke()

    # -- HookProvider -------------------------------------------------------

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self.before_tool_call)
        registry.add_callback(AfterToolCallEvent, self.after_tool_call)
        registry.add_callback(BeforeNodeCallEvent, self.before_node_call)

    # -- hook 2: every tool call, and hook 1a: agents-as-tools --------------

    def before_tool_call(self, event: BeforeToolCallEvent) -> None:
        denial = self.evaluate_tool_call(event)
        if denial is not None:
            event.cancel_tool = denial

    def evaluate_tool_call(self, event: BeforeToolCallEvent) -> "str | None":
        """Authorize the call and, if it is a delegation, mint the child Guard.
        Returns None to allow, or the denial message. Shared by the hook path
        and the `InterventionHandler` path — they differ only in how the
        refusal is delivered."""
        agent = event.agent
        tool_use = event.tool_use
        tool_name = tool_use["name"]

        guard = self.guard_for(agent)
        if guard is None:
            return (
                f"denied: agent {self._agent_name(agent)!r} holds no delegated "
                f"authority (no Guard bound), so it may not call {tool_name!r}"
            )

        # Authorize the call itself. For a sub-agent tool this gates the
        # *right to delegate*; for a normal tool it gates the action.
        request = self._scope_for(tool_use)
        if request is not None:
            v2 = self._strict_single_hook and guard.schema_version == 2
            snapshot = _snapshot_params(tool_use) if v2 else None
            extra = (
                dict(capture=Capture.FRAMEWORK_POST_HOOK, adapter=_ADAPTER_INFO,
                    authorized_params=snapshot)
                if v2 else {}
            )
            decision = guard.check(
                request.scope,
                context=dict(request.context),
                metered=request.metered,
                tool=tool_name,
                disposition=request.disposition,
                **extra,
            )
            if self._on_decision is not None:
                self._on_decision(self._agent_name(agent), tool_name, decision)
            if not decision:
                return f"authority denied for {tool_name!r}: {decision.explain()}"
            if v2:
                # Nothing here calls the tool body -- Strands does, elsewhere -- so the
                # outcome is closed out later by after_tool_call, whichever way it fires
                # for this call. See the module docstring's "EXECUTION BINDING".
                self._pending[tool_use["toolUseId"]] = _PendingOutcome(
                    guard=guard, call_id=decision.call_id, snapshot=snapshot,
                    started_at=time.monotonic(),
                )

        # Agents-as-tools: this call IS a delegation — mint the child's Guard.
        selected = event.selected_tool
        if selected is not None and getattr(selected, "tool_type", None) == "agent":
            child_agent = getattr(selected, "agent", None)
            if child_agent is None:  # pragma: no cover - defensive
                return None
            child_name = getattr(selected, "tool_name", None) or self._agent_name(child_agent)
            task = str(_tool_input(tool_use).get("input", ""))
            return self._mint(guard, child_agent, child_name, task)

        return None

    # -- hook 2b: the tool call has finished (0.9.0 execution binding, strict mode only) ----

    def after_tool_call(self, event: AfterToolCallEvent) -> None:
        pending = self._pending.pop(event.tool_use["toolUseId"], None)
        if pending is None:
            return  # default mode, a denial (never stashed), or a foreign toolUseId
        if event.cancel_message is not None:
            # This adapter's OWN denial never stashes a pending entry (see
            # evaluate_tool_call), so reaching here with cancel_message set means some
            # OTHER before-hook vetoed the call AFTER this one already authorized it.
            # ABANDONED, not a fabricated RETURNED -- error_code is NOT attached
            # (Guard.record_outcome only permits it together with RAISED).
            pending.guard.record_outcome(
                pending.call_id, BodyState.ABANDONED,
                invoked_params=pending.snapshot, duration_ms=_elapsed_ms(pending.started_at),
            )
        elif event.exception is not None:
            pending.guard.record_outcome(
                pending.call_id, BodyState.RAISED, error_code=type(event.exception).__name__,
                invoked_params=pending.snapshot, duration_ms=_elapsed_ms(pending.started_at),
            )
        else:
            pending.guard.record_outcome(
                pending.call_id, BodyState.RETURNED,
                invoked_params=pending.snapshot, duration_ms=_elapsed_ms(pending.started_at),
            )

    # -- the same enforcement, as a Strands InterventionHandler -------------

    def as_intervention(self, name: str = "attenu-guard") -> InterventionHandler:
        """Expose this guard through Strands' own authorization seam, for
        `Agent(interventions=[...])`.

        `Deny` is applied by `strands/interventions/registry.py:127-129` as
        exactly the `event.cancel_tool` this adapter sets directly, so the
        guarantee is identical; the difference is idiom and ordering
        (interventions run at `HookOrder.INTERVENTION_INPUT`, i.e. after
        default-order hooks). Interventions have no multi-agent lifecycle
        method, so a Swarm/Graph still needs `register_hooks` for
        `BeforeNodeCallEvent`. In STRICT execution-binding mode
        (`strict_single_hook=True`), it ALSO still needs `register_hooks` for
        `AfterToolCallEvent` -- an intervention only ever supplies the before-call
        decision, so authorizing exclusively through `as_intervention()` with no
        `agent.hooks.add_hook(self)`/`register_hooks` anywhere would stash pending
        outcomes in `self._pending` that nothing ever pops, wedging `complete()`.
        """
        outer = self

        class _DelegationGuardIntervention(InterventionHandler):
            @property
            def name(self) -> str:
                return name

            @property
            def on_error(self) -> str:
                return "deny"  # a crashing policy check must fail closed

            def before_tool_call(self, event: BeforeToolCallEvent, **kwargs: Any):
                denial = outer.evaluate_tool_call(event)
                return Proceed() if denial is None else Deny(reason=denial)

        return _DelegationGuardIntervention()

    # -- hook 1b: swarm / graph handoff -------------------------------------

    def before_node_call(self, event: BeforeNodeCallEvent) -> None:
        orchestrator = event.source
        node = orchestrator.nodes[event.node_id]
        agent = node.executor

        # The entry node starts the chain; it must be the agent the root Guard
        # was issued to, otherwise we do not know what authority it holds.
        history = getattr(getattr(orchestrator, "state", None), "node_history", None) or []
        if not history:
            if self.guard_for(agent) is None:
                event.cancel_node = (
                    f"denied: entry node {event.node_id!r} holds no delegated authority"
                )
            return

        parent_guard = self.guard_for(history[-1].executor)
        if parent_guard is None:
            event.cancel_node = (
                f"denied: {history[-1].node_id!r} holds no delegated authority, "
                f"so it may not hand off to {event.node_id!r}"
            )
            return

        task = str(
            getattr(orchestrator.state, "handoff_message", None)
            or getattr(orchestrator.state, "task", "")
        )
        error = self._mint(parent_guard, agent, event.node_id, task)
        if error is not None:
            event.cancel_node = error

    # -- shared minting -----------------------------------------------------

    def _mint(self, parent_guard: Guard, child_agent: Any, child_name: str, task: str) -> "str | None":
        """Delegate `parent_guard` -> a child Guard bound to `child_agent`.
        Returns None on success, or a denial message to cancel with."""
        if child_name in self._revoked_names:
            return f"denied: authority for {child_name!r} has been revoked"

        request = self._authority_for(child_name, task)
        if request is None:
            return (
                f"denied: no Authority defined for delegation to {child_name!r} "
                f"(authority_for returned None)"
            )

        try:
            child = parent_guard.delegate(child_name, request, task=task)
        except AuthorityError as exc:
            return f"denied: cannot delegate to {child_name!r}: {exc.reason} ({exc})"

        self._by_obj[id(child_agent)] = child
        self._by_name[child_name] = child
        return None

    # -- misc ---------------------------------------------------------------

    @staticmethod
    def _agent_name(agent: Any) -> str:
        return str(getattr(agent, "name", None) or f"agent-{id(agent):x}")
