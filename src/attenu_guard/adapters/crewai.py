"""attenu_guard.adapters.crewai — enforce attenu-guard authority attenuation inside CrewAI.

Hook points used (CrewAI 1.15.16, paths relative to site-packages/)
------------------------------------------------------------------
1. CHILD CREATION — `crewai/tools/agent_tools/delegate_work_tool.py` +
   `ask_question_tool.py`. CrewAI's delegation is *a tool call*: an agent with
   `allow_delegation=True` gets the `Delegate work to coworker` /
   `Ask question to coworker` tools injected (`crewai/crew.py:1746`,
   `crewai/agent/core.py:1221`). We intercept that call in the global
   `before_tool_call` hook, and mint the coworker's Guard there with
   `parent_guard.delegate(...)` — before `BaseAgentTool._execute` runs the
   coworker's task (`crewai/tools/agent_tools/base_agent_tools.py:110-120`).

2. TOOL INVOCATION — `crewai.hooks.register_before_tool_call_hook`
   (`crewai/hooks/tool_hooks.py:208`). CrewAI dispatches this at
   `InterceptionPoint.PRE_TOOL_CALL` on every tool path:
   `crewai/utilities/tool_utils.py:286` (text tool call, sync; shared by both
   executors), `:123` (its async twin), `crewai/experimental/agent_executor.py:2024`
   (native function calling on the DEFAULT executor — `Agent.executor_class`
   defaults to the experimental `AgentExecutor` in 1.15.16),
   `crewai/agents/crew_agent_executor.py:962` (the same, on the deprecated
   executor) and `crewai/utilities/agent_utils.py:1693` — always *before* the
   tool body. Verified against the installed 1.15.16 source (AST + frame
   tracing); see tests/integrations/test_crewai_conformance.py DECLARED_PATHS.
   We run `guard.check(scope, context=..., tool=...)` there.

Blocking semantics — why we do NOT raise `AuthorityDenied`
----------------------------------------------------------
`crewai/hooks/dispatch.py:264` is explicit: "Raises HookAborted ... to abort;
**any other exception is swallowed (fail-open)**". Letting `AuthorityDenied`
escape a hook would therefore be *silently ignored and the tool would run*.
So this bridge converts every denial — and every internal error of its own —
into `crewai.hooks.HookAborted`, which CrewAI honours. CrewAI then substitutes
its own generic "Tool execution blocked by hook." string; a paired
`after_tool_call` hook replaces that with the machine-readable attenu-guard
reason (CrewAI runs POST_TOOL_CALL even on a blocked call — `tool_utils.py:126`),
so the model is told *why* it was denied and can adapt instead of retrying.

Usage
-----
Give the bridge the orchestrator's root Guard, a `ToolPolicy` per tool (which
scope it needs and how to read the request context out of the tool arguments),
and the `Authority` you are willing to hand each coworker. Then install it —
globally, for the process — and run your crew as usual::

    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role="orchestrator",
        tool_policies={
            "crm_query":  ToolPolicy("crm.read",   lambda a: {"rows": a["rows"]}),
            "crm_export": ToolPolicy("crm.export", lambda a: {"egress": "any"}),
        },
        delegation_authorities={
            "summarizer": Authority(scopes={"crm.read"},
                                    ceilings=[RowLimit(5_000), EgressRank("none")],
                                    ttl=900),
        },
    )
    with bridge:                       # or bridge.install() / bridge.uninstall()
        crew.kickoff()

Everything is fail-closed: an agent with no Guard, a tool with no policy, a
coworker with no configured `Authority`, and any internal error in the bridge
all deny. attenu-guard never invents authority for you — you write the
`Authority` for each delegation, exactly as the library intends.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain — see `Guard.issue`) — TWO MODES
-----------------------------------------------------------------------------------------
The bridge does not itself invoke the tool body -- CrewAI does, via `ToolUsage.use`/`ause`
-- so it cannot observe completion the way a wrapper that calls the body itself can. The
only way it CAN observe completion at all is CrewAI's own post hook, `_after_tool_call` --
and that hook is not a GUARANTEED terminal observer: a THIRD-PARTY `before_tool_call` hook
(not this bridge's own) can still veto a call after this bridge already authorized it (see
"STRICT MODE" below). Per the execution-binding spec's own governing principle -- an honest
unobserved beats a promised outcome that can be lost -- this bridge therefore ships with
TWO modes, controlled by `CrewAIGuardBridge(..., strict_single_hook=...)`:

  * DEFAULT (`strict_single_hook=False`): every `guard.check()` call passes NO `capture`/
    `authorized_params` at all. On a v2 chain the Guard itself stamps its own default,
    honest `Capture.PRE_HOOK_ONLY` (`Guard.check()`'s documented behavior for a bare call);
    this bridge never stashes a pending outcome and `_after_tool_call` never calls
    `record_outcome()`. This is the only mode that requires NO attestation about what else
    is registered in the process.
  * STRICT (`strict_single_hook=True`): an explicit attestation that this bridge's before/
    after `tool_call` hooks are the ONLY tool-call hooks in the process. `_before_tool_call`
    then passes `capture=Capture.FRAMEWORK_POST_HOOK` to `guard.check()` on every regular
    tool check (not the delegation-tool check, which never calls `check()` at all -- it
    mints via `parent.delegate()`, so there is nothing to bind an outcome to), and
    `_after_tool_call` closes it out from CrewAI's own post-hook result
    (`ToolCallHookContext.raw_tool_result` -- see `crewai/hooks/tool_hooks.py`), which the
    framework runs for every dispatch path, including a hook-blocked call. `duration_ms` is
    an OBSERVATION window (before-hook to after-hook), not a body-execution timer -- it can
    include other hooks' dispatch time, cache lookups and CrewAI's own formatting overhead;
    this matches `Guard.record_outcome`'s own documented contract ("observation start to
    observation end"), not a body-only clock.

CORRELATION: `ToolCallHookContext.tool_input` is the SAME object CrewAI passes to both the
before and after hook for one dispatch (`tool_utils.py` constructs it once and reuses it
for `hook_context`/`after_hook_context` alike), including on the parallel/native-function-
calling and async paths where several dispatches can be in flight on one thread at once
(CrewAI's own async executor can interleave `before(A), before(B), after(A), after(B)`).
`id(ctx.tool_input)` is therefore this bridge's per-DISPATCH key -- not a thread-local slot,
which an earlier version of this file used and which a second, concurrently-authorized call
could silently overwrite before the first call's outcome was recorded. Reading `ctx.tool_input`
NEVER falls back to a fresh `{}` on a falsey value (`getattr(ctx, "tool_input", {})`, not
`getattr(ctx, "tool_input", None) or {}`): CrewAI reuses the SAME object across its own
before/after hooks even for a ZERO-ARGUMENT tool call, where `tool_input` is `{}` -- a `... or
{}` substitutes a BRAND NEW, unrelated `{}` literal on that falsey value, breaking correlation
for every zero-argument tool (an earlier version of this file had exactly that bug).

Distinct dispatches CAN still legitimately share one `id(tool_input)` -- e.g. two concurrent
calls whose arguments were parsed from identical text, if CrewAI's own parser interns/caches
the result. A PRIOR version of this file queued same-key entries in a FIFO `collections.deque`
on the theory that two dispatches sharing one tool+args identity are "semantically symmetric",
so pairing completions to entries in append order would be as correct as any other pairing --
Codex review round 3, finding 2 proved that theory false: nothing requires two same-key
dispatches to COMPLETE in the order they were AUTHORIZED (a later-authorized call can finish
first, e.g. because an unrelated hook blocks it near-instantly while an earlier one's real tool
body is still running), and CrewAI gives this bridge no per-dispatch token to tell two
completions on the same key apart -- so a wrong FIFO pairing silently cross-binds outcomes
(the earlier call's `record_outcome` gets the LATER call's actual result, and vice versa),
each individually self-consistent and therefore undetectable by the offline verifier. `self.
_pending` is now a single-slot `dict[int, _Pending]`, not a queue: `_before_tool_call` fails
CLOSED on a second, concurrent dispatch that finds its key already occupied by a still-live
entry -- denying the second outright, via `HookAborted`, WITHOUT ever authorizing it or giving
it a slot to collide with -- rather than trying to correlate both. This trades a (rare, already
adversarial) false denial for the alternative of a silently wrong, undetectable ledger record;
per this whole round's governing principle, an honest denial beats a promised outcome that can
be cross-bound to the wrong call. The one entry that DOES occupy a key holds the strong
reference to `tool_input` that keeps its `id()` from being reused by a different,
concurrently-live object while it remains live -- see `_Pending`'s own docstring.

RESIDUAL: CrewAI still runs POST_TOOL_CALL for the collision-denied call too (it was blocked
via `HookAborted`, same as any other denial), and this bridge has no way to tell, from
`id(tool_input)` alone, whether a given `_after_tool_call` invocation is that collision-denied
call's OWN completion or the FIRST call's genuine one -- so if the collision-denied call's
after-hook fires before the first call's real completion, it WOULD find the first call's entry
still resident. `_before_tool_call` marks the occupying entry `collided=True` the instant a
collision is detected specifically to close the ONE consequence of that ambiguity this file
can still control: a collision-denied call, having been blocked via `HookAborted`, can ONLY
ever produce a blocked-looking `raw_tool_result` (`_BLOCKED_BY_HOOK_PREFIX`) -- it can never
look like a genuine `RETURNED`/deferred completion. So `_after_tool_call` classifies a
`collided` entry's completion BEFORE ever touching `self._pending` for it: when the completion
does NOT look blocked (that shape can only be the first call's own real result), it is popped
and recorded normally; when it DOES look blocked, the entry is left exactly where it is --
PEEKED, never popped -- for a later, trustworthy invocation to consume, rather than removed and
either recorded wrong or silently dropped by whichever invocation happened to arrive first.
(Codex review round 4, finding 1: an earlier version of this classification popped
UNCONDITIONALLY before checking `blocked`/`collided` at all -- so if the collision-denied
call's own blocked after-hook fired FIRST, it silently consumed and discarded the first call's
still-live entry, and the first call's later, genuine completion then found nothing to record
against: one allow, zero outcomes, `complete()` wedged. Peeking first, and only ever popping a
non-ambiguous completion, closes that.) The one gap that remains, and cannot be closed with
`id(tool_input)` alone: if the FIRST call's own completion is GENUINELY a third-party veto (a
legitimate `ABANDONED`), its blocked-looking `_after_tool_call` invocation is ALSO ambiguous
under a `collided` entry and is ALSO left unconsumed -- that specific, already-adversarial
combination (an in-flight identity collision AND a genuine third-party veto of the surviving
call) permanently loses a legitimate `ABANDONED` record rather than ever writing a wrong one.
The offline verifier's `unaccounted`/`incomplete` classification for that lost case is the
least-bad failure mode CrewAI's own hook surface leaves available here; there is no framework
signal this file could use to close it entirely.

HONESTY NOTE on `BodyState.RAISED` (strict mode): CrewAI's own `ToolUsage.use`/`ause`
(`crewai/tools/tool_usage.py`) catches every exception the tool body raises, internally, and
turns it into a formatted error STRING before `_after_tool_call` ever runs -- by the time
this bridge's post hook sees a result, a raised exception and an ordinary return are the
same shape (a string). So this adapter can never honestly report `BodyState.RAISED` -- there
is no framework signal that distinguishes "the body raised and CrewAI caught it" from "the
body returned this string" at the one hook point that observes completion. Every completed,
non-deferred call is therefore recorded `BodyState.RETURNED`, whatever it actually did
inside CrewAI's own try/except.

HONESTY NOTE on "the body never ran at all" (strict mode): `_before_tool_call` is a GLOBAL
CrewAI hook (`register_before_tool_call_hook`) -- `strict_single_hook=True` is this bridge's
caller attesting no OTHER code registers one, but this file cannot verify that attestation
itself, so it still guards against it: if a THIRD-PARTY `before_tool_call` hook vetoes a call
after this bridge already authorized it and stashed a pending outcome, CrewAI still runs
`_after_tool_call` for the blocked dispatch (`tool_utils.py`), with `ctx.raw_tool_result` set
to its own literal `"Tool execution blocked by hook. Tool: ..."` string
(`_BLOCKED_BY_HOOK_PREFIX`, both dispatch paths) rather than a real tool result.
`_after_tool_call` matches that exact, framework-owned prefix and records `BodyState.ABANDONED`
(this bridge's own observation was cut short by something outside its control -- the same
category `ABANDONED` covers elsewhere in this package for a caller-cancelled wrapper) instead
of a fabricated `RETURNED` for a body that never ran, or dropping the record. `error_code` is
NOT attached to that `ABANDONED` entry: `Guard.record_outcome` only permits `error_code`
together with `BodyState.RAISED`. (A call THIS bridge itself blocks never reaches this path:
`_authorize` never creates a pending outcome for a denial.)
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from crewai.hooks import (
    HookAborted,
    register_after_tool_call_hook,
    register_before_tool_call_hook,
    unregister_after_tool_call_hook,
    unregister_before_tool_call_hook,
)

from attenu_guard import (
    Authority,
    AuthorityError,
    Decision,
    Guard,
    ReasonCode,
    __version__,
)
from attenu_guard.reasons import BodyState, Capture, Disposition

__all__ = ["ToolPolicy", "Denial", "CrewAIGuardBridge", "DELEGATION_TOOLS"]


# CrewAI sanitizes every tool name before it reaches a hook
# (`crewai/utilities/string_utils.py:26`), so "Delegate work to coworker"
# arrives as "delegate_work_to_coworker".
try:  # pragma: no cover - trivial import shim
    from crewai.utilities.string_utils import sanitize_tool_name as _sanitize_tool_name
except ImportError:  # pragma: no cover
    def _sanitize_tool_name(name: str) -> str:
        return "_".join(str(name).lower().split())


DELEGATION_TOOLS = frozenset(
    {
        _sanitize_tool_name("Delegate work to coworker"),
        _sanitize_tool_name("Ask question to coworker"),
    }
)


def _normalize_role(name: Any) -> str:
    """Mirror CrewAI's own coworker matching.

    `BaseAgentTool.sanitize_agent_name` (base_agent_tools.py:20-35) collapses
    whitespace, strips quotes and casefolds; `_get_coworker` (:37-44) also
    unwraps a `[...]` list the LLM may emit. We match on the same normal form
    so `coworker: "Summarizer"` finds the Guard registered for role
    `"summarizer"`.
    """
    if name is None:
        return ""
    text = " ".join(str(name).split())
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].split(",")[0]
    return text.replace('"', "").replace("'", "").strip().casefold()


@dataclass(frozen=True)
class ToolPolicy:
    """Maps one CrewAI tool onto the authority it consumes.

    scope:      the attenu-guard scope the tool needs, e.g. "crm.read".
    context_fn: reads the request context out of the tool's arguments, e.g.
                ``lambda args: {"rows": args["rows"]}``. Whatever it returns is
                handed to `Guard.check(context=...)` and evaluated against the
                ceilings. Omit it for a scope-only check.
    disposition: optional `Disposition` the authority source knows about this
                tool (`held_pending_grant` · `withheld_tier2` · `unresolved`);
                recorded on a `deny` so "held" never reads as "denied". Omit
                for a grantable tool (a deny is then `out_of_authority`).
    """

    scope: str
    context_fn: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None
    disposition: Optional[str] = None


@dataclass(frozen=True)
class Denial:
    """A recorded refusal — for tests, dashboards and incident review."""

    role: str
    tool_name: str
    tool_input: Mapping[str, Any]
    reason_text: str
    decision: Optional[Decision] = None


@dataclass
class _PendingOutcome:
    """An allowed, v2 tool check waiting on `_after_tool_call` to close it out."""

    guard: Guard
    call_id: str
    tool_name: str
    snapshot: Any
    started_at: float


@dataclass
class _Pending:
    """State for ONE tool dispatch, keyed by `id(ctx.tool_input)` in
    `CrewAIGuardBridge._pending` -- see the module docstring's "CORRELATION".

    `tool_input` is a strong reference to the dispatch's own `ToolCallHookContext.tool_input`
    dict, which is what makes `id(tool_input)` a safe key: as long as this entry is in
    `_pending`, that reference keeps the object alive, so its `id()` cannot be reused by a
    different, concurrently-live object. `denial` and `outcome` are mutually exclusive (a
    denied call never gets a pending outcome).

    `collided`: set True on this entry the moment a SECOND, concurrent dispatch is seen sharing
    this same key while this entry is still live (`_before_tool_call` fails that second one
    closed rather than queueing it -- see the module docstring's "CORRELATION"). It marks this
    entry's own eventual `_after_tool_call` completion as no longer fully trustworthy: CrewAI
    still runs POST_TOOL_CALL for the collision-denied call too, and if THAT fires first, it
    would find this entry still resident. A blocked-looking completion on a `collided` entry is
    therefore PEEKED, never popped -- left resident for a later, trustworthy invocation, rather
    than consumed and either mis-recorded or silently dropped (see `_after_tool_call`) -- but a
    genuinely RETURNED/deferred-looking one is still popped and recorded immediately: the
    collision-denied call can only ever produce a blocked-looking completion (that is how it was
    denied), never that shape, so a non-blocked completion on a `collided` entry can only be
    this entry's own real one.
    """

    tool_input: Any
    denial: Optional[Denial] = None
    outcome: Optional[_PendingOutcome] = None
    collided: bool = False


def _is_deferred_result(result: Any) -> bool:
    """True for a generator/async-generator/future -- a shape `_after_tool_call` sees but does
    not itself consume. In practice `ctx.raw_tool_result` is CrewAI's own formatted/raw tool
    return, never a generator, but the check costs nothing and keeps this adapter consistent
    with the other attenu-guard adapters' `deferred` handling."""
    if inspect.isgenerator(result) or inspect.isasyncgen(result):
        return True
    if isinstance(result, (asyncio.Future, concurrent.futures.Future)):
        return True
    return False


def _body_state_for(result: Any) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.CrewAIGuardBridge._authorize",
}


def _freeze(value: Any) -> Any:
    """A genuinely immutable, fully decoupled rebuild of `value` -- NEVER calls a copy protocol
    (`copy.deepcopy`) on it. A mutable class can implement `__deepcopy__` to hand back itself (or
    another object it still owns) -- `deepcopy` SUCCEEDING is not proof the result is independent
    of the live object graph, so a "snapshot" built that way can silently change out from under
    the commitment when the tool body (or CrewAI itself) later mutates the original in place.
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


def _snapshot_params(tool_input: Mapping[str, Any]) -> Any:
    """An immutable snapshot of the tool call's arguments, taken at authorization time -- BEFORE
    CrewAI invokes the tool body -- and reused as both `authorized_params` and `invoked_params`,
    exactly as adapters/langgraph.py does: CrewAI's `ToolCallHookContext.tool_input` is a single
    mutable dict shared between the before and after hook contexts (`tool_utils.py`), so reading
    it again after the body ran would not prove anything about what the body actually saw."""
    return _freeze(dict(tool_input))


_BLOCKED_BY_HOOK_PREFIX = "Tool execution blocked by hook. Tool: "
"""CrewAI's own literal prefix for a hook-vetoed call's synthetic result
(`crewai/utilities/tool_utils.py`, both dispatch paths: `blocked_message =
f"Tool execution blocked by hook. Tool: {tool_calling.tool_name}"`). See the module
docstring's honesty note on "the body never ran at all"."""


class CrewAIGuardBridge:
    """Installs attenu-guard as CrewAI's tool-authorization layer.

    Args:
        root_guard: the orchestrator's Guard (from `Guard.issue(...)`).
        root_role: the `Agent.role` that holds `root_guard`.
        tool_policies: `{tool name: ToolPolicy}`. Names are matched after
            CrewAI's own sanitization, so "CRM Query" and "crm_query" both work.
        delegation_authorities: `{coworker role: Authority}` — the authority
            this bridge is willing to *request* on that coworker's behalf. The
            Guard grants `meet(parent, request)`, so it can only ever shrink.
        revoke_on_deny: if True, the first denial revokes the offending agent's
            whole subtree (`guard.revoke()`), so a compromised sub-agent is cut
            off for the rest of the run rather than left to keep probing.
        deny_message_fn: renders the message handed back to the model on a
            denial. Defaults to a machine-readable one-liner.
        default_policy / default_delegation_authority: OBSERVE-MODE hooks for
            sampling (attenu-derive) — called with the (sanitized) tool name /
            (normalized) coworker role when no ToolPolicy / Authority was
            declared, and their result is used as if it had been declared, so
            every call is authorized-and-RECORDED on the audit log with the
            generated scope/context instead of denied. Deny stays the default
            without the hooks.
    """

    def __init__(
        self,
        *,
        root_guard: Guard,
        root_role: str,
        tool_policies: Mapping[str, ToolPolicy],
        delegation_authorities: Mapping[str, Authority],
        revoke_on_deny: bool = False,
        deny_message_fn: Optional[Callable[[Denial], str]] = None,
        delegation_tools: frozenset = DELEGATION_TOOLS,
        default_policy: Optional[Callable[[str], ToolPolicy]] = None,
        default_delegation_authority: Optional[Callable[[str], Authority]] = None,
        strict_single_hook: bool = False,
    ) -> None:
        """
        strict_single_hook: OPT-IN to `Capture.FRAMEWORK_POST_HOOK` execution binding (on a
            `schema_version=2` chain -- see the module docstring's "EXECUTION BINDING (0.9.0)"
            and "STRICT MODE"). Pass `True` only when you can attest this bridge's before/after
            `tool_call` hooks are the ONLY tool-call hooks registered in this process -- i.e. no
            other code calls `register_before_tool_call_hook`/`register_after_tool_call_hook`
            (directly, or via a THIRD-PARTY plugin) that could veto a call after this bridge
            already authorized it, or substitute this bridge's observation of the result. The
            default, `False`, is the honest choice when that cannot be attested: every v2 `allow`
            is `Capture.PRE_HOOK_ONLY` (the Guard's own default when no `capture` is passed) and
            no outcome is ever recorded by this bridge -- an honest unobserved, never a promised
            outcome that can be lost.
        """
        self._root_role = _normalize_role(root_role)
        self._guards: dict[str, Guard] = {self._root_role: root_guard}
        self._policies = {
            _sanitize_tool_name(name): policy for name, policy in tool_policies.items()
        }
        self._delegation_authorities = {
            _normalize_role(role): authority
            for role, authority in delegation_authorities.items()
        }
        self._delegation_tools = frozenset(
            _sanitize_tool_name(name) for name in delegation_tools
        )
        self._revoke_on_deny = revoke_on_deny
        self._deny_message_fn = deny_message_fn or _default_deny_message
        self._default_policy = default_policy
        self._default_delegation_authority = default_delegation_authority
        self._strict_single_hook = strict_single_hook
        self._denials: list[Denial] = []
        self._lock = threading.Lock()
        # Keyed by id(ctx.tool_input) -- ONE dispatch, not one thread. A SINGLE slot, not a
        # queue: two dispatches CAN legitimately share the same tool_input object identity (see
        # the module docstring's "CORRELATION" -- e.g. CrewAI's own argument-parse caching for
        # identical call text), but nothing guarantees they COMPLETE in the order they were
        # authorized, so queueing them risked cross-binding one call's outcome to another's
        # (Codex review round 3, finding 2). A second, concurrent dispatch under a key that is
        # already occupied is fail-closed -- denied outright -- rather than given a slot.
        self._pending: dict[int, _Pending] = {}
        self._installed = False

    # ---- lifecycle -------------------------------------------------------

    def install(self) -> "CrewAIGuardBridge":
        """Register the global before/after tool-call hooks. Idempotent."""
        if not self._installed:
            register_before_tool_call_hook(self._before_tool_call)
            register_after_tool_call_hook(self._after_tool_call)
            self._installed = True
        return self

    def uninstall(self) -> None:
        """Remove the hooks. Idempotent."""
        if self._installed:
            unregister_before_tool_call_hook(self._before_tool_call)
            unregister_after_tool_call_hook(self._after_tool_call)
            self._installed = False

    def __enter__(self) -> "CrewAIGuardBridge":
        return self.install()

    def __exit__(self, *exc_info: Any) -> None:
        self.uninstall()

    # ---- introspection ---------------------------------------------------

    def guard_for(self, role: str) -> Optional[Guard]:
        """The Guard currently held by `role`, or None if it holds none."""
        with self._lock:
            return self._guards.get(_normalize_role(role))

    @property
    def denials(self) -> list[Denial]:
        with self._lock:
            return list(self._denials)

    # ---- hook point 2: every tool invocation -----------------------------

    def _before_tool_call(self, ctx: Any) -> None:
        """PRE_TOOL_CALL. Returns None to allow; raises HookAborted to block.

        The outer try/except is load-bearing, not defensive noise: CrewAI's
        dispatcher swallows any non-HookAborted exception and lets the tool run
        (`crewai/hooks/dispatch.py:264`), so a bug in this bridge — or in a
        user-supplied `context_fn` — would otherwise fail OPEN.
        """
        tool_input = getattr(ctx, "tool_input", {})
        key = id(tool_input)
        entry = _Pending(tool_input=tool_input)
        with self._lock:
            collided_with = self._pending.get(key)
            if collided_with is not None:
                collided_with.collided = True
            else:
                self._pending[key] = entry
        if collided_with is not None:
            # Codex review round 3, finding 2: a second, concurrent dispatch sharing this exact
            # tool_input object identity while the first is still unresolved. CrewAI gives this
            # bridge no per-dispatch token to tell the two completions apart later, so queueing
            # both risks cross-binding one call's outcome to the other's -- fail closed instead:
            # deny the SECOND outright, never give it a slot. See the module docstring's
            # "CORRELATION" for the full reasoning and its documented residual.
            self._deny(
                entry,
                role=_normalize_role(getattr(getattr(ctx, "agent", None), "role", "")),
                tool_name=_sanitize_tool_name(getattr(ctx, "tool_name", "") or ""),
                tool_input=tool_input,
                reason_text=(
                    "a second, concurrent tool dispatch shares this call's argument object "
                    "identity with one still awaiting its outcome; refusing to authorize the "
                    "second rather than risk mis-binding either call's execution-binding record"
                ),
            )
            return
        try:
            self._authorize(ctx, entry)
        except HookAborted:
            raise
        except BaseException as exc:  # noqa: BLE001 - deliberate catch-all
            self._deny(
                entry,
                role=_normalize_role(getattr(getattr(ctx, "agent", None), "role", "")),
                tool_name=_sanitize_tool_name(getattr(ctx, "tool_name", "") or ""),
                tool_input=tool_input,
                reason_text=f"bridge internal error, failing closed: {exc!r}",
            )

    def _authorize(self, ctx: Any, entry: "_Pending") -> None:
        tool_name = _sanitize_tool_name(getattr(ctx, "tool_name", "") or "")
        role = _normalize_role(getattr(getattr(ctx, "agent", None), "role", ""))
        args: Mapping[str, Any] = getattr(ctx, "tool_input", {})

        if tool_name in self._delegation_tools:
            self._authorize_delegation(role, tool_name, args, entry)
            return

        guard = self.guard_for(role)
        if guard is None:
            self._deny(
                entry,
                role,
                tool_name,
                args,
                f"no authority: agent {role!r} holds no delegated Guard",
            )

        policy = self._policies.get(tool_name)
        if policy is None and self._default_policy is not None:
            policy = self._default_policy(tool_name)
        if policy is None:
            # No authority is known for this tool: put the refusal on the
            # ledger (record_denial) as `unresolved`, not only in `denials` —
            # an operator's Decisions queue is a fold over the ledger.
            decision = guard.record_denial(
                ReasonCode.NO_AUTHORITY,
                f"no tool policy declared for {tool_name!r}",
                tool=tool_name,
                disposition=Disposition.UNRESOLVED,
            )
            self._deny(
                entry,
                role,
                tool_name,
                args,
                f"no tool policy declared for {tool_name!r}",
                decision=decision,
            )

        context = dict(policy.context_fn(args)) if policy.context_fn else {}
        # STRICT MODE (opt-in, see __init__'s "strict_single_hook"): only then does this bridge
        # promise FRAMEWORK_POST_HOOK observation and stash a pending outcome. Otherwise (the
        # default), check() gets no capture/authorized_params at all, so a v2 guard stamps its
        # own default PRE_HOOK_ONLY -- honest, since this bridge cannot guarantee it is the only
        # thing observing this call.
        v2 = self._strict_single_hook and guard.schema_version == 2
        snapshot = _snapshot_params(args) if v2 else None
        extra = (
            dict(capture=Capture.FRAMEWORK_POST_HOOK, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(policy.scope, context=context, tool=tool_name,
                               disposition=policy.disposition, **extra)
        if not decision:
            self._deny(entry, role, tool_name, args, decision.explain(), decision=decision)
            return
        if v2:
            # Nothing calls the tool body here -- CrewAI does, elsewhere, entirely outside this
            # hook -- so the outcome is closed out later, in `_after_tool_call`, from whatever
            # CrewAI's OWN post hook hands back (see the module docstring's "Execution binding").
            entry.outcome = _PendingOutcome(
                guard=guard, call_id=decision.call_id, tool_name=tool_name,
                snapshot=snapshot, started_at=time.monotonic(),
            )

    # ---- hook point 1: child creation ------------------------------------

    def _authorize_delegation(
        self, role: str, tool_name: str, args: Mapping[str, Any], entry: "_Pending"
    ) -> None:
        """Mint the coworker's attenuated Guard at the delegation tool call."""
        parent = self.guard_for(role)
        if parent is None:
            self._deny(
                entry,
                role,
                tool_name,
                args,
                f"no authority: agent {role!r} holds no Guard and cannot delegate",
            )

        coworker = _normalize_role(
            args.get("coworker") or args.get("co_worker") or args.get("agent") or ""
        )
        if not coworker:
            self._deny(entry, role, tool_name, args, "delegation names no coworker")

        requested = self._delegation_authorities.get(coworker)
        if requested is None and self._default_delegation_authority is not None:
            requested = self._default_delegation_authority(coworker)
        if requested is None:
            self._deny(
                entry,
                role,
                tool_name,
                args,
                f"no Authority configured for coworker {coworker!r}; "
                "refusing to delegate authority that was never written down",
            )

        task_text = str(args.get("task") or args.get("question") or "")
        try:
            child = parent.delegate(coworker, requested, task=task_text)
        except AuthorityError as exc:
            self._deny(
                entry,
                role,
                tool_name,
                args,
                f"delegation refused by chain: {exc.reason}",
            )
        else:
            with self._lock:
                self._guards[coworker] = child

    # ---- denial plumbing -------------------------------------------------

    def _deny(
        self,
        entry: "_Pending",
        role: str,
        tool_name: str,
        tool_input: Mapping[str, Any],
        reason_text: str,
        decision: Optional[Decision] = None,
    ) -> None:
        """Record the refusal and abort the tool call. Never returns."""
        denial = Denial(
            role=role,
            tool_name=tool_name,
            tool_input=dict(tool_input),
            reason_text=reason_text,
            decision=decision,
        )
        with self._lock:
            self._denials.append(denial)
        entry.denial = denial  # entry is this call's own object -- no lock needed for its fields

        # Don't re-revoke an already-revoked subtree: that would append a
        # second `kill` to the audit log on every subsequent probe.
        already_revoked = decision is not None and any(
            r.code == ReasonCode.REVOKED for r in decision.reasons
        )
        if self._revoke_on_deny and not already_revoked:
            guard = self.guard_for(role)
            if guard is not None:
                try:
                    guard.revoke()
                except Exception:  # noqa: BLE001 - revocation must never unblock
                    pass

        raise HookAborted(reason=self._deny_message_fn(denial), source=self)

    def _after_tool_call(self, ctx: Any) -> Optional[str]:
        """POST_TOOL_CALL. CrewAI runs this even for a blocked call, so it is
        where the generic "Tool execution blocked by hook." message gets
        replaced with the real attenu-guard reason."""
        tool_input = getattr(ctx, "tool_input", {})
        key = id(tool_input)
        tool_name = _sanitize_tool_name(getattr(ctx, "tool_name", "") or "")
        raw_result = getattr(ctx, "raw_tool_result", None)
        blocked = isinstance(raw_result, str) and raw_result.startswith(_BLOCKED_BY_HOOK_PREFIX)

        # Single slot, not a queue (Codex review round 3, finding 2 -- see the module
        # docstring's "CORRELATION"): AT MOST one entry can ever be live for this key. PEEK,
        # don't pop, when the completion looks blocked AND the slot was ever collided -- Codex
        # review round 4, finding 1: popping unconditionally, THEN classifying, let a collision-
        # denied dispatch's OWN blocked after-hook (which CrewAI still runs -- see below) consume
        # and discard the FIRST call's still-live entry if IT fires first, silently losing that
        # first call's later, genuine completion (one allow, zero outcomes, complete() wedged).
        # Classify BEFORE ever removing the entry from the dict, so an ambiguous invocation
        # leaves it exactly as it was for a later, trustworthy one to consume.
        with self._lock:
            entry = self._pending.get(key)
            ambiguous = entry is not None and blocked and entry.collided
            if entry is not None and not ambiguous:
                del self._pending[key]
        if entry is None:
            return None
        if ambiguous:
            # AMBIGUOUS (see the module docstring's "CORRELATION"): a blocked-looking completion
            # on an entry a collision ever touched could be THIS entry's own genuine third-party
            # veto, or a collision-denied dispatch's phantom completion bleeding through via the
            # shared key -- this bridge cannot tell which, and this invocation might not even
            # belong to this entry's own dispatch at all. Do nothing: leave the slot resident,
            # render no denial message, complete no coworker lifecycle marker, record no
            # outcome. A later, trustworthy (non-blocked, or no-longer-collided) invocation for
            # this key still consumes it normally.
            return None

        denial = entry.denial
        outcome = entry.outcome
        if denial is None and tool_name in self._delegation_tools:
            args = tool_input
            coworker = _normalize_role(args.get("coworker") or args.get("co_worker") or args.get("agent") or "")
            child = self.guard_for(coworker) if coworker else None
            if child is not None:
                child.complete()                  # the coworker returned: lifecycle end on the ledger (informational)
        if outcome is not None and denial is None:
            # Execution binding (0.9.0, strict mode only): close out the check() this dispatch's
            # `_authorize` made, from CrewAI's OWN post-hook result -- see the module docstring's
            # "Execution binding" and its honesty notes on RAISED and "the body never ran at all".
            if blocked:
                # Not ambiguous (handled above): entry.collided is False here, so this is a
                # genuine third-party veto. `ABANDONED`, not dropped and not a fabricated
                # `RETURNED`: this bridge's own observation was cut short by something outside
                # its control, the same way a caller-cancelled wrapper reports `ABANDONED`
                # elsewhere in this package. `error_code` is NOT attached -- `Guard.record_
                # outcome` only permits it together with `RAISED`.
                outcome.guard.record_outcome(
                    outcome.call_id, BodyState.ABANDONED,
                    invoked_params=outcome.snapshot, duration_ms=_elapsed_ms(outcome.started_at),
                )
            else:
                # A collision-denied dispatch can ONLY ever produce a blocked-looking result
                # (that is how it was denied) -- so a non-blocked, genuine-looking completion
                # can only be this entry's own real one, safe to record here regardless of
                # whether this key was ever collided.
                outcome.guard.record_outcome(
                    outcome.call_id, _body_state_for(raw_result),
                    invoked_params=outcome.snapshot, duration_ms=_elapsed_ms(outcome.started_at),
                )
        if denial is None:
            return None
        if tool_name != denial.tool_name:
            return None
        return self._deny_message_fn(denial)


def _default_deny_message(denial: Denial) -> str:
    return (
        f"AuthorityDenied [{denial.tool_name}]: {denial.reason_text}. "
        "This action exceeds the authority delegated to you; do not retry it. "
        "Continue with what you are authorized to do, or report that you cannot."
    )
