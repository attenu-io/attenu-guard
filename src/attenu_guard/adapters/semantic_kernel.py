"""
attenu_guard.adapters.semantic_kernel — a thin attenu-guard integration for Microsoft
Semantic Kernel.

Tested against semantic-kernel 1.36.0 (Python >= 3.10).

HOOK POINTS USED
----------------
1. Child creation / delegation — an **AUTO_FUNCTION_INVOCATION filter**
   (`FilterTypes.AUTO_FUNCTION_INVOCATION`, registered via
   `Kernel.add_filter`, `semantic_kernel/filters/kernel_filters_extension.py:37`).

   `HandoffOrchestration` implements a handoff by minting, on each agent's
   kernel, a zero-argument `Handoff-transfer_to_<Target>` KernelFunction
   (`semantic_kernel/agents/orchestration/handoffs.py:190-221`). When the model
   calls it, `Kernel.invoke_function_call` builds an
   `AutoFunctionInvocationContext` and runs the auto-invocation filter stack
   (`semantic_kernel/kernel.py:437-441`). That is the exact moment control
   transfers, so it is where this adapter mints the child's attenuated Guard
   via `parent_guard.delegate(...)`. Semantic Kernel itself uses this same
   filter slot for its own handoff bookkeeping
   (`handoffs.py:222`, `_handoff_function_filter`), so we are using the
   framework's own idiom rather than fighting it.

   Because minting goes through `Guard.delegate`, a handoff attempted from a
   revoked or expired parent raises `AuthorityError` and the transfer itself
   fails — the delegation *edge* is enforced, not just the tools downstream.

2. Tool invocation — a **FUNCTION_INVOCATION filter**
   (`FilterTypes.FUNCTION_INVOCATION`). `KernelFunction.invoke` builds the
   filter stack with `inner_function=self._invoke_internal` and awaits it
   (`semantic_kernel/functions/kernel_function.py:271-275`), so a filter that
   returns *without* awaiting `next(context)` provably prevents the function
   body from ever running.

   This is deliberately the *lower* of the two tool hooks. An
   AUTO_FUNCTION_INVOCATION filter would only see calls the LLM made inside the
   auto-tool-calling loop; a FUNCTION_INVOCATION filter also fires for a direct
   `kernel.invoke(...)`, for prompt-template function calls, and for anything
   else that reaches a `KernelFunction` — one registration, no bypass.

TWO SEMANTIC KERNEL TRAPS THIS ADAPTER IS BUILT AROUND
------------------------------------------------------
`HandoffAgentActor.__init__` runs `self._kernel = agent.kernel.clone()`
(`handoffs.py:175`), and `Kernel.clone()` **deepcopies** both the plugin list
and all three filter lists (`semantic_kernel/kernel.py:547-555`). Therefore:

  * **Filters must be plain functions/closures, never callable objects.**
    `copy.deepcopy` treats a function as atomic, so a closure survives `clone()`
    with its identity *and* its closed-over cells intact. A callable object is
    deep-copied, which would silently fork the `Guard` it holds — a later
    `revoke()` on the original would then not reach the agent actually running.
    Every filter registered below is a closure over one shared
    `DelegationChain`.

  * **Never keep enforcement state inside a plugin instance.** The plugin object
    is deep-copied per actor, so an in-plugin call counter, budget, or audit
    sink is duplicated and defeated. Authority state belongs in the
    `DelegationChain`, reached through the filter closure.

USAGE
-----
Build one `DelegationChain` for the run, holding the root agent's `Guard`.
Declare, per tool, what authority it consumes (`ToolPolicy`). Call
`attach_guard(...)` once per agent, on that agent's own `Kernel`, *before*
handing the agents to an orchestration. Give the orchestrator's `attach_guard`
an `authority_for` map so it knows what to grant each handoff target.

    POLICIES = {
        "Crm-crm_query":  ToolPolicy("crm.read",   context=lambda a: {"rows": a["rows"]}),
        "Crm-crm_export": ToolPolicy("crm.export", context=lambda a: {"egress": "any"}),
    }

    chain = DelegationChain(root_agent="Orchestrator", root_guard=root_guard)

    attach_guard(orchestrator.kernel, agent_name="Orchestrator", chain=chain,
                 policies=POLICIES,
                 authority_for={"Summarizer": Authority(scopes={"crm.read"},
                                ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)})
    attach_guard(summarizer.kernel, agent_name="Summarizer", chain=chain, policies=POLICIES)

Every tool call is then checked against *that agent's* authority before its body
runs, and every allow/deny lands in the chain's hash-chained audit log.
`chain.revoke("Summarizer")` cascades to the whole subtree immediately.

EXECUTION BINDING (`record_outcome`, 0.9.0, OPT-IN via `schema_version=2`)
---------------------------------------------------------------------
TWO MODES, gated by `strict_single_hook` (an `attach_guard(...)` parameter, default
`False`) -- see the "Round 2 correction" below for why this is no longer a bare,
unconditional claim.

Pinned `Kernel.add_filter`/`construct_call_stack`
(`semantic_kernel/filters/kernel_filters_extension.py:36-51`, `:108-117`) fold EVERY
`FilterTypes.FUNCTION_INVOCATION` filter registered on the SAME kernel into ONE composed
chain, per kernel, not per filter. `add_filter`'s own docstring: "the first filter added,
will be the first to be executed, but it will also be the last executed for the part
after `await next(context)`" -- verified by tracing `construct_call_stack`'s
`stack.insert(0, ...)` loop by hand: the FIRST-added filter ends up OUTERMOST (the entry
point), the LAST-added filter ends up INNERMOST, closest to `inner_function` (the real
tool body). `attach_guard(...)` registers `_dg_tool_gate` via one `add_filter` call
(`:542` below) -- but `kernel.add_filter` remains a public method on the SAME `kernel`
object for the rest of its life, so nothing stops a caller from registering another
`FUNCTION_INVOCATION` filter on it before OR after `attach_guard(...)` returns.

`_dg_tool_gate` genuinely awaits whatever `next` it was handed, so `Capture.WRAPPER_ASYNC`
(when unlocked, see below) is never a fabricated pre-hook read -- but a sibling filter
positioned closer to `inner_function` in the SAME kernel's chain can still stand between
this gate's own `await next(context)` and the real tool body:

* Sibling added AFTER this gate (so it ends up INNER, closer to the body), short-circuits
  (sets `context.result` without calling its own `next`): this gate's own `await
  next(context)` still returns genuinely, so `_body_state_for(context.result.value)` is
  recorded honestly for whatever the sibling put there -- `RETURNED` for a body that never
  ran.
* Sibling added AFTER this gate, calls its own `next` more than once (a retry) for what
  the model sees as one function call: this gate's `await next(context)` is awaited once
  and returns once with the final attempt's `context.result` -- one honest record,
  under-reporting that the body ran more than once.
* Sibling added BEFORE this gate (so it ends up OUTER, ahead of it), short-circuits before
  this gate is ever reached: nothing is recorded, nothing false -- safe by construction for
  THIS gate, though the sibling itself controls whether the check ever runs at all.
* This gate is the ONLY `FUNCTION_INVOCATION` filter on the kernel, or the last one added
  (innermost, closest to `inner_function`): safe by construction -- nothing between it and
  the real tool body can fabricate what it observes.

`strict_single_hook=False` (the default): `capture`/`authorized_params` are never passed
to `guard.check()`. `Guard.check()` itself stamps `Capture.PRE_HOOK_ONLY` and
`record_outcome()` is never called -- authorization is enforced exactly as always (this
gate still denies before `next(context)` runs, still raises/short-circuits on denial), and
nothing about the tool body's actual completion is claimed, regardless of what other
`FUNCTION_INVOCATION` filters are on this kernel, now or later.

`strict_single_hook=True`: an explicit caller attestation that `_dg_tool_gate` is the ONLY
`FilterTypes.FUNCTION_INVOCATION` filter that will ever be registered on this kernel, for
its whole lifetime -- unlocks `Capture.WRAPPER_ASYNC` and `record_outcome()`. This package
has no way to verify the attestation from inside `_dg_tool_gate`: `Kernel` exposes no
construction-time listing of a kernel's full, FINAL filter roster the way `pydantic-ai`'s
`for_agent()` offers for batch 1's equivalent detect-and-refuse pattern (`add_filter`
stays callable after `attach_guard` returns), so a wrong attestation reproduces exactly
the residuals enumerated above. Set it only when you control every
`FUNCTION_INVOCATION` filter on this kernel, for the kernel's entire lifetime.

`BodyState.RAISED`, genuinely (independent of `strict_single_hook`, once
`record_outcome()` actually runs under strict mode): verified directly against pinned
semantic-kernel 1.44.1: `KernelFunction.invoke`'s own `try`/`except Exception as e: ...;
raise e` around `await stack(function_context)` re-raises unchanged, and
`KernelFunctionFromMethod._invoke_internal` does not swallow its own exception either --
a raise from the tool body reaches this filter's `await next(context)` as a real Python
exception, so `BodyState.RAISED` (with `error_code = type(exc).__name__`) is genuinely
observed, not inferred.

The SAME registered filter also gates `invoke_stream` (both call sites share one
`FilterTypes.FUNCTION_INVOCATION` stack, subject to the same composition rules above).
There, `KernelFunctionFromMethod._invoke_internal_stream` sets `context.result.value` to
the raw generator/async-generator without consuming it -- the actual iteration happens in
`invoke_stream` itself, AFTER `next(context)` has already returned to this filter -- so
`context.result.value` is inspected for generator-ness (`_is_deferred_result`) and
reported as `BodyState.DEFERRED` when it is one, never fabricated as `RETURNED`.

`_freeze()` snapshot of `dict(context.arguments)` — the function's own raw invocation
arguments, not the derived `policy.context_for(...)` ceiling context — taken immediately
before `await next(context)` runs, only under `strict_single_hook=True`.
`asyncio.CancelledError` on the filter's own `await` is `BodyState.ABANDONED`, still
re-raised.

ROUND 2 CORRECTION (Codex review, batch 2, finding 1): the previous revision of this
section claimed `Capture.WRAPPER_ASYNC` was unconditionally "a genuine ... observation"
for every `_dg_tool_gate` call. That was wrong -- verified against pinned
`kernel_filters_extension.py` as documented above -- because `construct_call_stack` folds
EVERY `FUNCTION_INVOCATION` filter registered on the same kernel into ONE composed chain,
and `kernel.add_filter` stays callable for the kernel's whole lifetime, not only before
`attach_guard(...)` runs. `strict_single_hook` (default `False`) is the fix: genuine
capture is now an explicit, scoped opt-in, not a default claim this adapter could not
actually back.

On `schema_version=1` (the default), nothing in this whole section applies. The
delegation gate (`_dg_delegation_gate`) never calls `guard.check()` at all — a handoff
mints the target's Guard via `chain.delegate()` -> `Guard.delegate()`, not a scope check —
so it stays outside execution binding entirely, in either mode, same as every adapter
whose delegation is a mint rather than a priced call (`adapters.langchain`/
`adapters.llama_index`/`adapters.camel`, unlike `adapters.ag2`/`adapters.agent_framework`).

This module imports `semantic_kernel` and `attenu_guard` and nothing else.
Copy it into your project as-is.
"""
from __future__ import annotations

import asyncio
import inspect
import time

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Mapping

from semantic_kernel.exceptions.function_exceptions import FunctionExecutionException
from semantic_kernel.filters.filter_types import FilterTypes
from semantic_kernel.functions.function_result import FunctionResult

from attenu_guard import Authority, AuthorityDenied, Decision, Guard, ReasonCode, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition

# Reason code for "this principal holds no Authority in the chain at all".
# `getattr` because older attenu-guard releases predate the constant; the
# wire value is the contract, not the Python name.
NO_AUTHORITY = getattr(ReasonCode, "NO_AUTHORITY", "no_authority")

_ADAPTER_INFO = {"module": __name__, "version": __version__, "hook_path": f"{__name__}._dg_tool_gate"}


def _is_deferred_result(result: Any) -> bool:
    if inspect.isgenerator(result) or inspect.isasyncgen(result):
        return True
    return False


def _body_state_for(result: Any) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


from ._snapshot import freeze as _freeze


__all__ = [
    "ToolPolicy",
    "UNGUARDED",
    "GuardedCall",
    "DelegationChain",
    "attach_guard",
    "authority_denial",
    "MissingGuardError",
    "UnmappedToolError",
    "HANDOFF_PLUGIN_NAME",
    "HANDOFF_FUNCTION_PREFIX",
]

# Semantic Kernel's own names for the synthetic handoff plugin/functions
# (`semantic_kernel/agents/orchestration/handoffs.py:147` and `:194`).
HANDOFF_PLUGIN_NAME = "Handoff"
HANDOFF_FUNCTION_PREFIX = "transfer_to_"

OnDenial = Literal["raise", "result"]
"""What to do when the Guard denies a tool call.

`"raise"`  — raise `attenu_guard.AuthorityDenied`. The default.
             In a direct `kernel.invoke(...)` this propagates to the caller,
             so a denial can never be mistaken for a successful call. Inside
             the LLM's auto-tool-calling loop, Semantic Kernel catches it in
             `Kernel._inner_auto_function_invoke_handler`
             (`semantic_kernel/kernel.py:470-476`) and turns it into a tool
             result the model reads — `str(AuthorityDenied)` is
             `Decision.explain()`, so the reason codes reach the model — and
             the loop continues. Graceful in the loop, loud outside it.

`"result"` — short-circuit with a `FunctionResult` carrying the denial text and
             do NOT call `next(context)`. The model sees a clean, purpose-built
             tool result instead of an error string. The tool body still never
             runs, but a direct `kernel.invoke(...)` caller that ignores the
             result value would not notice the denial — which is why this is
             not the default.
"""

OnUnmapped = Literal["deny", "allow"]
"""What to do when an invoked function has no `ToolPolicy`.

`"deny"` (default) fails closed: a tool whose authority cost nobody declared
cannot be shown to be within the agent's authority.
"""


class MissingGuardError(FunctionExecutionException):
    """No `Guard` is bound for this agent in the `DelegationChain`.

    Fail-closed: a missing Guard means this agent was never delegated to (or the
    chain was not wired), which would otherwise silently disable enforcement.
    """


class UnmappedToolError(FunctionExecutionException):
    """An invoked KernelFunction has no `ToolPolicy` declaring what authority it
    consumes. Fail-closed by default; pass `on_unmapped="allow"` to let unmapped
    functions through."""


# ==========================================================================
# Policy: what authority does this tool consume?
#
# attenu-guard deliberately does not decide this for you — the integrator
# declares it, once, per tool.
# ==========================================================================

@dataclass(frozen=True)
class ToolPolicy:
    """The authority one KernelFunction consumes.

    scope
        The scope string checked against the agent's authority, e.g.
        `"crm.read"`.
    context
        Either a mapping, or a callable taking the invocation's
        `KernelArguments` and returning the context mapping passed to
        `Guard.check(context=...)` — the quantities the typed ceilings are
        evaluated against (e.g. `{"rows": 4200}`, `{"egress": "any"}`).
        `None` means an empty context: fine for a scope-only check.
    metered
        Forwarded to `Guard.check(metered=...)`. Set it on tools that consume a
        metered resource (rows, spend, calls) so a Guard issued with
        `strict_metering=True` refuses a call that declares no quantity at all,
        instead of treating it as free.
    """

    scope: str
    context: Callable[[Mapping[str, Any]], Mapping[str, Any]] | Mapping[str, Any] | None = None
    metered: bool = False
    disposition: str | None = None        # see attenu_guard.Disposition

    def context_for(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.context is None:
            return {}
        if callable(self.context):
            return self.context(arguments)
        return self.context


UNGUARDED = ToolPolicy(scope="")
"""Sentinel `ToolPolicy` marking a function as needing no authority at all
(pure computation, formatting helpers, ...). Map a function to `UNGUARDED` to
let it through without a `Guard.check()` — an explicit, greppable exemption
rather than a silent gap."""


@dataclass(frozen=True)
class GuardedCall:
    """One authorization event, as an in-memory mirror of the audit log keyed to
    Semantic Kernel's own names. Recorded only when the `DelegationChain` was
    built with `trace=True`; the durable, tamper-evident record is always the
    chain's `audit_log()`."""

    agent: str
    tool: str
    scope: str
    decision: Decision


# ==========================================================================
# The chain: one shared, mutable registry of agent-name -> Guard.
#
# This object is what every filter closes over. It must be shared by identity
# across `Kernel.clone()`, which is why it is reached through a closure cell
# (deepcopy-atomic) and never stored on a plugin or a callable-object filter.
# ==========================================================================

class DelegationChain:
    """Maps Semantic Kernel agent names to their `Guard`s for one run."""

    def __init__(self, root_agent: str, root_guard: Guard, *, trace: bool = False):
        self._guards: dict[str, Guard] = {root_agent: root_guard}
        self._root_agent = root_agent
        self._root = root_guard
        self._trace = trace
        self.decisions: list[GuardedCall] = []

    # ---- identity ------------------------------------------------------
    @property
    def root(self) -> Guard:
        return self._root

    @property
    def root_agent(self) -> str:
        return self._root_agent

    @property
    def agents(self) -> Mapping[str, Guard]:
        return dict(self._guards)

    # ---- binding -------------------------------------------------------
    def guard_for(self, agent_name: str) -> Guard | None:
        return self._guards.get(agent_name)

    def bind(self, agent_name: str, guard: Guard) -> Guard:
        """Attach an already-minted Guard to an agent name."""
        self._guards[agent_name] = guard
        return guard

    def delegate(self, sender: str, target: str, authority: Authority, task: str) -> Guard:
        """Mint `target`'s Guard as an attenuation of `sender`'s and bind it.

        Raises `MissingGuardError` if the sender holds no Guard, and
        `attenu_guard.AuthorityError` if the chain refuses the delegation
        structurally (revoked/expired parent, depth or fanout overflow).
        """
        parent = self.guard_for(sender)
        if parent is None:
            raise MissingGuardError(
                f"agent {sender!r} holds no Guard, so it cannot delegate to {target!r}")
        return self.bind(target, parent.delegate(target, authority, task=task))

    # ---- chain controls ------------------------------------------------
    def revoke(self, agent_name: str) -> list:
        """Cascade-revoke an agent and every descendant it delegated to."""
        guard = self.guard_for(agent_name)
        if guard is None:
            raise MissingGuardError(f"agent {agent_name!r} holds no Guard, nothing to revoke")
        return self._root.revoke(guard.node_id)

    # ---- introspection -------------------------------------------------
    def audit_log(self):
        return self._root.audit_log()

    def graph(self) -> dict:
        return self._root.graph()

    def _record(self, agent: str, tool: str, scope: str, decision: Decision) -> None:
        if self._trace:
            self.decisions.append(GuardedCall(agent, tool, scope, decision))

    def record_refusal(self, agent: str, tool: str, reason: str, message: str,
                       disposition: str | None = None) -> Decision | None:
        """Put an ADAPTER-level refusal (unmapped tool, unknown agent, undeclared
        handoff target) on the audit trail.

        Without this, a fail-closed refusal leaves no trace: there is no Guard to
        run `check()` against, so the tamper-evident log would show the attempt
        as never having happened — precisely the events an incident responder
        most wants. Recorded against the chain root, which always exists.

        Uses `Guard.record_denial` where the installed attenu-guard has it,
        and degrades to trace-only otherwise, so this adapter works against
        v0.2.0 as tagged. See the findings note on this API gap.
        """
        recorder = getattr(self._root, "record_denial", None)
        decision = None
        if recorder is not None:
            decision = recorder(reason, message, scope=tool, tool=tool, disposition=disposition)
        if self._trace and decision is not None:
            self.decisions.append(GuardedCall(agent, tool, tool, decision))
        return decision


# ==========================================================================
# The integration: two filters, registered on one agent's Kernel.
# ==========================================================================

def attach_guard(
    kernel,
    *,
    agent_name: str,
    chain: DelegationChain,
    policies: Mapping[str, ToolPolicy],
    authority_for: Mapping[str, Authority] | Callable[[str, str], Authority | None] | None = None,
    task_for: Callable[[str, str], str] | None = None,
    on_denial: OnDenial = "raise",
    on_unmapped: OnUnmapped = "deny",
    exempt_plugins: Iterable[str] = (HANDOFF_PLUGIN_NAME,),
    delegation_plugin: str = HANDOFF_PLUGIN_NAME,
    delegation_prefix: str = HANDOFF_FUNCTION_PREFIX,
    strict_single_hook: bool = False,
):
    """Register attenu-guard's two filters on one agent's `Kernel`.

    Call this once per agent, on `agent.kernel`, before handing the agents to an
    orchestration — `HandoffOrchestration` clones each agent's kernel at actor
    construction (`handoffs.py:175`), and the clone carries the filters with it.

    Parameters
    ----------
    kernel
        The `semantic_kernel.Kernel` belonging to THIS agent. Semantic Kernel has
        no per-agent filter registry — filters live on the kernel — so agents
        must not share one kernel if they are to have different authority.
        `attach_guard` raises `ValueError` if the same kernel is guarded twice.
    agent_name
        This agent's `Agent.name`. It is the key into `chain`, and it is what
        makes the same filter code resolve a different Guard per agent.
    policies
        Maps a function name to the authority it consumes. Keys are matched
        against `fully_qualified_name` first (`"Crm-crm_query"` — Semantic Kernel
        joins plugin and function with a hyphen,
        `semantic_kernel/functions/kernel_function_metadata.py:26-34`) and then
        against the bare function name (`"crm_query"`).
    authority_for
        Only needed on an agent that hands off. Either a mapping from target
        agent name to the `Authority` to request for it, or a callable
        `(sender, target) -> Authority | None`. Returning `None` refuses the
        handoff. Omit it entirely and the delegation filter is not registered.
        The granted authority is always `parent.authority.meet(request)`, so a
        too-generous entry here is met down, never honoured as written.
    task_for
        Optional `(sender, target) -> str` for the `task=` recorded on the
        delegation. Defaults to `"handoff: <sender> -> <target>"`.
    exempt_plugins
        Plugins the tool gate skips. Defaults to Semantic Kernel's synthetic
        `Handoff` plugin, whose functions are control transfer rather than
        tools — the delegation filter governs those instead.
    strict_single_hook
        See the module docstring's "EXECUTION BINDING ... TWO MODES" -- `False`
        (default) never claims genuine execution capture, safe no matter what other
        `FilterTypes.FUNCTION_INVOCATION` filters are on THIS kernel, now or added
        later (`kernel.add_filter` is always available after `attach_guard` returns).
        `True` attests this is the ONLY function-invocation filter that will ever run
        on this kernel, for its whole lifetime.

    Returns the kernel, so it can be used inline.
    """
    if getattr(kernel, "_attenu_guard_agent", None) is not None:
        raise ValueError(
            f"this Kernel is already guarded as {kernel._attenu_guard_agent!r}; "
            f"give {agent_name!r} its own Kernel (filters are per-kernel, not per-agent)")

    exempt = frozenset(exempt_plugins)

    # ---------------------------------------------------------------- #
    # Hook 2: the tool gate. A plain function — see the module docstring
    # on Kernel.clone() deepcopying filters.
    # ---------------------------------------------------------------- #
    async def _dg_tool_gate(context, next):
        function = context.function
        metadata = function.metadata

        if metadata.plugin_name in exempt:
            await next(context)
            return

        policy = _resolve_policy(policies, metadata)
        if policy is None:
            if on_unmapped == "allow":
                await next(context)
                return
            message = (f"{agent_name}: no ToolPolicy declared for "
                       f"{function.fully_qualified_name!r}; refusing to run it. Declare its "
                       f"scope, map it to UNGUARDED, or pass on_unmapped='allow'.")
            chain.record_refusal(agent_name, function.fully_qualified_name,
                                 "unmapped_tool", message, disposition=Disposition.UNRESOLVED)
            raise UnmappedToolError(message)
        if policy is UNGUARDED:
            await next(context)
            return

        guard = chain.guard_for(agent_name)
        if guard is None:
            message = (f"{agent_name}: no Guard bound in the delegation chain, so "
                       f"{function.fully_qualified_name!r} cannot be authorized. This agent "
                       f"was never delegated to.")
            chain.record_refusal(agent_name, function.fully_qualified_name,
                                 NO_AUTHORITY, message)
            raise MissingGuardError(message)

        v2 = strict_single_hook and guard.schema_version == 2
        snapshot = _freeze(dict(context.arguments)) if v2 else None
        extra = dict(capture=Capture.WRAPPER_ASYNC, adapter=_ADAPTER_INFO,
                    authorized_params=snapshot) if v2 else {}
        decision = guard.check(
            policy.scope,
            context=policy.context_for(context.arguments),
            metered=policy.metered,
            tool=function.fully_qualified_name,
            disposition=policy.disposition,
            **extra,
        )
        chain._record(agent_name, function.fully_qualified_name, policy.scope, decision)

        if not decision:
            if on_denial == "raise":
                raise AuthorityDenied(decision)
            # Short-circuit: returning without awaiting next(context) means
            # KernelFunction._invoke_internal is never reached
            # (semantic_kernel/functions/kernel_function.py:271-275).
            context.result = FunctionResult(
                function=metadata,
                value=f"Authorization denied for {function.fully_qualified_name}: "
                      f"{decision.explain()}",
                metadata={"attenu_guard": decision.to_dict()},
            )
            return

        call_id = decision.call_id if v2 else None
        if call_id is None:
            await next(context)
            return

        started_at = time.monotonic()
        try:
            await next(context)
        except asyncio.CancelledError:
            guard.record_outcome(call_id, BodyState.ABANDONED,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
            raise
        except Exception as exc:
            guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))
            raise
        result_value = context.result.value if context.result is not None else None
        guard.record_outcome(call_id, _body_state_for(result_value),
                             invoked_params=snapshot, duration_ms=_elapsed_ms(started_at))

    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, _dg_tool_gate)

    # ---------------------------------------------------------------- #
    # Hook 1: the delegation gate, on the auto-invocation loop, where
    # Handoff-transfer_to_<Target> is called.
    # ---------------------------------------------------------------- #
    if authority_for is not None:
        resolve_authority = (
            authority_for if callable(authority_for)
            else (lambda sender, target, _m=authority_for: _m.get(target))
        )

        async def _dg_delegation_gate(context, next):
            metadata = context.function.metadata
            if (metadata.plugin_name != delegation_plugin
                    or not (metadata.name or "").startswith(delegation_prefix)):
                await next(context)
                return

            function_name = metadata.fully_qualified_name
            target = metadata.name[len(delegation_prefix):]
            request = resolve_authority(agent_name, target)
            if request is None:
                message = (f"{agent_name}: handoff to {target!r} refused — no Authority "
                           f"declared for that target in authority_for.")
                chain.record_refusal(agent_name, function_name, NO_AUTHORITY, message)
                raise MissingGuardError(message)

            task = (task_for(agent_name, target) if task_for
                    else f"handoff: {agent_name} -> {target}")
            # Guard.delegate raises AuthorityError if the parent is revoked or
            # expired, or if a depth/fanout ceiling is hit — so an unauthorized
            # handoff fails here, before control transfers.
            chain.delegate(agent_name, target, request, task)

            await next(context)

        kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION, _dg_delegation_gate)

    # Marker so a double-attach is caught rather than silently doubling every
    # check (and every audit entry). Kernel is a pydantic model, so this goes
    # through object.__setattr__ rather than field assignment.
    object.__setattr__(kernel, "_attenu_guard_agent", agent_name)
    return kernel


def authority_denial(exc: BaseException | None) -> Decision | None:
    """Return the `Decision` behind a denial, or `None` if `exc` was not one.

    Needed because `Kernel.invoke(...)` swallows the original exception and
    re-raises `KernelInvokeException(...) from exc`
    (`semantic_kernel/kernel.py:206-213`), so `except AuthorityDenied` does not
    catch a denial that came through the kernel-level convenience API. (The
    function-level `KernelFunction.invoke(...)` re-raises unwrapped —
    `semantic_kernel/functions/kernel_function.py:288-290` — as does the direct
    filter path.) This walks the `__cause__` chain so a caller can write:

        try:
            await kernel.invoke(plugin_name="Crm", function_name="crm_export", ...)
        except Exception as exc:
            decision = authority_denial(exc)
            if decision is None:
                raise
            log.warning("blocked: %s", decision.explain())
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, AuthorityDenied):
            return exc.decision
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return None


def _resolve_policy(policies: Mapping[str, ToolPolicy], metadata) -> ToolPolicy | None:
    """Fully-qualified name first (`"Crm-crm_query"`), then the bare function
    name (`"crm_query"`) so a plugin can be renamed without rewriting policy."""
    policy = policies.get(metadata.fully_qualified_name)
    if policy is None:
        policy = policies.get(metadata.name)
    return policy
