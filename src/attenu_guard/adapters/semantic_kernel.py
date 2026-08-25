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

This module imports `semantic_kernel` and `attenu_guard` and nothing else.
Copy it into your project as-is.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Mapping

from semantic_kernel.exceptions.function_exceptions import FunctionExecutionException
from semantic_kernel.filters.filter_types import FilterTypes
from semantic_kernel.functions.function_result import FunctionResult

from attenu_guard import Authority, AuthorityDenied, Decision, Guard, ReasonCode
from attenu_guard.reasons import Disposition

# Reason code for "this principal holds no Authority in the chain at all".
# `getattr` because older attenu-guard releases predate the constant; the
# wire value is the contract, not the Python name.
NO_AUTHORITY = getattr(ReasonCode, "NO_AUTHORITY", "no_authority")

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

        decision = guard.check(
            policy.scope,
            context=policy.context_for(context.arguments),
            metered=policy.metered,
            tool=function.fully_qualified_name,
            disposition=policy.disposition,
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

        await next(context)

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
