# SPDX-License-Identifier: Apache-2.0
"""The delegate contract of ``anthropics/commerce-agents``, enforced.

``commerce_common.delegation``'s module docstring states the contract in one sentence:
*"A delegate receives a task brief and the session handles, never the conversation or the
executor, and returns one schema-validated result; it cannot write, present, or invoke
other delegates."* Today the second half of that sentence is held by construction and by
each delegate author: the delegate gets a :class:`~commerce_common.delegation.DelegationContext`
rather than the executor, and the one delegate the repo ships keeps writes out with a
name test inside its own runner. Nothing on the shared dispatch point records what a
delegate was allowed to do, checks it against what its parent held, or leaves a record a
reviewer can check later.

This module puts those three things on the dispatch point. It hooks
:meth:`commerce_common.execution.BaseToolExecutor.dispatch`, which is where every tool
call on every path arrives -- the Messages API runtime, the Agent SDK toolset, the MCP
server, and a delegate's own reads all route through it. Nothing here imports
``commerce_common`` at module import time, so the module loads with the repo absent.

Three entry points, all running the same authorization core:

``guarded_executor_class(MerchantToolExecutor, policy, grants)``
    A subclass whose ``dispatch`` authorizes first. **Start here.** The repo already
    documents ``executor_class`` as "the seam for a deployment's own
    ``MerchantToolExecutor`` subclass" and takes it on every consumption path -- the
    Messages API orchestrator, the Agent SDK toolset and the MCP server -- with a test
    of its own that asserts all three do. Nothing is patched: the deployment hands this
    class over the same seam it would use for its own wording or error mapping.

``guard_executor(executor, guard, policy, grants)``
    The same thing for one executor instance you already hold, by replacing its bound
    ``dispatch``. For a call site that constructs the executor directly rather than
    through a runtime that takes ``executor_class``.

``install(policy, grants, root=...)``
    Patches ``BaseToolExecutor.dispatch`` once, process-wide, so an executor built
    somewhere neither of the above reaches is guarded too. This is a monkeypatch. Read
    the "Which entry point" section below before using it.

All three resolve the authorizing node the same way, in order: the guard bound to the
delegate body currently running (a ``contextvars`` binding this module sets around
``delegate.run``), then the guard bound to the executor instance, then the installed
root. :func:`authorize_as` is how a turn puts its own root at the head of that order. A
dispatch that resolves to no guard is HELD, never allowed.

Which entry point
-----------------
The class seam covers every executor a deployment's own runtime builds. It does not cover
one a third-party delegate constructs internally, because that runner names the class
itself: ``AnalysisRunner._read`` writes ``MerchantToolExecutor(...)`` rather than the
deployment's ``executor_class``, so the seam the repo documents on every path stops at the
delegate's own reads. ``install()`` covers that, at the cost of patching a class the
application does not own.

The change that would remove the need for ``install()`` is to carry ``executor_class``
into the analysis delegate the way every other path already carries it. ``README.md``
"Where the seam stops" states it as a verified diff, for a reader who vendors or forks the
packages: commerce-agents is a reference implementation that does not accept contributions
(its ``README.md:193``), so that diff is not a proposal to anyone. The wiring does NOT
exist upstream today -- this module works against the repo as it is.

What a delegate holds
---------------------
A delegate's authority is not written by hand. :meth:`DelegateGrant.from_tools` derives
it from the tools the delegate's own surface declares -- for the shipped analysis
delegate that is ``merchant_agent.analysis.ANALYSIS_READ_TOOLS`` -- mapped through the
same ``policy`` the executor authorizes against. :meth:`attenu_guard.Guard.delegate` then
takes the meet with the parent's authority, so the child is a subset of the parent by
construction whatever the grant asked for, and the ``spawn`` entry on the ledger records
both what was requested and what was granted.

Ceilings ride the same rule. ``MerchantAgentConfig.max_campaign_budget`` is one number
for the whole deployment: the operator's turn and any delegate that reaches
``stage_campaign`` are checked against the same limit, because the delegate holds the
same config object. Put that number on the root node as a
:class:`~attenu_guard.SpendCap` and a delegate's cap can be lower and can never be
higher.
"""
from __future__ import annotations

import contextlib
import contextvars
import functools
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from attenu_guard import Authority, AuthorityError, Disposition, ReasonCode

__all__ = [
    "AUTHORITY_GATE",
    "UNGUARDED",
    "DelegateGrant",
    "ToolPolicy",
    "authorize_as",
    "bind",
    "current_guard",
    "guard_executor",
    "guarded_executor_class",
    "held_text",
    "install",
    "scopes_for",
]

#: The ``ToolOutcome.blocked`` gate name for a call this module refused. It sits beside
#: the repo's own gate names (``merchant_agent.gates.PROVENANCE_GATE`` and its
#: neighbours), so a host that already renders a held call renders this one unchanged.
AUTHORITY_GATE = "authority"


class _Unguarded:
    """The sentinel for a tool that spends no authority. Distinct from an absent policy
    entry, which is refused."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNGUARDED"


#: A tool that spends no authority: dispatched without a ``check()``. Use it for a tool
#: whose effect is already covered by another scope, never to make an unmapped tool run.
UNGUARDED = _Unguarded()


@dataclass(frozen=True)
class ToolPolicy:
    """What one tool costs.

    :param scope: The scope the call consumes, e.g. ``"pricing.stage"``.
    :param context: Optional callable taking the call's arguments (the tool input with
        the ``status`` line already split off, exactly what the handler will receive) and
        returning the ceiling context for ``check()``, e.g.
        ``lambda args: {"spend": args["budget"]}``.
    """

    scope: str
    context: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None


@dataclass(frozen=True)
class DelegateGrant:
    """What a delegate asks its parent for, at the moment the parent dispatches it.

    The request is an input to :meth:`attenu_guard.Guard.delegate`, never an output of
    it: the child's authority is the meet of this request with the parent's, so a grant
    that asks for more than the parent holds yields the parent's, not the request's.

    :param agent_id: The child's name on the chain and in the ledger.
    :param scopes: Scopes the delegate asks to hold.
    :param ceilings: Ceilings it asks to be bound by.
    :param ttl: Seconds the child's authority stays valid.
    :param task: What the ``spawn`` entry records as the delegation's task. A plain
        string by default; a callable is passed the call's arguments and must return a
        string. Whatever it returns is written to the ledger, so returning model-authored
        text puts that text in the evidence bundle unless it is exported with
        ``redact_task=True``.
    """

    agent_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    ceilings: tuple = ()
    ttl: int | None = None
    task: str | Callable[[dict[str, Any]], str] = "delegate"

    @classmethod
    def from_tools(
        cls,
        agent_id: str,
        tools: Sequence[str],
        policy: Mapping[str, Any],
        *,
        ceilings: Sequence[Any] = (),
        ttl: int | None = None,
        task: str | Callable[[dict[str, Any]], str] = "delegate",
    ) -> "DelegateGrant":
        """Derive the request from the tools the delegate's surface declares.

        :param agent_id: The child's name on the chain.
        :param tools: The delegate's declared tool names, e.g.
            ``merchant_agent.analysis.ANALYSIS_READ_TOOLS``.
        :param policy: The same tool-to-scope map the executor authorizes against.
        :param ceilings: Ceilings to request beside the derived scopes.
        :param ttl: Seconds the child's authority stays valid.
        :param task: What the ``spawn`` entry records.
        :returns: The grant.
        :raises KeyError: When a declared tool has no policy entry. A delegate whose
            surface names a tool nobody mapped is a gap in the policy, not a tool to wave
            through.
        """
        return cls(
            agent_id=agent_id,
            scopes=frozenset(scopes_for(tools, policy)),
            ceilings=tuple(ceilings),
            ttl=ttl,
            task=task,
        )

    def authority(self) -> Authority:
        """This grant as an :class:`~attenu_guard.Authority`.

        :returns: The requested authority.
        """
        return Authority(scopes=self.scopes, ceilings=self.ceilings, ttl=self.ttl)

    def task_for(self, arguments: Mapping[str, Any]) -> str:
        """The task string recorded on the ``spawn`` entry for one call.

        :param arguments: The delegate call's arguments.
        :returns: The task string.
        """
        return self.task(dict(arguments)) if callable(self.task) else self.task


def scopes_for(tools: Sequence[str], policy: Mapping[str, Any]) -> set[str]:
    """The scopes a set of tool names consumes under ``policy``.

    :param tools: Tool names.
    :param policy: Tool-to-:class:`ToolPolicy` map; ``UNGUARDED`` entries contribute
        nothing.
    :returns: The scope set.
    :raises KeyError: When a tool has no policy entry.
    """
    out: set[str] = set()
    for name in tools:
        if name not in policy:
            raise KeyError(
                f"tool {name!r} has no policy entry; map it to a ToolPolicy or to UNGUARDED"
            )
        entry = policy[name]
        if entry is not UNGUARDED:
            out.add(entry.scope)
    return out


# ---------------------------------------------------------------------------------------
# The authorizing node
# ---------------------------------------------------------------------------------------

#: The node authorizing right now. Set around a delegate's ``run`` so any executor built
#: inside that body -- including one the delegate's own runner constructs, which nothing
#: outside can reach -- authorizes as the child rather than as the parent.
_CURRENT: contextvars.ContextVar[Any] = contextvars.ContextVar("attenu_commerce_guard", default=None)

#: Where :func:`guard_executor` stores an executor's own guard.
_GUARD_ATTR = "_attenu_guard"

#: The process-wide fallback :func:`install` sets. Only ever read last.
_INSTALLED_ROOT: list[Any] = []

#: True while one guarded ``dispatch`` is running its authorization and inner call. A
#: second authorizer stacked on the SAME call sees it and passes straight through, so a
#: stacking that slipped past the construction-time refusals costs one ``check()``, not
#: two. The delegate branch clears it before running the delegate body, because the calls
#: a delegate makes are new calls that must be authorized against the child -- clearing it
#: there is what keeps this a same-call guard rather than a "nested dispatch" one.
_IN_DISPATCH: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "attenu_commerce_in_dispatch", default=False)


def current_guard() -> Any:
    """The node a dispatch would authorize against right now, or ``None``.

    Resolution order: the delegate body currently running, then the executor's own guard
    (that part needs the executor, so this function only answers the first and third),
    then the installed root.

    :returns: A :class:`~attenu_guard.Guard`, or ``None`` when nothing is bound.
    """
    return _CURRENT.get() or (_INSTALLED_ROOT[0] if _INSTALLED_ROOT else None)


@contextlib.contextmanager
def authorize_as(guard: Any):
    """Bind ``guard`` as the authorizing node for everything inside the block.

    How a turn puts its own chain root at the head of the resolution order, which is what
    a class-seam integration needs: the executor class is fixed at deployment time and the
    chain is per request. The binding is a ``contextvars`` one, so a task created inside
    the block inherits it and a task created outside does not; a delegate running inside
    rebinds to its own child and restores this one on the way out.

    :param guard: The node to authorize against.
    :yields: The same guard.
    """
    token = _CURRENT.set(guard)
    try:
        yield guard
    finally:
        _CURRENT.reset(token)


def bind(executor: Any, guard: Any) -> Any:
    """Pin ``guard`` to one executor instance, for a call site with no turn scope.

    Read after the delegate body and before the installed root. :func:`guard_executor`
    does this for you; use it directly on an instance of a
    :func:`guarded_executor_class`.

    :param executor: The executor.
    :param guard: The node its calls authorize against.
    :returns: The same executor.
    """
    setattr(executor, _GUARD_ATTR, guard)
    return executor


def _resolve(executor: Any) -> Any:
    """The node one executor's dispatch authorizes against.

    :param executor: The executor being dispatched on.
    :returns: A :class:`~attenu_guard.Guard`, or ``None``.
    """
    return (
        _CURRENT.get()
        or getattr(executor, _GUARD_ATTR, None)
        or (_INSTALLED_ROOT[0] if _INSTALLED_ROOT else None)
    )


def held_text(decision: Any) -> str:
    """The operator-readable line a denial puts in the tool result.

    :param decision: The denied :class:`~attenu_guard.Decision`.
    :returns: One sentence naming the scope and the reason.
    """
    return (
        f"That call is outside this agent's authority: {decision.explain()} "
        "Nothing ran. A wider authority is the deployment's to grant."
    )


# ---------------------------------------------------------------------------------------
# The hook
# ---------------------------------------------------------------------------------------

def _guarded_dispatch(inner, executor, policy, grants, on_unmapped):
    """Build one guarded ``dispatch``.

    :param inner: The dispatch this wraps: a bound method for an instance hook, the
        unbound function for a class hook (which is then called with ``executor`` first).
    :param executor: The executor instance, or ``None`` for a class hook (resolved
        per-call from ``self``).
    :param policy: Tool-to-:class:`ToolPolicy` map.
    :param grants: Delegate-name-to-:class:`DelegateGrant` map.
    :param on_unmapped: ``"deny"`` or ``"allow"`` for a tool absent from ``policy``.
    :returns: An async callable with ``dispatch``'s signature.
    """
    from commerce_common.streaming import ToolOutcome

    async def dispatch(self_or_name, *rest):
        # An instance hook is called `dispatch(name, tool_input)`; a class hook is called
        # `dispatch(self, name, tool_input)`. One body serves both. Every call site in the
        # repo passes both arguments positionally (execution.py:216, agent_sdk.py:215).
        if executor is None:
            this, name, tool_input = self_or_name, rest[0], rest[1]
            call_inner = functools.partial(inner, this)
        else:
            this, name, tool_input = executor, self_or_name, rest[0]
            call_inner = inner

        # A second authorizer stacked on this same call: authorize once, not twice. The
        # construction-time refusals below make this unreachable through the public API;
        # it is the runtime backstop for a stacking they did not see.
        if _IN_DISPATCH.get():
            return await call_inner(name, tool_input)

        guard = _resolve(this)
        if guard is None:
            return ToolOutcome.held(
                AUTHORITY_GATE,
                f"{name} was not dispatched: no authority is bound to this executor. "
                "Open a turn with authorize_as(guard), or bind one with bind() / "
                "guard_executor() / install(root=...).",
            )

        # `dispatch` splits the status line off before any argument is validated
        # (execution.py). Do the same here so the policy's context callable and the
        # ledger see the arguments the handler will actually receive, not the model's
        # display line beside them.
        arguments, _status = this.split_status(name, dict(tool_input or {}))

        entry = policy.get(name)
        if entry is None:
            if on_unmapped == "deny":
                guard.record_denial(
                    ReasonCode.NO_AUTHORITY,
                    f"{name} is not in the policy map",
                    tool=name,
                    disposition=Disposition.UNRESOLVED,
                )
                return ToolOutcome.held(
                    AUTHORITY_GATE,
                    f"{name} is not a tool this deployment maps to an authority; nothing ran.",
                )
            entry = UNGUARDED

        if entry is not UNGUARDED:
            try:
                context = dict(entry.context(arguments)) if entry.context else {}
            except Exception as failed:  # noqa: BLE001 - a policy bug must not open the tool
                # `execute` would turn a raised exception into its "temporarily
                # unavailable" line, which says the wrong thing about an unevaluated
                # ceiling. Fail closed, and say which policy entry is broken.
                guard.record_denial(
                    ReasonCode.NO_AUTHORITY,
                    f"the policy context for {name} raised {type(failed).__name__}",
                    tool=name,
                    disposition=Disposition.UNRESOLVED,
                )
                return ToolOutcome.held(
                    AUTHORITY_GATE,
                    f"{name} could not be authorized: this deployment's policy entry for it "
                    f"raised {type(failed).__name__}. Nothing ran.",
                )
            decision = guard.check(entry.scope, context=context, tool=name)
            if not decision:
                return ToolOutcome.held(AUTHORITY_GATE, held_text(decision))

        # A delegate call: mint the child HERE, at the delegation site, and bind it for
        # the body's duration. `_run_delegate` and everything under it -- including an
        # executor the delegate's own runner builds -- then authorizes as the child.
        delegate_names = getattr(this, "_delegates", None) or {}
        if name in delegate_names:
            grant = grants.get(name)
            if grant is None:
                guard.record_denial(
                    ReasonCode.NO_AUTHORITY,
                    f"{name} has no delegate grant",
                    tool=name,
                    disposition=Disposition.UNRESOLVED,
                )
                return ToolOutcome.held(
                    AUTHORITY_GATE,
                    f"{name} is a delegate this deployment has not granted an authority; "
                    "nothing ran.",
                )
            try:
                child = guard.delegate(
                    grant.agent_id, grant.authority(), grant.task_for(arguments)
                )
            except AuthorityError as failed:
                # Structural: a revoked or expired parent, or a depth/fanout overflow.
                # `delegate()` has already written the `spawn_denied` entry.
                return ToolOutcome.held(
                    AUTHORITY_GATE,
                    f"{name} was not started: {failed}. Nothing ran.",
                )
            # `_IN_DISPATCH` is deliberately NOT set here. The delegate body's own tool
            # calls are new calls that must be authorized against the child, so entering
            # a delegate opens a fresh authorization scope exactly as it rebinds the node.
            token = _CURRENT.set(child)
            try:
                return await call_inner(name, tool_input)
            finally:
                _CURRENT.reset(token)

        reentry = _IN_DISPATCH.set(True)
        try:
            return await call_inner(name, tool_input)
        finally:
            _IN_DISPATCH.reset(reentry)

    # The mark every "is this already authorized?" check reads. It rides on the function
    # object, so it is visible through a class attribute, a bound method and an instance
    # attribute alike -- which is what makes the check work in every direction.
    dispatch._attenu_guarded = True
    return dispatch


def _already_guarded(dispatch: Any) -> bool:
    """Whether a ``dispatch`` (class attribute, bound method or instance attribute) is
    already an authorization path.

    :param dispatch: The dispatch to inspect.
    :returns: True when a second authorizer would double-authorize every call.
    """
    return bool(getattr(dispatch, "_attenu_guarded", False))


def guarded_executor_class(
    base: Any,
    policy: Mapping[str, Any],
    grants: Mapping[str, DelegateGrant] | None = None,
    *,
    on_unmapped: str = "deny",
    name: str | None = None,
) -> Any:
    """A subclass of ``base`` whose ``dispatch`` authorizes before it routes.

    The integration the repo already has a seam for. ``MerchantAgent``, the Agent SDK
    toolset and the MCP server each take ``executor_class`` -- documented as "the seam
    for a deployment's own ``MerchantToolExecutor`` subclass" -- so this class goes in
    over the supported parameter and nothing is patched::

        Guarded = guarded_executor_class(MerchantToolExecutor, POLICY, GRANTS)
        agent = MerchantAgent(backend=..., config=..., executor_class=Guarded)

        root = Guard.issue("merchant-turn", OPERATOR_AUTHORITY, task=...)
        with authorize_as(root):
            async for event in agent.stream_turn(messages, session, state):
                ...

    Override only ``dispatch``, so a deployment's own subclass (its ``domain_error``
    mapping, its wording) can be the ``base`` and keeps everything it defines.

    :param base: The executor class to subclass, e.g. ``MerchantToolExecutor``.
    :param policy: Tool-to-:class:`ToolPolicy` map.
    :param grants: Delegate-name-to-:class:`DelegateGrant` map.
    :param on_unmapped: ``"deny"`` (default) or ``"allow"`` for a tool absent from
        ``policy``.
    :param name: The subclass's ``__name__``; defaults to ``Guarded<base>``.
    :returns: The subclass.
    :raises ValueError: When ``on_unmapped`` is not one of the two values, or ``base``
        already authorizes -- either because it is itself a guarded class, or because
        :func:`install` has patched the ``dispatch`` this subclass would call inward to.
    """
    if on_unmapped not in ("deny", "allow"):
        raise ValueError(f"on_unmapped must be 'deny' or 'allow', not {on_unmapped!r}")
    if _already_guarded(base.dispatch) or getattr(base, "_attenu_guarded", False):
        raise ValueError(
            f"{base.__name__}.dispatch already authorizes; a guarded subclass over it "
            "would run check() twice for every tool call. Subclass the unguarded "
            "executor, or uninstall() first if an installation is active."
        )
    hook = _guarded_dispatch(base.dispatch, None, policy, dict(grants or {}), on_unmapped)
    return type(name or f"Guarded{base.__name__}", (base,), {
        "dispatch": hook,
        # Marked on the class as well as on the function: the function mark is what every
        # check reads, and this one makes the fact visible to `isinstance`-style
        # introspection and to a reader of `vars(cls)`.
        "_attenu_guarded": True,
        "__doc__": f"{base.__name__} with attenu-guard on its dispatch point.",
    })


def guard_executor(
    executor: Any,
    guard: Any,
    policy: Mapping[str, Any],
    grants: Mapping[str, DelegateGrant] | None = None,
    *,
    on_unmapped: str = "deny",
) -> Any:
    """Guard one executor instance.

    Replaces the instance's bound ``dispatch``, which ``BaseToolExecutor.execute`` looks
    up on ``self`` -- so both the exception-safe ``execute`` path and a host's direct
    ``dispatch`` call are covered, and no other executor in the process is touched.

    :param executor: A :class:`~commerce_common.execution.BaseToolExecutor` instance.
    :param guard: The node this executor's calls authorize against, unless a delegate
        body is running.
    :param policy: Tool-to-:class:`ToolPolicy` map.
    :param grants: Delegate-name-to-:class:`DelegateGrant` map. A delegate registered on
        the executor with no grant is held.
    :param on_unmapped: ``"deny"`` (default) or ``"allow"`` for a tool absent from
        ``policy``.
    :returns: The same executor, guarded.
    :raises ValueError: When ``on_unmapped`` is not one of the two values, or this
        executor already authorizes -- whether from an earlier :func:`guard_executor`
        call or because it is an instance of a :func:`guarded_executor_class`.
    """
    if on_unmapped not in ("deny", "allow"):
        raise ValueError(f"on_unmapped must be 'deny' or 'allow', not {on_unmapped!r}")
    # Read the dispatch this instance actually resolves, not a bookkeeping attribute: an
    # instance of a guarded CLASS carries no attribute of ours, and wrapping it again
    # would run check() twice for every call.
    if _already_guarded(executor.dispatch) or getattr(type(executor), "_attenu_guarded", False):
        raise ValueError(
            f"{type(executor).__name__}.dispatch already authorizes; a second guard means "
            "two check() calls per tool. Use bind(executor, guard) to give an instance of "
            "a guarded_executor_class its node."
        )
    setattr(executor, _GUARD_ATTR, guard)
    executor.dispatch = _guarded_dispatch(
        executor.dispatch, executor, policy, dict(grants or {}), on_unmapped
    )
    return executor


class _Installation:
    """The handle :func:`install` returns."""

    def __init__(self, cls: Any, original: Any) -> None:
        self._cls = cls
        self._original = original
        self.active = True

    def uninstall(self) -> None:
        """Put the class's own ``dispatch`` back and drop the root binding.

        :returns: ``None``.
        """
        if not self.active:
            return
        self._cls.dispatch = self._original
        _INSTALLED_ROOT.clear()
        self.active = False

    def __enter__(self) -> "_Installation":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.uninstall()
        return False


def install(
    policy: Mapping[str, Any],
    grants: Mapping[str, DelegateGrant] | None = None,
    *,
    root: Any = None,
    executor_cls: Any = None,
    on_unmapped: str = "deny",
) -> _Installation:
    """Guard every executor in the process, including ones built out of reach.

    This patches ``dispatch`` on the executor class. It is the only way, against the repo
    as it stands, to guard an executor a third-party delegate constructs inside its own
    runner -- ``AnalysisRunner._read`` names ``MerchantToolExecutor`` directly, and no
    reference to that instance leaves the method. Prefer :func:`guarded_executor_class`
    for every executor a deployment's own runtime builds, and read "Where the seam stops"
    in ``README.md`` for the change that would make this unnecessary.

    Because the patch is on the class, it is process-wide and lasts until
    ``uninstall()``. Use the returned handle as a context manager in a test.

    A :func:`guarded_executor_class` built BEFORE this call is unaffected: it holds a
    direct reference to the dispatch it captured, so its instances authorize once, not
    twice. Building one WHILE an installation is active is refused there.

    :param policy: Tool-to-:class:`ToolPolicy` map.
    :param grants: Delegate-name-to-:class:`DelegateGrant` map.
    :param root: The node an executor authorizes against when nothing nearer is bound.
        An executor that :func:`guard_executor` bound uses its own guard instead.
    :param executor_cls: The class to patch; defaults to
        :class:`commerce_common.execution.BaseToolExecutor`, which every role executor
        inherits ``dispatch`` from.
    :param on_unmapped: ``"deny"`` (default) or ``"allow"`` for a tool absent from
        ``policy``.
    :returns: A handle with ``uninstall()``, usable as a context manager.
    :raises ValueError: When ``on_unmapped`` is invalid, an installation is active, or
        the class already authorizes.
    """
    if on_unmapped not in ("deny", "allow"):
        raise ValueError(f"on_unmapped must be 'deny' or 'allow', not {on_unmapped!r}")
    if _INSTALLED_ROOT:
        raise ValueError("an installation is already active; uninstall() it first")

    if executor_cls is None:
        from commerce_common.execution import BaseToolExecutor

        executor_cls = BaseToolExecutor

    original = executor_cls.dispatch
    if _already_guarded(original):
        raise ValueError(
            f"{executor_cls.__name__}.dispatch already authorizes; patching it again "
            "means two check() calls per tool. Pass the unguarded class, or the base a "
            "guarded_executor_class was built from."
        )
    executor_cls.dispatch = _guarded_dispatch(
        original, None, policy, dict(grants or {}), on_unmapped
    )
    _INSTALLED_ROOT.append(root)
    return _Installation(executor_cls, original)
