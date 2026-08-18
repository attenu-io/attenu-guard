"""dg_smolagents — a thin delegation-guard integration for smolagents.

Tested against smolagents 1.26.0 (Hugging Face, Apache-2.0), Python 3.12.

WHY THIS EXISTS
---------------
smolagents has no authorization model. A sub-agent ("managed agent") is
handed to a manager as just another callable tool — `_setup_managed_agents`
only stamps `inputs`/`output_type` onto it (smolagents/agents.py:369-386) and
`_validate_tools_and_managed_agents` only checks that names are unique
(agents.py:404-415). Nothing in the framework relates a child's powers to its
parent's: the sub-agent runs with whatever tool list its *author* gave it,
even if the manager holds none of those tools. The only thing standing
between a poisoned sub-agent and its most dangerous tool is the prompt text
in `prompts/toolcalling_agent.yaml` (`managed_agent.task`), which is advice,
not enforcement. This module supplies the missing enforcement.

THE TWO HOOK POINTS
-------------------
1. **Tool invocation** -> `GuardedTool`, a `smolagents.Tool` subclass that
   wraps another `Tool` and runs `guard.check(scope, ...)` inside `forward()`,
   before the inner tool's body. This is the one place that covers *both*
   agent flavours, because both funnel through `Tool.__call__` -> `forward`:
     - `ToolCallingAgent.execute_tool_call` (agents.py:1453-1500) calls
       `tool(**arguments, sanitize_inputs_outputs=True)`;
     - `CodeAgent` injects the same `Tool` objects into its Python sandbox as
       callables (`agents.py:492` -> `LocalPythonExecutor.send_tools`,
       local_python_executor.py:1763), which the generated code then calls.
   Subclassing `Tool` is smolagents' own extension mechanism, so no
   monkeypatching is involved and the model-facing JSON schema is unchanged
   (`name`/`description`/`inputs`/`output_type` are mirrored from the inner
   tool).

2. **Delegation / handoff** -> `DelegatedAgent`, a proxy you put in
   `managed_agents=[...]` instead of the raw sub-agent. smolagents offers no
   callback at handoff time (`step_callbacks` fire in `_finalize_step`,
   agents.py:620-623 — i.e. *after* a step has already executed, far too late
   to authorize anything), so the construction site is the hook: because a
   managed agent is duck-typed as a tool, substituting a callable proxy is
   enough. On each manager -> sub-agent call the proxy mints a fresh child
   Guard with `parent_guard.delegate(...)` — provably narrower than the
   parent — and binds it into the sub-agent's `GuardedTool`s for that call.

USAGE
-----
    ref  = GuardRef()                       # holds the sub-agent's live Guard
    sub  = ToolCallingAgent(
        tools=guard_tools(ref, {crm_query: "crm.read", crm_export: "crm.export"},
                          context_fns={"crm_query": lambda rows: {"rows": rows},
                                       "crm_export": lambda destination: {"egress": "any"}}),
        model=model, name="summarizer", description="Summarises CRM data.")
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*", "mail.send"},
                       ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    manager = ToolCallingAgent(tools=[], model=model, managed_agents=[
        DelegatedAgent(sub, parent_guard=root, guard_ref=ref,
                       authority=Authority(scopes={"crm.read"},
                                           ceilings=[RowLimit(5_000), EgressRank("none")],
                                           ttl=900))])
    manager.run("Prepare the Q3 pipeline report.")

A denial raises `AuthorityDenied` from inside `forward`, so the tool body
never runs. smolagents catches it in `execute_tool_call` and re-raises it as
`AgentToolExecutionError` (an `AgentError`), which `_run_stream` records on
the step as an observation (agents.py:597-600) instead of killing the run —
so the model *sees* "you are not authorized to do that" and can adapt. That
is the behaviour we want by default; pass `on_denied="return"` if you would
rather hand the model the denial as ordinary tool output.

This module imports `smolagents` (it subclasses `Tool`), but nothing from
`delegation_guard` beyond the public API — no library changes are needed.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Optional, Union

from smolagents import Tool

from delegation_guard import AuthorityDenied, Guard

__all__ = [
    "GuardRef",
    "UnboundGuard",
    "GuardedTool",
    "guard_tools",
    "DelegatedAgent",
]


class UnboundGuard(RuntimeError):
    """Raised when a `GuardedTool` is invoked while its `GuardRef` holds no
    Guard — i.e. the sub-agent was driven outside of any delegation.

    This is a wiring error, not a policy outcome (there is no authority to
    evaluate against and therefore nothing meaningful to audit), but it is
    still *fail-closed*: it is raised from `forward()`, so the wrapped tool
    body never runs, and smolagents surfaces it as a tool error like any
    other.
    """


GuardLike = Union[Guard, "GuardRef", Callable[[], Guard], None]


class GuardRef:
    """A mutable, late-bound handle on "the Guard currently in force for this
    agent".

    A sub-agent's tools are wired up once, at construction time, but its
    authority is minted per handoff — `DelegatedAgent` calls
    `parent.delegate(...)` each time the manager hands work over, so each
    delegation gets its own node id, its own task string, and its own `spawn`
    entry in the audit log. `GuardRef` is the indirection that lets the
    already-constructed tools see that fresh Guard.

    It is deliberately never reset to a *wider* Guard after a call: the last
    (narrowest) delegated Guard stays in force, so a stray tool invocation
    between handoffs is evaluated against attenuated authority rather than
    the orchestrator's. If nothing has been delegated yet, it holds `None`
    and every guarded call fails closed with `UnboundGuard`.
    """

    __slots__ = ("guard",)

    def __init__(self, guard: Optional[Guard] = None):
        self.guard = guard

    def resolve(self) -> Guard:
        if self.guard is None:
            raise UnboundGuard(
                "no Guard is bound to this GuardRef: the tool was invoked "
                "outside any delegation. Mint one with parent.delegate(...) "
                "(DelegatedAgent does this for you) before running the agent."
            )
        return self.guard

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        node = getattr(self.guard, "node_id", None)
        return f"GuardRef(node_id={node!r})"


def _resolve(guard_like: GuardLike) -> Guard:
    """Accept a `Guard`, a `GuardRef`, or a zero-arg callable returning one."""
    if guard_like is None:
        raise UnboundGuard("no Guard supplied")
    if isinstance(guard_like, GuardRef):
        return guard_like.resolve()
    if isinstance(guard_like, Guard):
        return guard_like
    if callable(guard_like):
        got = guard_like()
        if got is None:
            raise UnboundGuard("guard provider returned None")
        return got
    raise TypeError(f"cannot resolve a Guard from {guard_like!r}")


class GuardedTool(Tool):
    """Wraps a `smolagents.Tool` so every invocation is authorized first.

    Parameters
    ----------
    inner : smolagents.Tool
        The real tool. Its `name`, `description`, `inputs`, `output_type` and
        `output_schema` are mirrored onto the wrapper, so the model sees an
        identical JSON schema and cannot tell the wrapper is there.
    guard : Guard | GuardRef | callable
        The authority to check against. Use the Guard belonging to THIS agent
        (typically a `GuardRef` filled in by `DelegatedAgent`), never the
        orchestrator's broader one.
    scope : str
        The scope this tool needs, e.g. `"crm.read"`.
    context_fn : callable, optional
        Receives the exact `*args, **kwargs` the tool was called with and
        returns the context mapping for `guard.check()` (e.g.
        `{"rows": rows}`), which is what typed ceilings are evaluated
        against. Omit for a scope-only check. If it raises, the tool body
        still does not run — fail-closed.
    metered : bool
        Passed through to `guard.check(metered=...)`; set True for tools that
        consume a metered ceiling so a Guard issued with
        `strict_metering=True` refuses an undeclared quantity.
    on_denied : {"raise", "return"}
        `"raise"` (default) raises `AuthorityDenied`; smolagents converts it
        into an `AgentToolExecutionError` observation the model can react to.
        `"return"` returns `decision.explain()` as the tool's output instead —
        only sensible for tools whose `output_type` is `"string"`.
    """

    # `forward` takes (*args, **kwargs) because it proxies an arbitrary tool;
    # smolagents' signature-vs-`inputs` check is skipped the same way its own
    # dynamic wrappers do it (tools.py:646, 769, 1217; check at tools.py:198).
    skip_forward_signature_validation = True

    def __init__(self, inner: Tool, guard: GuardLike, scope: str, *,
                 context_fn: Optional[Callable[..., Mapping]] = None,
                 metered: bool = False,
                 on_denied: str = "raise"):
        if on_denied not in ("raise", "return"):
            raise ValueError('on_denied must be "raise" or "return"')
        super().__init__()
        self.inner = inner
        self.guard = guard
        self.scope = scope
        self.context_fn = context_fn
        self.metered = metered
        self.on_denied = on_denied

        # Mirror the model-facing schema so the wrapper is invisible upstream.
        self.name = inner.name
        self.description = inner.description
        self.inputs = inner.inputs
        self.output_type = inner.output_type
        output_schema = getattr(inner, "output_schema", None)
        if output_schema is not None:
            self.output_schema = output_schema

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        guard = _resolve(self.guard)
        context: Mapping = self.context_fn(*args, **kwargs) if self.context_fn else {}
        decision = guard.check(self.scope, context=context,
                               metered=self.metered, tool=self.name)
        if not decision:
            if self.on_denied == "return":
                return f"AUTHORITY DENIED: {decision.explain()}"
            raise AuthorityDenied(decision)
        # Sanitization/coercion already happened in our own `Tool.__call__`;
        # call the inner tool plainly so it is not applied twice.
        return self.inner(*args, **kwargs)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"GuardedTool(name={self.name!r}, scope={self.scope!r})"


def guard_tools(guard: GuardLike,
                scopes: Mapping[Tool, str],
                *,
                context_fns: Optional[Mapping[str, Callable[..., Mapping]]] = None,
                metered: Optional[Iterable[str]] = None,
                on_denied: str = "raise") -> list:
    """Wrap a whole tool list in one call — the usual entry point.

        tools = guard_tools(ref, {crm_query: "crm.read", crm_export: "crm.export"},
                            context_fns={"crm_query": lambda rows: {"rows": rows}})

    `scopes` maps each `Tool` instance to the scope it requires;
    `context_fns` and `metered` are keyed by TOOL NAME. Returns a list of
    `GuardedTool`s in the same order, ready to pass to `tools=[...]`.
    """
    context_fns = context_fns or {}
    metered_names = set(metered or ())
    return [
        GuardedTool(tool, guard, scope,
                    context_fn=context_fns.get(tool.name),
                    metered=tool.name in metered_names,
                    on_denied=on_denied)
        for tool, scope in scopes.items()
    ]


class DelegatedAgent:
    """Put this in `managed_agents=[...]` in place of the raw sub-agent.

    smolagents exposes a managed agent to its manager as a callable tool: it
    needs only `.name`, `.description` (asserted in `_setup_managed_agents`,
    agents.py:372-375), the `.inputs`/`.output_type` smolagents itself stamps
    on, and `__call__(task, **kwargs)`. This proxy satisfies exactly that
    contract, and interposes a delegation on the way through:

      1. optionally `parent_guard.enforce(delegate_scope)` — may this parent
         hand off to this sub-agent at all?
      2. `child = parent_guard.delegate(agent_id, authority, task=task)` —
         the child's authority is `meet(parent, requested)`, so it can only
         ever shrink, whatever `authority` asks for;
      3. bind `child` into `guard_ref` so the sub-agent's `GuardedTool`s
         authorize against it;
      4. run the real sub-agent (`MultiStepAgent.__call__`, agents.py:868).

    Every minted child Guard is kept in `.child_guards`, which is what you
    revoke: `root.revoke(delegated.child_guards[-1].node_id)` cascades to the
    whole subtree, and because `guard_ref` still points at that Guard, every
    subsequent tool call by the sub-agent is denied with `REVOKED`.

    Attribute reads not defined here fall through to the wrapped agent, so
    `delegated.memory`, `delegated.tools`, ... behave as expected.
    """

    def __init__(self, agent, *, parent_guard: Guard, authority,
                 guard_ref: GuardRef, agent_id: Optional[str] = None,
                 delegate_scope: Optional[str] = None,
                 delegate_context: Optional[Mapping] = None):
        self.agent = agent  # must be set first: __getattr__ forwards to it
        self.parent_guard = parent_guard
        self.authority = authority
        self.guard_ref = guard_ref
        self.agent_id = agent_id or getattr(agent, "name", None) or "sub_agent"
        self.delegate_scope = delegate_scope
        self.delegate_context = dict(delegate_context or {})
        self.child_guards: list[Guard] = []

        # The tool-facing identity smolagents reads off a managed agent.
        self.name = agent.name
        self.description = agent.description

    # -- the delegation hook ------------------------------------------------
    def mint(self, task: str) -> Guard:
        """Mint (and bind) a fresh child Guard for `task`.

        Raises `AuthorityDenied` if `delegate_scope` is set and the parent
        may not delegate, and `AuthorityError` for structural failures
        (parent revoked or expired, chain depth/fanout exceeded).
        """
        if self.delegate_scope:
            self.parent_guard.enforce(self.delegate_scope,
                                      context=self.delegate_context,
                                      tool=self.name)
        child = self.parent_guard.delegate(self.agent_id, self.authority, task=task)
        self.child_guards.append(child)
        self.guard_ref.guard = child
        return child

    def __call__(self, task: str, **kwargs) -> Any:
        self.mint(task)
        return self.agent(task, **kwargs)

    # -- transparent proxy --------------------------------------------------
    def __getattr__(self, item: str) -> Any:
        # Only reached when normal lookup fails. Guard the recursion on
        # `agent` itself, which is set first in __init__.
        if item == "agent":
            raise AttributeError(item)
        return getattr(self.agent, item)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"DelegatedAgent(name={self.name!r}, "
                f"parent={self.parent_guard.node_id!r}, "
                f"delegations={len(self.child_guards)})")
