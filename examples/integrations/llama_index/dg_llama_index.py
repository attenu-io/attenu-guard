"""
dg_llama_index — delegation-guard x LlamaIndex agents (llama-index-core 0.14.x).

Two hook points, both on LlamaIndex's *public* extension surface:

1. DELEGATION — `GuardedAgentWorkflow.get_tools()` (override of the public
   `AgentWorkflow.get_tools`, site-packages/llama_index/core/agent/workflow/
   multi_agent_workflow.py:248) wraps the framework-injected `handoff` tool
   (built at :216-247 from the module-level `handoff` coroutine at :73).
   When agent A hands off to agent B, the wrapper mints B's Guard with
   `guard_of(A).delegate(B, grants[B], task=reason)` — so B's authority is the
   *meet* of A's authority and what B was granted, and can never be wider.
   A structural refusal (revoked/expired parent, depth or fanout ceiling) also
   cancels the handoff itself: `next_agent` is cleared and the model is told
   why, so control never reaches an agent that holds no authority.

2. TOOL INVOCATION — `guarded_tool()` returns a `FunctionTool` whose body is a
   wrapper declaring a `ctx: Context` parameter. LlamaIndex injects the live
   `Context` into exactly those tools (multi_agent_workflow.py:356-363), so the
   wrapper can resolve the calling agent's Guard from `ctx.store` and run
   `guard.check(...)` BEFORE the real tool body. On denial it raises
   `AuthorityDenied`, which `AgentWorkflow._call_tool` turns into
   `ToolOutput(is_error=True, exception=<AuthorityDenied>)`
   (multi_agent_workflow.py:366-377) — the model sees a normal tool error and
   can recover, while the caller still gets the structured `Decision` off
   `ToolOutput.exception`. The wrapped body never runs.

Guards are scoped to one workflow `Context`: `ctx.store["dg_guard_run"]` holds a
short run token and the live Guards hang off a process-local registry keyed by
it (see the note above `_REGISTRY` for why they cannot be stored directly).
They therefore survive repeated `.run()` calls on the same Context and are never
shared between concurrent runs.

Usage
-----
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"},
                       ceilings=[RowLimit(100_000)], ttl=3600), task="board pack")

    wf = GuardedAgentWorkflow(
        agents=[orchestrator, summarizer], root_agent="orchestrator",
        root_guard=root,
        grants={"summarizer": Authority(scopes={"crm.read"},
                                        ceilings=[RowLimit(5_000)], ttl=900)},
    )
    ctx = Context(wf)
    await wf.run(user_msg="summarise Q3", ctx=ctx)

where the agents' tools were built with
`guarded_tool(crm_query, scope="crm.read", context=lambda kw: {"rows": kw["rows"]})`.

delegation-guard deliberately does not decide *what* authority a task needs —
`grants` is written by the integrator.
"""

import uuid
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from llama_index.core.agent.workflow import AgentWorkflow
from llama_index.core.agent.workflow.workflow_events import (
    AgentInput,
    AgentWorkflowStartEvent,
)
from llama_index.core.tools import (
    AsyncBaseTool,
    BaseTool,
    FunctionTool,
    ToolMetadata,
    adapt_to_async_tool,
)
from llama_index.core.workflow import Context, step

from delegation_guard import (
    Authority,
    AuthorityDenied,
    AuthorityError,
    Decision,
    Guard,
    Reason,
)

__all__ = [
    "GUARDS_KEY",
    "NO_GUARD_BOUND",
    "GuardedAgentWorkflow",
    "attach_guards",
    "guard_of",
    "release_guards",
    "guarded_tool",
    "guards_of",
]

#: `ctx.store` key holding the run token that identifies this run's Guards.
GUARDS_KEY = "dg_guard_run"

#: Reason code used when a tool is invoked by an agent that holds no Guard.
#: Not part of delegation-guard's `ReasonCode` vocabulary — it is an adapter
#: wiring fault, surfaced as a denial so the failure mode is closed, not open.
NO_GUARD_BOUND = "no_guard_bound"

#: A per-call context bag, or a callable turning the tool kwargs into one.
ContextSpec = Union[Mapping[str, Any], Callable[[Dict[str, Any]], Mapping[str, Any]], None]


# --------------------------------------------------------------------------
# Guard registry
#
# Guards are LIVE handles onto a delegation `Chain`, not state data, so they
# cannot live in `ctx.store` itself:
#   * every `ctx.store.set(...)` commits a deep copy of the whole state
#     (workflows/context/state_store.py:1029-1037 -> :566-597), which would
#     clone the Chain and silently detach children from the real root; and
#   * a second `.run()` on the same Context re-serializes the store to JSON
#     (workflows/context/context.py:293-297), which a Guard cannot survive.
# So the store holds only a short, serializable run token, and the Guards live
# in a process-local registry keyed by it. That is also the honest security
# model: a Guard is not a bearer token you can serialize and replay.
# --------------------------------------------------------------------------
_REGISTRY: Dict[str, Dict[str, Guard]] = {}


async def _run_key(ctx: Context, create: bool = False) -> Optional[str]:
    key = await ctx.store.get(GUARDS_KEY, default=None)
    if key is None and create:
        key = uuid.uuid4().hex
        await ctx.store.set(GUARDS_KEY, key)
    return key


async def _live_guards(ctx: Context) -> Dict[str, Guard]:
    """The live registry dict for this run (never writes to the store)."""
    key = await _run_key(ctx)
    return _REGISTRY.get(key, {}) if key else {}


async def guards_of(ctx: Context) -> Dict[str, Guard]:
    """A snapshot of the ``{agent_name: Guard}`` registry for this run."""
    return dict(await _live_guards(ctx))


async def attach_guards(ctx: Context, guards: Mapping[str, Guard]) -> None:
    """Seed/extend the registry. Call before `.run()` to pre-bind a root Guard
    (also what `GuardedAgentWorkflow` does for you), or use it to guard a
    single standalone `FunctionAgent`, which has no `current_agent_name`."""
    key = await _run_key(ctx, create=True)
    _REGISTRY.setdefault(key, {}).update(guards)


async def release_guards(ctx: Context) -> None:
    """Drop this run's Guards. Call when the Context is finished with; the
    registry is otherwise process-lifetime."""
    key = await _run_key(ctx)
    if key:
        _REGISTRY.pop(key, None)


async def guard_of(ctx: Context, agent_name: Optional[str] = None) -> Optional[Guard]:
    """The Guard held by `agent_name`, defaulting to the agent currently
    holding the turn. Falls back to the sole registered Guard when the
    workflow does not track a current agent (a standalone agent run)."""
    registry = await _live_guards(ctx)
    if agent_name is None:
        agent_name = await ctx.store.get("current_agent_name", default=None)
    if agent_name is None:
        return next(iter(registry.values())) if len(registry) == 1 else None
    return registry.get(agent_name)


def _denied(code: str, message: str) -> AuthorityDenied:
    return AuthorityDenied(Decision.deny(Reason(code, message=message)))


# --------------------------------------------------------------------------
# Hook point 2 — tool invocation
# --------------------------------------------------------------------------
def _resolve_target(tool_or_fn):
    """Return (async callable, ToolMetadata, ctx_param_name_of_the_inner_fn)."""
    if isinstance(tool_or_fn, FunctionTool):
        return tool_or_fn.async_fn, tool_or_fn.metadata, tool_or_fn.ctx_param_name
    if isinstance(tool_or_fn, BaseTool):
        inner: AsyncBaseTool = adapt_to_async_tool(tool_or_fn)

        async def _call_any(**kwargs):
            out = await inner.acall(**kwargs)
            return out.raw_output if out.raw_output is not None else out.content

        return _call_any, tool_or_fn.metadata, None
    built = FunctionTool.from_defaults(fn=tool_or_fn)
    return built.async_fn, built.metadata, built.ctx_param_name


def guarded_tool(
    tool_or_fn,
    *,
    scope: str,
    context: ContextSpec = None,
    metered: bool = False,
    name: Optional[str] = None,
    description: Optional[str] = None,
    return_direct: Optional[bool] = None,
) -> FunctionTool:
    """Wrap a callable (or an existing `BaseTool`) so that
    ``guard.check(scope, context=..., tool=...)`` runs before its body.

    `context` is either a fixed mapping (``{"egress": "any"}``) or a callable
    taking the tool's kwargs and returning one
    (``lambda kw: {"rows": kw["rows"]}``). It is what delegation-guard's typed
    ceilings are evaluated against.

    The returned tool keeps the original name / description / JSON schema, so
    the model sees no difference; only a `ctx: Context` parameter is added, and
    LlamaIndex fills that in itself — it is never model-supplied.
    """
    target, base_meta, inner_ctx_param = _resolve_target(tool_or_fn)
    meta = ToolMetadata(
        name=name or base_meta.name,
        description=description or base_meta.description,
        fn_schema=base_meta.fn_schema,
        return_direct=base_meta.return_direct if return_direct is None else return_direct,
    )
    tool_name = meta.get_name()

    def _context_for(kwargs: Dict[str, Any]) -> Mapping[str, Any]:
        if context is None:
            return {}
        if callable(context):
            return context(kwargs)
        return context

    async def _guarded(ctx: Context, **kwargs):
        guard = await guard_of(ctx)
        if guard is None:
            agent = await ctx.store.get("current_agent_name", default="<unknown>")
            raise _denied(
                NO_GUARD_BOUND,
                f"agent {agent!r} holds no delegated authority; "
                f"refusing tool {tool_name!r}",
            )
        decision = guard.check(
            scope, context=_context_for(kwargs), metered=metered, tool=tool_name
        )
        if not decision:
            # Raised, not returned: AgentWorkflow._call_tool converts it into
            # ToolOutput(is_error=True, exception=exc), so the model gets a
            # recoverable tool error AND the caller keeps the full Decision.
            raise AuthorityDenied(decision)
        if inner_ctx_param:
            kwargs = dict(kwargs, **{inner_ctx_param: ctx})
        return await target(**kwargs)

    return FunctionTool.from_defaults(async_fn=_guarded, tool_metadata=meta)


# --------------------------------------------------------------------------
# Hook point 1 — delegation (handoff)
# --------------------------------------------------------------------------
class GuardedAgentWorkflow(AgentWorkflow):
    """`AgentWorkflow` that mints an attenuated Guard on every handoff.

    Extra arguments:
      root_guard: the Guard held by `root_agent` (from `Guard.issue(...)`).
      grants:     ``{agent_name: Authority}`` — what each agent may *request*
                  when it is handed off to. The authority it actually receives
                  is ``parent.authority.meet(request)``, never wider. An agent
                  with no entry cannot be handed off to at all.
      on_delegate: optional ``(parent_name, child_name, child_guard) -> None``
                  callback, for logging/telemetry.
    """

    def __init__(
        self,
        *args: Any,
        root_guard: Guard,
        grants: Optional[Mapping[str, Authority]] = None,
        on_delegate: Optional[Callable[[str, str, Guard], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._dg_root_guard = root_guard
        self._dg_grants: Dict[str, Authority] = dict(grants or {})
        self._dg_on_delegate = on_delegate

    # -- seed the root agent's Guard once per run --------------------------
    @step
    async def init_run(self, ctx: Context, ev: AgentWorkflowStartEvent) -> AgentInput:
        out = await super().init_run(ctx, ev)
        if self.root_agent not in await _live_guards(ctx):
            await attach_guards(ctx, {self.root_agent: self._dg_root_guard})
        return out

    # -- wrap the framework-injected `handoff` tool ------------------------
    async def get_tools(
        self, agent_name: str, input_str: Optional[str] = None
    ) -> Sequence[AsyncBaseTool]:
        tools = await super().get_tools(agent_name, input_str)
        return [
            self._guard_handoff_tool(t) if t.metadata.get_name() == "handoff" else t
            for t in tools
        ]

    def _guard_handoff_tool(self, orig: AsyncBaseTool) -> AsyncBaseTool:
        if not isinstance(orig, FunctionTool):  # pragma: no cover - defensive
            return orig
        handoff_fn = orig.async_fn
        grants = self._dg_grants
        on_delegate = self._dg_on_delegate

        async def _guarded_handoff(ctx: Context, to_agent: str, reason: str) -> str:
            sender = await ctx.store.get("current_agent_name")
            parent = await guard_of(ctx, sender)

            # Let LlamaIndex decide first whether the route is legal at all
            # (unknown target / not in `can_handoff_to`); it signals success by
            # setting `next_agent`.
            message = await handoff_fn(ctx=ctx, to_agent=to_agent, reason=reason)
            if await ctx.store.get("next_agent", default=None) != to_agent:
                return message

            refusal = None
            child = None
            if parent is None:
                refusal = f"{sender} holds no delegated authority and cannot hand off."
            elif to_agent not in grants:
                refusal = (
                    f"No authority grant is defined for {to_agent}; "
                    "the handoff was refused."
                )
            else:
                try:
                    child = parent.delegate(to_agent, grants[to_agent], task=reason)
                except AuthorityError as exc:
                    refusal = f"Delegation to {to_agent} refused ({exc.reason}): {exc}"

            if refusal is not None:
                # Cancel the routing decision too — control must not reach an
                # agent that holds no authority.
                await ctx.store.set("next_agent", None)
                return refusal

            await attach_guards(ctx, {to_agent: child})
            if on_delegate is not None:
                on_delegate(sender, to_agent, child)
            return message

        return FunctionTool.from_defaults(
            async_fn=_guarded_handoff, tool_metadata=orig.metadata
        )
