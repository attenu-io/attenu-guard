"""attenu-guard x Langflow — a custom component that authorizes tool calls.

Tested against lfx 1.11.5 / langchain-core 1.5.x, Python 3.14.

WHAT IT DOES
------------
Drop this component between a tool and the agent that uses it. It takes a tool
list in and hands back the same tools, each of which runs `guard.check(scope)`
before its body. It also issues the Guard those checks run against — and when
one of these components is fed the `Guard` output of another, the second Guard
is minted with `parent.delegate(...)`, so the downstream agent's authority is
the meet of what it asks for and what the upstream agent holds. Chain two of
them in a flow and the second agent cannot hold more than the first.

Three outputs:

  Guarded Tools  the tool list, ready for an Agent component's `tools` port
  Guard          this agent's Guard, for a downstream component's `Parent
                 Authority` port — that edge is the delegation
  Evidence       the delegation graph, the hash-chained audit log, and the
                 result of re-verifying it

HOOK POINT
----------
Langflow tools are LangChain `BaseTool`s, and `BaseTool.invoke` -> `run` ->
`_run` is the single funnel every tool call goes through, whichever agent
component drives it. `guard_langchain_tool` builds a
`langchain_core.tools.StructuredTool` whose function authorizes and only then
calls `inner.invoke(...)`, mirroring the inner tool's `name`, `description` and
`args_schema` so the model sees an identical tool. That is LangChain's own
composition API — no monkeypatching, and nothing in Langflow is modified.

INSTALL
-------
Langflow discovers custom components under the directory named by the
`LANGFLOW_COMPONENTS_PATH` environment variable, in `<base>/<category>/`. See
the README next to this file.

Everything above the `Component` class is plain Python: it imports
`langchain_core` and `attenu_guard`, and works with Langflow absent.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from attenu_guard import (
    AuditLog,
    Authority,
    AuthorityDenied,
    CallLimit,
    EgressRank,
    Guard,
    RowLimit,
    SpendCap,
)

__all__ = [
    "parse_authority",
    "parse_scopes",
    "guard_langchain_tool",
    "guard_langchain_tools",
    "evidence_payload",
    "UnpricedToolError",
    "AttenuGuardToolsComponent",
]


class UnpricedToolError(ValueError):
    """A tool arrived whose scope nobody declared.

    Fail-closed by default: the authority such a call consumes is undeclared, so
    it cannot be shown to be within the agent's authority. Set `On Unmapped` to
    `allow` to pass unmapped tools through unwrapped.
    """


# ==========================================================================
# Pure logic — no Langflow, no lfx
# ==========================================================================

_CEILINGS: Dict[str, Callable[[Any], Any]] = {
    "max_rows": lambda v: RowLimit(int(v)),
    "max_spend": lambda v: SpendCap(float(v)),
    "egress": lambda v: EgressRank(str(v)),
    "max_calls": lambda v: CallLimit(int(v)),
}


def parse_authority(text: str) -> Authority:
    """Build an `Authority` from the component's JSON field.

        {"scopes": ["crm.read"],
         "ceilings": {"max_rows": 5000, "egress": "none"},
         "ttl": 900}

    `scopes` is required; `ceilings` and `ttl` are optional. An unknown ceiling
    key is rejected rather than ignored — a typo must not silently widen what
    the agent may do.
    """
    if not text or not text.strip():
        raise ValueError(
            "Authority is required: state the scopes this agent may use, e.g. "
            '{"scopes": ["crm.read"], "ceilings": {"max_rows": 5000}, "ttl": 900}')
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Authority is not valid JSON: {e}") from e
    if not isinstance(spec, dict):
        raise ValueError("Authority must be a JSON object.")

    scopes = spec.get("scopes")
    if not scopes:
        raise ValueError('Authority needs a non-empty "scopes" list.')
    if isinstance(scopes, str):
        scopes = [scopes]

    ceilings = []
    for key, value in (spec.get("ceilings") or {}).items():
        if key not in _CEILINGS:
            raise ValueError(
                f"unknown ceiling {key!r}; known keys are "
                f"{sorted(_CEILINGS)}. A misspelt ceiling would leave the "
                f"agent unbounded on that axis, so it is refused.")
        ceilings.append(_CEILINGS[key](value))

    kwargs: Dict[str, Any] = {"scopes": set(scopes), "ceilings": ceilings}
    if spec.get("ttl") is not None:
        kwargs["ttl"] = int(spec["ttl"])
    return Authority(**kwargs)


def parse_scopes(text: str) -> Dict[str, str]:
    """Parse the tool-name -> scope map from the component's JSON field.

        {"crm_query": "crm.read", "crm_export": "crm.export"}
    """
    if not text or not text.strip():
        return {}
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Tool Scopes is not valid JSON: {e}") from e
    if not isinstance(spec, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in spec.items()):
        raise ValueError('Tool Scopes must be a JSON object of '
                         '{"tool_name": "scope"} pairs.')
    return spec


def guard_langchain_tool(tool: Any,
                         guard_provider: Callable[[], Guard],
                         scope: str,
                         *,
                         context_fn: Optional[Callable[..., Mapping]] = None,
                         metered: bool = False,
                         on_denied: str = "raise") -> Any:
    """Return a tool that authorizes, then runs `tool`.

    `guard_provider` is called per invocation, so a Guard revoked after the flow
    was built is seen by the very next call. On a denial with
    `on_denied="raise"` the wrapper raises `AuthorityDenied` and the tool body
    never runs; with `"return"` it hands the explanation back as the tool's
    output for the model to read.
    """
    from langchain_core.tools import StructuredTool

    if on_denied not in ("raise", "return"):
        raise ValueError('on_denied must be "raise" or "return"')

    def _authorize(kwargs: Mapping[str, Any]) -> Optional[str]:
        guard = guard_provider()
        context: Mapping = context_fn(**kwargs) if context_fn else {}
        decision = guard.check(scope, context=context, metered=metered,
                               tool=tool.name)
        if decision:
            return None
        if on_denied == "return":
            return f"AUTHORITY DENIED: {decision.explain()}"
        raise AuthorityDenied(decision)

    def _run(**kwargs: Any) -> Any:
        denied = _authorize(kwargs)
        return denied if denied is not None else tool.invoke(dict(kwargs))

    async def _arun(**kwargs: Any) -> Any:
        denied = _authorize(kwargs)
        if denied is not None:
            return denied
        return await tool.ainvoke(dict(kwargs))

    return StructuredTool.from_function(
        func=_run, coroutine=_arun,
        name=tool.name, description=tool.description,
        args_schema=tool.args_schema, infer_schema=tool.args_schema is None,
        return_direct=getattr(tool, "return_direct", False),
    )


def guard_langchain_tools(tools: Iterable[Any],
                          guard_provider: Callable[[], Guard],
                          scopes: Mapping[str, str],
                          *,
                          context_fns: Optional[Mapping[str, Callable]] = None,
                          metered: Optional[Iterable[str]] = None,
                          on_denied: str = "raise",
                          on_unmapped: str = "deny") -> List[Any]:
    """Wrap a whole tool list, keyed by tool name.

    With `on_unmapped="deny"` (the default) a tool whose scope is not in
    `scopes` raises `UnpricedToolError`, so adding a tool to the flow and
    forgetting to price it fails loudly instead of arriving unguarded.
    """
    if on_unmapped not in ("deny", "allow"):
        raise ValueError('on_unmapped must be "deny" or "allow"')
    context_fns = context_fns or {}
    metered_names = set(metered or ())
    out: List[Any] = []
    for tool in tools:
        scope = scopes.get(tool.name)
        if scope is None:
            if on_unmapped == "allow":
                out.append(tool)
                continue
            raise UnpricedToolError(
                f"tool {tool.name!r} has no scope in Tool Scopes, so the "
                f"authority it consumes is undeclared and the call cannot be "
                f"authorized. Add it, or set On Unmapped to 'allow'.")
        out.append(guard_langchain_tool(
            tool, guard_provider, scope,
            context_fn=context_fns.get(tool.name),
            metered=tool.name in metered_names, on_denied=on_denied))
    return out


def evidence_payload(guard: Guard) -> Dict[str, Any]:
    """The reviewer's view: delegation graph, audit log, and re-verification."""
    entries = guard.audit_log().entries
    verified, error = AuditLog.verify(entries)
    return {
        "agent_id": guard.agent_id,
        "node_id": guard.node_id,
        "chain_id": guard.chain_id,
        "authority": guard.authority.to_wire(),
        "graph": guard.graph(),
        "audit_log": entries,
        "verified": verified,
        "verification_error": error,
        "decisions": [
            {"seq": e["seq"], "event": e["event"], "scope": e.get("scope"),
             "tool": e.get("tool"), "reason": e.get("reason")}
            for e in entries if e["event"] in ("allow", "deny")
        ],
    }


# ==========================================================================
# The Langflow component
# ==========================================================================

try:
    from lfx.custom.custom_component.component import Component
    from lfx.io import (
        DropdownInput,
        HandleInput,
        MessageTextInput,
        MultilineInput,
        Output,
    )
    from lfx.schema.data import Data
except ImportError:  # pragma: no cover - Langflow 1.6 and earlier
    try:
        from langflow.custom import Component  # type: ignore
        from langflow.io import (  # type: ignore
            DropdownInput,
            HandleInput,
            MessageTextInput,
            MultilineInput,
            Output,
        )
        from langflow.schema import Data  # type: ignore
    except ImportError:
        Component = None  # type: ignore


if Component is not None:

    class AttenuGuardToolsComponent(Component):
        """Authorize every tool call against this agent's authority."""

        display_name = "Attenu Guard Tools"
        description = (
            "Check each tool call against the scopes and ceilings this agent "
            "holds before the tool runs, and record every decision in a "
            "hash-chained audit log. Feed the Guard output into another Attenu "
            "Guard Tools component to narrow a downstream agent."
        )
        documentation = "https://attenu.io/docs/"
        icon = "shield"
        name = "AttenuGuardTools"

        inputs = [
            HandleInput(
                name="tools",
                display_name="Tools",
                input_types=["Tool"],
                is_list=True,
                info="The tools this agent may use. Each is returned wrapped.",
                value=[],
            ),
            HandleInput(
                name="parent_guard",
                display_name="Parent Authority",
                input_types=["AttenuGuard"],
                required=False,
                info=(
                    "The Guard output of the delegating agent's component. When "
                    "connected, this agent's authority is the meet of what it "
                    "asks for below and what the parent holds, so it can only "
                    "be narrower. Leave empty for the first agent in the chain."
                ),
            ),
            MessageTextInput(
                name="agent_id",
                display_name="Agent ID",
                value="agent",
                info="Name recorded for this agent in the audit log.",
            ),
            MessageTextInput(
                name="task",
                display_name="Task",
                value="",
                info="What this agent was asked to do; recorded on the "
                     "delegation entry.",
            ),
            MultilineInput(
                name="authority",
                display_name="Authority",
                value='{\n  "scopes": ["crm.read"],\n'
                      '  "ceilings": {"max_rows": 5000, "egress": "none"},\n'
                      '  "ttl": 900\n}',
                info='JSON. "scopes" is required; "ceilings" may set max_rows, '
                     'max_spend, egress or max_calls; "ttl" is in seconds.',
            ),
            MultilineInput(
                name="tool_scopes",
                display_name="Tool Scopes",
                value='{\n  "crm_query": "crm.read"\n}',
                info='JSON map of tool name to the scope that tool consumes.',
            ),
            DropdownInput(
                name="on_denied",
                display_name="On Denied",
                options=["raise", "return"],
                value="raise",
                info="raise: the run stops with the denial. return: the model "
                     "reads the denial as the tool's output and can adapt.",
                advanced=True,
            ),
            DropdownInput(
                name="on_unmapped",
                display_name="On Unmapped",
                options=["deny", "allow"],
                value="deny",
                info="deny: a tool with no scope in Tool Scopes is an error. "
                     "allow: it passes through unguarded.",
                advanced=True,
            ),
        ]

        outputs = [
            Output(display_name="Guarded Tools", name="guarded_tools",
                   method="build_guarded_tools"),
            Output(display_name="Guard", name="guard", method="build_guard"),
            Output(display_name="Evidence", name="evidence",
                   method="build_evidence"),
        ]

        # -- the Guard ------------------------------------------------------
        def build_guard(self) -> Guard:
            """Issue this agent's Guard, or delegate it from the parent's.

            Memoized: all three outputs describe one Guard and one audit log.
            """
            existing = getattr(self, "_attenu_guard", None)
            if existing is not None:
                return existing

            authority = parse_authority(self.authority)
            agent_id = (self.agent_id or "agent").strip() or "agent"
            task = (self.task or "").strip() or f"{agent_id} task"
            parent = self.parent_guard
            if isinstance(parent, list):        # a HandleInput may arrive listed
                parent = parent[0] if parent else None

            if parent is None:
                guard = Guard.issue(agent_id, authority, task=task)
            elif isinstance(parent, Guard):
                # The delegation. The child's authority is meet(parent, request):
                # it can only shrink, whatever the Authority field asks for.
                guard = parent.delegate(agent_id, authority, task=task)
            else:
                raise TypeError(
                    "Parent Authority must be the Guard output of another "
                    f"Attenu Guard Tools component, not {type(parent).__name__}.")

            self._attenu_guard = guard
            self.status = f"{agent_id}: {guard.authority}"
            return guard

        # -- the tools ------------------------------------------------------
        def build_guarded_tools(self) -> List[Any]:
            guard = self.build_guard()
            tools = list(self.tools or [])
            guarded = guard_langchain_tools(
                tools, self.build_guard, parse_scopes(self.tool_scopes),
                on_denied=self.on_denied or "raise",
                on_unmapped=self.on_unmapped or "deny")
            self.status = (f"{guard.agent_id}: {len(guarded)} tool(s) guarded "
                           f"by {guard.authority}")
            return guarded

        # -- the evidence ---------------------------------------------------
        def build_evidence(self) -> Data:
            payload = evidence_payload(self.build_guard())
            self.status = (
                f"{len(payload['decisions'])} decision(s), "
                f"audit log verified: {payload['verified']}")
            return Data(data=payload)
