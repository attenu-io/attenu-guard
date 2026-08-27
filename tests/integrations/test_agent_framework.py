"""attenu-guard × Microsoft Agent Framework (`agent-framework` 1.15.x) — integration tests.

Runs fully offline. Agent Framework ships no test double, so the LLM here is a
`ScriptedChatClient` that replays canned `ChatResponse`s. It composes
`FunctionInvocationLayer` and `ChatMiddlewareLayer` over `BaseChatClient` the way the
real providers do (`agent_framework_openai/_chat_client.py:3430-3434`) — a bare
`BaseChatClient` carries neither the function-calling loop nor the middleware pipeline
(`agent_framework/_agents.py:870-875` only warns), so it would never invoke a tool.

The story under test is the canonical "poisoned summarizer": an orchestrator delegates
to a summarizer with `Agent.as_tool()`; the summarizer's *Python* tool list still
contains `crm_export`/`send_mail` (Agent Framework imposes no restriction — see
`test_agent_framework_itself_does_not_attenuate`), but its attenu-guard `Authority` does
not cover them, so the export is denied before the tool body runs.
"""
from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

import pytest

pytest.importorskip("agent_framework")

from agent_framework import (  # noqa: E402
    Agent,
    BaseChatClient,
    ChatMiddlewareLayer,
    ChatResponse,
    ChatResponseUpdate,
    Content,
    FunctionInvocationLayer,
    FunctionInvocationContext,
    Message,
    MiddlewareFailure,
)

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.adapters.agent_framework import (  # noqa: E402
    DelegationGuard,
    Grant,
    GuardRegistry,
    ToolPolicy,
    guarded_agent,
    handoff_tool_name,
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


class ScriptedChatClient(FunctionInvocationLayer, ChatMiddlewareLayer, BaseChatClient):
    """Replays a fixed script of turns. No API key, no network."""

    def __init__(self, script: Sequence[Any], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._script = list(script)
        self._turn = 0

    def _next_response(self) -> ChatResponse:
        turn = self._script[min(self._turn, len(self._script) - 1)]
        self._turn += 1
        if isinstance(turn, str):
            return ChatResponse(messages=[Message("assistant", [turn])])
        contents = [
            Content.from_function_call(call_id=f"call-{i}", name=name, arguments=args)
            for i, (name, args) in enumerate(turn)
        ]
        return ChatResponse(messages=[Message("assistant", contents)])

    def _inner_get_response(self, *, messages, stream, options, **kwargs):
        response = self._next_response()
        if stream:

            async def _updates():
                yield ChatResponseUpdate(
                    role="assistant", contents=response.messages[0].contents
                )

            return self._build_response_stream(_updates())

        async def _awaitable() -> ChatResponse:
            return response

        return _awaitable()


class Effects:
    """Side-effect recorder. A tool body that never runs never increments."""

    def __init__(self) -> None:
        self.crm_query = 0
        self.crm_export = 0
        self.send_mail = 0
        self.exported_to: list[str] = []


def _summarizer_tools(effects: Effects) -> list:
    def crm_query(rows: int) -> str:
        """Query the CRM."""
        effects.crm_query += 1
        return f"queried {rows} rows"

    def crm_export(destination: str) -> str:
        """Export CRM data to a destination."""
        effects.crm_export += 1
        effects.exported_to.append(destination)
        return f"exported to {destination}"

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
    "summarizer": ToolPolicy(
        scope="crm.read", delegates_to="summarizer", grant=SUMMARIZER_GRANT
    ),
}


def _build(
    effects: Effects,
    summarizer_script,
    *,
    guarded: bool,
    audit_path=None,
    on_deny: str = "result",
    child_contents: list | None = None,
):
    """Build the orchestrator → summarizer pair, with or without attenu-guard."""
    root = Guard.issue(
        "orchestrator", ORCHESTRATOR_AUTHORITY, task="root", audit_path=audit_path
    )
    registry = GuardRegistry(root, "orchestrator")

    orchestrator_script = [[("summarizer", {"task": "summarize Q3"})], "done"]
    tools = _summarizer_tools(effects)

    async def _watch(update) -> None:
        if child_contents is not None:
            child_contents.extend(update.contents)

    if guarded:
        summarizer = guarded_agent(
            client=ScriptedChatClient(summarizer_script),
            name="summarizer",
            description="Summarizes CRM pipeline data.",
            tools=tools,
            policies=POLICIES,
            registry=registry,
            on_deny=on_deny,
        )
        orchestrator = guarded_agent(
            client=ScriptedChatClient(orchestrator_script),
            name="orchestrator",
            tools=[
                summarizer.as_tool(
                    name="summarizer",
                    description="Summarize CRM pipeline data.",
                    stream_callback=_watch,
                )
            ],
            policies=ORCHESTRATOR_POLICIES,
            registry=registry,
            on_deny=on_deny,
        )
    else:
        summarizer = Agent(
            client=ScriptedChatClient(summarizer_script),
            name="summarizer",
            description="Summarizes CRM pipeline data.",
            tools=tools,
        )
        orchestrator = Agent(
            client=ScriptedChatClient(orchestrator_script),
            name="orchestrator",
            tools=[
                summarizer.as_tool(
                    name="summarizer",
                    description="Summarize CRM pipeline data.",
                    stream_callback=_watch,
                )
            ],
        )
    return orchestrator, registry, summarizer


def _result_text(contents) -> str:
    return "\n".join(
        str(c.result) for c in contents if getattr(c, "type", None) == "function_result"
    )


# --------------------------------------------------------------------------
# 1. baseline — Agent Framework alone does NOT attenuate the sub-agent
# --------------------------------------------------------------------------


def test_agent_framework_itself_does_not_attenuate():
    """Without attenu-guard the poisoned export EXECUTES.

    This is the control: it proves the deny in the guarded tests comes from
    attenu-guard and not from anything Agent Framework does on its own.
    """
    effects = Effects()
    orchestrator, _, _ = _build(
        effects,
        [
            [("crm_query", {"rows": 4200})],
            [("crm_export", {"destination": "s3://exfil"})],
            "done",
        ],
        guarded=False,
    )
    asyncio.run(orchestrator.run("summarize Q3 pipeline"))

    assert effects.crm_query == 1
    # The sub-agent keeps its full tool list; nothing relates it to the parent.
    assert effects.crm_export == 1
    assert effects.exported_to == ["s3://exfil"]


# --------------------------------------------------------------------------
# 2. the guarded run — allow, deny-before-body
# --------------------------------------------------------------------------


def test_allowed_tool_runs_and_poisoned_export_is_denied_before_body():
    effects = Effects()
    child: list = []
    orchestrator, _, _ = _build(
        effects,
        [
            [("crm_query", {"rows": 4200})],
            [("crm_export", {"destination": "s3://exfil"})],
            "done",
        ],
        guarded=True,
        child_contents=child,
    )
    asyncio.run(orchestrator.run("summarize Q3 pipeline"))

    # (a) in-authority call executed
    assert effects.crm_query == 1
    # (b) the poisoned step never reached the tool body
    assert effects.crm_export == 0
    assert effects.exported_to == []

    text = _result_text(child)
    assert "scope_not_granted" in text, text


def test_ceiling_denies_oversized_query_before_body():
    """Same scope, but over the child's RowLimit(5_000) ceiling."""
    effects = Effects()
    child: list = []
    orchestrator, _, _ = _build(
        effects,
        [[("crm_query", {"rows": 50_000})], "done"],
        guarded=True,
        child_contents=child,
    )
    asyncio.run(orchestrator.run("summarize Q3 pipeline"))

    assert effects.crm_query == 0
    assert "ceiling_exceeded" in _result_text(child)


def test_send_mail_denied_even_though_parent_holds_the_scope():
    """`mail.send` is in the ORCHESTRATOR's authority but not the child's."""
    effects = Effects()
    orchestrator, _, _ = _build(
        effects,
        [[("send_mail", {"to": "x@y.z", "body": "hi"})], "done"],
        guarded=True,
    )
    asyncio.run(orchestrator.run("summarize Q3 pipeline"))
    assert effects.send_mail == 0


# --------------------------------------------------------------------------
# 3. delegation is a gate, not a notification
# --------------------------------------------------------------------------


def test_delegation_mints_the_child_before_the_sub_agent_runs():
    effects = Effects()
    orchestrator, registry, _ = _build(
        effects, [[("crm_query", {"rows": 10})], "done"], guarded=True
    )
    assert registry.get("summarizer") is None

    asyncio.run(orchestrator.run("summarize Q3"))

    child = registry.get("summarizer")
    assert child is not None
    assert child.is_narrower_than(registry.root)
    assert effects.crm_query == 1


def test_denied_delegation_never_starts_the_sub_agent():
    """Denying the `as_tool` call stops the whole sub-agent, and mints no child."""
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")
    registry = GuardRegistry(root, "orchestrator")

    summarizer = guarded_agent(
        client=ScriptedChatClient([[("crm_query", {"rows": 10})], "done"]),
        name="summarizer",
        description="Summarizes CRM pipeline data.",
        tools=_summarizer_tools(effects),
        policies=POLICIES,
        registry=registry,
    )
    orchestrator = guarded_agent(
        client=ScriptedChatClient([[("summarizer", {"task": "go"})], "done"]),
        name="orchestrator",
        tools=[summarizer.as_tool(name="summarizer", description="delegate")],
        # The delegation is priced at a scope the orchestrator does not hold.
        policies={
            "summarizer": ToolPolicy(
                scope="admin.reset", delegates_to="summarizer", grant=SUMMARIZER_GRANT
            )
        },
        registry=registry,
    )
    response = asyncio.run(orchestrator.run("summarize Q3"))

    assert registry.get("summarizer") is None, "child minted despite the denial"
    assert effects.crm_query == 0, "sub-agent ran despite the denial"
    contents = [c for m in response.messages for c in m.contents]
    assert "scope_not_granted" in _result_text(contents)


# --------------------------------------------------------------------------
# 4. revocation cascades
# --------------------------------------------------------------------------


def test_revocation_denies_subsequent_tool_calls():
    effects = Effects()
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root")
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    summarizer = guarded_agent(
        client=ScriptedChatClient([[("crm_query", {"rows": 100})], "done"]),
        name="summarizer",
        tools=_summarizer_tools(effects),
        policies=POLICIES,
        registry=registry,
    )
    asyncio.run(summarizer.run("go"))
    assert effects.crm_query == 1

    registry.revoke("summarizer")

    summarizer2 = guarded_agent(
        client=ScriptedChatClient([[("crm_query", {"rows": 100})], "done"]),
        name="summarizer",
        tools=_summarizer_tools(effects),
        policies=POLICIES,
        registry=registry,
    )
    response = asyncio.run(summarizer2.run("go again"))

    assert effects.crm_query == 1, "revoked agent still executed a tool body"
    contents = [c for m in response.messages for c in m.contents]
    assert "revoked" in _result_text(contents)


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
            [("crm_query", {"rows": 4200})],
            [("crm_export", {"destination": "s3://exfil"})],
            "done",
        ],
        guarded=True,
        audit_path=audit_path,
    )
    asyncio.run(orchestrator.run("summarize Q3 pipeline"))

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


def _direct(policies, *, agent_name="summarizer", registry=None, on_deny="result"):
    """Drive DelegationGuard.process directly, the way the pipeline does."""
    return DelegationGuard(
        agent_name=agent_name,
        registry=registry,
        policies=policies,
        on_deny=on_deny,
    )


def _context(name: str, arguments):
    class _Fn:
        pass

    fn = _Fn()
    fn.name = name
    return FunctionInvocationContext(function=fn, arguments=arguments)


def _run_guard(guard, ctx):
    ran = []

    async def call_next() -> None:
        ran.append(True)

    asyncio.run(guard.process(ctx, call_next))
    return bool(ran)


def test_unmapped_tool_is_fail_closed():
    """A tool with no ToolPolicy is denied, not silently allowed."""
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    guard = _direct({}, registry=registry)
    ctx = _context("crm_query", {"rows": 1})
    assert _run_guard(guard, ctx) is False
    assert "no ToolPolicy" in str(ctx.result)


def test_agent_with_no_delegated_guard_is_fail_closed():
    """An agent nobody delegated to has no authority at all."""
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")  # never delegates

    guard = _direct(POLICIES, registry=registry)
    ctx = _context("crm_query", {"rows": 1})
    assert _run_guard(guard, ctx) is False
    assert "holds no delegated authority" in str(ctx.result)


def test_on_deny_failure_mode_raises_middleware_failure():
    """`MiddlewareFailure` is the loop's documented fail-closed escape; an ordinary
    exception would be converted into a tool-error result and the loop would keep
    running (`agent_framework/_tools.py:1642-1643`)."""
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    guard = _direct(POLICIES, registry=registry, on_deny="failure")
    ctx = _context("crm_export", {"destination": "s3://exfil"})
    with pytest.raises(MiddlewareFailure):
        _run_guard(guard, ctx)


def test_on_deny_failure_aborts_the_whole_run():
    effects = Effects()
    orchestrator, _, _ = _build(
        effects,
        [
            [("crm_query", {"rows": 10})],
            [("crm_export", {"destination": "s3://exfil"})],
            "done",
        ],
        guarded=True,
        on_deny="failure",
    )
    with pytest.raises(MiddlewareFailure):
        asyncio.run(orchestrator.run("summarize Q3 pipeline"))
    assert effects.crm_export == 0


def test_pydantic_model_arguments_are_normalised():
    """`FunctionInvocationContext.arguments` is `BaseModel | Mapping`
    (`agent_framework/_middleware.py:324`); the ceiling must see the fields either way.
    """
    from pydantic import BaseModel

    class Args(BaseModel):
        rows: int

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    registry.delegate("orchestrator", "summarizer", SUMMARIZER_GRANT)

    guard = _direct(POLICIES, registry=registry)
    assert _run_guard(guard, _context("crm_query", Args(rows=10))) is True
    assert _run_guard(guard, _context("crm_query", Args(rows=50_000))) is False


def test_invalid_on_deny_is_rejected():
    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    with pytest.raises(ValueError):
        _direct(POLICIES, registry=registry, on_deny="explode")


def test_handoff_tool_name_matches_the_orchestrations_convention():
    """`agent_framework_orchestrations._handoff.get_handoff_tool_name` (`:124-126`)
    is the name a policy map must key on for handoff edges."""
    orchestrations = pytest.importorskip("agent_framework_orchestrations._handoff")
    assert handoff_tool_name("worker") == orchestrations.get_handoff_tool_name("worker")


def test_guarded_agent_puts_the_guard_first():
    """Middleware ordering is trust ordering: anything ahead of the guard can
    substitute a result before the check runs (`agent_framework/_tools.py:3165`)."""

    from agent_framework import FunctionMiddleware

    class Passthrough(FunctionMiddleware):
        async def process(self, context, call_next):
            await call_next()

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY)
    registry = GuardRegistry(root, "orchestrator")
    other = Passthrough()
    agent = guarded_agent(
        client=ScriptedChatClient(["done"]),
        name="orchestrator",
        tools=[],
        policies={},
        registry=registry,
        middleware=[other],
    )
    assert isinstance(agent.middleware[0], DelegationGuard)
    assert agent.middleware[1] is other
