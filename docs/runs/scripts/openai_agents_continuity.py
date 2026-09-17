"""openai_agents_continuity.py — does the PARENT's own view keep the child's call?

Imports the scenario from ``examples/integrations/openai_agents/demo.py`` and
adds printing only. The orchestrator reads 60,000 rows and hands off; the
summarizer is then denied three times — a row ceiling, a scope it does not
hold, and a revocation.

The parent's own view here is ``result.new_items``: the run's single item list
across the handoff, which the SDK attributes to an agent item by item.

This row was the open one. A per-tool wrapper intercepts a call, but
interception is not a record; the last line answers whether the wrapper writes
to the chain at all, and whose node the entry carries.

Offline: the SDK's own ``agents.testing.ScriptedModel``. No API key, no network.

    pip install 'attenu-guard[crypto]' openai-agents==0.22.0
    python docs/runs/scripts/openai_agents_continuity.py
"""
from __future__ import annotations

import asyncio
import importlib.metadata as md
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _report as report  # noqa: E402

FW = "openai agents"
REPO = Path(__file__).resolve().parents[3]
RECIPE = REPO / "examples" / "integrations" / "openai_agents" / "demo.py"

_spec = importlib.util.spec_from_file_location("attenu_oai_recipe", RECIPE)
recipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recipe)  # type: ignore[union-attr]

from agents import Agent, RunConfig, Runner  # noqa: E402

from attenu_guard import Authority, EgressRank, Guard, RowLimit  # noqa: E402
from attenu_guard.adapters.openai_agents import (  # noqa: E402
    DelegationGuardHooks, GuardRegistry, guarded_tool,
)

OUTPUT_CHARS = 110


def _get(raw, key):
    return raw.get(key) if isinstance(raw, dict) else getattr(raw, key, None)


def print_item_list(result) -> None:
    report.head(FW, "result.new_items — the run's single item list across the "
                    "handoff, with the agent the SDK attributes each item to")
    for item in result.new_items:
        raw = getattr(item, "raw_item", None)
        agent = getattr(getattr(item, "agent", None), "name", None)
        out = _get(raw, "output")
        if out is not None:
            rest = (f"call_id={_get(raw, 'call_id')} "
                    f"output={str(out)[:OUTPUT_CHARS]!r}")
        else:
            rest = (f"name={_get(raw, 'name')} call_id={_get(raw, 'call_id')} "
                    f"args={_get(raw, 'arguments')}")
        print(f"  {type(item).__name__:<23}agent={agent!r:<17}{rest}")


async def run() -> int:
    print(f"versions: openai-agents {md.version('openai-agents')}")

    root = Guard.issue(
        recipe.ORCHESTRATOR,
        Authority(scopes={"crm.*", "mail.send"},
                  ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        task="deliver the Q3 pipeline summary",
        schema_version=2,
    )
    registry = GuardRegistry(root_agent=recipe.ORCHESTRATOR, root_guard=root)
    registry.grant(recipe.SUMMARIZER,
                   Authority(scopes={"crm.read"},
                             ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
                   task="summarize Q3 pipeline")

    tools = [
        guarded_tool(recipe.crm_query, "crm.read",
                     context_fn=lambda a: {"rows": a.get("rows", 0)}, registry=registry),
        guarded_tool(recipe.crm_export, "crm.export",
                     context_fn=lambda a: {"egress": "any"}, registry=registry),
    ]
    summarizer = Agent(name=recipe.SUMMARIZER,
                       instructions="Summarize the Q3 pipeline.", tools=tools)
    orchestrator = Agent(name=recipe.ORCHESTRATOR,
                         instructions="Delegate summarization work.",
                         tools=tools, handoffs=[summarizer])

    recipe.EXECUTED.clear()
    result = await Runner.run(
        orchestrator, "Summarize the Q3 pipeline.",
        context=registry, hooks=DelegationGuardHooks(),
        run_config=RunConfig(model=recipe.script(registry), tracing_disabled=True),
    )

    report.print_bodies(FW, recipe.EXECUTED)
    print_item_list(result)
    report.print_child_guards(FW, root)
    ok = report.tail(FW, root)

    bundle = report.bundle_of(root)
    child = registry.guard_for(recipe.SUMMARIZER).node_id
    wrote = any(e.get("node") == child and e["event"] in ("allow", "deny")
                for e in bundle["entries"])
    print(f"  the per-tool wrapper WROTE child-attributed entries to the "
          f"ledger: {wrote}")
    print(f"\n  the run's own answer: {result.final_output}")
    return 0 if (ok and wrote) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
