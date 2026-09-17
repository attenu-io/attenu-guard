"""crewai_continuity.py — does the PARENT's own view keep the child's call?

Imports the scenario from ``examples/integrations/crewai/demo.py`` and adds
printing only. The orchestrator delegates to a summarizer, which reads, is
denied an export, and is revoked.

The parent's own view here is the only one CrewAI gives it: the messages
CrewAI passes to the orchestrator's own model calls. This script records every
one of them by wrapping the recipe's scripted ``BaseLLM`` — the wrapper records
and forwards, it decides nothing.

Offline: the recipe's scripted ``BaseLLM``. No API key, no network.

    pip install 'attenu-guard[crypto]' crewai==1.15.18
    python docs/runs/scripts/crewai_continuity.py
"""
from __future__ import annotations

import copy
import importlib.metadata as md
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _report as report  # noqa: E402

FW = "crewai"
REPO = Path(__file__).resolve().parents[3]
RECIPE = REPO / "examples" / "integrations" / "crewai" / "demo.py"

_spec = importlib.util.spec_from_file_location("attenu_crewai_recipe", RECIPE)
recipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recipe)  # type: ignore[union-attr]

from attenu_guard import Authority, EgressRank, Guard, RowLimit  # noqa: E402
from attenu_guard.adapters.crewai import CrewAIGuardBridge, ToolPolicy  # noqa: E402

COWORKER_ANSWER = "summary of 4200 Q3 pipeline rows"


def record_calls(llm, seen: list) -> None:
    """Wrap the scripted model so every call CrewAI makes is recorded verbatim."""
    inner = llm.call

    def call(messages, *a, **kw):
        # CrewAI passes the same list object to every call and keeps appending to it, so store a copy:
        # a reference would print every call with the list as it stood at the end of the run.
        seen.append((getattr(kw.get("from_agent"), "role", "?"), copy.deepcopy(messages)))
        return inner(messages, *a, **kw)

    llm.call = call


def _last(messages) -> tuple[str, str]:
    if isinstance(messages, str):
        return "user", messages
    last = messages[-1]
    if isinstance(last, dict):
        return last.get("role", "?"), str(last.get("content", ""))
    return getattr(last, "role", "?"), str(getattr(last, "content", last))


def _text(messages) -> str:
    if isinstance(messages, str):
        return messages
    return "\n".join(str(m.get("content", "") if isinstance(m, dict) else m)
                     for m in messages)


def print_parent_view(seen: list) -> None:
    report.head(FW, "the ORCHESTRATOR's own view — every model call CrewAI made "
                    "for it")
    parent = [m for role, m in seen if role == recipe.ORCHESTRATOR]
    child = [m for role, m in seen if role == recipe.SUMMARIZER]
    print(f"  CrewAI made {len(parent)} model call(s) for the "
          f"{recipe.ORCHESTRATOR} and {len(child)} for the {recipe.SUMMARIZER}")
    for i, messages in enumerate(parent):
        role, content = _last(messages)
        n = 1 if isinstance(messages, str) else len(messages)
        print(f"  [{recipe.ORCHESTRATOR} model call {i}] LAST message only, "
              f"{n} in the list, role={role}:")
        print(f"    {content!r}")
    print("  (each block above is the LAST message of that call, not the whole "
          "list — the earlier ones are the system/task prompt)")
    for i, messages in enumerate(parent):
        whole = _text(messages)
        print(f"  [{recipe.ORCHESTRATOR} model call {i}] "
              f"mentions 'crm_query': {'crm_query' in whole} · "
              f"mentions 'crm_export': {'crm_export' in whole} · "
              f"carries the coworker's final answer ('{COWORKER_ANSWER}'): "
              f"{COWORKER_ANSWER in whole}")


def main() -> int:
    print(f"versions: crewai {md.version('crewai')}")

    root = Guard.issue(
        recipe.ORCHESTRATOR,
        Authority(scopes={"crm.*", "mail.send"},
                  ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        task="deliver the Q3 pipeline summary",
        schema_version=2,
    )
    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role=recipe.ORCHESTRATOR,
        tool_policies={
            "crm_query": ToolPolicy(scope="crm.read",
                                    context_fn=lambda a: {"rows": int(a.get("rows", 0))}),
            "crm_export": ToolPolicy(scope="crm.export",
                                     context_fn=lambda a: {"egress": "any"}),
        },
        delegation_authorities={
            recipe.SUMMARIZER: Authority(scopes={"crm.read"},
                                         ceilings=[RowLimit(5_000), EgressRank("none")],
                                         ttl=900),
        },
        revoke_on_deny=True,
        strict_single_hook=True,
    )

    seen: list = []
    llm = recipe.build_llm()
    record_calls(llm, seen)
    recipe.EXECUTED.clear()
    with bridge:
        recipe.build_crew(llm).kickoff()

    report.print_bodies(FW, recipe.EXECUTED)
    print_parent_view(seen)
    report.print_child_guards(FW, root)
    ok = report.tail(FW, root)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
