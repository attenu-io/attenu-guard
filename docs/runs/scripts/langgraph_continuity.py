"""langgraph_continuity.py — does the PARENT's own view keep the child's call?

Imports the scenario from
``examples/integrations/langgraph/subagent_middleware/demo.py`` and adds
printing only. The supervisor holds ``web.search`` and ``brief.write`` and
spawns a researcher and a writer; the writer asks for a search its own grant
does not cover, so that call is denied and the brief is written anyway.

The parent's own view here is ``out["messages"]`` — LangChain's own message
list, the thing a supervisor reads back after the run.

Offline: the recipe's scripted ``BaseChatModel``. No API key, no network.

    pip install 'attenu-guard[crypto]' langchain==1.3.17 langgraph==1.2.11 deepagents==0.7.6
    python docs/runs/scripts/langgraph_continuity.py
"""
from __future__ import annotations

import importlib.metadata as md
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _report as report  # noqa: E402

FW = "langgraph"
REPO = Path(__file__).resolve().parents[3]
RECIPE = (REPO / "examples" / "integrations" / "langgraph" / "subagent_middleware"
          / "demo.py")

_spec = importlib.util.spec_from_file_location("attenu_lg_recipe", RECIPE)
recipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recipe)  # type: ignore[union-attr]


def print_supervisor_view(out: dict) -> None:
    report.head(FW, "the SUPERVISOR's own view (out['messages'], LangChain's list)")
    for m in out["messages"]:
        line = f"  {type(m).__name__:<13}name={m.name!r} content={m.content!r}"
        calls = getattr(m, "tool_calls", None)
        if calls:
            line += f" tool_calls={[(c['name'], c['args']) for c in calls]}"
        print(line)


def main() -> int:
    print("versions: " + " · ".join(
        f"{p} {md.version(p)}"
        for p in ("langchain", "langchain-core", "langgraph", "deepagents")))

    out, sink, root, _guarded = recipe.run_guarded()

    print_supervisor_view(out)
    report.print_bodies(FW, sink)
    report.print_child_guards(FW, root)
    ok = report.tail(FW, root)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
