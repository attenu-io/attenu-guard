"""claude_code_continuity.py — does the PARENT's own view keep the child's call?

Imports the scenario from
``examples/integrations/claude_code/hooks_receipt/demo.py`` and adds printing
only. There is no API key in this environment and this lane runs no live model,
so the demo feeds the exact ``PreToolUse`` JSON to the hook on stdin, one
subprocess per call, the way Claude Code would.

What this row cannot answer: the ``transcript_path`` in the payload is
synthesised by the demo and points at a file that does not exist, so there is
nothing here to say about what a real parent transcript holds. The cell stays
"not established" until someone runs a live session.

What it does answer: five separate operating-system processes append to one
hash-chained ledger, and the child's calls are on it, attributed by the
``agent_id`` / ``agent_type`` fields Claude Code's own hook contract carries.

The temp-directory prefix is replaced by ``<tmpdir>/`` in this output, because
no absolute path belongs in a published file. That substitution is the single
change to the bytes.

    pip install 'attenu-guard[crypto]'
    PYTHONPATH=src python docs/runs/scripts/claude_code_continuity.py
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _report as report  # noqa: E402

FW = "claude code"
REPO = Path(__file__).resolve().parents[3]
RECIPE = (REPO / "examples" / "integrations" / "claude_code" / "hooks_receipt"
          / "demo.py")

_spec = importlib.util.spec_from_file_location("attenu_cc_recipe", RECIPE)
recipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recipe)  # type: ignore[union-attr]

hook = recipe.hook
SESSION = "continuity"


def print_registration(project: Path) -> None:
    report.head(FW, "how the hook is registered "
                    "(sample_project/.claude/settings.json)")
    settings = json.loads(
        (project / ".claude" / "settings.json").read_text(encoding="utf-8"))
    hooks = settings.get("hooks") or {}
    pre = hooks.get("PreToolUse") or []
    print(f"  PreToolUse entries: {len(pre)}")
    for i, entry in enumerate(pre):
        print(f"    [{i}] keys={sorted(entry)}  "
              f"matcher present: {'matcher' in entry}")
        for h in entry.get("hooks") or []:
            print(f"        command={h.get('command')}")
    print(f"  one PreToolUse entry with no matcher runs for EVERY tool call, "
          f"the parent's and the subagents' alike; the recipe's contract also "
          f"registers {', '.join(k for k in hooks if k != 'PreToolUse')}")


def print_payload(project: Path, tmp: str) -> None:
    report.head(FW, "the PreToolUse payload this run feeds the hook on stdin")
    agent_type, tool_name, tool_input = recipe.SCRIPT[0]
    payload = recipe.pre_tool_use(SESSION, project, tool_name, tool_input,
                                  agent_type)
    text = json.dumps(payload, indent=2, sort_keys=True).replace(tmp + "/",
                                                                 "<tmpdir>/")
    print(f"  {text}")
    print("  transcript_path above is SYNTHESISED by demo.pre_tool_use for the "
          "offline run. It is where Claude Code would name the transcript; no "
          "such file is written here.")
    print(f"  exists on disk: {Path(payload['transcript_path']).exists()}")


def main() -> int:
    print("versions: no framework package — the seam is Claude Code's own hook "
          "contract")
    print(f"  pinned contract: {recipe.CONTRACT['sources']['hooks']} "
          f"(verified {recipe.CONTRACT['verified_on']})")

    with tempfile.TemporaryDirectory() as td:
        project = recipe.fresh_project(Path(td))
        print_registration(project)
        print_payload(project, td)

        report.head(FW, "the five calls, one hook subprocess each")
        sink, responses = recipe.run_script(project, SESSION)
        for (agent, tool, _), response in zip(recipe.SCRIPT, responses):
            verdict = "DENIED " if recipe.denied(response) else "allowed"
            why = (recipe.reason(response).split(". ")[0]
                   if recipe.denied(response) else "within its derived permissions")
            print(f"  {agent:<11} {tool:<9} {verdict}  {why}")
        report.print_bodies(FW, [t for t, _ in sink])

        attenu_dir = hook.find_project_root(project) / ".attenu"
        ledger_path = attenu_dir / f"ledger-{SESSION}.jsonl"
        from attenu_guard import AuditLog
        entries = AuditLog.load(ledger_path)
        verified, _why = AuditLog.verify(entries)
        report.head(FW, "the ledger the five separate hook processes appended to")
        print(f"  {ledger_path.name}: {len(entries)} entries, "
              f"AuditLog.verify={verified}")

        bundle = hook.export_evidence(attenu_dir, ledger_path)
        report.print_node_map(FW, bundle)
        report.print_entries(FW, bundle)
        rep = hook.evidence.verify_bundle(bundle, hook.signer_for(attenu_dir))
        report.head(FW, "verify_bundle")
        print(f"  ok={rep['ok']}")
        print(f"  checks={rep['checks']}")
        report.print_child_attribution(FW, bundle)
        roster = hook.derive_roster(project)
        print(f"  subagents declared in the project: {sorted(roster.agents)}")

    return 0 if (verified and rep["ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
