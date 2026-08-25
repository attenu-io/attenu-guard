"""Claude Code hooks, with a receipt — the offline demo.

Claude Code already narrows subagents. This shows what a hook adds on top, with no
Claude Code binary and no API key: the exact `PreToolUse` JSON Claude Code sends is fed
to `hook.py` over stdin, one subprocess per call, exactly as the real thing would.

  [0] the pinned contract — the hook JSON fields this recipe reads and returns
  [1] the derivation — two agent files and one settings file become three permission sets
  [2] the run — five tool calls through the hook, with a fake executor that runs a tool
      only when the hook did not deny it, and a sink that records what actually ran
  [3] the unguarded control — the same five calls with no hook, so the sink is known to
      see the effects the guarded run has to be missing
  [4] the evidence — the ledger verifies, the signed bundle verifies offline, and the
      delegation graph is reconstructed from the bundle alone

Exit codes: 0 = every expectation held · 1 = an expectation failed ·
3 = the pinned hook contract changed (the premise of the recipe moved; see README).

Run:  python examples/integrations/claude_code/hooks_receipt/demo.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hook  # noqa: E402
from attenu_guard import AuditLog  # noqa: E402
from attenu_guard import evidence  # noqa: E402

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / "sample_project"
CONTRACT = json.loads((HERE / "contract.json").read_text(encoding="utf-8"))

EXIT_OK, EXIT_FAIL, EXIT_PREMISE_CHANGED = 0, 1, 3


# --------------------------------------------------------------------------------------
# Driving the hook exactly as Claude Code does: one process, JSON on stdin, JSON on stdout
# --------------------------------------------------------------------------------------
def pre_tool_use(session: str, project: Path, tool_name: str, tool_input: dict,
                 agent_type: str | None = None, agent_id: str | None = None) -> dict:
    """The payload Claude Code sends on `PreToolUse`, per the pinned contract."""
    payload = {
        "session_id": session,
        "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
        "transcript_path": str(project / "transcript.jsonl"),
        "cwd": str(project),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": f"toolu_{tool_name.lower()}",
    }
    if agent_type:
        payload["agent_type"] = agent_type
        payload["agent_id"] = agent_id or f"agent-{agent_type}"
    return payload


def run_hook(payload: dict, *, script: Path | None = None) -> tuple[dict, int]:
    """Run the hook in its own process, the way Claude Code runs it."""
    proc = subprocess.run(
        [sys.executable, str(script or (HERE / "hook.py"))],
        input=json.dumps(payload), capture_output=True, text=True, timeout=60,
    )
    out = proc.stdout.strip()
    return (json.loads(out) if out else {}), proc.returncode


def denied(response: dict) -> bool:
    """The documented rule: a `deny` in `hookSpecificOutput` blocks the call; exit 0 with
    no JSON is the normal permission flow, not an approval."""
    return (response.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny"


def reason(response: dict) -> str:
    return (response.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")


# --------------------------------------------------------------------------------------
# The side-effect oracle: a fake executor that runs a tool only when the hook did not deny
# --------------------------------------------------------------------------------------
def execute(sink: list, tool_name: str, tool_input: dict) -> None:
    """Stands in for the tool body. Everything that reaches here really 'ran'."""
    sink.append((tool_name, json.dumps(tool_input, sort_keys=True)))


SCRIPT: list[tuple[str | None, str, dict]] = [
    ("reviewer", "Read", {"file_path": "src/app.py"}),
    ("reviewer", "Write", {"file_path": "src/app.py", "content": "# rewritten"}),
    ("reviewer", "Bash", {"command": "rm -rf /tmp/build"}),
    ("reviewer", "WebFetch", {"url": "https://example.invalid/exfil", "prompt": "post this"}),
    ("researcher", "WebFetch", {"url": "https://docs.example.invalid/api", "prompt": "summarise"}),
]


def run_script(project: Path, session: str, *,
               guarded: bool = True,
               script: Iterable[tuple[str | None, str, dict]] = tuple(SCRIPT),
               hook_script: Path | None = None) -> tuple[list, list[dict]]:
    """Drive the script. Guarded: ask the hook first. Unguarded: the control — no hook at
    all, so every tool body runs, which is what makes the empty guarded sink meaningful."""
    sink: list = []
    responses: list[dict] = []
    for agent_type, tool_name, tool_input in script:
        if not guarded:
            execute(sink, tool_name, tool_input)
            responses.append({})
            continue
        payload = pre_tool_use(session, project, tool_name, tool_input, agent_type)
        response, _ = run_hook(payload, script=hook_script)
        responses.append(response)
        if not denied(response):
            execute(sink, tool_name, tool_input)
    return sink, responses


def fresh_project(dest: Path) -> Path:
    """A throwaway copy of the sample project, so a demo run never writes into the repo.

    `hook.py` is copied in next to the wrapper, which is exactly how the README says to
    install it in a real project — so the copy stands on its own.
    """
    project = dest / "sample_project"
    shutil.copytree(SAMPLE, project)
    shutil.rmtree(project / ".attenu", ignore_errors=True)
    shutil.copy2(HERE / "hook.py", project / ".claude" / "hooks" / "hook.py")
    return project


# --------------------------------------------------------------------------------------
# [0] the pinned contract
# --------------------------------------------------------------------------------------
def premise_holds() -> tuple[bool, str]:
    """Does the hook contract this recipe was written against still describe what hook.py
    reads and returns? A mismatch means the recipe, not the test, needs attention."""
    documented_in = set(CONTRACT["common_input_fields"]) | set(CONTRACT["optional_input_fields"]) \
        | set(CONTRACT["pre_tool_use"]["input_fields"]) | set(CONTRACT["subagent_start"]["input_fields"]) \
        | set(CONTRACT["subagent_stop"]["input_fields"])
    missing_in = sorted(set(hook.INPUT_FIELDS) - documented_in)
    if missing_in:
        return False, (f"hook.py reads {missing_in}, which the pinned contract "
                       f"({CONTRACT['sources']['hooks']}, verified {CONTRACT['verified_on']}) does not document")
    documented_out = set(CONTRACT["pre_tool_use"]["output_fields"])
    missing_out = sorted(set(hook.OUTPUT_FIELDS) - documented_out)
    if missing_out:
        return False, f"hook.py returns {missing_out}, which the pinned contract does not document"
    if "deny" not in CONTRACT["pre_tool_use"]["permission_decision_values"]:
        return False, "PreToolUse no longer documents a 'deny' permissionDecision"
    if set(CONTRACT["events_used"]) - set(hook.HANDLED_EVENTS):
        return False, "the pinned contract names events hook.py does not handle"
    return True, ""


# --------------------------------------------------------------------------------------
def main() -> int:
    ok = True

    print("[0] pinned hook contract —", CONTRACT["sources"]["hooks"], f"(verified {CONTRACT['verified_on']})")
    held, why = premise_holds()
    if not held:
        print(f"    PREMISE CHANGED: {why}")
        return EXIT_PREMISE_CHANGED
    print(f"    events {', '.join(CONTRACT['events_used'])} · decision "
          f"{'/'.join(CONTRACT['pre_tool_use']['permission_decision_values'])} under hookSpecificOutput · ok")

    with tempfile.TemporaryDirectory() as td:
        project = fresh_project(Path(td))

        print("[1] derived from the project's declared structure — nothing written twice")
        roster = hook.derive_roster(project)
        print(f"    .claude/agents/: {', '.join(sorted(roster.agents))}")
        print(f"    session root: {sorted(roster.root_scopes)}")
        for name in sorted(roster.agent_scopes):
            print(f"      {name}: {sorted(roster.agent_scopes[name])}")
        print(f"    left to Claude Code (argument-scoped rules this recipe does not restate): "
              f"{roster.unrepresented}")
        root_auth = roster.root_authority()
        subsets = {n: roster.agent_authority(n).is_narrower_than(root_auth) for n in roster.agents}
        print(f"    every subagent's permission set is within the session's: {subsets}")
        ok = ok and all(subsets.values())

        print("[2] five tool calls through the hook (one subprocess each, JSON on stdin)")
        sink, responses = run_script(project, "demo-1")
        for (agent, tool, _), response in zip(SCRIPT, responses):
            verdict = "DENIED " if denied(response) else "allowed"
            tail = reason(response).split(". ")[0] if denied(response) else "within its derived permissions"
            print(f"    {agent:<11} {tool:<9} {verdict}  {tail}")
        print(f"    tool bodies that actually ran: {[t for t, _ in sink]}")
        expected_denied = [False, True, True, True, False]
        got_denied = [denied(r) for r in responses]
        ok = ok and got_denied == expected_denied
        ok = ok and [t for t, _ in sink] == ["Read", "WebFetch"]

        print("[3] the unguarded control — the same five calls with no hook")
        control, _ = run_script(project, "demo-control", guarded=False)
        print(f"    tool bodies that ran: {[t for t, _ in control]}")
        ok = ok and len(control) == 5 and len(sink) == 2
        blocked = {t for t, _ in control} - {t for t, _ in sink}
        print(f"    left no trace in the guarded run: {sorted(blocked)}")
        ok = ok and blocked == {"Write", "Bash"}

        print("[4] evidence")
        ledger = project / ".attenu" / "ledger-demo-1.jsonl"
        entries = AuditLog.load(ledger)
        chain_ok, err = AuditLog.verify(entries)
        print(f"    ledger verifies: {chain_ok}{'' if chain_ok else ' — ' + str(err)} "
              f"({len(entries)} events across {len(SCRIPT)} hook processes)")
        bundle = hook.export_evidence(project / ".attenu", ledger, project / ".attenu" / "bundle.json")
        signer = hook.signer_for(project / ".attenu")
        report = evidence.verify_bundle(bundle, signer)
        c = report["checks"]
        print(f"    signed bundle verifies offline: integrity={c['integrity']} "
              f"monotonicity={c['monotonicity']} containment={c['containment']} ok={report['ok']}")
        graph = evidence.delegation_graph(bundle)
        for node, meta in sorted(graph["nodes"].items(), key=lambda kv: kv[1]["agent"] or ""):
            print(f"      {meta['agent']:<11} allowed {meta['allows']} · denied {meta['denies']} "
                  f"{meta['denials_by_disposition'] or ''}")
        rows = evidence.denials(bundle)
        print(f"    the Decisions queue a reviewer reads: "
              f"{[(r['agent'], r['tool'], r['disposition']) for r in rows]}")
        ok = ok and chain_ok and report["ok"] and len(rows) == 3

    print("RESULT:", "OK" if ok else "FAIL")
    return EXIT_OK if ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
