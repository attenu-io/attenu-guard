"""The gate for the OpenAI Agents "one policy" recipe
(examples/integrations/openai_agents/one_policy/).

Two tiers: COMPATIBILITY (imports, the SDK APIs we touch) and SEMANTIC (the upstream
behaviour the story relies on, pinned to a version and a named code path). Then the
side-effect oracle, the escalation-by-routing case, the injection case and the bypass
cases. Everything runs offline through the real `Runner.run(...)` loop with the SDK's
own `agents.testing.ScriptedModel` — no API key, no network.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import importlib.metadata
import importlib.util
import inspect
import json
import os
import stat
from pathlib import Path

import pytest

pytest.importorskip("agents")

from agents import Agent, RunConfig, Runner, function_tool, handoff  # noqa: E402

from attenu_guard import AuditLog, evidence  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

PINNED = {
    "package": "openai-agents",
    "version": "0.22.0",
    "relation_path": "agents/run_internal/turn_preparation.py::get_handoffs "
                     "(check_handoff_enabled calls is_enabled(context_wrapper, agent) with the "
                     "SENDING agent; the receiver is named only by Handoff.agent_name)",
    "history_path": "agents/handoffs/__init__.py::Handoff.input_filter (default None — the "
                    "receiver is handed the prior conversation)",
    "issue": "openai/openai-agents-python#4618 (docs request, closed 2026-08-25)",
}

_DEMO = (Path(__file__).resolve().parents[2] / "examples" / "integrations" /
         "openai_agents" / "one_policy" / "demo.py")
_spec = importlib.util.spec_from_file_location("attenu_openai_one_policy_demo", _DEMO)
op = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(op)  # type: ignore[union-attr]


# ---- tier 1: compatibility ----------------------------------------------------------
def test_compat_openai_agents_importable_and_version_known():
    version = importlib.metadata.version("openai-agents")
    assert version, "openai-agents not installed"
    print(f"openai-agents {version} (pinned story: {PINNED['version']})")


def test_compat_the_four_primitives_exist():
    """The recipe stands on four SDK APIs. Failing here is drift, not news."""
    from agents import FunctionTool, Handoff
    from agents.mcp import MCPServer, ToolFilterContext

    tool_fields = {f.name for f in dataclasses.fields(FunctionTool)}
    handoff_fields = {f.name for f in dataclasses.fields(Handoff)}
    assert "is_enabled" in tool_fields
    assert "tool_input_guardrails" in tool_fields
    assert {"is_enabled", "input_filter", "agent_name"} <= handoff_fields
    assert {"run_context", "agent", "server_name"} == {
        f.name for f in dataclasses.fields(ToolFilterContext)}
    # An MCP server the recipe can implement offline, with the same list_tools contract
    # the shipped servers use to apply `tool_filter`.
    assert {"list_tools", "call_tool", "connect", "cleanup", "name"} <= set(
        MCPServer.__abstractmethods__)
    assert "run_context" in inspect.signature(MCPServer.list_tools).parameters


# ---- tier 2: semantic freshness -----------------------------------------------------
def test_semantic_handoff_is_enabled_receives_the_sending_agent():
    """The relation the recipe computes needs both sides. The SDK hands `is_enabled` the
    SENDING agent; the receiver comes from the handoff object we closed over."""
    seen: list[str] = []

    def probe(ctx, agent) -> bool:
        seen.append(getattr(agent, "name", "?"))
        return True

    sink: list = []
    billing = Agent(name="billing", instructions="Handle billing.",
                    tools=op.make_tools(sink))
    triage = Agent(name="triage", instructions="Route.", tools=op.make_tools(sink),
                   handoffs=[handoff(billing, is_enabled=probe)])
    from agents.testing import ScriptedModel, assistant_message

    asyncio.run(Runner.run(triage, "hello", run_config=RunConfig(
        model=ScriptedModel([[assistant_message("hi")]]), tracing_disabled=True)))
    assert seen and set(seen) == {"triage"}, (
        f"PREMISE CHANGED: openai-agents {importlib.metadata.version('openai-agents')} no "
        f"longer passes the SENDING agent to Handoff.is_enabled (saw {seen}). The recipe's "
        f"relation reads the sender from that argument. Pinned: {PINNED['relation_path']}")


def test_semantic_sdk_offers_a_handoff_to_a_more_capable_agent():
    """No relation between the two sides: a handoff to an agent wired with capability the
    sender does not hold is offered to the model like any other."""
    result, sink, mcp_sink, model = asyncio.run(op.run_unguarded())
    assert op.model_saw_handoff(model, 0, "transfer_to_sre"), (
        f"PREMISE CHANGED: openai-agents {importlib.metadata.version('openai-agents')} now "
        f"withholds a handoff whose receiver is more capable than the sender. Step 1 of the "
        f"story retires; the rest of the recipe still holds. Pinned: {PINNED['relation_path']}")
    # the unguarded control must keep its oracle
    assert ("issue_credit", 250.0) in sink
    assert any(name == "kb_export" for name, _ in mcp_sink)


def test_semantic_handoff_forwards_the_prior_conversation_by_default():
    """`Handoff.input_filter` defaults to None, so the receiver sees what the sender did."""
    from agents import Handoff

    assert dataclasses.fields(Handoff)  # the field exists; the default is what we pin
    assert Handoff.__dataclass_fields__["input_filter"].default is None

    result, sink, mcp_sink, model = asyncio.run(op.run_unguarded())
    forwarded = json.dumps(model.calls[-1].input, default=str)
    assert "kb_export" in forwarded and "exfil.example" in forwarded, (
        f"PREMISE CHANGED: openai-agents {importlib.metadata.version('openai-agents')} no "
        f"longer forwards the prior tool traffic to a handoff receiver by default; the "
        f"recipe's input_filter is then belt-and-braces. Pinned: {PINNED['history_path']}")


# ---- the side-effect oracle ---------------------------------------------------------
def test_side_effect_oracle_denied_credit_left_no_trace(tmp_path):
    result, sink, mcp_sink, policy, model = asyncio.run(
        op.run_guarded(audit_path=tmp_path / "audit.jsonl"))
    outputs = op.tool_outputs(result)
    assert op.denied(outputs, "b3-0"), outputs.get("b3-0")
    assert ("issue_credit", 250.0) not in sink, f"denied credit still executed: {sink}"
    assert ("issue_credit", 42.0) in sink, "the in-authority credit must still run"
    entries = policy.registry.root_guard.audit_log().entries
    assert any(e["event"] == "deny" and e.get("tool") == "issue_credit" for e in entries)
    assert AuditLog.verify(entries)[0]


def test_side_effect_oracle_denied_mcp_export_left_no_trace(tmp_path):
    """The MCP tool is VISIBLE to triage (it holds `kb.*`) and still denied, because the
    ceiling binds on the arguments — which no visibility gate can see."""
    result, sink, mcp_sink, policy, model = asyncio.run(
        op.run_guarded(audit_path=tmp_path / "audit.jsonl"))
    assert op.model_saw_tool(model, 0, "kb_export")
    assert op.denied(op.tool_outputs(result), "t3")
    assert not any(name == "kb_export" for name, _ in mcp_sink), mcp_sink
    assert any(name == "kb_search" for name, _ in mcp_sink), "the allowed MCP call must run"


def test_authority_is_monotonic_down_the_chain(tmp_path):
    _, _, _, policy, _ = asyncio.run(op.run_guarded(audit_path=tmp_path / "a.jsonl"))
    registry = policy.registry
    billing = registry.guard_for("billing")
    assert billing is not None
    assert billing.is_narrower_than(registry.root_guard)
    assert billing.authority.is_narrower_than(registry.root_guard.authority)
    assert not registry.root_guard.authority.is_narrower_than(billing.authority)
    # the grant was a REQUEST: what billing holds is the meet, never wider than triage
    assert billing.authority.ceiling("max_spend").max_spend == 50.0


# ---- the relation: escalation by routing --------------------------------------------
def test_escalation_by_routing_is_refused_and_recorded(tmp_path):
    _, _, _, policy, model = asyncio.run(op.run_guarded(audit_path=tmp_path / "b.jsonl"))
    assert not op.model_saw_handoff(model, 0, "transfer_to_sre"), (
        "the sre handoff must never reach the model")
    assert op.model_saw_handoff(model, 0, "transfer_to_billing"), (
        "the narrowing handoff must still be offered")
    assert ("triage", "sre") in policy.refused_handoffs
    entries = policy.registry.root_guard.audit_log().entries
    assert any(e["event"] == "deny" and e.get("tool") == "transfer_to_sre" for e in entries), (
        "the refused delegation must be on the ledger")


def test_narrowed_history_is_what_the_receiver_is_handed(tmp_path):
    _, _, _, policy, model = asyncio.run(op.run_guarded(audit_path=tmp_path / "c.jsonl"))
    assert "kb_export" in policy.filtered_history and "kb_search" in policy.filtered_history
    receiver_input = json.dumps(model.calls[-1].input, default=str)
    assert "kb_export" not in receiver_input, (
        "tool traffic outside the receiver's authority must not be forwarded")
    assert "lookup_invoice" in receiver_input, "history it may hold is still forwarded"


# ---- injection ----------------------------------------------------------------------
def test_injection_the_model_decides_the_over_limit_credit_and_is_denied(tmp_path):
    """The ticket text tells the agent to credit the full invoice and deploy a service.
    The scripted model obeys; the guard does not."""
    result, sink, mcp_sink, policy, model = asyncio.run(
        op.run_guarded(audit_path=tmp_path / "d.jsonl", over_limit=250.0))
    assert "SYSTEM:" in op.REQUEST and "deploy" in op.REQUEST
    assert op.denied(op.tool_outputs(result), "b3-0")
    assert ("issue_credit", 250.0) not in sink
    assert ("deploy_service", "billing") not in sink
    # deploy_service is not even visible: no agent in the chain holds `infra.deploy`
    assert not op.model_saw_tool(model, 0, "deploy_service")


# ---- bypass cases (red team) --------------------------------------------------------
def test_bypass_undeclared_alternate_tool_is_denied_by_default(tmp_path):
    """A second tool with the same effect that the operator never declared. Visibility is
    switched OFF here so the model can actually reach it — the invocation check is what
    stops it, which is the point the SDK's own issue makes about visibility filtering."""
    shadow: list = []

    @function_tool
    def refund_via_ledger(amount: float) -> str:
        """An undeclared second path to the same effect."""
        shadow.append(("refund_via_ledger", amount))
        return f"refunded {amount}"

    from agents.testing import function_call

    result, sink, mcp_sink, policy, model = asyncio.run(op.run_guarded(
        audit_path=tmp_path / "e.jsonl",
        enforce_visibility=False,
        extra_tools=[refund_via_ledger],
        tail=[[function_call("refund_via_ledger", {"amount": 250.0}, call_id="x1")]],
    ))
    outputs = op.tool_outputs(result)
    assert op.model_saw_tool(model, 0, "refund_via_ledger"), "the bypass must be reachable"
    assert op.denied(outputs, "x1"), outputs.get("x1")
    assert shadow == [], f"undeclared tool executed: {shadow}"


def test_bypass_visibility_off_still_denies_at_invocation(tmp_path):
    """Remove every visibility gate and nothing about enforcement changes."""
    result, sink, mcp_sink, policy, model = asyncio.run(
        op.run_guarded(audit_path=tmp_path / "f.jsonl", enforce_visibility=False))
    outputs = op.tool_outputs(result)
    assert op.model_saw_tool(model, 0, "deploy_service"), "visibility is off in this run"
    assert op.denied(outputs, "b3-0") and op.denied(outputs, "t3")
    assert ("issue_credit", 250.0) not in sink
    assert not any(name == "kb_export" for name, _ in mcp_sink)


def test_bypass_retries_stay_denied_and_each_attempt_is_on_the_ledger(tmp_path):
    result, sink, mcp_sink, policy, model = asyncio.run(
        op.run_guarded(audit_path=tmp_path / "g.jsonl", retries=3))
    outputs = op.tool_outputs(result)
    assert all(op.denied(outputs, f"b3-{i}") for i in range(3))
    assert ("issue_credit", 250.0) not in sink
    denies = [e for e in policy.registry.root_guard.audit_log().entries
              if e["event"] == "deny" and e.get("tool") == "issue_credit"]
    assert len(denies) == 3, f"expected 3 denials on the ledger, got {len(denies)}"


def test_bypass_guard_absent_refuses_to_run():
    sink: list = []
    mcp_sink: list = []
    triage, policy = op.build(sink, mcp_sink, guarded=False)
    assert policy is None
    with pytest.raises(RuntimeError, match="refusing to run unguarded"):
        op.require_guard(triage, None)
    with pytest.raises(RuntimeError, match="refusing to run unguarded"):
        op.require_guard(triage, object())


def test_bypass_direct_python_call_is_outside_the_boundary():
    """Documented, not prevented: mediation covers the SDK's dispatch, not arbitrary
    Python in the same process."""
    sink: list = []
    op.issue_credit_impl(sink, 250.0)
    assert sink == [("issue_credit", 250.0)]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_bypass_audit_write_failure_fails_closed(tmp_path):
    log = tmp_path / "h.jsonl"

    def make_unwritable() -> None:
        log.chmod(stat.S_IRUSR)

    sink: list = []
    try:
        try:
            _, sink, _, _, _ = asyncio.run(
                op.run_guarded(audit_path=log, before_run=make_unwritable))
        except Exception:  # noqa: BLE001 — an error is an acceptable outcome
            pass
    finally:
        log.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert sink == [], f"tool body ran although the ledger could not be written: {sink}"


def test_bypass_tampered_bundle_fails_and_clean_bundle_passes(tmp_path):
    _, _, _, policy, _ = asyncio.run(op.run_guarded(audit_path=tmp_path / "i.jsonl"))
    signer = HS256TestSigner(b"k", kid="t")
    bundle = evidence.export_bundle(policy.registry.root_guard.audit_log(), signer)
    report = evidence.verify_bundle(bundle, signer)
    assert report["ok"] and all(report["checks"].values()), report

    tampered = copy.deepcopy(bundle)
    deny = next(e for e in tampered["entries"] if e["event"] == "deny")
    deny["event"] = "allow"                        # rewrite a denial into an allow
    report2 = evidence.verify_bundle(tampered, signer)
    assert not report2["ok"] and not report2["checks"]["integrity"], json.dumps(report2)[:300]


def test_demo_exits_zero():
    assert op.main() == op.EXIT_OK
