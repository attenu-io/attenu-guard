"""
Integration test: attenu-guard x Haystack (deepset `haystack-ai` 3.1.0).

Runs entirely offline: the "model" is a scripted `ChatGenerator` component that
replays tool calls, so no API key is needed.

What is asserted is the *user-felt* outcome, not the internals: a sub-agent that was
delegated narrow authority tries to exfiltrate, and the tool body is proven never to
have run (via the side-effect flags the tool would have set).

The test drives the SHIPPED example (`examples/integrations/haystack/demo.py` +
`attenu_guard.adapters.haystack`), so a green run also proves the example works.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("haystack")

from haystack.components.agents import Agent  # noqa: E402
from haystack.dataclasses import ChatMessage  # noqa: E402
from haystack.tools import AgentTool, ComponentTool, Tool  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityError,
    EgressRank,
    Guard,
    RowLimit,
)

# --------------------------------------------------------------------------
# Load the example module by path.
#
# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path — the example
# directory is itself named `haystack`, and adding its parent would shadow the real
# framework package. Loading by file location with an explicit module name avoids that.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "haystack"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"attenu_example_{name}", _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


import attenu_guard.adapters.haystack as dg_hs  # noqa: E402

demo = _load("demo")


def _guards_only(entries, event):
    return [e for e in entries if e["event"] == event]


# ==========================================================================
# Hook point 1 — delegation: the child can only ever be narrower
# ==========================================================================

def test_child_authority_is_narrower_than_parent():
    root = Guard.issue("coordinator", demo.COORDINATOR_AUTHORITY, task="root")
    child = root.delegate("researcher", demo.RESEARCHER_AUTHORITY, task="research")

    assert child.is_narrower_than(root) is True
    assert child.authority.covers_scope("crm.read") is True
    assert child.authority.covers_scope("crm.export") is False
    assert child.authority.covers_scope("mail.send") is False


def test_delegation_cannot_widen_beyond_parent():
    """A child that ASKS for more than the parent holds is met down, silently."""
    root = Guard.issue(
        "coordinator",
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


def test_the_agent_tool_call_is_the_delegation_moment():
    """The child Guard appears on the chain because the parent's model called the AgentTool."""
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(ops, researcher_script=demo.SMALL_READ)

    assert [n["agent"] for n in root.graph()["nodes"]] == ["coordinator"]
    demo.run(coordinator, root)

    nodes = root.graph()["nodes"]
    assert [n["agent"] for n in nodes] == ["coordinator", "researcher"]
    assert nodes[1]["depth"] == 1


def test_parallel_delegations_in_one_turn_are_siblings_not_a_chain():
    """Haystack runs a turn's tool calls in parallel; each must see the same parent."""
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(
        ops,
        researcher_script=demo.SMALL_READ,
        children=("researcher_emea", "researcher_apac", "researcher_amer"),
    )

    demo.run(coordinator, root)

    nodes = root.graph()["nodes"]
    assert len(nodes) == 4
    assert [n["depth"] for n in nodes] == [0, 1, 1, 1], "a fan-out was recorded as a chain"


# ==========================================================================
# Hook point 2 — Tool.invoke, through a real (offline) agent run
# ==========================================================================

def test_allowed_tool_executes_and_reaches_its_body():
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(ops, researcher_script=demo.SMALL_READ)

    demo.run(coordinator, root)

    assert ops.rows_returned == 120, "an in-authority read must reach the tool body"


def test_poisoned_export_is_denied_before_the_tool_body_runs():
    """The canonical scenario. `crm_export` must never touch its body."""
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(
        ops, researcher_script=demo.POISONED, raise_on_tool_failure=True
    )

    with pytest.raises(dg_hs.AuthorityDeniedTool) as exc:
        demo.run(coordinator, root)

    assert ops.rows_returned == 4200, "the legitimate read should have happened first"
    assert ops.exported_to is None, "THE TOOL BODY RAN — enforcement failed"
    codes = {r.code for r in exc.value.decision.reasons}
    assert "scope_not_granted" in codes


def test_denial_is_returned_to_the_model_as_a_tool_error_by_default():
    """Haystack's default (`raise_on_tool_invocation_failure=False`) keeps the run alive."""
    ops = demo.Ops()
    root, coordinator, researcher = demo.build_scenario(ops, researcher_script=demo.POISONED)

    result = demo.run(coordinator, root)

    assert ops.exported_to is None, "THE TOOL BODY RAN — enforcement failed"
    assert result["last_message"].text == "Reported to the user."
    denies = demo.denials(root)
    assert [d["tool"] for d in denies] == ["crm_export"]
    assert denies[0]["reason"] == "scope_not_granted"
    del researcher


def test_the_sub_agents_model_is_actually_shown_the_denial():
    """The denial reaches the model as an error tool-result it can adapt to."""
    ops = demo.Ops()
    root = Guard.issue("solo", demo.RESEARCHER_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.POISONED),
        tools=dg_hs.guard_tools(demo.build_tools(ops), demo.RESEARCHER_POLICIES),
        system_prompt="Research.",
    )

    result = demo.run(agent, root)

    assert ops.exported_to is None
    errors = [
        r.result
        for m in result["messages"]
        for r in (m.tool_call_results or [])
        if r.error
    ]
    assert len(errors) == 1
    assert "attenu-guard denied `crm_export`" in errors[0]
    assert "crm.export" in errors[0]


def test_ceiling_exceeded_is_denied_even_though_the_scope_is_granted():
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(
        ops, researcher_script=demo.OVERSIZED, raise_on_tool_failure=True
    )

    with pytest.raises(dg_hs.AuthorityDeniedTool) as exc:
        demo.run(coordinator, root)

    assert ops.rows_returned is None
    codes = {r.code for r in exc.value.decision.reasons}
    assert "ceiling_exceeded" in codes


def test_on_deny_raise_stops_the_run_whatever_the_agent_is_configured_to_do():
    """`on_deny='raise'` raises AuthorityDenied, which Haystack does not catch."""
    from attenu_guard import AuthorityDenied

    ops = demo.Ops()
    root = Guard.issue("solo", demo.RESEARCHER_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.POISONED),
        tools=dg_hs.guard_tools(demo.build_tools(ops), demo.RESEARCHER_POLICIES, on_deny="raise"),
        raise_on_tool_invocation_failure=False,  # the framework would have swallowed it
    )

    with pytest.raises(AuthorityDenied):
        demo.run(agent, root)
    assert ops.exported_to is None


def test_the_async_run_path_is_guarded_too():
    """`Agent.run_async` goes through `Tool.invoke_async`, which is guarded as well."""
    ops = demo.Ops()
    root = Guard.issue("solo", demo.RESEARCHER_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.POISONED),
        tools=dg_hs.guard_tools(demo.build_tools(ops), demo.RESEARCHER_POLICIES),
        raise_on_tool_invocation_failure=True,
    )

    async def go():
        with dg_hs.authority(root):
            return await agent.run_async(messages=[ChatMessage.from_user("Summarise Q3")])

    with pytest.raises(dg_hs.AuthorityDeniedTool):
        asyncio.run(go())

    assert ops.rows_returned == 4200
    assert ops.exported_to is None, "THE TOOL BODY RAN on the async path"


# ==========================================================================
# Hook point 3 — the before_tool ConfirmationHook
# ==========================================================================

def test_confirmation_hook_blocks_equally():
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(ops, researcher_script=demo.POISONED, use_hook=True)

    demo.run(coordinator, root)

    assert ops.rows_returned == 4200
    assert ops.exported_to is None, "THE TOOL BODY RAN — the before_tool hook did not stop it"
    assert [d["tool"] for d in demo.denials(root)] == ["crm_export"]


def test_confirmation_hook_refuses_to_carry_a_delegation_point():
    """This hook point cannot mint a child Guard, so it says so instead of failing open."""
    strategy = dg_hs.AttenuationStrategy(
        {"ask": dg_hs.ToolPolicy(None, delegates_to="child", grant=dg_hs.Grant(demo.RESEARCHER_AUTHORITY))}
    )
    root = Guard.issue("solo", demo.COORDINATOR_AUTHORITY, task="root")

    with dg_hs.authority(root), pytest.raises(ValueError, match="delegation point"):
        strategy.run(tool_name="ask", tool_description="", tool_params={})


# ==========================================================================
# Cascade revocation
# ==========================================================================

def test_revoking_the_sub_agent_by_name_refuses_the_next_delegation():
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(
        ops, researcher_script=demo.SMALL_READ, raise_on_tool_failure=True
    )
    demo.run(coordinator, root)
    assert ops.rows_returned == 120

    revoked = root.revoke_agent("researcher")
    assert revoked, "nothing was revoked"
    ops.rows_returned = None

    with pytest.raises((dg_hs.AuthorityDeniedTool, AuthorityError)):
        demo.run(coordinator, root)

    assert ops.rows_returned is None, "a revoked sub-agent still reached its tool body"


def test_whole_subtree_revocation_stops_further_delegation():
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(
        ops, researcher_script=demo.SMALL_READ, raise_on_tool_failure=True
    )

    root.revoke()  # the whole chain, root included

    with pytest.raises((dg_hs.AuthorityDeniedTool, AuthorityError)):
        demo.run(coordinator, root)

    assert ops.rows_returned is None
    assert [n["agent"] for n in root.graph()["nodes"]] == ["coordinator"]


# ==========================================================================
# Fail-closed defaults
# ==========================================================================

def test_unmapped_tool_is_denied_and_recorded_as_unresolved():
    ops = demo.Ops()
    root = Guard.issue("solo", demo.COORDINATOR_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.SMALL_READ),
        tools=dg_hs.guard_tools(demo.build_tools(ops), {}),  # no policies at all
        raise_on_tool_invocation_failure=True,
    )

    with pytest.raises(dg_hs.AuthorityDeniedTool, match="no ToolPolicy"):
        demo.run(agent, root)

    assert ops.rows_returned is None, "an unmapped tool must not run under the fail-closed default"
    denies = _guards_only(root.audit_log().entries, "deny")
    assert len(denies) == 1
    assert denies[0]["reason"] == "no_authority"
    assert denies[0]["disposition"] == "unresolved"


def test_no_guard_in_scope_is_denied():
    """Forgetting `with authority(...)` must not silently disable enforcement."""
    ops = demo.Ops()
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.SMALL_READ),
        tools=dg_hs.guard_tools(demo.build_tools(ops), demo.RESEARCHER_POLICIES),
        raise_on_tool_invocation_failure=True,
    )

    with pytest.raises(dg_hs.AuthorityDeniedTool, match="no Guard is in force"):
        agent.run(messages=[ChatMessage.from_user("Summarise Q3")])

    assert ops.rows_returned is None


def test_unguarded_tool_is_an_explicit_opt_out():
    ops = demo.Ops()
    root = Guard.issue("solo", demo.RESEARCHER_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.SMALL_READ),
        tools=dg_hs.guard_tools(demo.build_tools(ops), {"crm_query": dg_hs.UNGUARDED}),
        raise_on_tool_invocation_failure=True,
    )

    demo.run(agent, root)

    assert ops.rows_returned == 120
    assert _guards_only(root.audit_log().entries, "allow") == [], "UNGUARDED must spend no authority"


def test_a_delegation_policy_needs_both_the_child_and_the_grant():
    with pytest.raises(ValueError, match="must be given together"):
        dg_hs.ToolPolicy(None, delegates_to="child")


# ==========================================================================
# The guarded tool stays the tool Haystack thinks it is
# ==========================================================================

def test_guarding_preserves_the_tools_own_type_and_metadata():
    """`_get_func_params` keys off `isinstance(tool, ComponentTool)` — that must survive."""
    ops = demo.Ops()
    inner = Agent(chat_generator=demo.ScriptedChatGenerator(["ok"]), tools=demo.build_tools(ops))
    agent_tool = AgentTool(agent=inner, name="ask", description="Delegate.")

    guarded = dg_hs.guard_tool(agent_tool, dg_hs.UNGUARDED)

    assert isinstance(guarded, AgentTool)
    assert isinstance(guarded, ComponentTool)
    assert isinstance(guarded, Tool)
    assert guarded.name == agent_tool.name
    assert guarded.parameters == agent_tool.parameters
    assert guarded.outputs_to_string == agent_tool.outputs_to_string
    assert guarded._component is inner
    assert type(agent_tool) is AgentTool, "the original tool must not be mutated"


def test_a_guarded_tool_refuses_to_be_serialized():
    """It is bound to a live Guard; silently serializing it would be a footgun."""
    ops = demo.Ops()
    guarded = dg_hs.guard_tools(demo.build_tools(ops), demo.RESEARCHER_POLICIES)[0]

    with pytest.raises(NotImplementedError, match="cannot be serialized"):
        guarded.to_dict()


def test_guarding_twice_does_not_stack_two_checks():
    """Re-guarding re-binds the policy; two stacked checks would double-charge metering."""
    ops = demo.Ops()
    once = dg_hs.guard_tools(demo.build_tools(ops), demo.RESEARCHER_POLICIES)
    twice = dg_hs.guard_tools(once, demo.RESEARCHER_POLICIES)

    root = Guard.issue("solo", demo.RESEARCHER_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.SMALL_READ),
        tools=twice,
        raise_on_tool_invocation_failure=True,
    )
    demo.run(agent, root)

    assert ops.rows_returned == 120
    assert len(_guards_only(root.audit_log().entries, "allow")) == 1, "the check ran twice"


# ==========================================================================
# What Haystack itself enforces about a sub-agent's authority: nothing
# ==========================================================================

def test_haystack_itself_does_not_attenuate_a_sub_agent():
    """Baseline, pinned so the weekly unpinned CI job flags the day this changes.

    `AgentTool` wraps a whole `Agent` that keeps its OWN tool list. Nothing in Haystack
    relates a sub-agent's tools to the caller's — a sub-agent can hold tools the agent
    delegating to it does not have.
    """
    ops = demo.Ops()
    tools = demo.build_tools(ops)
    export_only = [t for t in tools if t.name == "crm_export"]

    sub = Agent(
        chat_generator=demo.ScriptedChatGenerator(
            [[("crm_export", {"destination": "s3://anywhere/dump.csv"})], "done"]
        ),
        tools=export_only,
    )
    # The caller holds ONLY crm_query, yet delegates to a sub-agent that can export.
    caller = Agent(
        chat_generator=demo.ScriptedChatGenerator(
            [[("ask", {"messages": [{"role": "user", "content": "go"}]})], "done"]
        ),
        tools=[
            *[t for t in tools if t.name == "crm_query"],
            AgentTool(agent=sub, name="ask", description="Delegate."),
        ],
    )

    caller.run(messages=[ChatMessage.from_user("go")])

    assert ops.exported_to == "s3://anywhere/dump.csv", (
        "Haystack now attenuates sub-agents by itself — re-check the INTEGRATIONS.md row"
    )


# ==========================================================================
# Audit trail
# ==========================================================================

def test_audit_log_verifies_and_records_the_deny():
    ops = demo.Ops()
    root, coordinator, _ = demo.build_scenario(ops, researcher_script=demo.POISONED)

    demo.run(coordinator, root)

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    assert ok is True, err

    events = [e["event"] for e in entries]
    assert events[0] == "root"
    assert "spawn" in events

    denies = _guards_only(entries, "deny")
    assert len(denies) == 1
    assert denies[0]["scope"] == "crm.export"
    assert denies[0]["tool"] == "crm_export"
    assert denies[0]["reason"] == "scope_not_granted"

    allows = _guards_only(entries, "allow")
    assert [a["tool"] for a in allows] == ["crm_query"]


def test_the_shipped_demo_runs_and_ends_ok(capsys):
    demo.main()
    assert capsys.readouterr().out.rstrip().endswith("RESULT: OK")


def test_an_ordinary_tool_failure_is_left_exactly_as_haystack_raised_it():
    """Guarding must not swallow or reshape a normal tool error, or its cause."""
    from haystack.tools.errors import ToolInvocationError

    def boom(rows: int) -> str:
        raise ZeroDivisionError("the tool itself failed")

    tool = Tool(
        name="crm_query",
        description="Read rows from the CRM.",
        parameters={"type": "object", "properties": {"rows": {"type": "integer"}}, "required": ["rows"]},
        function=boom,
    )
    root = Guard.issue("solo", demo.RESEARCHER_AUTHORITY, task="root")
    agent = Agent(
        chat_generator=demo.ScriptedChatGenerator(demo.SMALL_READ),
        tools=dg_hs.guard_tools([tool], demo.RESEARCHER_POLICIES),
        raise_on_tool_invocation_failure=True,
    )

    with pytest.raises(ToolInvocationError) as exc:
        demo.run(agent, root)

    assert not isinstance(exc.value, dg_hs.AuthorityDeniedTool)
    assert isinstance(exc.value.__cause__, ZeroDivisionError), "the original cause was suppressed"
    # The call WAS authorized — the failure is the tool's, not the Guard's.
    assert [e["event"] for e in root.audit_log().entries] == ["root", "allow"]
