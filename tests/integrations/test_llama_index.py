"""
Integration test: delegation-guard x LlamaIndex agents (llama-index-core 0.14.23).

Runs entirely offline: the LLM is `llama_index.core.llms.MockFunctionCallingLLM`
driven by a scripted `response_generator` that emits `ToolCallBlock`s, so no API
key is needed.

What is asserted is the *user-felt* outcome, not the internals: a sub-agent that
was handed off narrow authority tries to exfiltrate, and the tool body is proven
never to have run (via the side-effect list the tool body would have appended to).

The test drives the SHIPPED example (`examples/integrations/llama_index/demo.py`
+ `delegation_guard.adapters.llama_index`), so a green run also proves the example works.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("llama_index.core")

from delegation_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    Guard,
    ReasonCode,
    RowLimit,
)

# --------------------------------------------------------------------------
# Load the example modules by path.
#
# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path — the
# example directory is itself named `llama_index`, and adding its parent would
# shadow the real framework package. Loading by file location with an explicit
# module name avoids that entirely.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = (
    Path(__file__).resolve().parents[2] / "examples" / "integrations" / "llama_index"
)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # so `demo` can `import dg_llama_index`
    spec.loader.exec_module(mod)
    return mod


import delegation_guard.adapters.llama_index as dg_li
demo = _load("demo")


# --------------------------------------------------------------------------
# One workflow run shared by the assertions below (it is deterministic).
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def story():
    return asyncio.run(demo.run_story())


@pytest.fixture(scope="module")
def greedy():
    return asyncio.run(demo.run_greedy_handoff())


@pytest.fixture(scope="module")
def ungranted():
    return asyncio.run(demo.run_ungranted_handoff())


# ---- (a) the in-authority call actually runs -----------------------------
def test_summarizer_query_within_authority_executes(story):
    assert "crm_query" in story.executed, (
        "the delegated, in-authority tool body must actually run; "
        f"executed={story.executed}"
    )
    call = story.call("crm_query")
    assert call.tool_output.is_error is False
    assert "4200" in call.tool_output.content


# ---- (b) the poisoned step is blocked BEFORE the tool body ---------------
def test_poisoned_export_never_reaches_the_tool_body(story):
    # The user-felt symptom: no exfiltration happened. The tool body appends to
    # demo.EXECUTED as its first statement, so its absence proves the body never
    # ran — not merely that the result was discarded.
    assert "crm_export" not in story.executed, (
        "crm_export must be denied BEFORE its body runs; " f"executed={story.executed}"
    )

    call = story.call("crm_export")
    assert call.tool_output.is_error is True, "denial must surface as a tool error"
    exc = call.tool_output.exception
    assert isinstance(exc, AuthorityDenied), f"expected AuthorityDenied, got {exc!r}"
    codes = {r.code for r in exc.decision.reasons}
    assert ReasonCode.SCOPE_NOT_GRANTED in codes
    assert ReasonCode.CEILING_EXCEEDED in codes  # EgressRank("none") vs egress="any"


def test_orchestrator_broad_authority_is_not_inherited_by_the_child(story):
    # The orchestrator holds crm.* and could export; the summarizer cannot.
    orch = story.guards["orchestrator"]
    summ = story.guards["summarizer"]
    assert orch.would_allow("crm.export", context={"egress": "any"})
    assert not summ.would_allow("crm.export", context={"egress": "any"})


# ---- structural: the child can only ever shrink --------------------------
def test_child_authority_is_narrower_than_parent(story):
    child = story.guards["summarizer"]
    parent = story.guards["orchestrator"]
    assert child.authority.is_narrower_than(parent.authority)
    assert not parent.authority.is_narrower_than(child.authority)


def test_handoff_cannot_mint_a_wider_child(greedy):
    """A handoff whose grant *requests* more than the parent holds is met down."""
    parent = greedy.guards["orchestrator"]
    child = greedy.guards["exfiltrator"]

    # requested: crm.*, mail.send, admin.delete / RowLimit(10_000_000) /
    # EgressRank("any") / ttl 999_999 — wider than the parent on every axis.
    assert child.authority.is_narrower_than(parent.authority)
    assert not child.authority.covers_scope("admin.delete")
    assert child.authority.ceiling("max_rows").max_rows == 100_000  # not 10M
    assert child.authority.ttl == 3600  # not 999_999


def test_the_met_down_grant_is_enforced_at_the_point_of_use(greedy):
    """Not just a narrower token: the framework actually refuses the calls."""
    assert greedy.executed == ["crm_query"], (
        "only the within-parent read may run; " f"executed={greedy.executed}"
    )

    within = greedy.call("crm_query", occurrence=0)  # 90_000 <= parent's 100_000
    assert within.tool_output.is_error is False

    over = greedy.call("crm_query", occurrence=1)  # 500_000, grant asked for 10M
    assert over.tool_output.is_error is True
    assert {r.code for r in over.tool_output.exception.decision.reasons} == {
        ReasonCode.CEILING_EXCEEDED
    }

    purge = greedy.call("admin_purge")  # grant asked for admin.delete
    assert purge.tool_output.is_error is True
    assert {r.code for r in purge.tool_output.exception.decision.reasons} == {
        ReasonCode.SCOPE_NOT_GRANTED
    }


def test_handoff_without_a_grant_is_refused_and_control_stays_put(ungranted):
    """`can_handoff_to` allows the route; delegation-guard refuses it because
    no Authority was written for the target — and clearing `next_agent` keeps
    control with the sender instead of handing it to an unguarded agent."""
    assert sorted(ungranted.guards) == ["orchestrator"]
    # the target's tools never ran, so it never took a turn
    assert ungranted.executed == ["send_mail"], (
        "the shadow agent must never have executed anything; "
        f"executed={ungranted.executed}"
    )
    assert "refused" in ungranted.call("handoff").tool_output.content


# ---- (c) cascade revocation -----------------------------------------------
def test_revocation_denies_every_later_tool_call(story):
    assert story.revoked, "the summarizer node must have been revoked"
    # after revocation the same in-authority call that succeeded before is denied
    assert story.executed.count("crm_query") == 1, (
        "the post-revocation crm_query body must NOT have run; "
        f"executed={story.executed}"
    )
    call = story.call("crm_query", occurrence=1)  # the second crm_query call
    assert call.tool_output.is_error is True
    exc = call.tool_output.exception
    assert isinstance(exc, AuthorityDenied)
    assert {r.code for r in exc.decision.reasons} == {ReasonCode.REVOKED}


# ---- (d) tamper-evident audit trail ---------------------------------------
def test_audit_log_verifies_and_records_the_denial(story):
    ok, err = AuditLog.verify(story.audit)
    assert ok, f"audit chain failed to verify: {err}"

    denies = [e for e in story.audit if e["event"] == "deny"]
    assert any(
        e.get("tool") == "crm_export"
        and e.get("reason") == ReasonCode.SCOPE_NOT_GRANTED
        for e in denies
    ), f"no scope denial for crm_export in {denies}"
    assert any(
        e.get("tool") == "crm_query" and e.get("reason") == ReasonCode.REVOKED
        for e in denies
    ), f"no revocation denial for crm_query in {denies}"

    # the delegation itself is on the record, with requested vs granted
    spawns = [e for e in story.audit if e["event"] == "spawn"]
    assert len(spawns) == 1
    assert spawns[0]["agent"] == "summarizer"
    assert spawns[0]["requested"]["ttl"] == 900
    assert sorted(spawns[0]["granted"]["scopes"]) == ["crm.read"]


def test_tampering_with_the_audit_log_is_detected(story):
    forged = [dict(e) for e in story.audit]
    victim = next(i for i, e in enumerate(forged) if e["event"] == "deny")
    forged[victim]["event"] = "allow"
    ok, err = AuditLog.verify(forged)
    assert not ok and err


def test_graph_shows_the_revoked_subtree(story):
    nodes = {n["agent"]: n for n in story.graph["nodes"]}
    assert nodes["orchestrator"]["revoked"] is False
    assert nodes["summarizer"]["revoked"] is True
    assert nodes["summarizer"]["parent"] == nodes["orchestrator"]["id"]


# ---- adapter-level unit checks (fail closed) ------------------------------
def test_unbound_agent_fails_closed():
    """A tool invoked by an agent with no Guard in the registry is denied,
    not silently allowed."""
    ran = []

    def touch() -> str:
        ran.append("touch")
        return "ok"

    tool = dg_li.guarded_tool(touch, scope="crm.read")

    class _FakeStore:
        def __init__(self, data):
            self._data = data

        async def get(self, key, default=None):
            return self._data.get(key, default)

        async def set(self, key, value):
            self._data[key] = value

    class _FakeCtx:
        # an agent holding the turn, but no run token / no Guards registered
        store = _FakeStore({"current_agent_name": "ghost"})

    with pytest.raises(AuthorityDenied) as exc:
        asyncio.run(tool.async_fn(ctx=_FakeCtx()))
    assert ran == []
    assert exc.value.decision.reasons[0].code == dg_li.NO_GUARD_BOUND


def test_guarded_tool_preserves_the_tool_contract():
    def crm_query(rows: int) -> str:
        """Query the CRM."""
        return f"{rows} rows"

    tool = dg_li.guarded_tool(crm_query, scope="crm.read")
    assert tool.metadata.name == "crm_query"
    assert "rows" in tool.metadata.fn_schema.model_fields
    assert tool.requires_context is True  # ctx is injected, not model-supplied
    assert "ctx" not in tool.metadata.fn_schema.model_fields


@pytest.mark.parametrize("as_tool", [False, True])
def test_guarded_tool_wraps_callables_and_existing_tools_alike(as_tool):
    """`guarded_tool` accepts a plain callable or an already-built BaseTool."""
    from llama_index.core.tools import FunctionTool

    ran = []

    def crm_query(rows: int) -> str:
        """Query the CRM."""
        ran.append(rows)
        return f"{rows} rows"

    target = FunctionTool.from_defaults(fn=crm_query) if as_tool else crm_query
    tool = dg_li.guarded_tool(
        target, scope="crm.read", context=lambda kw: {"rows": kw["rows"]}
    )

    guard = Guard.issue(
        "agent",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=60),
        task="t",
    )

    class _Store:
        def __init__(self):
            self._d = {"current_agent_name": "agent"}

        async def get(self, key, default=None):
            return self._d.get(key, default)

        async def set(self, key, value):
            self._d[key] = value

    class _Ctx:
        store = _Store()

    asyncio.run(dg_li.attach_guards(_Ctx(), {"agent": guard}))
    ctx = _Ctx()
    ctx.store = _Ctx.store  # same store -> same run token

    assert asyncio.run(tool.async_fn(ctx=ctx, rows=100)) == "100 rows"
    assert ran == [100]

    with pytest.raises(AuthorityDenied):
        asyncio.run(tool.async_fn(ctx=ctx, rows=99_999))
    assert ran == [100]  # the body did not run the second time


def test_guarded_tool_wraps_a_non_function_basetool():
    """The generic `BaseTool` path (query-engine tools, tool specs, ...)."""
    from llama_index.core.tools import AsyncBaseTool, ToolMetadata, ToolOutput

    ran = []

    class _Echo(AsyncBaseTool):
        @property
        def metadata(self):
            return ToolMetadata(name="echo", description="Echo.", fn_schema=None)

        def call(self, **kwargs):
            ran.append(kwargs)
            return ToolOutput(
                tool_name="echo",
                content=str(kwargs),
                raw_input=kwargs,
                raw_output=str(kwargs),
            )

        async def acall(self, **kwargs):
            return self.call(**kwargs)

        def __call__(self, *args, **kwargs):
            return self.call(**kwargs)

    tool = dg_li.guarded_tool(_Echo(), scope="crm.export")
    assert tool.metadata.name == "echo"

    guard = Guard.issue(
        "agent", Authority(scopes={"crm.read"}, ttl=60), task="t"
    )  # no crm.export

    class _Store:
        def __init__(self):
            self._d = {"current_agent_name": "agent"}

        async def get(self, key, default=None):
            return self._d.get(key, default)

        async def set(self, key, value):
            self._d[key] = value

    class _Ctx:
        store = _Store()

    asyncio.run(dg_li.attach_guards(_Ctx(), {"agent": guard}))
    with pytest.raises(AuthorityDenied):
        asyncio.run(tool.async_fn(ctx=_Ctx(), value=1))
    assert ran == []


def test_delegation_is_refused_when_the_parent_is_revoked():
    """Structural failure at handoff time must not hand the child any authority."""
    root = Guard.issue(
        "orchestrator",
        Authority(scopes={"crm.*"}, ceilings=[RowLimit(100)], ttl=60),
        task="root",
    )
    root.revoke()
    with pytest.raises(Exception):
        root.delegate("child", Authority(scopes={"crm.read"}, ttl=10), task="t")
