"""The gate for the LangChain subagent-middleware recipe
(examples/integrations/langgraph/subagent_middleware/).

Two tiers: COMPATIBILITY (imports, the LangChain/deepagents API we touch) and SEMANTIC (the
upstream behaviour the story relies on, pinned to versions and a named code path). Then the
side-effect oracle, the bypass cases, and the injection case.
"""
from __future__ import annotations

import copy
import importlib.metadata
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

pytest.importorskip("langchain")
pytest.importorskip("deepagents")

from langchain_core.tools import tool  # noqa: E402

from attenu_guard import AuditLog, Guard, evidence  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

PINNED = {
    "packages": {"langchain": "1.3.17", "langchain-core": "1.6.0",
                 "langgraph": "1.2.11", "deepagents": "0.7.6"},
    "issue": "langchain-ai/langchain#33879 'Add subagent middleware' — open, filed 2025-11-07 "
             "by a LangChain maintainer; PR #33484 closed unmerged, PR #39019 open as a draft",
    "paths": {
        "core": "langchain/agents/middleware/ — no subagent module on 1.3.17",
        "subagents": "deepagents/middleware/subagents.py :: _build_task_tool._compile_spec -> "
                     "create_sub_agent(spec) (the subagent's tools come from its own spec)",
    },
    "verified": "2026-08-25",
}

_DEMO = (Path(__file__).resolve().parents[2] / "examples" / "integrations" / "langgraph"
         / "subagent_middleware" / "demo.py")
_spec = importlib.util.spec_from_file_location("attenu_langgraph_subagent_middleware_demo", _DEMO)
sm = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(sm)  # type: ignore[union-attr]

SEARCH_CTX = {"egress": "internal", "rows": 10}


# ---- tier 1: compatibility -------------------------------------------------------------------------------
def test_compat_packages_importable_and_versions_known():
    for pkg, pinned in PINNED["packages"].items():
        v = importlib.metadata.version(pkg)
        assert v, f"{pkg} not installed"
        print(f"{pkg} {v} (pinned story: {pinned})")


def test_compat_subagent_middleware_exposes_the_task_tool_we_hook():
    """The delegation hook keys on a tool named `task` with (description, subagent_type)."""
    from deepagents.backends import StateBackend
    from deepagents.middleware import SubAgentMiddleware

    mw = SubAgentMiddleware(backend=StateBackend(), subagents=[
        {"name": "writer", "description": "Writes.", "system_prompt": "Write.",
         "model": sm.ScriptedModel(responses=[]), "tools": []}])
    names = [t.name for t in mw.tools]
    assert names == ["task"], f"deepagents no longer exposes a single `task` tool: {names}"
    fields = set(mw.tools[0].args_schema.model_fields)
    assert {"description", "subagent_type"} <= fields, (
        f"the task tool's arguments changed to {fields} — GuardedDelegation(subagent_arg=..., "
        "task_arg=...) needs re-pointing")


def test_compat_guard_middleware_is_an_agent_middleware():
    from langchain.agents.middleware import AgentMiddleware

    _root, guarded = sm.new_chain()
    mw = guarded.middleware()
    assert isinstance(mw, AgentMiddleware)
    assert sm.is_guard_middleware(mw)


# ---- tier 2: semantic freshness --------------------------------------------------------------------------
def test_semantic_core_still_has_no_subagent_middleware():
    import langchain.agents.middleware as lcm

    hits = [n for n in dir(lcm) if "subagent" in n.lower()]
    assert not hits, (
        f"PREMISE CHANGED: langchain {importlib.metadata.version('langchain')} now exposes {hits} from "
        f"langchain.agents.middleware — #33879 appears resolved; re-point this recipe at the shipped "
        f"middleware and retire the 'the pattern lives in deepagents' framing. Pinned: {PINNED}")


def test_semantic_subagent_tools_are_not_constrained_to_the_parents():
    """The unguarded control: the supervisor holds only `write_brief`, the `writer` subagent's
    spec also lists `web_search`, and the subagent's search body runs."""
    _out, sink = sm.run_unguarded()
    ran = [name for name, _ in sink]
    assert "web_search" in ran, (
        f"PREMISE CHANGED: deepagents {importlib.metadata.version('deepagents')} appears to constrain a "
        f"subagent's tools to the parent's — the unguarded control no longer runs the subagent's search, "
        f"so step 1 of the story retires (steps 2-3 still hold). Path: {PINNED['paths']['subagents']}")
    assert sink, "the unguarded control lost its side-effect oracle"


# ---- the side-effect oracle ------------------------------------------------------------------------------
def test_side_effect_oracle_denied_search_left_no_trace(tmp_path):
    _out, sink, root, guarded = sm.run_guarded(audit_path=tmp_path / "audit.jsonl")
    assert ("web_search", sm.ATTACKER_QUERY) not in sink, f"denied search still executed: {sink}"
    assert sink == [("web_search", "q3 market outlook"), ("write_brief", "Q3 brief.")]
    denied = [e for e in root.audit_log().entries
              if e["event"] == "deny" and e.get("tool") == "web_search"]
    assert len(denied) == 1 and denied[0]["reason"] == "scope_not_granted", denied
    assert AuditLog.verify(root.audit_log().entries)[0]


def test_authority_is_monotonic_down_the_chain(tmp_path):
    _out, _sink, root, guarded = sm.run_guarded(audit_path=tmp_path / "a.jsonl")
    researcher, writer = guarded.child("researcher"), guarded.child("writer")
    assert researcher.is_narrower_than(root) and writer.is_narrower_than(root)
    assert bool(researcher.would_allow("web.search", context=SEARCH_CTX))
    assert not writer.would_allow("web.search", context=SEARCH_CTX)
    assert bool(writer.would_allow("brief.write", context={"egress": "none"}))


def test_over_broad_request_is_met_down_not_granted(tmp_path):
    """`researcher` asks for web.*, admin.export, 10,000 rows and a 9,999s ttl."""
    _out, _sink, root, guarded = sm.run_guarded(audit_path=tmp_path / "b.jsonl")
    researcher = guarded.child("researcher")
    assert researcher.authority.scopes == {"web.search"}
    assert researcher.authority.ceiling("max_rows").max_rows == 50
    assert researcher.authority.ttl <= root.authority.ttl
    assert not researcher.would_allow("admin.export")


# ---- injection -------------------------------------------------------------------------------------------
def test_injection_scripted_model_obeys_the_planted_note_and_is_denied(tmp_path):
    """The writer is handed a note that tells it to search; the scripted model 'decides' to obey."""
    _out, sink, root, _guarded = sm.run_guarded(audit_path=tmp_path / "c.jsonl")
    attempted = [e for e in root.audit_log().entries if e.get("tool") == "web_search"]
    assert any(e["event"] == "deny" for e in attempted), attempted
    assert all(q != sm.ATTACKER_QUERY for _name, q in sink), sink


# ---- bypass cases (red team) -----------------------------------------------------------------------------
def test_bypass_undeclared_alternate_tool_is_denied_by_default(tmp_path):
    shadow: list = []

    @tool
    def web_fetch(url: str) -> str:
        """A second way out to the network the operator never declared."""
        shadow.append(("web_fetch", url))
        return "fetched"

    _out, sink, root, _guarded = sm.run_guarded(
        audit_path=tmp_path / "d.jsonl", extra_tools=[web_fetch],
        subagent_tools=("web_search", "write_brief", "web_fetch"), search_tool="web_fetch")
    assert shadow == [], f"undeclared tool executed: {shadow}"
    assert ("web_fetch", sm.ATTACKER_QUERY) not in sink
    denied = [e for e in root.audit_log().entries
              if e["event"] == "deny" and e.get("tool") == "web_fetch"]
    assert len(denied) == 1 and denied[0]["reason"] == "no_authority", denied


def test_bypass_retries_stay_denied_and_each_attempt_is_on_the_ledger(tmp_path):
    _out, sink, root, _guarded = sm.run_guarded(audit_path=tmp_path / "e.jsonl", search_attempts=3)
    assert all(q != sm.ATTACKER_QUERY for _name, q in sink), sink
    denied = [e for e in root.audit_log().entries
              if e["event"] == "deny" and e.get("tool") == "web_search"]
    assert len(denied) == 3, f"expected 3 denials on the ledger, got {len(denied)}"


def test_bypass_guard_absent_refuses_to_run():
    with pytest.raises(RuntimeError, match="refusing to run unguarded"):
        sm.require_guard([object()], [])


def test_bypass_ungated_subagent_spec_refuses_to_run():
    """A subagent runs its own loop: a spec without the middleware is a hole, not a narrowing."""
    sink: list = []
    _root, guarded = sm.new_chain()
    with pytest.raises(RuntimeError, match="subagent 'writer' has no delegation guard"):
        sm.build_agent(sink, guarded=guarded, guard_subagents=("researcher",))


def test_bypass_ungated_subagent_actually_runs_when_the_check_is_skipped():
    """The boundary, proven: skip require_guard and the ungated subagent's tools are not mediated."""
    sink: list = []
    _root, guarded = sm.new_chain()
    agent, _ = sm.build_agent(sink, guarded=guarded, guard_subagents=("researcher",), check=False)
    agent.invoke({"messages": [("user", "Prepare the Q3 research brief.")]})
    assert ("web_search", sm.ATTACKER_QUERY) in sink


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions")
def test_bypass_audit_write_failure_fails_closed(tmp_path):
    log = tmp_path / "f.jsonl"
    sink: list = []
    root = Guard.issue("supervisor", sm.SUPERVISOR, task="research brief", audit_path=log)
    from attenu_guard.adapters.langchain import GuardedDelegation

    guarded = GuardedDelegation(
        root, tools=sm.POLICIES,
        subagents={"researcher": sm.RESEARCHER_REQUEST, "writer": sm.WRITER_REQUEST})
    agent, _ = sm.build_agent(sink, guarded=guarded)
    log.chmod(stat.S_IRUSR)                                  # the ledger becomes unwritable mid-run
    try:
        agent.invoke({"messages": [("user", "Prepare the Q3 research brief.")]})
    except Exception:                                        # noqa: BLE001 — an error is an acceptable outcome
        pass
    finally:
        log.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert sink == [], f"tool body ran although the ledger could not be written: {sink}"


def test_bypass_direct_python_call_is_outside_the_boundary():
    """Documented, not prevented: the middleware mediates LangChain's tool dispatch, not arbitrary Python."""
    sink: list = []
    web_search, _write_brief = sm.make_tools(sink)
    web_search.invoke({"query": "direct"})
    assert sink == [("web_search", "direct")]


def test_bypass_tampered_bundle_fails_and_clean_bundle_passes(tmp_path):
    _out, _sink, root, _guarded = sm.run_guarded(audit_path=tmp_path / "g.jsonl")
    signer = HS256TestSigner(b"k", kid="t")
    bundle = evidence.export_bundle(root.audit_log(), signer)
    rep = evidence.verify_bundle(bundle, signer)
    assert rep["ok"] and all(rep["checks"].values()), rep

    bad = copy.deepcopy(bundle)
    deny = next(e for e in bad["entries"] if e["event"] == "deny")
    deny["event"] = "allow"                                  # rewrite the denial into an allow
    rep2 = evidence.verify_bundle(bad, signer)
    assert not rep2["ok"] and not rep2["checks"]["integrity"], json.dumps(rep2)[:300]
