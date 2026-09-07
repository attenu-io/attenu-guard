"""tests/test_ledger_completeness.py — two things that happen must leave a record. stdlib only.

Both were found by real runs against an open-source agent (open-swe, 2026-09):

  B1  an unlisted tool call passed through under `allow_unlisted=True` ran and left NOTHING on the
      audit trail. A passthrough is a thing that happened; the ledger has to say so, and it has to
      say it WITHOUT claiming the chain authorized it (an `allow` under a scope the node does not
      hold would be a containment failure, and a lie). `Guard.record_passthrough()` writes an
      `allow` marked `policy="unlisted"`; the bundle verifier counts those as UNGATED rather than
      checking them for containment, and reports the count.

  B2  a refused delegation ("this sub-agent has no declared Authority") went straight back to the
      model with no ledger entry at all. A refusal is a deny.

Run: PYTHONPATH=src python3 tests/test_ledger_completeness.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attenu_guard import Authority, Guard, Reason  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402
from attenu_guard.evidence import LEDGER_FIELDS, export_bundle, verify_bundle  # noqa: E402
from attenu_guard.reasons import Capture, Disposition, Policy, ReasonCode  # noqa: E402

ADAPTERS = ROOT / "src" / "attenu_guard" / "adapters"
MIRRORED = ("langchain", "openhands", "astrbot")


def _root(**kw):
    return Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600), **kw)


def _events(guard):
    return [(e["event"], e.get("tool"), e.get("policy"), e.get("reason")) for e in guard.audit_log().entries]


class RecordPassthrough(unittest.TestCase):
    def test_passthrough_writes_an_allow_marked_unlisted(self):
        g = _root()
        d = g.record_passthrough("integration_push_unmapped")
        self.assertTrue(d)
        entry = g.audit_log().entries[-1]
        self.assertEqual(entry["event"], "allow")
        self.assertEqual(entry["policy"], Policy.UNLISTED)
        self.assertEqual(entry["tool"], "integration_push_unmapped")

    def test_policy_is_a_published_ledger_field(self):
        self.assertIn("policy", LEDGER_FIELDS)

    def test_v2_passthrough_is_pre_hook_only_and_never_pends_completion(self):
        g = _root(schema_version=2)
        d = g.record_passthrough("integration_push_unmapped")
        entry = g.audit_log().entries[-1]
        self.assertEqual(entry["capture"], Capture.PRE_HOOK_ONLY)
        self.assertEqual(entry["adapter"]["hook_path"], "Guard.record_passthrough")
        self.assertIsNotNone(d.call_id)
        self.assertTrue(g.complete(), "a passthrough must never leave the node awaiting an outcome")

    def test_bundle_verifies_and_reports_the_passthrough_as_ungated(self):
        g = _root()
        g.check("repo.read", tool="read_file")
        g.record_passthrough("integration_push_unmapped")
        signer = HS256TestSigner(secret=b"k", kid="k")
        report = verify_bundle(export_bundle(g.audit_log(), signer, strict=True), signer)
        self.assertTrue(report["ok"])
        self.assertTrue(report["checks"]["containment"])
        self.assertEqual(report["actions_checked"], 1)
        self.assertEqual(report["ungated"], 1)


class RefusedDelegationIsADeny(unittest.TestCase):
    def test_reason_code_is_named(self):
        self.assertEqual(ReasonCode.DELEGATION_REFUSED, "delegation_refused")

    def test_record_denial_puts_a_refusal_on_the_trail(self):
        g = _root()
        d = g.record_denial(Reason(ReasonCode.DELEGATION_REFUSED, requested="planner"),
                            tool="task", disposition=Disposition.UNRESOLVED)
        self.assertFalse(d)
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"]), ("deny", "delegation_refused"))


class AdapterSourceContract(unittest.TestCase):
    """The three adapters that share this gate logic must all be fixed, not just the one the bug
    was found in. Source-text, because langchain/openhands/astrbot are not installed in the
    stdlib CI job (same rationale as tests/test_adapters_contract.py)."""

    def test_allow_unlisted_records_a_passthrough(self):
        bad = []
        for name in MIRRORED:
            src = (ADAPTERS / f"{name}.py").read_text()
            block = re.search(r"if self\.allow_unlisted:\n(.*?return self\._Gate\(\))", src, re.S)
            self.assertIsNotNone(block, f"{name}: no allow_unlisted branch found")
            if "record_passthrough(" not in block.group(1):
                bad.append(f"{name}: an allow_unlisted passthrough leaves nothing on the ledger")
        self.assertEqual(bad, [])

    def test_refused_delegation_is_recorded(self):
        bad = []
        for name in MIRRORED:
            src = (ADAPTERS / f"{name}.py").read_text()
            block = src[src.index("def _gate_delegation"):]
            block = block[:block.index("\n    def ", 1)]
            if "record_denial(" not in block:
                bad.append(f"{name}: a refused delegation never reaches the ledger")
            if "ReasonCode.DELEGATION_REFUSED" not in block:
                bad.append(f"{name}: refusal reason is not the named ReasonCode constant")
        self.assertEqual(bad, [])


class AdapterBehaviour(unittest.TestCase):
    """openhands and astrbot import nothing from their frameworks, so their gate can be driven
    directly here. The langchain adapter needs langchain_core installed and is exercised in the
    pinned `integrations` CI job (tests/integrations/test_langgraph.py)."""

    def _openhands(self, **kw):
        from attenu_guard.adapters import openhands as oh
        g = _root()
        return g, oh.GuardedDelegation(g, tools={}, **kw)

    def _astrbot(self, **kw):
        from attenu_guard.adapters import astrbot as ab
        g = _root()
        return g, ab.GuardedDelegation(g, tools={}, **kw)

    def test_openhands_unlisted_passthrough_is_ledgered(self):
        g, gd = self._openhands(allow_unlisted=True)
        gate = gd._gate("integration_push_unmapped", {})
        self.assertIsNone(gate.denial)
        self.assertEqual(_events(g)[-1],
                         ("allow", "integration_push_unmapped", Policy.UNLISTED, None))

    def test_astrbot_unlisted_passthrough_is_ledgered(self):
        g, gd = self._astrbot(allow_unlisted=True)
        gate = gd._gate("integration_push_unmapped", {}, None)
        self.assertIsNone(gate.denial)
        self.assertEqual(_events(g)[-1],
                         ("allow", "integration_push_unmapped", Policy.UNLISTED, None))

    def test_openhands_refused_delegation_is_ledgered(self):
        g, gd = self._openhands(subagents={"known": Authority(scopes={"repo.read"}, ttl=60)})
        gate = gd._gate("task", {"subagent_type": "planner"})
        self.assertIsNotNone(gate.denial)
        self.assertFalse(gate.denial)
        self.assertEqual(_events(g)[-1], ("deny", "task", None, "delegation_refused"))

    def test_astrbot_refused_delegation_is_ledgered(self):
        g, gd = self._astrbot(subagents={"known": Authority(scopes={"repo.read"}, ttl=60)})
        gate = gd._gate_delegation(g, "planner", "do a thing")
        self.assertIsNotNone(gate.denial)
        self.assertFalse(gate.denial)
        self.assertEqual(_events(g)[-1], ("deny", "planner", None, "delegation_refused"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
