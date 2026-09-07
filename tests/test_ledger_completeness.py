"""tests/test_ledger_completeness.py — two things that happen must leave a record. stdlib only.

Both were found by real runs against an open-source agent (open-swe, 2026-09):

  B1  an unlisted tool call passed through under `allow_unlisted=True` ran and left NOTHING on the
      audit trail. A passthrough is a thing that happened; the ledger has to say so, and it has to
      say it WITHOUT claiming the chain authorized it (an `allow` under a scope the node does not
      hold would be a containment failure, and a lie). `Guard.record_passthrough()` writes an
      `allow` marked `policy="unlisted"`; the bundle verifier counts those as UNGATED rather than
      checking them for containment, and reports the count.

  B3  a tool registered AFTER install() ran and never appeared on the ledger at all — the
      adapters guarded the tools they were handed, at the moment they were handed them, and
      nothing after. Both now cover the registration seam itself.

  B4  when the operator's context function raised, the body correctly never ran and NOTHING was
      written. Same class as B1/B2: a refusal must leave a record. Recorded as a `deny` with
      the existing `no_authority` reason (its vocabulary already covers an adapter-level
      refusal upstream of scope/ceiling evaluation) and `disposition=unresolved`.

  B5  the OpenHands gate keyed on the raw `subagent_type`, so the SDK's own aliases (`default`
      -> `general-purpose`) missed a declared sub-agent entirely. Resolved through the SDK's
      registry before minting.

  B2  a refused delegation ("this sub-agent has no declared Authority") went straight back to the
      model with no ledger entry at all. It is a `deny` now. Its sibling — a delegation the CHAIN
      refuses structurally (revoked/expired parent, depth/fanout) — was already recorded, once, as
      `spawn_denied`; that stays one entry and `denials()` folds it instead of the adapter writing
      a second. One decision, one entry.

Run: PYTHONPATH=src python3 tests/test_ledger_completeness.py
"""
import re
import sys
import types
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attenu_guard import Authority, AuthorityError, Guard, Reason  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402
from attenu_guard.evidence import (  # noqa: E402
    LEDGER_FIELDS, denials, export_bundle, verify_bundle,
)
from attenu_guard.reasons import Capture, Disposition, Policy, ReasonCode  # noqa: E402

ADAPTERS = ROOT / "src" / "attenu_guard" / "adapters"
MIRRORED = ("langchain", "openhands", "astrbot")


def _pkg(registry):
    """A stand-in parent package whose attribute lookup reaches the stub module."""
    pkg = types.ModuleType("pkg_stub")
    pkg.registry = registry
    return pkg


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

    def test_structural_refusal_is_recorded_exactly_once_and_folded(self):
        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600), max_depth=1)
        child = g.delegate("planner", Authority(scopes={"repo.read"}, ttl=60), task="plan")
        with self.assertRaises(AuthorityError):
            child.delegate("writer", Authority(scopes={"repo.read"}, ttl=30), task="write")
        events = [e["event"] for e in g.audit_log().entries]
        self.assertEqual(events.count("spawn_denied"), 1)
        self.assertEqual(events.count("deny"), 0, "a structural refusal must not be recorded twice")
        signer = HS256TestSigner(secret=b"k", kid="k")
        rows = denials(export_bundle(g.audit_log(), signer))
        self.assertEqual([(r["event"], r["requested"], r["node"], r["reason"]) for r in rows],
                         [("spawn_denied", "writer", child.node_id, "max_depth")])

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
            # ... and exactly one: the AuthorityError branch must NOT write a second entry beside
            # the `spawn_denied` Guard.delegate() already wrote. One decision, one entry.
            if block.count("record_denial(") != 1:
                bad.append(f"{name}: {block.count('record_denial(')} record_denial calls in "
                           f"_gate_delegation; a structurally refused delegation is already "
                           f"recorded as spawn_denied")
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


class GateErrorIsRecorded(unittest.TestCase):
    """B4. The refusal is correct; its invisibility was the defect."""

    def _boom(self, *_a, **_k):
        raise RuntimeError("approval store unreachable")

    def test_openhands_gate_error_is_a_deny_on_the_ledger(self):
        from attenu_guard.adapters import openhands as oh
        g = _root()
        gd = oh.GuardedDelegation(g, tools={"push": oh.ToolPolicy("repo.read", self._boom)})
        gate = gd._gate("push", {"command": "git push"})
        self.assertIsNotNone(gate.denial)
        self.assertFalse(gate.denial)
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"], entry["tool"], entry["disposition"]),
                         ("deny", ReasonCode.NO_AUTHORITY, "push", Disposition.UNRESOLVED))
        self.assertEqual(entry["scope"], "repo.read")

    def test_astrbot_gate_error_is_a_deny_on_the_ledger(self):
        from attenu_guard.adapters import astrbot as ab
        g = _root()
        gd = ab.GuardedDelegation(g, tools={"push": ab.ToolPolicy("repo.read", self._boom)})
        gate = gd._gate("push", {"command": "git push"}, None)
        self.assertIsNotNone(gate.denial)
        self.assertFalse(gate.denial)
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"], entry["tool"], entry["disposition"]),
                         ("deny", ReasonCode.NO_AUTHORITY, "push", Disposition.UNRESOLVED))

    def test_a_gate_error_never_runs_the_body(self):
        from attenu_guard.adapters import openhands as oh
        g = _root()
        gd = oh.GuardedDelegation(g, tools={"push": oh.ToolPolicy("repo.read", self._boom)},
                                  on_deny="tool_error")
        ran = []
        # The OpenHands adapter surfaces a denial as ValueError, which the SDK's
        # `Agent._execute_action_event` turns into an AgentErrorEvent for the model.
        with self.assertRaises(ValueError):
            gd.call("push", _Action({"command": "git push"}), lambda: ran.append(1))
        self.assertEqual(ran, [], "the body ran despite the gate failing")
        self.assertEqual(g.audit_log().entries[-1]["event"], "deny")


class _Action:
    """The shape `_action_args` reads: any object whose fields are the tool call's arguments."""

    def __init__(self, args):
        for k, v in args.items():
            setattr(self, k, v)


class LateRegistrationIsCovered(unittest.TestCase):
    """B3. A tool registered after install() must be gated on the node that runs it."""

    def test_openhands_arms_the_registration_seam_and_restores_it(self):
        from attenu_guard.adapters import openhands as oh
        registry = types.ModuleType("registry_stub")
        registry._REG = {"early": lambda params, conv: ["early-tool"]}
        g = _root()
        gd = oh.GuardedDelegation(g, tools={})
        with mock.patch.dict(sys.modules, {"openhands.sdk.tool.registry": registry,
                                           "openhands.sdk.tool": _pkg(registry)}):
            with self.assertRaises(AssertionError):
                # RED marker: without arming, a late registration is a plain resolver.
                self._assert_guarded(registry._REG["early"], gd)
            with gd._lock:
                gd._arm_registry()
            self._assert_guarded(registry._REG["early"], gd)      # existing entries covered

            registry._REG["late"] = lambda params, conv: ["late-tool"]   # register_tool() writes here
            self._assert_guarded(registry._REG["late"], gd)       # ... and so are later ones

            gd.uninstall()
        self.assertNotIsInstance(registry._REG, oh._GuardingRegistry)
        self.assertEqual(sorted(registry._REG), ["early", "late"])
        for resolver in registry._REG.values():
            self.assertIsNone(getattr(resolver, "_attenu_guarded_by", None),
                              "uninstall() left a reference to the Guard behind")

    def _assert_guarded(self, resolver, gd):
        self.assertIs(getattr(resolver, "_attenu_guarded_by", None), gd)

    def test_astrbot_install_is_a_re_runnable_sweep_and_patches_nothing(self):
        # AstrBot's late-registration gap is NOT closed automatically, and that is a measured
        # decision, not an oversight: the seam that closes it may trade a denial for a
        # passthrough on the MCP-alias case, which cannot currently be settled because that case
        # is itself flaky on unpatched code (see install()'s docstring). What is pinned here is the
        # documented workaround — install() is a re-runnable sweep — and that the adapter leaves
        # the manager's own methods alone, which is what the rejected seam did not.
        from attenu_guard.adapters import astrbot as ab
        gd = ab.GuardedDelegation(_root(), tools={})
        mgr = _Manager([_Tool("early")])
        swept = []
        gd._sweep = lambda manager: swept.append(manager) or []
        gd.install(mgr)
        mgr.func_list.append(_Tool("late_plugin"))
        gd.install(mgr)                                   # the workaround: sweep again
        self.assertEqual(swept, [mgr, mgr])
        for method in ("add_func", "get_func", "get_full_tool_set"):
            self.assertNotIn(method, mgr.__dict__,
                             f"install() patched {method} on the manager instance")

    def test_astrbot_install_documents_the_gap_it_leaves_open(self):
        src = (ADAPTERS / "astrbot.py").read_text()
        block = src[src.index("def install"):src.index("def _sweep")]
        self.assertIn("H12", block, "install() does not name the gap it leaves open")
        self.assertIn("install()` again", block, "install() does not give the workaround")


class _Tool:
    def __init__(self, name):
        self.name = name
        self.active = True


class _Manager:
    """The two methods an AstrBot agent gets its tools through, over a plain list."""

    def __init__(self, tools):
        self.func_list = list(tools)

    def add_func(self, name):
        self.func_list.append(_Tool(name))

    def get_func(self, name):
        return next((t for t in self.func_list if t.name == name), None)

    def get_full_tool_set(self):
        return list(self.func_list)


class SubagentAliasIsResolved(unittest.TestCase):
    """B5. `default` is the SDK's alias for `general-purpose`; the declared name covers it."""

    def _gd(self, g):
        from attenu_guard.adapters import openhands as oh
        return oh.GuardedDelegation(
            g, tools={}, subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=60)})

    def _sdk(self, mapping):
        registry = types.ModuleType("subagent_registry_stub")

        def get_agent_factory(name):
            canonical = mapping.get(name, name)
            if canonical not in mapping.values():
                raise ValueError(f"no agent factory {name!r}")
            return types.SimpleNamespace(definition=types.SimpleNamespace(name=canonical))

        registry.get_agent_factory = get_agent_factory
        return {"openhands.sdk.subagent.registry": registry,
                "openhands.sdk.subagent": _pkg(registry)}

    def test_the_alias_mints_the_declared_subagent_under_its_canonical_name(self):
        g = _root()
        gd = self._gd(g)
        with mock.patch.dict(sys.modules, self._sdk({"default": "general-purpose",
                                                     "general-purpose": "general-purpose"})):
            gate = gd._gate_delegation(g, {"subagent_type": "default", "prompt": "go"})
        self.assertIsNone(gate.denial, "the SDK alias was refused for a declared sub-agent")
        self.assertIsNotNone(gate.child)
        spawn = g.audit_log().entries[-1]
        self.assertEqual((spawn["event"], spawn["agent"]), ("spawn", "general-purpose"))
        self.assertIn("requested as 'default'", spawn["task"])

    def test_an_omitted_selector_is_still_refused_not_resolved_to_the_default(self):
        g = _root()
        gd = self._gd(g)
        with mock.patch.dict(sys.modules, self._sdk({"default": "general-purpose",
                                                     "general-purpose": "general-purpose"})):
            gate = gd._gate_delegation(g, {"prompt": "go"})
        self.assertFalse(gate.denial)
        self.assertEqual(g.audit_log().entries[-1]["reason"], ReasonCode.DELEGATION_REFUSED)

    def test_an_unknown_name_is_refused_unchanged(self):
        g = _root()
        gd = self._gd(g)
        with mock.patch.dict(sys.modules, self._sdk({"general-purpose": "general-purpose"})):
            gate = gd._gate_delegation(g, {"subagent_type": "nope", "prompt": "go"})
        self.assertFalse(gate.denial)
        self.assertEqual(g.audit_log().entries[-1]["reason"], ReasonCode.DELEGATION_REFUSED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
