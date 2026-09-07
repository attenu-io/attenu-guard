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

  B6  AstrBot rewrites an MCP tool's name (`push.record` -> `push_record`) and keeps the
      server's own on `mcp_tool.name`, which is what goes out on the wire. A policy declared
      under the published name bound to nothing and the call ran as an unlisted passthrough.
      Either spelling binds now, the published name is on the ledger entry's context, and a
      policy that binds to NO registered tool is said out loud at install time.

  B7  on the `Agent.tools is None` branch, AstrBot's own `_PermissionGuardedTool` wrapped
      OUTSIDE this adapter's gate, and it returns an error string before delegating — so a
      call AstrBot refused never reached the ledger. The nesting is inverted: our gate is
      outermost, every call is recorded, and AstrBot's refusal is a result rather than an
      erasure.

  B8  the OpenHands SDK has a SECOND delegation mechanism (`DelegateExecutor`). It was not a
      spawn seam, so no child node was minted and the sub-agent's calls landed on the parent's.
      Hooked now — and bound to the CONVERSATION, because the SDK runs each sub-agent in a
      plain thread, which inherits no contextvars.

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
import asyncio
import threading
import types
from types import SimpleNamespace
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attenu_guard import (  # noqa: E402
    Authority, AuthorityDenied, AuthorityError, Guard, Reason,
)
from attenu_guard.wire import HS256TestSigner  # noqa: E402
from attenu_guard.evidence import (  # noqa: E402
    LEDGER_FIELDS, denials, export_bundle, verify_bundle,
)
from attenu_guard.reasons import (  # noqa: E402
    BodyState, Capture, Disposition, Policy, ReasonCode,
)

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
            lines = (ADAPTERS / f"{name}.py").read_text().splitlines()
            starts = [i for i, l in enumerate(lines) if l.strip() == "if self.allow_unlisted:"]
            self.assertEqual(len(starts), 1, f"{name}: expected one allow_unlisted branch")
            i = starts[0]
            branch = []
            for line in lines[i + 1:]:                 # the branch runs to its own `return`
                branch.append(line)
                if "return self._Gate(" in line:
                    break
            if "record_passthrough(" not in "\n".join(branch):
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

    def test_astrbot_re_sweeps_on_every_route_that_hands_out_tools(self):
        # `GuardedTool` needs the real astrbot package to build its base class, which the stdlib
        # CI job does not install (the pinned `integrations` job and the AstrBot battery exercise
        # the wrapping itself). What is pinned here is the SEAM that was missing: both methods an
        # agent gets its tools through re-sweep the manager first, so a tool appended by
        # `add_func()`, or a `func_list` rebuilt wholesale by the MCP paths, is covered.
        from attenu_guard.adapters import astrbot as ab
        gd = ab.GuardedDelegation(_root(), tools={})
        mgr = _Manager([_Tool("early")])
        swept = []
        gd._sweep = lambda manager: swept.append(manager) or []
        gd.install(mgr)
        self.assertEqual(swept, [mgr], "install() did not sweep the manager")

        mgr.func_list.append(_Tool("late_plugin"))               # add_func()'s route
        mgr.func_list = [_Tool("late_mcp")]                      # the MCP rebuild, wholesale
        mgr.get_full_tool_set()
        mgr.get_func("late_mcp")
        self.assertEqual(swept, [mgr, mgr, mgr],
                         "a tool handed out after install() was never re-swept")

        gd.uninstall()
        self.assertIs(mgr.get_full_tool_set.__func__, _Manager.get_full_tool_set)
        self.assertIs(mgr.get_func.__func__, _Manager.get_func)
        mgr.get_full_tool_set()
        self.assertEqual(len(swept), 3, "uninstall() left the sweep armed")


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


class McpNameRewrite(unittest.TestCase):
    """B6. The name the operator saw is the name the server publishes; AstrBot exposes another."""

    def _gd(self, tools, **kw):
        from attenu_guard.adapters import astrbot as ab
        g = _root()
        return g, ab.GuardedDelegation(g, tools=tools, **kw)

    def test_a_policy_under_the_published_name_binds_to_the_exposed_tool(self):
        from attenu_guard.adapters import astrbot as ab
        g, gd = self._gd({"push.record": ab.ToolPolicy("repo.read")}, allow_unlisted=True)
        gate = gd._gate("push_record", {}, None, _McpTool("push_record", "push.record"))
        self.assertIsNone(gate.denial)
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["scope"]), ("allow", "repo.read"))
        self.assertIsNone(entry.get("policy"), "it bound, so it is not an unlisted passthrough")

    def test_the_ledger_carries_the_name_the_server_published(self):
        from attenu_guard.adapters import astrbot as ab
        g, gd = self._gd({"push.record": ab.ToolPolicy("repo.read")})
        gd._gate("push_record", {}, None, _McpTool("push_record", "push.record"))
        self.assertEqual(g.audit_log().entries[-1]["context"]["mcp_tool"], "push.record")

    def test_the_exposed_name_still_wins_when_both_are_declared(self):
        from attenu_guard.adapters import astrbot as ab
        g, gd = self._gd({"push.record": ab.ToolPolicy("repo.write"),
                          "push_record": ab.ToolPolicy("repo.read")})
        gd._gate("push_record", {}, None, _McpTool("push_record", "push.record"))
        self.assertEqual(g.audit_log().entries[-1]["scope"], "repo.read")

    def test_a_policy_that_binds_to_nothing_is_reported(self):
        from attenu_guard.adapters import astrbot as ab
        reported = []
        g, gd = self._gd({"push.record": ab.ToolPolicy("repo.read"),
                          "typo_tool": ab.ToolPolicy("repo.read")},
                         on_unbound=reported.append)
        gd._sweep = lambda manager: []
        gd.install(_Manager([_McpTool("push_record", "push.record")]))
        self.assertEqual(reported, [["typo_tool"]],
                         "an MCP policy under the published name is bound, a misspelling is not")


class _McpTool:
    """The shape that matters: an exposed `name`, and the server's own on `mcp_tool.name`."""

    def __init__(self, name, published):
        self.name = name
        self.active = True
        self.mcp_tool = types.SimpleNamespace(name=published)


class GuardIsOutermost(unittest.TestCase):
    """B7. A layer that can refuse must not sit outside the layer that records."""

    def test_the_full_toolset_branch_is_re_nested_with_our_gate_outside(self):
        from attenu_guard.adapters import astrbot as ab
        gd = ab.GuardedDelegation(_root(), tools={})
        raw = _Tool("secret_delete_all")
        ours = _FakeGuarded(raw)
        theirs = _PermissionLike(ours, None)             # AstrBot's, wrapping ours: the bug
        tool_set = types.SimpleNamespace(tools=[theirs, _Tool("plain")])

        with mock.patch.object(ab, "GuardedTool", _FakeGuarded):
            rebuilt = gd._reassert_outermost(tool_set, None)

        outer = rebuilt.tools[0]
        self.assertIsInstance(outer, _FakeGuarded, "our gate is not outermost")
        self.assertIsInstance(outer._wrapped, _PermissionLike, "AstrBot's check was dropped")
        # innermost: the witness that says whether AstrBot's check let the body run at all
        from attenu_guard.adapters import astrbot as ab_mod
        self.assertIsInstance(outer._wrapped._wrapped, ab_mod._BodyWitness)
        self.assertIs(outer._wrapped._wrapped.wrapped, raw, "the tool is double-guarded")
        self.assertIs(rebuilt.tools[1], tool_set.tools[1], "an unrecognised entry was touched")

    def test_the_named_tool_branch_is_left_alone(self):
        from attenu_guard.adapters import astrbot as ab
        gd = ab.GuardedDelegation(_root(), tools={})
        ours = _FakeGuarded(_Tool("secret_delete_all"))
        tool_set = types.SimpleNamespace(tools=[ours])
        with mock.patch.object(ab, "GuardedTool", _FakeGuarded):
            rebuilt = gd._reassert_outermost(tool_set, None)
        self.assertIs(rebuilt.tools[0], ours, "the get_func branch was re-wrapped")


class _FakeGuarded:
    """Stands in for `GuardedTool`, which needs the real astrbot package to build its base."""

    def __init__(self, tool, owner=None):
        self._wrapped = tool
        self.name = getattr(tool, "name", None)

    @property
    def wrapped(self):
        return self._wrapped


class _PermissionLike:
    """Stands in for AstrBot's `_PermissionGuardedTool`: same two-argument shape."""

    def __init__(self, tool, manager):
        self._wrapped = tool
        self._mgr = manager
        self.name = getattr(tool, "name", None)


class DelegateExecutorIsASeam(unittest.TestCase):
    """B8. The SDK's second delegation mechanism mints a child, and it reaches the thread."""

    def _gd(self, **kw):
        from attenu_guard.adapters import openhands as oh
        g = _root()
        return g, oh.GuardedDelegation(
            g, tools={"terminal": oh.ToolPolicy("repo.read")},
            subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=60)}, **kw)

    def _sdk(self):
        registry = types.ModuleType("subagent_registry_stub")
        registry.get_agent_factory = lambda name: types.SimpleNamespace(
            definition=types.SimpleNamespace(
                name="general-purpose" if name in ("default", "general-purpose") else name))
        return {"openhands.sdk.subagent.registry": registry,
                "openhands.sdk.subagent": _pkg(registry)}

    def test_a_spawned_subagent_gets_its_own_node_and_its_calls_land_there(self):
        g, gd = self._gd()
        inner = _FakeDelegateExecutor()
        ex = gd.delegate_executor(inner)
        with mock.patch.dict(sys.modules, self._sdk()):
            ex(_Spawn(ids=["worker"]), conversation="parent-conv")   # agent_types omitted
        spawn = g.audit_log().entries[-1]
        self.assertEqual((spawn["event"], spawn["agent"]), ("spawn", "general-purpose"))
        child_node = spawn["node"]

        # The SDK runs each sub-agent in a plain Thread, which inherits no contextvars. The
        # child's call must still land on the CHILD's node, not the parent's.
        seen = []
        sub = inner._sub_agents["worker"]
        thread = threading.Thread(
            target=lambda: seen.append(
                gd.call("terminal", _Action({"command": "ls"}), lambda: "ok", conversation=sub)))
        thread.start()
        thread.join()
        self.assertEqual(seen, ["ok"])
        allow = g.audit_log().entries[-1]
        self.assertEqual((allow["event"], allow["tool"]), ("allow", "terminal"))
        self.assertEqual(allow["node"], child_node,
                         "the delegated call was recorded on the parent's node")

    def test_an_undeclared_agent_type_is_refused_before_anything_is_created(self):
        g, gd = self._gd()
        inner = _FakeDelegateExecutor()
        ex = gd.delegate_executor(inner)
        with mock.patch.dict(sys.modules, self._sdk()):
            ex(_Spawn(ids=["worker"], agent_types=["code-explorer"]), conversation=None)
        self.assertEqual(inner.calls, [], "the SDK created a sub-agent for a refused type")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"], entry["tool"]),
                         ("deny", ReasonCode.DELEGATION_REFUSED, "delegate"))

    def test_close_finalizes_every_child_and_unbinds_it(self):
        g, gd = self._gd()
        inner = _FakeDelegateExecutor()
        ex = gd.delegate_executor(inner)
        with mock.patch.dict(sys.modules, self._sdk()):
            ex(_Spawn(ids=["worker"]), conversation=None)
        ex.close()
        self.assertEqual(g.audit_log().entries[-1]["event"], "done")
        self.assertEqual(gd._conversation_guards, {})


class _Spawn:
    def __init__(self, ids, agent_types=None, command="spawn"):
        self.ids = ids
        self.agent_types = agent_types
        self.command = command


class _FakeDelegateExecutor:
    """The SDK's `DelegateExecutor` surface this adapter actually touches."""

    def __init__(self):
        self._sub_agents = {}
        self.calls = []
        self.closed = False

    def __call__(self, action, conversation=None):
        self.calls.append(action)
        for agent_id in getattr(action, "ids", None) or []:
            self._sub_agents[agent_id] = types.SimpleNamespace(agent_id=agent_id)
        return types.SimpleNamespace(is_error=False)

    def close(self):
        self.closed = True


class GuardIsAnIdentity(unittest.TestCase):
    """B10. Copying a Guard must not fork the ledger — and must not crash the host."""

    def test_deepcopy_returns_the_same_guard_and_the_ledger_still_chains(self):
        import copy

        g = _root()
        holder = {"tool": g, "other": [1, 2, 3]}
        clone = copy.deepcopy(holder)                  # used to raise TypeError on itertools.count
        self.assertIs(clone["tool"], g)
        self.assertEqual(clone["other"], [1, 2, 3])
        self.assertIsNot(clone["other"], holder["other"], "deepcopy stopped copying everything")
        g.check("repo.read", tool="read_file")
        entries = g.audit_log().entries
        self.assertEqual([e["seq"] for e in entries], list(range(len(entries))))

    def test_copy_returns_the_same_guard(self):
        import copy

        g = _root()
        self.assertIs(copy.copy(g), g)


class AsyncNodeAuthorizesEagerly(unittest.TestCase):
    """B9. A guard whose enforcement depends on the caller awaiting is not a guard."""

    def _node(self, guard, scope="denied.scope"):
        from attenu_guard.adapters.langgraph import guard_node

        @guard_node(guard, scope)
        async def f():
            return "ran"

        return f

    def test_an_unawaited_denied_call_raises_and_is_recorded(self):
        g = Guard.issue("a", Authority(scopes=set(), ttl=60), chain_id="c", schema_version=2)
        f = self._node(g)
        with self.assertRaises(AuthorityDenied):
            f()                                        # NOT awaited: the check must still run
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"]), ("deny", "scope_not_granted"))

    def test_an_unawaited_allowed_call_still_writes_its_allow(self):
        g = Guard.issue("a", Authority(scopes={"repo.read"}, ttl=60), chain_id="c",
                        schema_version=2)
        f = self._node(g, "repo.read")
        coro = f()
        self.addCleanup(coro.close)
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["scope"]), ("allow", "repo.read"))
        self.assertEqual(entry["capture"], Capture.WRAPPER_ASYNC)

    def test_awaiting_still_binds_the_outcome(self):
        g = Guard.issue("a", Authority(scopes={"repo.read"}, ttl=60), chain_id="c",
                        schema_version=2)
        f = self._node(g, "repo.read")
        self.assertEqual(asyncio.run(f()), "ran")
        events = [e["event"] for e in g.audit_log().entries]
        self.assertEqual(events[-2:], ["allow", "outcome"])
        self.assertEqual(g.audit_log().entries[-1]["body_state"], BodyState.RETURNED)

    def test_v1_is_unchanged(self):
        g = Guard.issue("a", Authority(scopes=set(), ttl=60), chain_id="c")
        with self.assertRaises(AuthorityDenied):
            self._node(g)()
        self.assertEqual(g.audit_log().entries[-1]["event"], "deny")


class ContextFailureIsRecordedEverywhere(unittest.TestCase):
    """B4, across every adapter. One helper, so no adapter can forget."""

    #: adapters that call an operator context callable at gate time and route it through the
    #: shared helper. google_adk was missed on the first pass and is listed here so it cannot be
    #: missed again; it catches `AuthorityDenied` and hands ADK a denial dict, which is that
    #: framework's contract, but the LEDGER ROW is the helper's.
    ADAPTERS = ("a2a", "ag2", "agent_framework", "agno", "autogen", "camel", "claude_sdk",
                "crewai", "google_adk", "haystack", "langchain", "langgraph", "llama_index",
                "openai_agents", "pydantic_ai", "semantic_kernel", "smolagents")
    #: the two that record the same deny inline, in their own idiom, because they return a
    #: denial to the model rather than raising. They are held to the same OUTCOME, not the same
    #: mechanism — see GateErrorIsRecorded.
    OWN_IDIOM = ("openhands", "astrbot")

    def test_every_such_adapter_routes_its_context_call_through_the_helper(self):
        bad = []
        for name in self.ADAPTERS:
            src = (ADAPTERS / f"{name}.py").read_text()
            if "_safe_context(" not in src:
                bad.append(f"{name}: calls a context function without the shared guard")
            if "from ._context import" not in src:
                bad.append(f"{name}: does not import the shared helper")
        self.assertEqual(bad, [])

    def test_every_adapter_with_a_context_callable_is_accounted_for(self):
        # The gap this closes: google_adk called an operator context function and was on neither
        # list, so B4 simply was not applied there and nothing said so. Any adapter that calls a
        # context callable at gate time must be in one list or the other.
        unaccounted = []
        for path in sorted(ADAPTERS.glob("*.py")):
            name = path.stem
            if name.startswith("_") or name in self.ADAPTERS or name in self.OWN_IDIOM:
                continue
            src = path.read_text()
            if re.search(r"(?:policy\.)?context(?:_fn|_for)?\(", src):
                unaccounted.append(f"{name}: calls a context callable but is on neither list")
        self.assertEqual(unaccounted, [])

    def test_the_two_own_idiom_adapters_record_the_same_deny(self):
        for name in self.OWN_IDIOM:
            src = (ADAPTERS / f"{name}.py").read_text()
            self.assertIn('constraint="context"', src, f"{name}: no context-failure deny")
            self.assertIn("ReasonCode.NO_AUTHORITY", src, f"{name}: wrong reason")
            self.assertIn("Disposition.UNRESOLVED", src, f"{name}: wrong disposition")

    def test_no_adapter_calls_a_context_callable_bare(self):
        # The shapes the bug had: `policy.context(...)`, `context_fn(...)`, `.context_for(...)`
        # evaluated straight into `guard.check(...)`, with nothing catching a raise.
        bare = re.compile(r"context=(?:dict\()?(?:policy\.)?context(?:_fn|_for)?\(")
        offenders = []
        for path in sorted(ADAPTERS.glob("*.py")):
            if path.name.startswith("_"):
                continue
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if bare.search(line):
                    offenders.append(f"{path.name}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_the_helper_records_a_deny_and_raises(self):
        from attenu_guard.adapters import _context

        g = _root()

        def boom(_args):
            raise RuntimeError("approval store unreachable")

        with self.assertRaises(AuthorityDenied):
            _context.evaluate(g, boom, {"q": 1}, tool="push", scope="repo.read")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"], entry["tool"], entry["scope"],
                          entry["disposition"]),
                         ("deny", ReasonCode.NO_AUTHORITY, "push", "repo.read",
                          Disposition.UNRESOLVED))

    def test_the_helper_is_transparent_when_nothing_fails(self):
        from attenu_guard.adapters import _context

        g = _root()
        self.assertEqual(_context.evaluate(g, None), {})
        self.assertEqual(_context.evaluate(g, {"rows": 5}), {"rows": 5})   # a literal mapping
        self.assertEqual(_context.evaluate(g, lambda a: {"rows": a["n"]}, {"n": 7}), {"rows": 7})
        self.assertEqual(len(g.audit_log().entries), 1, "a working context function wrote a row")


class SmolagentsParity(unittest.TestCase):
    """B11 and B12. Source-text: smolagents is not installed in the stdlib CI job."""

    def test_install_exists_and_records_undeclared_tools(self):
        src = (ADAPTERS / "smolagents.py").read_text()
        self.assertIn("def install(", src, "smolagents has no installer")
        block = src[src.index("class _UnlistedTool"):src.index("class DelegatedAgent")]
        self.assertIn("record_passthrough(", block,
                      "an undeclared smolagents tool still leaves no ledger entry")
        self.assertIn("allow_unlisted", block + src[src.index("def install("):],
                      "no incremental-rollout switch")

    def test_delegated_agent_mirrors_the_whole_model_facing_schema(self):
        src = (ADAPTERS / "smolagents.py").read_text()
        block = src[src.index("class DelegatedAgent"):]
        for field in ("self.name =", "self.description =", "self.inputs =", "self.output_type ="):
            self.assertIn(field, block, f"DelegatedAgent does not mirror {field}")


class InnerRefusalIsOnTheEntry(unittest.TestCase):
    """B7 follow-up. Our gate is outermost, so an inner layer's refusal is a RESULT — and a
    result the entry has to carry, or an `allow` read alone says the call went through."""

    def test_a_body_that_never_ran_is_recorded_as_an_outcome_and_still_verifies(self):
        from attenu_guard.adapters import astrbot as ab

        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        chain_id="c", schema_version=2)
        gd = ab.GuardedDelegation(g, tools={}, allow_unlisted=True)

        witness = ab._BodyWitness(_Tool("secret_delete_all"))          # never fires: refused
        tool = _PermissionLike(witness, None)

        result = asyncio.run(gd.call("secret_delete_all", {}, None,
                                     lambda: "error: Permission denied.", tool=tool))
        self.assertEqual(result, "error: Permission denied.")

        allow, outcome = g.audit_log().entries[-2:]
        self.assertEqual((allow["event"], allow["policy"]), ("allow", Policy.UNLISTED))
        self.assertEqual(outcome["event"], "outcome")
        self.assertEqual(outcome["call_id"], allow["call_id"], "the outcome is not bound to it")
        self.assertEqual(outcome["body_state"], BodyState.RETURNED)
        self.assertEqual(outcome["receipt"]["type"], "framework_refusal")
        self.assertEqual(outcome["receipt"]["ref"], "astrbot:_PermissionGuardedTool")

        signer = HS256TestSigner(secret=b"k", kid="k")
        report = verify_bundle(export_bundle(g.audit_log(), signer, strict=True), signer)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["execution_binding"]["per_call"][allow["call_id"]], "observed")

    def test_a_body_that_did_run_records_no_refusal(self):
        from attenu_guard.adapters import astrbot as ab

        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        chain_id="c", schema_version=2)
        gd = ab.GuardedDelegation(g, tools={}, allow_unlisted=True)
        witness = ab._BodyWitness(_Tool("echo_note"))

        def body():                                         # the real body IS reached this time
            witness.ran = True
            return "noted"

        asyncio.run(gd.call("echo_note", {}, None, body, tool=_PermissionLike(witness, None)))
        self.assertEqual([e["event"] for e in g.audit_log().entries[-1:]], ["allow"])

    def test_no_witness_means_no_outcome_and_no_error(self):
        from attenu_guard.adapters import astrbot as ab

        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        chain_id="c", schema_version=2)
        gd = ab.GuardedDelegation(g, tools={}, allow_unlisted=True)
        asyncio.run(gd.call("plain", {}, None, lambda: "ok", tool=_Tool("plain")))
        self.assertEqual(g.audit_log().entries[-1]["event"], "allow")

    def test_the_main_agent_toolset_as_astrbot_builds_it_carries_the_receipt(self):
        """The construction the battery traced, built through the adapter's own code.

        `install()` sweeps `func_list`, then `get_full_tool_set()` wraps each entry in AstrBot's
        `_PermissionGuardedTool` and `_reassert_outermost` re-nests it, giving
        `GuardedTool -> _PermissionGuardedTool -> _BodyWitness -> raw` — verified against a real
        AstrBot run. The tool here is DECLARED, which is what the earlier version got wrong: the
        receipt was bound to `gate.decision`, set only in strict mode, so on a normally-checked
        call there was no call_id to bind to and `_record_inner_refusal` gave up silently. Only
        the un-gated passthrough path — the one the first test happened to use — ever recorded.
        """
        from attenu_guard.adapters import astrbot as ab

        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        chain_id="c", schema_version=2)
        gd = ab.GuardedDelegation(g, tools={"secret_delete_all": ab.ToolPolicy("repo.read")})
        raw = _Tool("secret_delete_all")
        mgr = _PermissionManager([raw])
        with mock.patch.object(ab, "GuardedTool", _FakeGuarded):
            gd.install(mgr)
            handed = mgr.get_full_tool_set().tools[0]

        self.assertEqual(_chain(handed),
                         ["_FakeGuarded", "_PermissionLike", "_BodyWitness", "_Tool"])

        # AstrBot's permission check refuses: a value comes back, the body never runs.
        result = asyncio.run(gd.call("secret_delete_all", {}, None,
                                     lambda: "error: Permission denied.",
                                     tool=handed._wrapped))
        self.assertEqual(result, "error: Permission denied.")
        allow, outcome = g.audit_log().entries[-2:]
        self.assertEqual((allow["event"], allow["scope"]), ("allow", "repo.read"))
        self.assertIsNone(allow.get("policy"), "this must be the DECLARED path, not a passthrough")
        self.assertEqual(outcome["event"], "outcome")
        self.assertEqual(outcome["call_id"], allow["call_id"])
        self.assertEqual(outcome["receipt"]["type"], "framework_refusal")


def _chain(tool, depth=6):
    out = []
    while tool is not None and len(out) < depth:
        out.append(type(tool).__name__)
        tool = getattr(tool, "_wrapped", None)
    return out


class _PermissionManager(_Manager):
    """`get_full_tool_set()` as AstrBot's does it: every entry wrapped in its own permission
    proxy, around whatever this adapter put in `func_list`."""

    def get_full_tool_set(self):
        return SimpleNamespace(tools=[_PermissionLike(t, self) for t in self.func_list])



class ContextHelperGetsTheResolvedGuard(unittest.TestCase):
    """B15. `self.guard` may be a late-bound reference; only the resolved Guard can record."""

    def test_no_adapter_hands_the_helper_an_unresolved_reference(self):
        offenders = []
        for path in sorted(ADAPTERS.glob("*.py")):
            if path.name.startswith("_"):
                continue
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if "_safe_context(self." in line:
                    offenders.append(f"{path.name}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "a reference, not the resolved Guard, reaches the helper")

    def test_the_helper_resolves_a_reference_it_is_handed_anyway(self):
        # Second line of defence: the failure mode is silence, so the helper does not depend on
        # every call site being right forever. `_Ref` is the shape smolagents' and camel's
        # `GuardRef` present — a `resolve()` and no `record_denial` — driven here because neither
        # framework is installed in the stdlib CI job (the real classes are exercised in
        # tests/integrations/).
        from attenu_guard.adapters import _context

        g = _root()
        child = g.delegate("child", Authority(scopes={"repo.read"}, ttl=60), task="t")
        with self.assertRaises(AuthorityDenied):
            _context.evaluate(_Ref(child), lambda *a: 1 / 0, {}, tool="t", scope="repo.read")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"], entry["node"]),
                         ("deny", ReasonCode.NO_AUTHORITY, child.node_id),
                         "the refusal was lost on the delegated node")

    def test_something_that_is_not_a_guard_at_all_fails_loudly(self):
        from attenu_guard.adapters import _context

        with self.assertRaises(AttributeError):
            _context.evaluate(object(), lambda *a: 1 / 0, {}, tool="t", scope="s")


class _Ref:
    """The late-bound handle shape: `resolve()`, and deliberately no `record_denial`."""

    def __init__(self, guard):
        self._guard = guard

    def resolve(self):
        return self._guard


class WitnessOnEveryPath(unittest.TestCase):
    """B16. The receipt was written on one path; the rule is every path this gate covers."""

    def _gd(self, g):
        from attenu_guard.adapters import astrbot as ab
        return ab.GuardedDelegation(g, tools={}, allow_unlisted=True)

    def _guard(self):
        return Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                           chain_id="c", schema_version=2)

    def test_the_eager_sweep_installs_a_witness(self):
        from attenu_guard.adapters import astrbot as ab
        g = self._guard()
        gd = self._gd(g)
        mgr = _Manager([_Tool("secret_delete_all")])
        with mock.patch.object(ab, "GuardedTool", _FakeGuarded):
            gd._sweep(mgr)
        self.assertIsInstance(mgr.func_list[0]._wrapped, ab._BodyWitness,
                              "a swept tool has no witness, so its allow cannot say what happened")

    def test_guard_tools_installs_a_witness(self):
        from attenu_guard.adapters import astrbot as ab
        gd = self._gd(self._guard())
        with mock.patch.object(ab, "GuardedTool", _FakeGuarded):
            wrapped = gd.guard_tools([_Tool("echo_note")])
        self.assertIsInstance(wrapped[0]._wrapped, ab._BodyWitness)

    def test_a_witness_is_never_installed_twice(self):
        from attenu_guard.adapters import astrbot as ab
        once = ab._with_witness(_Tool("t"))
        self.assertIs(ab._with_witness(once), once)
        self.assertIs(ab._with_witness(_PermissionLike(once, None))._wrapped, once)

    def test_the_main_agent_path_records_the_receipt_when_the_body_is_refused(self):
        # No _PermissionGuardedTool in sight: the witness is directly inside our gate, which is
        # the shape the eager sweep produces (main agent, observe mode, named-tools branch).
        from attenu_guard.adapters import astrbot as ab
        g = self._guard()
        gd = self._gd(g)
        witness = ab._BodyWitness(_Tool("secret_delete_all"))
        result = asyncio.run(gd.call("secret_delete_all", {}, None,
                                     lambda: "error: Permission denied.", tool=witness))
        self.assertEqual(result, "error: Permission denied.")
        allow, outcome = g.audit_log().entries[-2:]
        self.assertEqual((allow["event"], outcome["event"]), ("allow", "outcome"))
        self.assertEqual(outcome["receipt"]["type"], "framework_refusal")

    def test_a_declared_tool_denied_by_our_own_gate_writes_no_receipt(self):
        # Our own deny is not an inner refusal: the body never ran because WE stopped it.
        from attenu_guard.adapters import astrbot as ab
        g = self._guard()
        gd = ab.GuardedDelegation(g, tools={"wipe": ab.ToolPolicy("admin.delete")})
        witness = ab._BodyWitness(_Tool("wipe"))
        asyncio.run(gd.call("wipe", {}, None, lambda: "ran", tool=witness))
        events = [e["event"] for e in g.audit_log().entries]
        self.assertEqual(events[-1], "deny")
        self.assertNotIn("outcome", events)


if __name__ == "__main__":
    unittest.main(verbosity=2)
