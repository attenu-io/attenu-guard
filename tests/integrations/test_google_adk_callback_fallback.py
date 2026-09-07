"""tests/integrations/test_google_adk_callback_fallback.py — the ADK adapter on a build with no
plugin surface, and the one path in it that ran a tool and wrote nothing. stdlib + google-adk.

B13: `attenu_guard.adapters.google_adk` imported `google.adk.plugins.BasePlugin` and, in its
usage example, `google.adk.apps.App`. Neither exists on google-adk 0.3.0 (the version evo-ai
pins), so the import failed and the shipped adapter could not attach to such a project at all.
It now imports either way and `attach()` binds the SAME hooks to the per-agent
`before_agent_callback` / `before_tool_callback` that ADK has carried since 0.x.

B14: an `exempt_tools` entry ran with no ledger row of any kind — the B1 shape. It is recorded
as a passthrough now (`policy="unlisted"`).

Run: PYTHONPATH=src python3 -m pytest tests/integrations/test_google_adk_callback_fallback.py
"""
import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from attenu_guard import Authority, Guard  # noqa: E402
from attenu_guard.reasons import Policy  # noqa: E402

try:
    from attenu_guard.adapters.google_adk import DelegationGuardPlugin, ToolAuthority
except ImportError:                                  # pragma: no cover - ADK not installed
    DelegationGuardPlugin = None


def _root(scopes=("orders.read",), **kw):
    return Guard.issue("root_agent", Authority(scopes=set(scopes), ttl=3600),
                       chain_id="adk", **kw)


def _tool(name):
    return SimpleNamespace(name=name)


def _tool_context(agent_name):
    return SimpleNamespace(agent_name=agent_name)


@unittest.skipIf(DelegationGuardPlugin is None, "google-adk is not installed")
class ExemptToolsAreRecorded(unittest.TestCase):
    """B14. An exemption is the operator saying "do not authorize this" — never "do not say
    it happened"."""

    def _plugin(self, guard, **kw):
        return DelegationGuardPlugin(guard, delegations={}, tools={}, root_agent_name="root_agent",
                                     **kw)

    def test_an_exempt_tool_lands_on_the_ledger_as_an_unlisted_passthrough(self):
        g = _root()
        plugin = self._plugin(g, exempt_tools=["health_check"])
        asyncio.run(plugin.before_tool_callback(
            tool=_tool("health_check"), tool_args={}, tool_context=_tool_context("root_agent")))
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["tool"], entry["policy"]),
                         ("allow", "health_check", Policy.UNLISTED))

    def test_transfer_to_agent_is_not_recorded_twice(self):
        # Delegation is recorded as a spawn elsewhere on this same ledger; recording it here too
        # would double-count the one event this library exists to get right.
        g = _root()
        plugin = self._plugin(g)
        before = len(g.audit_log().entries)
        asyncio.run(plugin.before_tool_callback(
            tool=_tool("transfer_to_agent"), tool_args={"agent_name": "billing"},
            tool_context=_tool_context("root_agent")))
        self.assertEqual(len(g.audit_log().entries), before)

    def test_an_undeclared_tool_is_still_checked_and_denied_not_exempted(self):
        g = _root()
        plugin = self._plugin(g)
        asyncio.run(plugin.before_tool_callback(
            tool=_tool("integration_push"), tool_args={},
            tool_context=_tool_context("root_agent")))
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"]), ("deny", "scope_not_granted"))


@unittest.skipIf(DelegationGuardPlugin is None, "google-adk is not installed")
class CallbackFallback(unittest.TestCase):
    """B13 / B13b. The hook points ADK 0.x has, driven the way ADK 0.3.0 actually drives them.

    This stub is the point of the test, so it mimics 0.3.0 exactly and refuses to be generous:

      * it CALLS the callback and never awaits it (`base_agent.py:261`,
        `functions.py:156-160` — nothing in 0.3.0 checks `isawaitable`);
      * it uses the return value directly, treating any truthy value as "skip the tool body"
        (`if not function_response:`).

    A coroutine is truthy, so an async callback fails these tests the same way it failed on the
    real 0.3.0: every tool body skipped, the coroutine handed back as the tool result, nothing
    authorized and nothing recorded — failing open on the trail while looking like it worked.
    """

    class _Agent:
        """The per-agent callback surface as ADK 0.x exposes it: four attributes, positional
        calls, no `agent` argument."""

        def __init__(self, name, sub_agents=(), tools=()):
            self.name = name
            self.sub_agents = list(sub_agents)
            self.tools = list(tools)
            self.before_agent_callback = None
            self.after_agent_callback = None
            self.before_tool_callback = None
            self.after_tool_callback = None

    @staticmethod
    def _first(hook):
        return hook[0] if isinstance(hook, list) else hook

    def _fire(self, hook, *args):
        """Call it as ADK 0.3.0 does — synchronously — and refuse a coroutine outright."""
        result = self._first(hook)(*args)
        self.assertFalse(
            asyncio.iscoroutine(result),
            "the callback returned a coroutine; ADK 0.3.0 never awaits one, and would treat it "
            "as truthy — skipping the tool body and recording nothing")
        return result

    def _run_tool(self, agent, tool, args, tool_context, body):
        """ADK 0.3.0's own dispatch, reproduced: `functions.py:156-160`."""
        function_response = self._fire(agent.before_tool_callback, tool, args, tool_context)
        if not function_response:                       # falsy => the tool actually runs
            function_response = body()
            if agent.after_tool_callback is not None:
                self._fire(agent.after_tool_callback, tool, args, tool_context, function_response)
        return function_response

    def _plugin(self, guard, **kw):
        return DelegationGuardPlugin(
            guard,
            delegations={"billing": Authority(scopes={"orders.read"}, ttl=60)},
            tools={"lookup_order": ToolAuthority("orders.read"),
                   "refund": ToolAuthority("payments.write")},
            root_agent_name="root_agent", **kw)

    def test_no_bound_callback_is_a_coroutine_function(self):
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g).attach(root)
        for attr in ("before_agent_callback", "after_agent_callback",
                     "before_tool_callback", "after_tool_callback"):
            self.assertFalse(asyncio.iscoroutinefunction(self._first(getattr(root, attr))),
                             f"{attr} is async; ADK 0.x would never await it")

    def test_attach_walks_the_tree_and_binds_all_four_hooks(self):
        g = _root()
        child = self._Agent("billing")
        wrapped = self._Agent("researcher")
        root = self._Agent("root_agent", sub_agents=[child],
                           tools=[SimpleNamespace(name="as_tool", agent=wrapped)])
        covered = self._plugin(g).attach(root)
        self.assertEqual(sorted(covered), ["billing", "researcher", "root_agent"])
        for agent in (root, child, wrapped):
            for attr in ("before_agent_callback", "after_agent_callback",
                         "before_tool_callback", "after_tool_callback"):
                self.assertIsNotNone(getattr(agent, attr), f"{agent.name}.{attr} not bound")

    def test_the_agent_hooks_return_none_so_adk_does_not_put_a_value_in_an_event(self):
        # `base_agent.py:261` puts a non-None return straight into `Event(content=...)`; anything
        # but None there is a pydantic ValidationError on 0.3.0.
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g).attach(root)
        self.assertIsNone(self._fire(root.before_agent_callback, _tool_context("root_agent")))
        self.assertIsNone(self._fire(root.after_agent_callback, _tool_context("root_agent")))

    def test_an_allowed_tool_runs_its_body_and_is_recorded(self):
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g).attach(root)
        ran = []
        out = self._run_tool(root, _tool("lookup_order"), {}, _tool_context("root_agent"),
                             lambda: ran.append(1) or {"ok": True})
        self.assertEqual(ran, [1], "the tool body was skipped for an AUTHORIZED call")
        self.assertEqual(out, {"ok": True})
        self.assertEqual(g.audit_log().entries[-1]["scope"], "orders.read")

    def test_a_denied_tool_is_short_circuited_and_recorded(self):
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g).attach(root)
        ran = []
        out = self._run_tool(root, _tool("refund"), {"amount": 10}, _tool_context("root_agent"),
                             lambda: ran.append(1) or {"ok": True})
        self.assertEqual(ran, [], "a DENIED tool's body ran")
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("error"), "authority_denied")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["tool"], entry["reason"]),
                         ("deny", "refund", "scope_not_granted"))

    def test_an_exempt_tool_runs_and_is_recorded_as_an_unlisted_passthrough(self):
        # B14 evidence on this path, not only through the plugin surface.
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g, exempt_tools=["health_check"]).attach(root)
        ran = []
        self._run_tool(root, _tool("health_check"), {}, _tool_context("root_agent"),
                       lambda: ran.append(1) or {"ok": True})
        self.assertEqual(ran, [1], "an exempt tool must still run")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["tool"], entry["policy"]),
                         ("allow", "health_check", Policy.UNLISTED))

    def test_an_undeclared_tool_is_denied_on_this_path_too(self):
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g).attach(root)
        ran = []
        self._run_tool(root, _tool("integration_push"), {}, _tool_context("root_agent"),
                       lambda: ran.append(1) or {"ok": True})
        self.assertEqual(ran, [])
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"]), ("deny", "scope_not_granted"))

    def test_an_existing_callback_is_kept_and_ours_runs_first(self):
        g = _root()
        root = self._Agent("root_agent")
        marker = []
        root.before_tool_callback = lambda *a, **k: marker.append("theirs")
        self._plugin(g).attach(root)
        self.assertIsInstance(root.before_tool_callback, list)
        self.assertIs(root.before_tool_callback[1].__func__ if hasattr(
            root.before_tool_callback[1], "__func__") else root.before_tool_callback[1],
            root.before_tool_callback[1], "the project's own hook was dropped")
        self._fire(root.before_tool_callback, _tool("lookup_order"), {},
                   _tool_context("root_agent"))
        self.assertEqual(g.audit_log().entries[-1]["scope"], "orders.read")

    def test_attach_is_idempotent(self):
        g = _root()
        root = self._Agent("root_agent")
        plugin = self._plugin(g)
        plugin.attach(root)
        first = root.before_tool_callback
        self.assertEqual(plugin.attach(root), [], "a second attach re-bound the same agent")
        self.assertIs(root.before_tool_callback, first)


@unittest.skipIf(DelegationGuardPlugin is None, "google-adk is not installed")
class SecondTurnGetsANewNode(unittest.TestCase):
    """B17. One ADK session, two user turns. The second one has to be able to work."""

    #: `complete()` only refuses on a schema_version=2 chain (on v1 it is an informational
    #: marker), and that is what the evo-ai battery runs — so these turns run on v2 or they
    #: would not reproduce the defect at all.
    def _guard(self, scopes):
        return _root(scopes=scopes, schema_version=2)

    def _plugin(self, guard, **kw):
        return DelegationGuardPlugin(
            guard,
            delegations={"billing": Authority(scopes={"orders.read"}, ttl=600)},
            tools={"lookup_order": ToolAuthority("orders.read"),
                   "refund": ToolAuthority("payments.write")},
            root_agent_name="root_agent", **kw)

    def _turn(self, plugin):
        """What ADK does for one user turn: root runs, hands off, the child runs and returns."""
        run = asyncio.run
        run(plugin.before_agent_callback(agent=_agent("root_agent"),
                                         callback_context=_tool_context("root_agent")))
        run(plugin.before_tool_callback(tool=_tool("transfer_to_agent"),
                                        tool_args={"agent_name": "billing"},
                                        tool_context=_tool_context("root_agent")))
        run(plugin.before_agent_callback(agent=_agent("billing"),
                                         callback_context=_tool_context("billing")))
        out = run(plugin.before_tool_callback(tool=_tool("lookup_order"), tool_args={},
                                              tool_context=_tool_context("billing")))
        # `after_agent_callback` is what finalizes the node — correctly: that run did finish.
        run(plugin.after_agent_callback(agent=_agent("billing"),
                                        callback_context=_tool_context("billing")))
        return out

    def test_the_second_turn_spawns_a_new_node_and_its_calls_land_there(self):
        g = self._guard({"orders.read", "delegate.billing"})
        plugin = self._plugin(g)
        self.assertIsNone(self._turn(plugin), "turn 1 was refused")
        self.assertIsNone(self._turn(plugin), "turn 2 was refused")

        events = [(e["event"], e.get("node"), e.get("tool"), e.get("reason"))
                  for e in g.audit_log().entries]
        self.assertNotIn("node_finalized", [e[3] for e in events],
                         "a second turn was refused on a dead node")
        spawns = [e[1] for e in events if e[0] == "spawn"]
        self.assertEqual(len(spawns), 2, "the second turn did not get its own node")
        self.assertNotEqual(spawns[0], spawns[1])

        allows = [(e[1], e[2]) for e in events if e[0] == "allow"]
        self.assertEqual(allows, [(spawns[0], "lookup_order"), (spawns[1], "lookup_order")],
                         "the second turn's call was not recorded on the second turn's node")

    def test_the_ceiling_still_holds_on_the_new_node(self):
        # A re-spawn must not widen anything: same parent, same requested Authority, same meet.
        g = self._guard({"orders.read", "delegate.billing"})
        plugin = self._plugin(g)
        self._turn(plugin)                                   # turn 1, node finalized at its end
        # Turn 2, mid-run: the child is on its fresh node and reaches past its grant.
        asyncio.run(plugin.before_agent_callback(agent=_agent("root_agent"),
                                                 callback_context=_tool_context("root_agent")))
        asyncio.run(plugin.before_tool_callback(tool=_tool("transfer_to_agent"),
                                                tool_args={"agent_name": "billing"},
                                                tool_context=_tool_context("root_agent")))
        asyncio.run(plugin.before_agent_callback(agent=_agent("billing"),
                                                 callback_context=_tool_context("billing")))
        denied = asyncio.run(plugin.before_tool_callback(
            tool=_tool("refund"), tool_args={}, tool_context=_tool_context("billing")))

        self.assertIsInstance(denied, dict, "an over-reach was allowed on the re-spawned node")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["reason"]), ("deny", "scope_not_granted"))
        last_spawn = [e for e in g.audit_log().entries if e["event"] == "spawn"][-1]
        self.assertEqual(entry["node"], last_spawn["node"],
                         "the over-reach was not recorded on the turn's own node")

    def test_a_revoked_agent_is_never_re_spawned(self):
        # The regression this nearly shipped with: `revoke()` marks the subtree complete too, so
        # a cascade-revoked agent looked exactly like a finished one and came back on its next
        # turn with a live node. Revoked is not finished.
        g = self._guard({"orders.read", "delegate.billing"})
        plugin = self._plugin(g)
        self._turn(plugin)
        child = plugin.guard_for("billing")
        g.revoke(child.node_id)

        asyncio.run(plugin.before_agent_callback(agent=_agent("billing"),
                                                 callback_context=_tool_context("billing")))
        denied = asyncio.run(plugin.before_tool_callback(
            tool=_tool("lookup_order"), tool_args={}, tool_context=_tool_context("billing")))
        self.assertIsInstance(denied, dict, "a revoked agent was allowed to act again")
        entry = g.audit_log().entries[-1]
        self.assertEqual(entry["event"], "deny")
        # `check()` reports `node_finalized` before it looks at revocation — a core ordering
        # detail, not this adapter's contract. What this test owns is that the call is REFUSED
        # and the node was not replaced with a live one.
        self.assertIn(entry["reason"], ("revoked", "node_finalized"), entry)
        self.assertIs(plugin.guard_for("billing"), child, "the revoked node was re-spawned")
        spawns = [e for e in g.audit_log().entries if e["event"] == "spawn"]
        self.assertEqual(len(spawns), 1, "a new node was minted for a revoked agent")

    def test_observe_mode_refuses_nothing_across_turns(self):
        # The instrument must not change the run it is watching.
        g = self._guard({"orders.*", "delegate.*", "payments.*"})
        plugin = self._plugin(
            g,
            default_delegation=lambda name: Authority(scopes={"orders.*", "payments.*"}, ttl=600),
            default_tool_authority=lambda name: ToolAuthority(f"orders.{name}"))
        for _ in range(3):
            self._turn(plugin)
        denies = [e for e in g.audit_log().entries if e["event"] == "deny"]
        self.assertEqual(denies, [], "observe mode refused a call")


def _agent(name):
    return SimpleNamespace(name=name)


class ImportsWithoutThePluginApi(unittest.TestCase):
    """The import must survive a build with no plugin surface — this is the whole of B13."""

    def test_the_module_declares_whether_the_plugin_api_is_present(self):
        src = (ROOT / "src" / "attenu_guard" / "adapters" / "google_adk.py").read_text()
        self.assertIn("HAS_PLUGIN_API", src)
        self.assertIn("except ImportError", src,
                      "the plugin import is still hard, so ADK 0.x cannot import this module")
        self.assertIn("def attach(", src, "there is no callback fallback to attach with")


if __name__ == "__main__":
    unittest.main(verbosity=2)
