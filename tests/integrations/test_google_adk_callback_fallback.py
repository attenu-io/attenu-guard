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


def _root(**kw):
    return Guard.issue("root_agent", Authority(scopes={"orders.read"}, ttl=3600),
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
    """B13. The hook points ADK has had since 0.x, driven exactly as ADK drives them."""

    class _Agent:
        """The per-agent callback surface, as ADK 0.x exposes it: four attributes, positional
        calls, no `agent` argument."""

        def __init__(self, name, sub_agents=(), tools=()):
            self.name = name
            self.sub_agents = list(sub_agents)
            self.tools = list(tools)
            self.before_agent_callback = None
            self.after_agent_callback = None
            self.before_tool_callback = None
            self.after_tool_callback = None

    def _plugin(self, guard, **kw):
        return DelegationGuardPlugin(guard, delegations={"billing": Authority(scopes={"orders.read"}, ttl=60)},
                                     tools={"lookup_order": ToolAuthority("orders.read"),
                                            "refund": ToolAuthority("payments.write")},
                                     root_agent_name="root_agent", **kw)

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

    def test_the_bound_callbacks_authorize_and_record_exactly_as_the_plugin_does(self):
        g = _root()
        root = self._Agent("root_agent")
        self._plugin(g).attach(root)

        # ADK 0.x calls these positionally, and awaits an awaitable result.
        asyncio.run(root.before_agent_callback(_tool_context("root_agent")))
        allowed = asyncio.run(root.before_tool_callback(
            _tool("lookup_order"), {}, _tool_context("root_agent")))
        self.assertIsNone(allowed, "an authorized call must not be short-circuited")
        self.assertEqual(g.audit_log().entries[-1]["scope"], "orders.read")

        denied = asyncio.run(root.before_tool_callback(
            _tool("refund"), {"amount": 10}, _tool_context("root_agent")))
        self.assertIsInstance(denied, dict, "a denial must short-circuit the tool body")
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["tool"], entry["reason"]),
                         ("deny", "refund", "scope_not_granted"))

    def test_an_existing_callback_is_kept_and_ours_runs_first(self):
        g = _root()
        root = self._Agent("root_agent")
        marker = []

        async def theirs(*a, **k):
            marker.append("theirs")

        root.before_tool_callback = theirs
        self._plugin(g).attach(root)
        self.assertIsInstance(root.before_tool_callback, list)
        self.assertIs(root.before_tool_callback[1], theirs, "the project's own hook was dropped")
        asyncio.run(root.before_tool_callback[0](
            _tool("lookup_order"), {}, _tool_context("root_agent")))
        self.assertEqual(g.audit_log().entries[-1]["scope"], "orders.read")

    def test_attach_is_idempotent(self):
        g = _root()
        root = self._Agent("root_agent")
        plugin = self._plugin(g)
        plugin.attach(root)
        first = root.before_tool_callback
        self.assertEqual(plugin.attach(root), [], "a second attach re-bound the same agent")
        self.assertIs(root.before_tool_callback, first)


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
