"""
tests/test_langgraph_adapter.py — unit tests for adapters/langgraph.py.

stdlib-only (unittest), no pytest, NO langgraph installed, runs with bare
`python3`:

    python3 tests/test_langgraph_adapter.py

adapters/langgraph.py's authorization-wrapping logic (`guard_node`,
`DelegatedToolNode`) is pure Python that wraps an arbitrary callable — it
never imports `langgraph`, so every test below runs (and must keep running)
with zero third-party packages installed. That guarantee is itself part of
what's tested: getting through the module-level `import attenu_guard.adapters.langgraph`
at all, in an environment without langgraph, is the first assertion.
"""
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))        # so adapters/langgraph.py's own
                                                    # `from attenu_guard import ...` resolves

import asyncio

from attenu_guard import Authority, AuthorityDenied, Guard, RowLimit
from attenu_guard.reasons import BodyState, Capture

from attenu_guard.adapters.langgraph import (
    DelegatedToolNode, add_guarded_node, guard_node, is_langgraph_available,
)

# Captured IMMEDIATELY after importing the adapter, before any test runs: did
# importing `attenu_guard.adapters.langgraph` drag `langgraph` into the
# process? This is the actual guarantee under test, and it holds whether or
# not langgraph happens to be installed on this machine (it IS installed in
# the integration-test venvs — see tests/integrations/test_langgraph.py).
_LANGGRAPH_IMPORTED_BY_ADAPTER = "langgraph" in sys.modules


class _Recorder:
    """A fake tool callable: records every call it receives and returns a
    small marker payload, so a test can assert both "was it called" and
    "what did it get called with"."""
    def __init__(self, name="tool"):
        self.__name__ = name
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True, "args": args, "kwargs": kwargs}


def _rows_context(*args, **kwargs):
    return {"rows": kwargs.get("rows", 0)}


def _make_tool_guard():
    """A root Guard delegated once, holding crm.read with a RowLimit(10)
    ceiling -- the Guard a 'summarizer' node's tools would be checked
    against."""
    root = Guard.issue("planner", Authority({"crm.read", "crm.write"}, [], ttl=3600))
    return root.delegate("summarizer", Authority({"crm.read"}, [RowLimit(10)], ttl=900),
                         task="summarize")


def _make_v2_tool_guard():
    """Same shape as _make_tool_guard, but on a schema_version=2 chain -- the guard the
    execution-binding wiring tests below check against."""
    root = Guard.issue("planner", Authority({"crm.read", "crm.write"}, [], ttl=3600),
                       schema_version=2)
    return root.delegate("summarizer", Authority({"crm.read"}, [RowLimit(10)], ttl=900),
                         task="summarize")


class TestModuleImportsWithoutLanggraph(unittest.TestCase):
    def test_importing_the_adapter_does_not_import_langgraph(self):
        # The guarantee: importing the adapter must NOT import langgraph
        # (lazy imports only). Asserted via the flag captured at module load,
        # so this passes on machines WITH langgraph installed too — the old
        # form asserted `not is_langgraph_available()`, which was a statement
        # about the machine, not the module, and failed on any dev box with
        # `pip install -e '.[langgraph]'`.
        self.assertFalse(_LANGGRAPH_IMPORTED_BY_ADAPTER)

    def test_is_langgraph_available_reports_reality(self):
        # Whatever this machine has, the probe must agree with a direct import.
        try:
            import langgraph  # noqa: F401
            really = True
        except ImportError:
            really = False
        self.assertEqual(is_langgraph_available(), really)

    def test_module_already_imported_successfully(self):
        # Reaching this line at all proves `import attenu_guard.adapters.langgraph`
        # (done at module load, above) succeeded with no langgraph on the
        # path. Make the guarantee an explicit, named assertion too.
        import attenu_guard.adapters.langgraph as lg
        self.assertTrue(hasattr(lg, "guard_node"))
        self.assertTrue(hasattr(lg, "DelegatedToolNode"))


# =========================================================================
# guard_node — the decorator form
# =========================================================================
class TestGuardNode(unittest.TestCase):
    def setUp(self):
        self.guard = _make_tool_guard()

    def test_allowed_call_passes_through_and_returns_the_tool_result(self):
        tool = _Recorder()
        wrapped = guard_node(self.guard, "crm.read", context_fn=_rows_context)(tool)

        result = wrapped(rows=5)

        self.assertEqual(len(tool.calls), 1)
        self.assertEqual(tool.calls[0], ((), {"rows": 5}))
        self.assertEqual(result, {"ok": True, "args": (), "kwargs": {"rows": 5}})

    def test_denied_call_raises_authority_denied_and_does_not_invoke_the_tool(self):
        tool = _Recorder()
        wrapped = guard_node(self.guard, "crm.read", context_fn=_rows_context)(tool)

        with self.assertRaises(AuthorityDenied) as ctx:
            wrapped(rows=999)  # RowLimit(10) ceiling -- 999 exceeds it

        self.assertEqual(tool.calls, [])  # the tool body must NEVER have run
        self.assertFalse(ctx.exception.decision.allowed)
        self.assertEqual(ctx.exception.decision.reasons[0].code, "ceiling_exceeded")

    def test_scope_not_granted_also_raises_and_blocks_the_tool(self):
        tool = _Recorder()
        # this Guard was only delegated crm.read, not crm.write
        wrapped = guard_node(self.guard, "crm.write")(tool)

        with self.assertRaises(AuthorityDenied) as ctx:
            wrapped()

        self.assertEqual(tool.calls, [])
        self.assertEqual(ctx.exception.decision.reasons[0].code, "scope_not_granted")

    def test_no_context_fn_means_empty_context(self):
        tool = _Recorder()
        wrapped = guard_node(self.guard, "crm.read")(tool)
        # no context_fn -> context={} always, regardless of call kwargs --
        # RowLimit sees no "rows" and treats it as unasserted this call, so
        # this allows even though 999 would exceed the ceiling if it were
        # actually threaded through as context.
        wrapped(rows=999)
        self.assertEqual(len(tool.calls), 1)

    def test_tool_label_defaults_to_the_wrapped_function_name_in_the_audit_log(self):
        def my_tool(**kw):
            return "ok"
        wrapped = guard_node(self.guard, "crm.read")(my_tool)
        wrapped()
        last = self.guard.audit_log().entries[-1]
        self.assertEqual(last["tool"], "my_tool")

    def test_explicit_tool_label_overrides_the_function_name(self):
        def my_tool(**kw):
            return "ok"
        wrapped = guard_node(self.guard, "crm.read", tool="custom-label")(my_tool)
        wrapped()
        last = self.guard.audit_log().entries[-1]
        self.assertEqual(last["tool"], "custom-label")

    def test_wrapped_callable_exposes_introspection_attributes(self):
        def my_tool(**kw):
            return "ok"
        wrapped = guard_node(self.guard, "crm.read")(my_tool)
        self.assertIs(wrapped.guard, self.guard)
        self.assertEqual(wrapped.tool_scope, "crm.read")
        self.assertIs(wrapped.__wrapped__, my_tool)

    def test_denial_is_logged_to_the_audit_trail_like_any_other_check(self):
        tool = _Recorder()
        wrapped = guard_node(self.guard, "crm.write")(tool)
        before = len(self.guard.audit_log().entries)
        with self.assertRaises(AuthorityDenied):
            wrapped()
        after = len(self.guard.audit_log().entries)
        self.assertEqual(after - before, 1)
        self.assertEqual(self.guard.audit_log().entries[-1]["event"], "deny")


# =========================================================================
# DelegatedToolNode — the object form, same semantics as guard_node
# =========================================================================
class TestDelegatedToolNode(unittest.TestCase):
    def setUp(self):
        self.guard = _make_tool_guard()

    def test_allowed_call_passes_through_and_returns_the_tool_result(self):
        tool = _Recorder()
        node = DelegatedToolNode(self.guard, "crm.read", tool, context_fn=_rows_context)

        result = node(rows=3)

        self.assertEqual(len(tool.calls), 1)
        self.assertEqual(result["kwargs"], {"rows": 3})

    def test_denied_call_raises_authority_denied_and_does_not_invoke_the_tool(self):
        tool = _Recorder()
        node = DelegatedToolNode(self.guard, "crm.read", tool, context_fn=_rows_context)

        with self.assertRaises(AuthorityDenied):
            node(rows=999)

        self.assertEqual(tool.calls, [])

    def test_exposes_guard_and_tool_scope_for_introspection(self):
        tool = _Recorder()
        node = DelegatedToolNode(self.guard, "crm.read", tool)
        self.assertIs(node.guard, self.guard)
        self.assertEqual(node.tool_scope, "crm.read")
        self.assertIs(node.fn, tool)

    def test_repr_is_informative(self):
        tool = _Recorder(name="summarize")
        node = DelegatedToolNode(self.guard, "crm.read", tool)
        text = repr(node)
        self.assertIn("crm.read", text)
        self.assertIn(self.guard.node_id, text)

    def test_state_style_single_arg_call_works_like_a_langgraph_node(self):
        # LangGraph nodes are conventionally called as node(state) -> dict.
        # DelegatedToolNode makes no assumption about the shape of `state`
        # -- it just forwards whatever it's called with.
        def summarize(state):
            return {"summary": f"{len(state['rows'])} rows summarized"}

        node = DelegatedToolNode(self.guard, "crm.read", summarize,
                                 context_fn=lambda state: {"rows": len(state["rows"])})
        out = node({"rows": [1, 2, 3]})
        self.assertEqual(out, {"summary": "3 rows summarized"})

    def test_state_style_call_denies_when_ceiling_exceeded(self):
        def summarize(state):
            return {"summary": "should not get here"}

        node = DelegatedToolNode(self.guard, "crm.read", summarize,
                                 context_fn=lambda state: {"rows": len(state["rows"])})
        big_state = {"rows": list(range(50))}  # 50 > RowLimit(10)
        with self.assertRaises(AuthorityDenied):
            node(big_state)


# =========================================================================
# add_guarded_node — duck-typed graph registration (no langgraph import)
# =========================================================================
class _FakeGraph:
    """Stands in for langgraph.graph.StateGraph: the only method
    add_guarded_node relies on is add_node(name, callable)."""
    def __init__(self):
        self.nodes = {}

    def add_node(self, name, fn):
        self.nodes[name] = fn


class TestAddGuardedNode(unittest.TestCase):
    def setUp(self):
        self.guard = _make_tool_guard()

    def test_registers_a_delegated_tool_node_on_the_graph(self):
        graph = _FakeGraph()
        tool = _Recorder()

        node = add_guarded_node(graph, "summarize", self.guard, "crm.read", tool,
                                context_fn=_rows_context)

        self.assertIn("summarize", graph.nodes)
        self.assertIs(graph.nodes["summarize"], node)
        self.assertIsInstance(node, DelegatedToolNode)

    def test_registered_node_still_enforces_authorization(self):
        graph = _FakeGraph()
        tool = _Recorder()
        add_guarded_node(graph, "summarize", self.guard, "crm.read", tool,
                         context_fn=_rows_context)

        graph.nodes["summarize"](rows=1)   # allowed
        self.assertEqual(len(tool.calls), 1)

        with self.assertRaises(AuthorityDenied):
            graph.nodes["summarize"](rows=999)  # denied -- ceiling exceeded
        self.assertEqual(len(tool.calls), 1)  # unchanged: still just the one allowed call


class TestExecutionBindingWiring(unittest.TestCase):
    """0.9.0: guard_node()/DelegatedToolNode as the reference wiring for record_outcome() --
    only active when the guard's chain is schema_version=2 (see test_v1_guard_gets_no_call_id_
    or_outcome below for the unchanged v1 behaviour)."""

    def setUp(self):
        self.guard = _make_v2_tool_guard()

    def test_sync_allowed_call_records_a_returned_outcome_with_wrapper_sync_capture(self):
        tool = _Recorder()

        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        def summarize(**kwargs):
            return tool(**kwargs)

        result = summarize(rows=1)
        self.assertTrue(result["ok"])
        entries = self.guard.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow")
        outcome = next(e for e in entries if e["event"] == "outcome")
        self.assertEqual(allow["capture"], Capture.WRAPPER_SYNC)
        self.assertEqual(allow["adapter"]["module"], "attenu_guard.adapters.langgraph")
        self.assertEqual(outcome["call_id"], allow["call_id"])
        self.assertEqual(outcome["body_state"], BodyState.RETURNED)
        self.assertIn("authorized_params_hash", allow)
        self.assertEqual(allow["authorized_params_hash"], outcome["invoked_params_hash"])

    def test_sync_raising_call_records_a_raised_outcome_with_error_code(self):
        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        def summarize(**kwargs):
            raise ValueError("boom")

        with self.assertRaises(ValueError):
            summarize(rows=1)
        outcome = next(e for e in self.guard.audit_log().entries if e["event"] == "outcome")
        self.assertEqual(outcome["body_state"], BodyState.RAISED)
        self.assertEqual(outcome["error_code"], "ValueError")

    def test_denied_call_never_records_an_outcome(self):
        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        def summarize(**kwargs):
            return {"ok": True}

        with self.assertRaises(AuthorityDenied):
            summarize(rows=999)   # ceiling exceeded
        outcomes = [e for e in self.guard.audit_log().entries if e["event"] == "outcome"]
        self.assertEqual(outcomes, [])

    def test_async_allowed_call_uses_wrapper_async_capture(self):
        tool = _Recorder()

        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        async def summarize(**kwargs):
            return tool(**kwargs)

        result = asyncio.run(summarize(rows=1))
        self.assertTrue(result["ok"])
        entries = self.guard.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow")
        outcome = next(e for e in entries if e["event"] == "outcome")
        self.assertEqual(allow["capture"], Capture.WRAPPER_ASYNC)
        self.assertEqual(outcome["body_state"], BodyState.RETURNED)

    def test_async_raising_call_records_a_raised_outcome(self):
        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        async def summarize(**kwargs):
            raise RuntimeError("async boom")

        with self.assertRaises(RuntimeError):
            asyncio.run(summarize(rows=1))
        outcome = next(e for e in self.guard.audit_log().entries if e["event"] == "outcome")
        self.assertEqual(outcome["body_state"], BodyState.RAISED)
        self.assertEqual(outcome["error_code"], "RuntimeError")

    def test_v1_guard_gets_no_call_id_or_outcome(self):
        guard = _make_tool_guard()   # schema_version=1 (the default)
        tool = _Recorder()

        @guard_node(guard, "crm.read", context_fn=_rows_context)
        def summarize(**kwargs):
            return tool(**kwargs)

        summarize(rows=1)
        entries = guard.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow")
        self.assertNotIn("call_id", allow)
        self.assertNotIn("capture", allow)
        self.assertEqual([e for e in entries if e["event"] == "outcome"], [])

    def test_delegated_tool_node_also_records_outcomes(self):
        tool = _Recorder()
        node = DelegatedToolNode(self.guard, "crm.read", tool, context_fn=_rows_context)
        node(rows=1)
        outcome = next(e for e in self.guard.audit_log().entries if e["event"] == "outcome")
        self.assertEqual(outcome["body_state"], BodyState.RETURNED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
