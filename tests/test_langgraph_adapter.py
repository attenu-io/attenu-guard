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
import inspect

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

    def test_a_callable_that_mutates_its_own_input_does_not_cause_a_params_mismatch(self):
        # Codex review item 3: invoked_params used to be computed AFTER the body ran, from the
        # SAME args/kwargs the body could have mutated in place -- a false substitution signal.
        received = {}

        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        def summarize(payload, rows=0):
            received["seen"] = dict(payload)
            payload["mutated"] = True   # mutate the wrapper's own input in place
            return {"ok": True}

        arg = {"original": True}
        summarize(arg, rows=1)
        self.assertEqual(received["seen"], {"original": True})   # the body saw it BEFORE mutation
        self.assertTrue(arg["mutated"])                          # the mutation still happened
        entries = self.guard.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow")
        outcome = next(e for e in entries if e["event"] == "outcome")
        # both hashes come from the SAME pre-invocation snapshot -- no false mismatch
        self.assertEqual(allow["authorized_params_hash"], outcome["invoked_params_hash"])

    def test_a_generator_return_value_is_reported_deferred_not_returned(self):
        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        def summarize(**kwargs):
            def gen():
                yield 1
                yield 2
            return gen()

        result = summarize(rows=1)
        self.assertEqual(list(result), [1, 2])   # the generator itself still works
        outcome = next(e for e in self.guard.audit_log().entries if e["event"] == "outcome")
        self.assertEqual(outcome["body_state"], BodyState.DEFERRED)

    def test_an_async_callable_object_is_detected_and_uses_wrapper_async_capture(self):
        class AsyncTool:
            async def __call__(self, **kwargs):
                return {"ok": True}

        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        async def summarize(**kwargs):
            return await AsyncTool()(**kwargs)

        result = asyncio.run(summarize(rows=1))
        self.assertTrue(result["ok"])
        allow = next(e for e in self.guard.audit_log().entries if e["event"] == "allow")
        self.assertEqual(allow["capture"], Capture.WRAPPER_ASYNC)

    def test_async_cancellation_is_reported_abandoned_and_still_propagates(self):
        @guard_node(self.guard, "crm.read", context_fn=_rows_context)
        async def summarize(**kwargs):
            await asyncio.sleep(10)
            return {"ok": True}   # never reached

        async def run():
            task = asyncio.ensure_future(summarize(rows=1))
            await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        outcome = next(e for e in self.guard.audit_log().entries if e["event"] == "outcome")
        self.assertEqual(outcome["body_state"], BodyState.ABANDONED)
        self.assertNotIn("error_code", outcome)

    def test_v1_async_wrapper_stays_sync_and_returns_an_unawaited_coroutine(self):
        # Codex review item 3/8: on v1 (the default), wrapping an async callable must NOT turn
        # `wrapped` itself into a coroutine function -- the pre-0.9.0 shape returned the raw
        # coroutine from a SYNC wrapper call, and the caller awaited the RESULT.
        guard = _make_tool_guard()   # schema_version=1

        @guard_node(guard, "crm.read", context_fn=_rows_context)
        async def summarize(**kwargs):
            return {"ok": True}

        self.assertFalse(inspect.iscoroutinefunction(summarize))
        result = summarize(rows=1)             # a plain (sync) call
        self.assertTrue(inspect.iscoroutine(result))   # ...that returned an unawaited coroutine
        self.assertEqual(asyncio.run(_await_it(result)), {"ok": True})


class TestSnapshotHardening(unittest.TestCase):
    """Release-gate finding 1 (CRITICAL): `adapters.langgraph` is the SHIPPED, original
    reference-wiring adapter -- untouched by either adversarial-review batch, which worked
    through every OTHER adapter instead. It still used raw `copy.deepcopy()`, with a fallback
    that returned the raw (live) dict on failure -- the exact aliasing gap every other adapter's
    `_freeze()` was built to close. A hostile `__deepcopy__` reproduced `snapshot["args"][0] is
    live`, and a later mutation changed the "snapshot". Separately, `tests/integrations/
    test_langgraph.py` -- despite its name and its own module docstring's claim to cover 'the
    SHIPPED adapter (attenu_guard.adapters.langgraph)' -- imports `attenu_guard.adapters.
    langchain` under the alias it then tests against, so this regression class had genuinely NO
    test coverage anywhere. Fixed by routing `_snapshot_params` through the shared
    `attenu_guard.adapters._snapshot.freeze()` every other adapter now uses (see finding 2)."""

    def test_snapshot_params_never_aliases_a_custom_deepcopy_that_returns_itself(self):
        from attenu_guard.adapters.langgraph import _snapshot_params

        class AliasingList(list):
            def __deepcopy__(self, memo):
                return self

        live_kwargs = {"x": AliasingList([1])}
        snapshot = _snapshot_params((), live_kwargs)

        self.assertIsNot(snapshot["kwargs"]["x"], live_kwargs["x"],
                         "the snapshot aliased the live container")
        live_kwargs["x"].append(2)
        self.assertEqual(snapshot["kwargs"]["x"], [1],
                         "mutating the live container changed the snapshot")

    def test_a_callable_that_mutates_its_own_input_does_not_cause_a_params_mismatch(self):
        # End-to-end through the real guard_node wrapper, not just the snapshot helper directly
        # -- the same class of test every other adapter's own "does not cause a params
        # mismatch" test runs, applied to the module Codex found had none.
        guard = _make_v2_tool_guard()
        seen = {}

        @guard_node(guard, "crm.read", context_fn=lambda payload: {"rows": payload.get("rows", 0)})
        def summarize(payload):
            seen["at_call_time"] = dict(payload)
            payload["mutated"] = True  # mutate the wrapper's own input in place
            return {"ok": True}

        arg = {"rows": 1}
        summarize(arg)
        self.assertEqual(seen["at_call_time"], {"rows": 1})  # the body saw it BEFORE mutation
        self.assertTrue(arg["mutated"])  # the mutation still happened
        entries = guard.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow")
        outcome = next(e for e in entries if e["event"] == "outcome")
        # both hashes come from the SAME pre-invocation snapshot -- no false mismatch
        self.assertEqual(allow["authorized_params_hash"], outcome["invoked_params_hash"])

    def test_snapshot_params_does_not_raise_on_a_circular_container(self):
        # Finding 2's own correction: the shared sanitizer's PATH-ACTIVE cycle tracking means a
        # self-referential argument is reported as the sanitizer's UNSUPPORTED sentinel instead
        # of raising RecursionError or silently producing an unserializable self-referential
        # dict. Verified directly (not assumed): stdlib copy.deepcopy has its own memo-based
        # cycle handling, so raw deepcopy(circular) succeeds and even produces a correctly
        # self-referential COPY -- meaning the OLD raw-deepcopy code in this exact file would
        # NOT have raised on this input, but every OTHER adapter's pre-consolidation hand-rolled
        # `_freeze()` (never routed through deepcopy at all) genuinely DID raise RecursionError
        # on it -- what the CHANGELOG's old "never raises" claim was wrong about. This test pins
        # the shared sanitizer's now-correct, now-consistent behaviour here too.
        #
        # Re-gate correction: this used to assert the literal string "<circular>" -- itself a
        # commitment-collision defect (a plain dict holding that exact string would freeze
        # identically to a genuine cycle). The sanitizer's UNSUPPORTED sentinel replaced it; see
        # attenu_guard.adapters._snapshot's own module docstring.
        from attenu_guard.adapters._snapshot import UNSUPPORTED
        from attenu_guard.adapters.langgraph import _snapshot_params

        circular = {"note": "before"}
        circular["self"] = circular
        snapshot = _snapshot_params((circular,), {})
        self.assertIs(snapshot["args"][0]["self"], UNSUPPORTED)

    def test_freeze_never_invokes_a_hostile_repr(self):
        # Re-gate finding (HIGH, symmetry with the TS adapter's own re-gate fix): the shared
        # sanitizer used to call repr(value) on anything it could not rebuild as a container --
        # a hostile class's own __repr__ override ran unconditionally, BEFORE authorization was
        # ever decided. Reproduced directly before this fix: a class whose __repr__ incremented
        # a counter and returned a plausible string had that __repr__ genuinely execute.
        from attenu_guard.adapters._snapshot import UNSUPPORTED, freeze

        calls = 0

        class Hostile:
            def __repr__(self):
                nonlocal calls
                calls += 1
                return "leaked"

        frozen = freeze({"arg": Hostile()})

        self.assertEqual(calls, 0)
        self.assertIs(frozen["arg"], UNSUPPORTED)

    def test_freeze_does_not_let_a_hostile_object_collide_with_the_old_sentinel_string(self):
        # Re-gate finding (HIGH): the pre-fix except-fallback was the literal string
        # f"<unrepresentable {type(value).__name__}>" -- a real dict value that happened to
        # equal that exact string froze to itself unchanged, producing the IDENTICAL frozen
        # shape (and therefore commitment) as the exotic value it was meant to stand in for.
        # Reproduced directly before this fix: freeze({"arg": Explodes()}) and
        # freeze({"arg": "<unrepresentable Explodes>"}) produced the exact same output. Both are
        # frozen here and asserted NOT to collide any more.
        from attenu_guard.adapters._snapshot import freeze

        class Explodes:
            def __repr__(self):
                raise RuntimeError("boom")

        frozen_hostile = freeze({"arg": Explodes()})
        frozen_literal = freeze({"arg": "<unrepresentable Explodes>"})
        self.assertNotEqual(frozen_hostile["arg"], frozen_literal["arg"])
        self.assertEqual(frozen_literal["arg"], "<unrepresentable Explodes>")  # a real string stays a real string

    def test_freeze_routes_bytes_to_the_same_marker(self):
        # bytes is outside the params_c14n_v1 JSON domain regardless -- canonical.dumps already
        # rejects it (no `bytes` case in its exact-type dispatch) -- so this is a no-op for the
        # final commit outcome; it only stops the raw snapshot from retaining a live bytes
        # reference for no purpose. No shipped adapter inspects the raw snapshot for anything
        # besides handing it to params.commit() (checked directly across every adapter module).
        from attenu_guard.adapters._snapshot import UNSUPPORTED, freeze

        frozen = freeze({"arg": b"raw bytes"})
        self.assertIs(frozen["arg"], UNSUPPORTED)

    def test_a_guarded_node_with_a_hostile_argument_still_authorizes_and_runs_but_commits_no_hash(self):
        # End-to-end through the real guard_node wrapper -- the same shape as the TS adapter's
        # own wrapper-level regression tests for this exact finding. Policy evaluation still
        # fully controls whether the body runs; only the commitment is absent.
        guard = _make_v2_tool_guard()
        calls = 0

        class Hostile:
            def __repr__(self):
                nonlocal calls
                calls += 1
                return "leaked"

        @guard_node(guard, "crm.read", context_fn=lambda payload: {"rows": 1})
        def summarize(payload):
            return {"ok": True}

        result = summarize(Hostile())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(calls, 0)
        entries = guard.audit_log().entries
        allow = next(e for e in entries if e["event"] == "allow")
        outcome = next(e for e in entries if e["event"] == "outcome")
        self.assertNotIn("authorized_params_hash", allow)
        self.assertEqual(allow["params_hash_reason"], "unsupported")
        self.assertNotIn("invoked_params_hash", outcome)
        self.assertEqual(outcome["params_hash_reason"], "unsupported")


async def _await_it(coro):
    return await coro


if __name__ == "__main__":
    unittest.main(verbosity=2)
