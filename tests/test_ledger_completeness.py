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

_UNSET = object()

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


class CamelGateRunsWithoutTheFramework(unittest.TestCase):
    """`GuardedFunctionTool._authorize` is exercised here with no `camel-ai` installed.

    `adapters/camel.py` passed `tool=self.tool_name` to the shared context helper. That
    attribute exists on neither `GuardedFunctionTool` nor CAMEL's `FunctionTool` — every other
    site in the file calls `get_function_name()` — so the gate raised `AttributeError` on every
    guarded call. It shipped because CAMEL is not installed in the stdlib job and the sweep that
    introduced the line is a source-text test, which cannot see that a name is wrong.

    So the gate is driven here against a STRICT stub: a stand-in `FunctionTool` that defines
    exactly what the real one gives the adapter and nothing else. An attribute the adapter is
    not entitled to raises, exactly as it did on the real framework. `unittest.mock` is
    deliberately not used — a mock answers to any name, which is the one property that would
    make this test unable to fail."""

    def _install_stub_camel(self):
        """A minimal `camel` package in `sys.modules`, restored on cleanup."""
        class FunctionTool:
            """Stand-in for `camel.toolkits.FunctionTool`.

            Only the members `adapters/camel.py` legitimately uses. Anything else is an
            AttributeError, which is the point."""

            def __init__(self, func=None, openai_tool_schema=None):
                self.func = func
                self.openai_tool_schema = openai_tool_schema or {
                    "function": {"name": getattr(func, "__name__", "stub_tool")}}

            def get_function_name(self):
                return self.openai_tool_schema["function"]["name"]

            def __call__(self, *args, **kwargs):
                return self.func(*args, **kwargs)

            async def async_call(self, *args, **kwargs):
                return self.func(*args, **kwargs)

        class AgentToolkit:
            def __init__(self, *a, **kw):
                pass

            def agent_run_subagent(self, *a, **kw):
                """Stand-in for the delegation entry point the adapter subclasses; the
                adapter copies this docstring onto its own override."""
                raise NotImplementedError

        camel = types.ModuleType("camel")
        toolkits = types.ModuleType("camel.toolkits")
        agent_toolkit = types.ModuleType("camel.toolkits.agent_toolkit")
        toolkits.FunctionTool = FunctionTool
        agent_toolkit.AgentToolkit = AgentToolkit
        toolkits.agent_toolkit = agent_toolkit
        camel.toolkits = toolkits
        added = {"camel": camel, "camel.toolkits": toolkits,
                 "camel.toolkits.agent_toolkit": agent_toolkit}
        saved = {k: sys.modules.get(k) for k in added}
        saved["attenu_guard.adapters.camel"] = sys.modules.get("attenu_guard.adapters.camel")
        sys.modules.update(added)
        sys.modules.pop("attenu_guard.adapters.camel", None)

        def restore():
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        self.addCleanup(restore)
        import importlib
        return importlib.import_module("attenu_guard.adapters.camel")

    def _tool(self, camel_mod, guard, context_fn=None):
        def stub_tool(rows=1):
            return rows
        return camel_mod.GuardedFunctionTool(stub_tool, guard, "repo.read",
                                             context_fn=context_fn)

    def test_an_allowed_call_passes_through_the_gate(self):
        camel_mod = self._install_stub_camel()
        g = _root()
        tool = self._tool(camel_mod, g)
        self.assertEqual(tool(rows=3), 3)
        entry = g.audit_log().entries[-1]
        self.assertEqual((entry["event"], entry["scope"]), ("allow", "repo.read"))

    def test_the_gate_names_the_tool_it_is_authorizing(self):
        """The regression itself: the helper is called with the tool's real name."""
        camel_mod = self._install_stub_camel()
        g = _root()
        seen = {}

        def context_fn(**kwargs):
            return {"rows": kwargs.get("rows", 0)}

        tool = self._tool(camel_mod, g, context_fn=context_fn)
        real = camel_mod._safe_context

        def spy(guard, compute, *args, **kwargs):
            seen.update(tool=kwargs.get("tool"), scope=kwargs.get("scope"))
            return real(guard, compute, *args, **kwargs)

        camel_mod._safe_context = spy
        self.addCleanup(setattr, camel_mod, "_safe_context", real)
        tool(rows=2)
        self.assertEqual(seen["scope"], "repo.read")
        self.assertEqual(seen["tool"], "stub_tool",
                         "the gate must name the tool, not raise reaching for it")

    def test_a_raising_context_function_is_a_recorded_denial_not_an_attribute_error(self):
        """The path the broken attribute sat on. It must reach the helper's own handler and
        produce a `deny`, never an AttributeError from the gate itself."""
        camel_mod = self._install_stub_camel()
        g = _root()

        def boom(**kwargs):
            raise KeyError("rows")

        tool = self._tool(camel_mod, g, context_fn=boom)
        with self.assertRaises(AuthorityDenied):
            tool(rows=1)
        entry = g.audit_log().entries[-1]
        self.assertEqual(entry["event"], "deny")
        self.assertEqual(entry["reason"], ReasonCode.NO_AUTHORITY)
        self.assertEqual(entry["tool"], "stub_tool")
def _rehash(entries):
    """Re-chain a hand-built bundle so integrity passes and the CONTENT is what is under test."""
    from attenu_guard.audit import GENESIS, _hash
    prev = GENESIS
    for e in entries:
        e["prev_hash"] = prev
        e["hash"] = _hash(prev, {k: v for k, v in e.items() if k != "hash"})
        prev = e["hash"]
    return entries


class PolicyIsValidatedBeforeItExcusesContainment(unittest.TestCase):
    """`policy` is what makes the verifier SKIP the containment check on an `allow`, so the value
    that buys that exemption has to be checked — on every chain version, not only v2.

    Found reading the verifier for the 0.16.0 release. `verify_bundle` skipped containment for
    any `allow` whose `policy` was merely non-None, while the only place the value was validated
    (`_validate_allow`) runs inside `_execution_binding`, which returns early on a
    schema_version=1 bundle. So on a v1 chain `"policy": "anything-at-all"` — or `0`, or `""` —
    turned an out-of-authority action into an accepted bundle reporting `containment: True`. The
    published vectors say `unlisted` is the only value v1 defines; the reference verifier did not
    enforce it, and containment is the check the whole bundle exists to make."""

    def _v1_bundle_with(self, policy_value, scope="repo.write"):
        g = _root()
        g.check("repo.read", tool="read_file")
        signer = HS256TestSigner(secret=b"k", kid="k")
        bundle = export_bundle(g.audit_log(), signer)
        import copy
        forged = copy.deepcopy([e for e in bundle["entries"] if e["event"] == "allow"][0])
        forged["seq"] = len(bundle["entries"])
        forged["scope"] = scope                     # NOT held by the node
        if policy_value is not _UNSET:
            forged["policy"] = policy_value
        bundle["entries"].append(forged)
        _rehash(bundle["entries"])
        from attenu_guard import evidence as _ev
        bundle["anchor"] = _ev._anchor_for(bundle["entries"], signer)
        return verify_bundle(bundle, signer), signer

    def test_an_out_of_authority_allow_is_a_containment_failure_when_unmarked(self):
        # The control: without `policy`, this is exactly the violation containment exists for.
        report, _ = self._v1_bundle_with(_UNSET)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"]["containment"])

    def test_an_unknown_policy_value_does_not_buy_a_containment_exemption_on_v1(self):
        for bogus in ("totally-made-up", "", 0, False, []):
            with self.subTest(policy=bogus):
                report, _ = self._v1_bundle_with(bogus)
                self.assertFalse(
                    report["ok"],
                    f"policy={bogus!r} excused an out-of-authority allow on a v1 chain")
                self.assertEqual(report["ungated"], 0,
                                 "an invalid policy value is not an un-gated call")

    def test_the_one_defined_value_still_works_on_v1(self):
        # The behaviour the release ships must not move: a real passthrough is exempt.
        report, _ = self._v1_bundle_with(Policy.UNLISTED)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["ungated"], 1)
        self.assertEqual(report["actions_checked"], 1)

    def test_policy_is_an_allow_only_field_on_every_event(self):
        """`policy` says HOW an ALLOW came to be. On anything else it is meaningless, and the
        verifier accepted it silently on `outcome`, `spawn` and `root` (only `deny` was checked)."""
        g = _root(schema_version=2)
        child = g.delegate("worker", Authority(scopes={"repo.read"}, ttl=60), task="t")
        d = g.check("repo.read", tool="read_file", capture=Capture.WRAPPER_SYNC,
                    adapter={"module": "m", "version": "1", "hook_path": "h"})
        g.record_outcome(d.call_id, BodyState.RETURNED, duration_ms=1)
        signer = HS256TestSigner(secret=b"k", kid="k")
        base = export_bundle(g.audit_log(), signer)
        import copy
        from attenu_guard import evidence as _ev
        for event in ("outcome", "spawn", "root"):
            with self.subTest(event=event):
                bundle = copy.deepcopy(base)
                for e in bundle["entries"]:
                    if e["event"] == event:
                        e["policy"] = Policy.UNLISTED
                _rehash(bundle["entries"])
                bundle["anchor"] = _ev._anchor_for(bundle["entries"], signer)
                report = verify_bundle(bundle, signer)
                self.assertFalse(report["ok"],
                                 f"policy on a {event!r} entry was accepted")


class WitnessIsPerCallNotPerTool(unittest.TestCase):
    """The AstrBot gate's "did the body actually run?" flag is state on the shared tool object.

    `_BodyWitness` is built ONCE per tool, at install time, and `GuardedDelegation.call` does
    `witness.ran = False` -> await the body -> `if not witness.ran: record a refusal receipt`.
    AstrBot is a chat bot: two conversations, or one model turn with parallel tool calls, invoke
    the SAME tool object concurrently on the same loop. The flag then belongs to whichever call
    wrote it last, and the receipt says something untrue about a tamper-evident ledger in both
    directions — a refused call reported as if its body ran, or a call that ran reported as
    refused.

    A lock cannot fix it: the flag has the wrong LIFETIME, not the wrong guard. It has to be per
    invocation."""

    def _adapter(self):
        import importlib
        return importlib.import_module("attenu_guard.adapters.astrbot")

    def _tool(self, ab, name, body):
        # `handler` is the first branch `_invoke_tool` takes, and the only one that does not
        # import AstrBot itself — the adapter is exercised, the framework is not needed.
        tool = SimpleNamespace(name=name, description="", parameters={},
                               active=True, handler=body or (lambda _e, **k: "ok"))
        return ab._BodyWitness(tool)

    def _receipts(self, guard):
        return [e.get("receipt", {}).get("type")
                for e in guard.audit_log().entries if e["event"] == "outcome"]

    def test_a_refused_body_is_still_reported_when_another_call_ran_concurrently(self):
        ab = self._adapter()
        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        schema_version=2)
        guarded = ab.GuardedDelegation(g, tools={"read_file": ab.ToolPolicy("repo.read")})

        started_box: list = []            # the Event is created under the running loop (py3.9)

        async def slow_body(_event, **kwargs):
            started_box[0].set()
            await asyncio.sleep(0.05)          # A's body genuinely runs, and is still running
            return "ok"

        witness = self._tool(ab, "read_file", slow_body)

        async def run_a():
            return await guarded.call("read_file", {}, None,
                                      lambda: witness.call(None), tool=witness)

        async def run_b():
            # B is refused by a layer BETWEEN the gate and the body — AstrBot's own
            # `_PermissionGuardedTool` does exactly this. The body never runs.
            await started_box[0].wait()
            return await guarded.call("read_file", {}, None,
                                      lambda: "error: Permission denied.", tool=witness)

        async def main():
            started_box.append(asyncio.Event())
            return await asyncio.gather(run_a(), run_b())

        asyncio.run(main())
        receipts = self._receipts(g)
        self.assertIn("framework_refusal", receipts,
                      "the refused call left no refusal receipt: a concurrent call's body "
                      "cleared the shared flag")
        self.assertEqual(receipts.count("framework_refusal"), 1,
                         "exactly one of the two calls was refused")

    def test_strict_mode_does_not_record_a_refused_body_as_returned(self):
        """In strict mode `_run` closes the outcome BEFORE the witness is consulted, so the
        refusal receipt is dropped by a swallowed DuplicateOutcomeError and the ledger keeps an
        `outcome/returned` carrying `invoked_params` — an affirmative claim that the body was
        invoked with those arguments, which is the claim execution binding exists to make true."""
        ab = self._adapter()
        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        schema_version=2)
        guarded = ab.GuardedDelegation(g, tools={"read_file": ab.ToolPolicy("repo.read")},
                                       strict_single_hook=True)
        witness = self._tool(ab, "read_file", None)
        asyncio.run(guarded.call("read_file", {"path": "x"}, None,
                                 lambda: "error: Permission denied.", tool=witness))
        outcome = [e for e in g.audit_log().entries if e["event"] == "outcome"][-1]
        self.assertEqual(outcome.get("receipt", {}).get("type"), "framework_refusal",
                         "strict mode recorded a refused body as an ordinary return")
        self.assertNotIn("invoked_params_hash", outcome,
                         "the body never ran, so nothing was invoked with those arguments")


class SpawnNeverLeavesASubAgentOnTheParentsAuthority(unittest.TestCase):
    """OpenHands' `delegate` seam mints a child per sub-agent id AFTER the SDK has created the
    conversations. `guard.delegate()` can refuse there — a revoked or expired parent, a depth or
    fanout ceiling — and that call was the one delegation site in the adapter with no
    `except AuthorityError` around it (`_gate_delegation`, the other seam, has one).

    The refusal then escaped mid-loop with the sub-agent conversations already live and NOT
    bound to any child Guard. `active_guard(conversation)` falls back to `current_guard() or
    self.root`, so those sub-agents ran their tools on the PARENT's node with the parent's full
    authority. With ids `["a", "b"]` and a fanout of one, `a` was attenuated and `b` silently
    was not, which is the widening this library exists to prevent."""

    def _executor(self, guarded, sub_agents):
        class _Inner:
            def __init__(self):
                self._sub_agents = sub_agents

            def __call__(self, action, conversation=None):
                return SimpleNamespace(is_error=False, command=action.command)

        return guarded.delegate_executor(_Inner())

    def _guarded(self, max_children):
        import importlib
        oh = importlib.import_module("attenu_guard.adapters.openhands")
        root = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                           max_fanout=max_children)
        return oh, oh.GuardedDelegation(
            root, tools={"terminal": oh.ToolPolicy("repo.read")},
            subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=900)})

    def test_a_ceiling_refusal_mid_spawn_does_not_leave_a_sub_agent_on_the_root(self):
        oh, guarded = self._guarded(max_children=1)
        subs = {"a": SimpleNamespace(id="a"), "b": SimpleNamespace(id="b")}
        executor = self._executor(guarded, subs)
        action = SimpleNamespace(command="spawn", ids=["a", "b"],
                                 agent_types=["general-purpose", "general-purpose"])

        executor(action, None)                       # must not raise out of the tool executor

        # `b` is the one the ceiling refused. `terminal` is inside the ROOT's authority, so if
        # the fallback still hands it the root's Guard the call goes through — which is the
        # widening. It must be refused instead, and said so on the trail.
        ran = []
        with self.assertRaises(ValueError):          # the adapter's denial convention
            guarded.call("terminal", SimpleNamespace(),
                         lambda: ran.append(True), conversation=subs["b"])
        self.assertEqual(ran, [], "a sub-agent the chain refused ran a tool")
        last = guarded.root.audit_log().entries[-1]
        self.assertEqual(last["event"], "deny")

        # The control: `a` WAS minted, and is unaffected.
        guarded.call("terminal", SimpleNamespace(), lambda: ran.append("a"),
                     conversation=subs["a"])
        self.assertEqual(ran, ["a"])

    def test_the_refusal_is_on_the_ledger(self):
        oh, guarded = self._guarded(max_children=1)
        subs = {"a": SimpleNamespace(id="a"), "b": SimpleNamespace(id="b")}
        executor = self._executor(guarded, subs)
        executor(SimpleNamespace(command="spawn", ids=["a", "b"],
                                agent_types=["general-purpose", "general-purpose"]), None)
        events = [e["event"] for e in guarded.root.audit_log().entries]
        self.assertIn("spawn_denied", events,
                      "a delegation the chain refused must be on the trail")

    def test_a_spawn_within_the_ceiling_is_unchanged(self):
        oh, guarded = self._guarded(max_children=4)
        subs = {"a": SimpleNamespace(id="a"), "b": SimpleNamespace(id="b")}
        executor = self._executor(guarded, subs)
        executor(SimpleNamespace(command="spawn", ids=["a", "b"],
                                agent_types=["general-purpose", "general-purpose"]), None)
        for name in ("a", "b"):
            bound = guarded.active_guard(subs[name])
            self.assertIsNot(bound, guarded.root)
            self.assertEqual(sorted(bound.authority.scopes), ["repo.read"])


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
            witness.mark_ran()                              # what `_BodyWitness.call` does
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


class RevocationIsReportedBeforeFinalization(unittest.TestCase):
    """B19. Both are denials; the difference is which one a reader acts on.

    A node can be both finalized and revoked: an agent finishes its run, whatever records that
    marks the node complete, and the operator revokes it afterwards. Testing finalization first
    reported `node_finalized` for such a node — the refusal correct, the reason wrong, when
    `revoked` is the name the closed vocabulary already has for it. Nothing about WHETHER a call
    is refused changes; every published vector is byte-identical.
    """

    def _chain(self, chain_id):
        g = Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                        chain_id=chain_id, schema_version=2)
        return g, g.delegate("child", Authority(scopes={"repo.read"}, ttl=600), task="t")

    def test_a_revoked_and_finalized_node_reports_revoked(self):
        g, child = self._chain("b19a")
        child.complete()
        g.revoke(child.node_id)
        decision = child.check("repo.read", tool="read_file")
        self.assertFalse(decision)
        self.assertEqual(decision.reasons[0].code, ReasonCode.REVOKED)
        self.assertEqual(g.audit_log().entries[-1]["reason"], ReasonCode.REVOKED)

    def test_a_child_revoked_by_a_whole_chain_kill_reports_revoked(self):
        # `revoke()` does not finalize anything (checked, not assumed), so this one never hit the
        # bug — it is here so the cascade path cannot regress into it either.
        g, child = self._chain("b19b")
        g.revoke()
        self.assertEqual(child.check("repo.read", tool="read_file").reasons[0].code,
                         ReasonCode.REVOKED)

    def test_a_merely_finalized_node_still_reports_node_finalized(self):
        g, child = self._chain("b19c")
        child.complete()
        self.assertEqual(child.check("repo.read", tool="read_file").reasons[0].code,
                         ReasonCode.NODE_FINALIZED)

    def test_a_revoked_node_that_was_never_finalized_is_unchanged(self):
        g, child = self._chain("b19d")
        g.revoke(child.node_id)
        self.assertEqual(child.check("repo.read", tool="read_file").reasons[0].code,
                         ReasonCode.REVOKED)

    def test_both_states_still_refuse_the_call(self):
        # The property that must not move: a denial is a denial either way.
        for label, revoke, finalize in (("revoked+complete", True, True),
                                        ("complete", False, True),
                                        ("revoked", True, False)):
            with self.subTest(label):
                g, child = self._chain(f"b19-{label}")
                if finalize:
                    child.complete()
                if revoke:
                    g.revoke(child.node_id)
                self.assertFalse(child.check("repo.read", tool="read_file"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
