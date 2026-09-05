# SPDX-License-Identifier: Apache-2.0
"""The gate for the commerce-agents recipe (examples/integrations/commerce-agents/).

Four tiers. COMPATIBILITY: the packages import, the adapter loads with them absent.
SEMANTIC: the upstream facts the recipe's claims rest on, each pinned to a commit and a
named module path -- these are the tests that fail when upstream moves under us, before
the README's file:line citations go stale. BEHAVIOUR: the side-effect oracle, narrowing,
the ceiling, and the bundle. BYPASS: the fail-closed edges.

The repo is not on any package index (its own CI asserts that); ``README.md`` has the
clone-and-editable-install lines.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("commerce_common")
pytest.importorskip("merchant_agent")
pytest.importorskip("merchant_agent_runtime")

from attenu_guard import Authority, Guard, SpendCap, evidence  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

#: The commit every file:line citation in README.md and in the adapter is stated against.
PINNED = {
    "repo": "anthropics/commerce-agents",
    "sha": "fd4d59224ab96b43c6dc6888207c67b3bd5a24cf",
    "paths": (
        "commerce-common/commerce_common/delegation.py (the contract, DelegationContext, DelegateExtension)",
        "commerce-common/commerce_common/execution.py (BaseToolExecutor.execute/dispatch/_run_delegate)",
        "merchant-agent/core/merchant_agent/executor.py (MerchantToolExecutor.handlers, components)",
        "merchant-agent/core/merchant_agent/analysis.py (ANALYSIS_READ_TOOLS)",
        "merchant-agent/core/merchant_agent/config.py (max_campaign_budget)",
        "merchant-agent/runtime-messages-api/merchant_agent_runtime/analysis.py (AnalysisRunner)",
    ),
}

_EXAMPLE = (Path(__file__).resolve().parents[2] / "examples" / "integrations" / "commerce-agents")
_spec = importlib.util.spec_from_file_location("attenu_commerce_demo", _EXAMPLE / "demo.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)  # type: ignore[union-attr]

sys.path.insert(0, str(_EXAMPLE))
import attenu_commerce as adapter  # noqa: E402


@pytest.fixture(autouse=True)
def _no_installation_leaks():
    """Fail loudly if a test leaves the class patch on, rather than poisoning the next.

    :returns: ``None``.
    """
    yield
    assert not adapter._INSTALLED_ROOT, "a test left install() active"


def _root(**kwargs) -> Guard:
    """A fresh chain root holding the operator's whole surface.

    :param kwargs: Overrides for ``Guard.issue``.
    :returns: The root guard.
    """
    return Guard.issue("merchant-turn", demo.OPERATOR_AUTHORITY, task="test",
                       chain_id="t", **kwargs)


def _executor(backend, config, session, **kwargs):
    """A MerchantToolExecutor over the demo store.

    :param backend: The store.
    :param config: The deployment config.
    :param session: The session context.
    :param kwargs: Extra ``MerchantToolExecutor`` arguments.
    :returns: The executor.
    """
    from commerce_common.skills import SkillRegistry
    from merchant_agent import MerchantSessionState
    from merchant_agent.executor import MerchantToolExecutor

    return MerchantToolExecutor(
        backend=backend, config=config, skills=SkillRegistry([]), session=session,
        state=kwargs.pop("state", None) or MerchantSessionState(), **kwargs)


# ---- tier 1: compatibility -------------------------------------------------------------

def test_compat_packages_importable_and_versions_known():
    import importlib.metadata

    for name in ("commerce-common", "merchant-agent-core", "merchant-agent-runtime"):
        version = importlib.metadata.version(name)
        assert version, f"{name} not installed"
        print(f"{name} {version} (pinned story: {PINNED['repo']}@{PINNED['sha'][:7]})")


def test_compat_adapter_imports_with_commerce_absent(monkeypatch):
    """The adapter module must load where commerce-agents is not importable.

    Only ``install()`` and the hook body touch ``commerce_common``, both lazily.
    """
    for name in [m for m in sys.modules if m == "commerce_common" or m.startswith("commerce_common.")]:
        monkeypatch.setitem(sys.modules, name, None)
    spec = importlib.util.spec_from_file_location("attenu_commerce_isolated",
                                                  _EXAMPLE / "attenu_commerce.py")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves a string annotation through sys.modules[cls.__module__].
    monkeypatch.setitem(sys.modules, "attenu_commerce_isolated", module)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    assert callable(module.guard_executor)
    assert module.AUTHORITY_GATE == "authority"


def test_compat_policy_covers_the_whole_merchant_surface():
    """Every name the executor can route must have a policy entry, or the recipe holds a
    tool the repo ships."""
    from commerce_common.execution import LOAD_SKILL
    from merchant_agent.enrichment import PRESENTATION_COMPONENTS

    executor = _executor(demo.DemoBackend(demo.new_config()), demo.new_config(), demo.new_session())
    routable = (
        set(executor._handlers)
        | set(PRESENTATION_COMPONENTS)
        | {LOAD_SKILL}
    )
    assert routable <= set(demo.POLICY), sorted(routable - set(demo.POLICY))


# ---- tier 2: the upstream facts the story rests on --------------------------------------

def test_semantic_execute_routes_through_dispatch():
    """``execute`` calls ``self.dispatch``, which is why replacing the instance attribute
    covers both entry points (execution.py:214-223)."""
    from commerce_common.execution import BaseToolExecutor

    body = inspect.getsource(BaseToolExecutor.execute)
    assert "await self.dispatch(" in body


def test_semantic_dispatch_is_the_single_routing_point():
    """Presentation, delegates and handlers are all routed from ``dispatch``
    (execution.py:236-243), so one hook covers the whole surface."""
    from commerce_common.execution import BaseToolExecutor

    body = inspect.getsource(BaseToolExecutor.dispatch)
    for marker in ("self.components.get(name)", "self._extensions.get(name)",
                   "self._delegates.get(name)", "self._handlers.get(name)"):
        assert marker in body, marker


def test_semantic_delegate_gets_the_handles_an_executor_needs():
    """``DelegationContext`` carries backend, config, session and state
    (delegation.py:21-31) -- everything ``MerchantToolExecutor.__init__`` requires, which
    is why a delegate can build the executor its own calls go through."""
    from commerce_common.delegation import DelegationContext

    fields = set(DelegationContext.__dataclass_fields__)
    assert {"backend", "config", "session", "state"} <= fields


def test_semantic_the_delegates_executor_carries_the_write_and_present_surface():
    """The executor ``AnalysisRunner._read`` builds (analysis.py:332-339) is an ordinary
    ``MerchantToolExecutor``: the five stage tools, apply, discard and the three
    presentation components are all on it. Only the runner's own name test keeps them out.
    """
    executor = _executor(demo.DemoBackend(demo.new_config()), demo.new_config(), demo.new_session())
    assert {"stage_listing_update", "stage_price_update", "stage_inventory_action",
            "stage_promotion", "stage_campaign", "apply_change",
            "discard_change"} <= set(executor._handlers)
    assert {"present_metrics", "present_digest",
            "present_change_preview"} <= set(executor.components)


def test_semantic_executor_class_is_a_documented_seam_on_the_orchestrator():
    """`executor_class` is what a deployment already passes to hand over its own executor
    subclass — so the class seam needs no new upstream API. Upstream asserts the same
    thing for all three consumption paths in
    `tests/test_consumption_paths.py::test_every_path_takes_a_deployments_own_executor_class`.
    """
    from merchant_agent_runtime.orchestrator import MerchantAgent

    assert "executor_class" in inspect.signature(MerchantAgent.__init__).parameters
    assert "executor_class" in (MerchantAgent.__doc__ or "")
    assert "self.executor_class(" in inspect.getsource(MerchantAgent)


def test_semantic_the_sdk_toolset_takes_it_too():
    """The Agent SDK path, when that package is installed."""
    pytest.importorskip("merchant_agent_sdk")
    from merchant_agent_sdk import merchant_tools

    source = inspect.getsource(merchant_tools)
    assert "executor_class: type[MerchantToolExecutor] = MerchantToolExecutor" in source
    assert "self.executor_class(" in source


def test_semantic_analysis_runner_takes_no_executor_class_today():
    """Why the README's diff needs its `AnalysisRunner.__init__` hunk: the constructor is
    keyword-only client/backend/config and never sets `self._executor_class`, so the
    `_read` change alone would raise TypeError then AttributeError."""
    from merchant_agent_runtime.analysis import AnalysisRunner, build_analysis_delegate

    parameters = inspect.signature(AnalysisRunner.__init__).parameters
    assert set(parameters) == {"self", "client", "backend", "config"}
    assert all(parameters[p].kind is inspect.Parameter.KEYWORD_ONLY
               for p in ("client", "backend", "config"))
    assert "_executor_class" not in inspect.getsource(AnalysisRunner.__init__)
    assert "executor_class" not in inspect.signature(build_analysis_delegate).parameters


def test_semantic_upstream_does_not_accept_contributions():
    """Pinned because the README says it: nothing in this recipe is offered upstream."""
    repo = Path(inspect.getfile(
        importlib.import_module("commerce_common"))).resolve().parents[2]
    readme = (repo / "README.md").read_text() if (repo / "README.md").exists() else ""
    if not readme:
        pytest.skip("installed from a wheel; the repo README is not on disk")
    assert ("it is not maintained and does not accept contributions" in readme), (
        "upstream changed its contribution stance; re-read README.md and revisit "
        "'Where the seam stops'")


def test_semantic_the_delegate_is_the_one_path_that_ignores_executor_class():
    """The gap this recipe's ``install()`` covers, stated as a test: every other path
    routes through the deployment's ``executor_class``; the analysis delegate names the
    concrete class instead."""
    from merchant_agent_runtime.analysis import AnalysisRunner

    body = inspect.getsource(AnalysisRunner._read)
    assert "MerchantToolExecutor(" in body
    assert "executor_class" not in body


def test_the_class_seam_guards_and_holds_when_no_node_is_bound():
    from merchant_agent.executor import MerchantToolExecutor

    config, session = demo.new_config(), demo.new_session()
    backend = demo.DemoBackend(config)
    guarded_cls = adapter.guarded_executor_class(MerchantToolExecutor, demo.POLICY)
    assert issubclass(guarded_cls, MerchantToolExecutor)
    tools = _executor(backend, config, session)
    tools.__class__ = guarded_cls  # same constructor arguments; only dispatch differs

    held = asyncio.run(tools.execute("get_business_snapshot", {}))
    assert held.blocked == adapter.AUTHORITY_GATE

    root = _root()

    async def inside():
        with adapter.authorize_as(root):
            return await tools.execute("get_business_snapshot", {})

    assert not asyncio.run(inside()).refused
    # and the binding does not outlive the block
    assert asyncio.run(tools.execute("get_business_snapshot", {})).blocked == adapter.AUTHORITY_GATE

    adapter.bind(tools, root)
    assert not asyncio.run(tools.execute("get_business_snapshot", {})).refused


def test_the_class_seam_keeps_a_deployments_own_subclass_intact():
    """A deployment's subclass can be the base: only ``dispatch`` is overridden."""
    from merchant_agent.executor import MerchantToolExecutor

    class Wording(MerchantToolExecutor):
        unavailable_text = "{name} is switched off for maintenance."

    guarded_cls = adapter.guarded_executor_class(Wording, demo.POLICY)
    assert guarded_cls.unavailable_text == "{name} is switched off for maintenance."
    assert guarded_cls.__name__ == "GuardedWording"
    assert set(guarded_cls.__dict__) - {"__doc__", "__module__", "__qualname__"} == {"dispatch"}


def test_semantic_the_shipped_runner_builds_its_own_executor():
    """``AnalysisRunner._read`` names ``MerchantToolExecutor`` inside the method and keeps
    no reference outside it -- the reason ``install()`` exists beside ``guard_executor``."""
    from merchant_agent_runtime.analysis import AnalysisRunner

    body = inspect.getsource(AnalysisRunner._read)
    assert "MerchantToolExecutor(" in body
    assert "MerchantSessionState()" in body  # the scratch state


def test_semantic_the_write_ladder_is_the_runners_own():
    """What keeps a write out of the shipped delegate today is a name test in its runner
    (analysis.py:361), not anything on the dispatch point."""
    from merchant_agent_runtime.analysis import AnalysisRunner

    assert "if name in ANALYSIS_READ_TOOLS:" in inspect.getsource(AnalysisRunner._execute)


def test_semantic_analysis_read_tools_is_the_four_reads():
    from merchant_agent.analysis import ANALYSIS_READ_TOOLS

    assert ANALYSIS_READ_TOOLS == ("get_business_snapshot", "query_metrics",
                                   "get_campaign_performance", "search_listings")


def test_semantic_campaign_budget_is_a_deployment_number():
    """``max_campaign_budget`` is on the config the delegate shares (config.py:57) and is
    checked by ``check_guardrails`` (changes.py:101-107): the same limit for the operator
    and for anything running under them."""
    from merchant_agent import MerchantAgentConfig
    from merchant_agent.changes import ChangeItem, ChangeKind, check_guardrails

    config = MerchantAgentConfig()
    assert config.max_campaign_budget == 10_000.0
    item = ChangeItem(target="cmp-1", field="budget", before=None, after=5_000.0)
    assert check_guardrails(ChangeKind.CAMPAIGN, [item], config) == []
    over = ChangeItem(target="cmp-1", field="budget", before=None, after=10_001.0)
    assert check_guardrails(ChangeKind.CAMPAIGN, [over], config)


# ---- tier 3: behaviour ------------------------------------------------------------------

def test_the_oracle_reads_side_effects_not_tool_results():
    """The three signals are store-side or body-side, none of them the tool result.

    `staged` is a `ChangeLedger.pending()` diff; `peer_ran` is set inside the peer
    delegate's own `run`; `presented` is set inside the component's `enrich` hook, which
    `run_presentation` awaits — so it records only when the presentation body was entered.
    """
    from merchant_agent.enrichment import PRESENTATION_COMPONENTS
    from merchant_agent.tools.presentation import PREVIEW_TOOL

    original = PRESENTATION_COMPONENTS[PREVIEW_TOOL]
    effects = demo.Effects()
    with demo.observing_presentation(effects):
        swapped = PRESENTATION_COMPONENTS[PREVIEW_TOOL]
        assert swapped is not original
        assert swapped.enrich is not original.enrich
        # everything else about the component is the repo's own
        assert (swapped.name, swapped.component, swapped.payload_model) == (
            original.name, original.component, original.payload_model)
        assert swapped.enrich_partial is original.enrich_partial
    assert PRESENTATION_COMPONENTS[PREVIEW_TOOL] is original, "the swap must be restored"
    assert effects.presented == [], "nothing was presented, so nothing is recorded"


def test_the_unguarded_delegate_writes_presents_and_calls_a_delegate():
    """The oracle for everything below: with nothing installed, all three bodies run."""
    config, session = demo.new_config(), demo.new_session()
    backend, effects = demo.DemoBackend(config), demo.Effects()
    peer = demo.peer_delegate(effects)
    delegate = demo.report_delegate(backend, effects, peer)
    _seed(backend, session)
    tools = _executor(backend, config, session, delegates=(delegate, peer))

    with demo.observing_presentation(effects):
        asyncio.run(tools.execute("draft_report", {"topic": "slow movers"}))
    assert effects.staged, "the write did not reach the store"
    assert effects.presented, "the presentation body did not run"
    assert effects.peer_ran, "the nested delegate did not run"


def test_guarded_the_three_forbidden_calls_are_held_before_the_body():
    config, session = demo.new_config(), demo.new_session()
    backend, effects = demo.DemoBackend(config), demo.Effects()
    peer = demo.peer_delegate(effects)
    delegate = demo.report_delegate(backend, effects, peer)
    _seed(backend, session)
    root = _root()
    grant = adapter.DelegateGrant("report", frozenset({"listing.read", "change.read"}), ttl=900)
    tools = _executor(backend, config, session, delegates=(delegate, peer))

    with demo.observing_presentation(effects), adapter.install(
            demo.POLICY, {"draft_report": grant}, root=root):
        asyncio.run(tools.execute("draft_report", {"topic": "slow movers"}))

    assert effects.staged == [], "a write reached the store"
    assert effects.presented == [], "a presentation rendered"
    assert not effects.peer_ran, "a nested delegate ran"

    denied = [e for e in root.audit_log().entries if e["event"] == "deny"]
    assert {e["tool"] for e in denied} == {"stage_price_update", "present_change_preview",
                                           "note_finding"}
    assert all(e["node"] != root.node_id for e in denied), "denials must sit on the CHILD node"


def test_the_child_is_a_subset_of_the_parent_and_the_spawn_records_both():
    root = _root()
    grant = adapter.DelegateGrant.from_tools(
        "analysis", ["query_metrics", "search_listings"], demo.POLICY, ttl=900)
    assert grant.scopes == {"metrics.read", "listing.read"}

    child = root.delegate(grant.agent_id, grant.authority(), "brief")
    assert child.is_narrower_than(root)
    assert child.authority.scopes < set(root.authority.scopes) | child.authority.scopes

    spawn = [e for e in root.audit_log().entries if e["event"] == "spawn"][0]
    assert set(spawn["requested"]["scopes"]) == {"metrics.read", "listing.read"}
    assert set(spawn["granted"]["scopes"]) == {"metrics.read", "listing.read"}


def test_a_grant_that_asks_for_more_than_the_parent_holds_gets_the_parent_s():
    """``delegate()`` takes the meet, so an over-broad request cannot widen a child."""
    root = Guard.issue("parent", Authority(scopes={"listing.read"}, ttl=900), chain_id="t")
    child = root.delegate("greedy", Authority(scopes={"listing.read", "change.apply"}, ttl=900),
                          task="brief")
    assert set(child.authority.scopes) == {"listing.read"}
    spawn = [e for e in root.audit_log().entries if e["event"] == "spawn"][0]
    assert set(spawn["requested"]["scopes"]) == {"listing.read", "change.apply"}
    assert set(spawn["granted"]["scopes"]) == {"listing.read"}


def test_the_shipped_analysis_delegate_runs_under_the_child_node():
    """The real ``AnalysisRunner``, offline: its reads authorize as the child, and the one
    the operator withheld is denied mid-run."""
    from merchant_agent.analysis import ANALYSIS_TOOL
    from merchant_agent_runtime.analysis import build_analysis_delegate

    config, session = demo.new_config(), demo.new_session()
    backend = demo.DemoBackend(config)
    root = _root()
    grant = adapter.DelegateGrant.from_tools(
        "analysis", ["get_business_snapshot", "query_metrics", "search_listings"],
        demo.POLICY, ttl=900)
    delegate = build_analysis_delegate(demo.analysis_script(), backend, config)
    tools = _executor(backend, config, session, delegates=(delegate,))

    with adapter.install(demo.POLICY, {ANALYSIS_TOOL: grant}, root=root):
        outcome = asyncio.run(tools.execute(ANALYSIS_TOOL, {"question": "what moved sales?"}))
    assert not outcome.refused, outcome.result_text

    entries = root.audit_log().entries
    child_id = [e for e in entries if e["event"] == "spawn"][0]["node"]
    allowed = [e for e in entries if e["event"] == "allow" and e["node"] == child_id]
    denied = [e for e in entries if e["event"] == "deny" and e["node"] == child_id]
    assert [e["tool"] for e in allowed] == ["query_metrics"]
    assert [e["tool"] for e in denied] == ["get_campaign_performance"]
    assert denied[0]["reason"] == "scope_not_granted"


def test_a_childs_ceiling_can_be_lower_and_never_higher():
    from merchant_agent import MerchantAgentConfig

    config, session = demo.new_config(), demo.new_session()
    backend = demo.DemoBackend(config)
    root = _root()
    draft = {"name": "Autumn", "objective": "Lift revenue", "budget": 5_000.0}

    operator = adapter.guard_executor(_executor(backend, config, session), root, demo.POLICY)
    assert not asyncio.run(operator.execute("stage_campaign", dict(draft))).refused

    drafter = root.delegate("drafter", Authority(scopes={"campaign.stage"},
                                                 ceilings=[SpendCap(2_000)], ttl=900), task="draft")
    child_tools = adapter.guard_executor(_executor(backend, config, session), drafter, demo.POLICY)
    held = asyncio.run(child_tools.execute("stage_campaign", dict(draft)))
    assert held.blocked == adapter.AUTHORITY_GATE
    # The request the chain refused is one the deployment's own guardrail passes.
    assert draft["budget"] < MerchantAgentConfig().max_campaign_budget

    # A child asking for MORE than the parent's cap gets the parent's.
    greedy = root.delegate("greedy", Authority(scopes={"campaign.stage"},
                                               ceilings=[SpendCap(50_000)], ttl=900), task="draft")
    assert greedy.authority.ceiling("max_spend").max_spend == config.max_campaign_budget


def test_the_run_verifies_offline_and_a_widened_grant_does_not():
    from merchant_agent.analysis import ANALYSIS_TOOL
    from merchant_agent_runtime.analysis import build_analysis_delegate
    from attenu_guard import AuditLog

    config, session = demo.new_config(), demo.new_session()
    backend = demo.DemoBackend(config)
    root = _root()
    grant = adapter.DelegateGrant.from_tools(
        "analysis", ["get_business_snapshot", "query_metrics", "search_listings"],
        demo.POLICY, ttl=900)
    delegate = build_analysis_delegate(demo.analysis_script(), backend, config)
    tools = _executor(backend, config, session, delegates=(delegate,))
    with adapter.install(demo.POLICY, {ANALYSIS_TOOL: grant}, root=root):
        asyncio.run(tools.execute(ANALYSIS_TOOL, {"question": "what moved sales?"}))

    signer = HS256TestSigner(b"demo-key", kid="demo")
    bundle = evidence.export_bundle(root.audit_log(), signer)
    report = evidence.verify_bundle(bundle, signer)
    assert report["ok"], report["failures"]
    assert report["checks"]["monotonicity"] is True
    assert report["checks"]["containment"] is True

    # The bundle alone carries the chain a reviewer reads.
    graph = evidence.delegation_graph(bundle)
    assert len(graph["nodes"]) == 2 and len(graph["edges"]) == 1
    assert [d["tool"] for d in evidence.denials(bundle)] == ["get_campaign_performance"]

    # Widen the child's grant, re-hash and re-sign: integrity green, monotonicity red.
    widened = AuditLog(None)
    for entry in json.loads(json.dumps(bundle))["entries"]:
        fields = {k: v for k, v in entry.items()
                  if k not in ("event", "seq", "ts", "hash", "prev_hash", "v")}
        if entry["event"] == "spawn":
            fields["granted"]["scopes"] = sorted(set(fields["granted"]["scopes"]) | {"billing.refund"})
        widened.append(entry["event"], entry["seq"], **fields)
    broken = evidence.verify_bundle(evidence.export_bundle(widened, signer), signer)
    assert broken["checks"]["integrity"] is True
    assert broken["checks"]["anchor"] == "verified"
    assert broken["checks"]["monotonicity"] is False
    assert broken["ok"] is False


# ---- tier 4: the fail-closed edges -------------------------------------------------------

def test_an_unmapped_tool_is_held_and_recorded():
    config, session = demo.new_config(), demo.new_session()
    root = _root()
    tools = adapter.guard_executor(
        _executor(demo.DemoBackend(config), config, session), root, {"search_listings": demo.POLICY["search_listings"]})
    held = asyncio.run(tools.execute("get_business_snapshot", {}))
    assert held.blocked == adapter.AUTHORITY_GATE
    denied = [e for e in root.audit_log().entries if e["event"] == "deny"]
    assert denied[0]["reason"] == "no_authority" and denied[0]["disposition"] == "unresolved"


def test_a_delegate_with_no_grant_is_held_and_never_runs():
    config, session = demo.new_config(), demo.new_session()
    backend, effects = demo.DemoBackend(config), demo.Effects()
    peer = demo.peer_delegate(effects)
    root = _root()
    tools = adapter.guard_executor(
        _executor(backend, config, session, delegates=(peer,)), root, demo.POLICY)
    held = asyncio.run(tools.execute("note_finding", {}))
    assert held.blocked == adapter.AUTHORITY_GATE
    assert not effects.peer_ran
    assert [e["reason"] for e in root.audit_log().entries if e["event"] == "deny"] == ["no_authority"]


def test_an_executor_with_no_guard_is_held_not_allowed():
    config, session = demo.new_config(), demo.new_session()
    tools = _executor(demo.DemoBackend(config), config, session)
    with adapter.install(demo.POLICY, {}, root=None):
        held = asyncio.run(tools.execute("get_business_snapshot", {}))
    assert held.blocked == adapter.AUTHORITY_GATE
    assert "no authority is bound" in held.result_text


def _allow_count(root) -> int:
    """How many ``allow`` entries the chain holds.

    :param root: The chain's root node.
    :returns: The count.
    """
    return len([e for e in root.audit_log().entries if e["event"] == "allow"])


def test_guarding_one_executor_twice_is_refused():
    config, session = demo.new_config(), demo.new_session()
    root = _root()
    tools = adapter.guard_executor(
        _executor(demo.DemoBackend(config), config, session), root, demo.POLICY)
    with pytest.raises(ValueError, match="already authorizes"):
        adapter.guard_executor(tools, root, demo.POLICY)


def test_guard_executor_over_a_guarded_class_instance_is_refused():
    """RED before the fix: this combination was accepted and wrote two `allow` entries
    for every tool call, because the instance carries no bookkeeping attribute of ours."""
    from merchant_agent.executor import MerchantToolExecutor

    config, session = demo.new_config(), demo.new_session()
    root = _root()
    guarded_cls = adapter.guarded_executor_class(MerchantToolExecutor, demo.POLICY)
    tools = _executor(demo.DemoBackend(config), config, session)
    tools.__class__ = guarded_cls

    with pytest.raises(ValueError, match="already authorizes"):
        adapter.guard_executor(tools, root, demo.POLICY)

    # One authorizer, one entry per call.
    adapter.bind(tools, root)
    asyncio.run(tools.execute("get_business_snapshot", {}))
    assert _allow_count(root) == 1


def test_a_guarded_class_over_a_guarded_class_is_refused():
    """The other direction: the base already authorizes, so the subclass would double it."""
    from merchant_agent.executor import MerchantToolExecutor

    once = adapter.guarded_executor_class(MerchantToolExecutor, demo.POLICY)
    with pytest.raises(ValueError, match="already authorizes"):
        adapter.guarded_executor_class(once, demo.POLICY)


def test_a_guarded_class_built_while_an_installation_is_active_is_refused():
    """`install()` patches the base, so a subclass built after it would call inward to
    the installed hook and authorize twice."""
    from merchant_agent.executor import MerchantToolExecutor

    with adapter.install(demo.POLICY, {}, root=_root()):
        with pytest.raises(ValueError, match="already authorizes"):
            adapter.guarded_executor_class(MerchantToolExecutor, demo.POLICY)


def test_installing_over_a_class_that_already_authorizes_is_refused():
    from merchant_agent.executor import MerchantToolExecutor

    guarded_cls = adapter.guarded_executor_class(MerchantToolExecutor, demo.POLICY)
    with pytest.raises(ValueError, match="already authorizes"):
        adapter.install(demo.POLICY, {}, root=_root(), executor_cls=guarded_cls)


def test_a_guarded_class_built_before_install_still_authorizes_once():
    """The benign order, asserted so it is not "fixed" into a refusal: the subclass holds
    a direct reference to the dispatch it captured, so the later class patch is not in
    its path."""
    from merchant_agent.executor import MerchantToolExecutor

    config, session = demo.new_config(), demo.new_session()
    root = _root()
    guarded_cls = adapter.guarded_executor_class(MerchantToolExecutor, demo.POLICY)
    tools = _executor(demo.DemoBackend(config), config, session)
    tools.__class__ = guarded_cls
    adapter.bind(tools, root)

    with adapter.install(demo.POLICY, {}, root=root):
        asyncio.run(tools.execute("get_business_snapshot", {}))
    assert _allow_count(root) == 1


def test_the_child_binding_is_dropped_when_the_delegate_returns():
    """A delegate body must not leave its narrower guard bound for the next tool call."""
    config, session = demo.new_config(), demo.new_session()
    backend, effects = demo.DemoBackend(config), demo.Effects()
    peer = demo.peer_delegate(effects)
    root = _root()
    grant = adapter.DelegateGrant("note", frozenset({"listing.read"}), ttl=900)
    tools = adapter.guard_executor(
        _executor(backend, config, session, delegates=(peer,)), root, demo.POLICY,
        {"note_finding": grant})

    async def run():
        await tools.execute("note_finding", {})
        assert adapter.current_guard() is None
        # The parent's own surface is intact afterwards.
        return await tools.execute("get_business_snapshot", {})

    assert not asyncio.run(run()).refused
    assert effects.peer_ran


def test_install_restores_the_class_on_exit():
    from commerce_common.execution import BaseToolExecutor

    original = BaseToolExecutor.dispatch
    with adapter.install(demo.POLICY, {}, root=_root()):
        assert BaseToolExecutor.dispatch is not original
    assert BaseToolExecutor.dispatch is original


def test_two_installations_at_once_are_refused():
    handle = adapter.install(demo.POLICY, {}, root=_root())
    try:
        with pytest.raises(ValueError, match="already active"):
            adapter.install(demo.POLICY, {}, root=_root())
    finally:
        handle.uninstall()


def test_a_revoked_parent_cannot_delegate_and_the_refusal_is_recorded():
    config, session = demo.new_config(), demo.new_session()
    backend, effects = demo.DemoBackend(config), demo.Effects()
    peer = demo.peer_delegate(effects)
    root = _root()
    grant = adapter.DelegateGrant("note", frozenset({"listing.read"}), ttl=900)
    tools = adapter.guard_executor(
        _executor(backend, config, session, delegates=(peer,)), root, demo.POLICY,
        {"note_finding": grant})
    root.revoke()
    held = asyncio.run(tools.execute("note_finding", {}))
    assert held.blocked == adapter.AUTHORITY_GATE
    assert not effects.peer_ran


def test_from_tools_refuses_a_tool_nobody_mapped():
    with pytest.raises(KeyError, match="no policy entry"):
        adapter.DelegateGrant.from_tools("x", ["not_a_tool"], demo.POLICY)


def test_the_status_line_never_reaches_the_policy_context():
    """``dispatch`` splits ``status`` off before any handler runs (execution.py:231); the
    hook does the same, so the model's display line is not part of a ceiling decision."""
    seen: list[dict] = []
    config, session = demo.new_config(), demo.new_session()
    root = _root()
    policy = dict(demo.POLICY)
    policy["stage_campaign"] = adapter.ToolPolicy(
        "campaign.stage", context=lambda args: (seen.append(dict(args)), {"spend": args["budget"]})[1])
    tools = adapter.guard_executor(
        _executor(demo.DemoBackend(config), config, session), root, policy)
    asyncio.run(tools.execute("stage_campaign",
                              {"status": "drafting a campaign", "name": "A", "budget": 100.0}))
    assert seen and "status" not in seen[0]


def test_a_policy_context_that_raises_holds_the_call():
    """A broken policy entry must not reach ``execute``'s "temporarily unavailable" line,
    which would say the tool failed rather than that it was never authorized."""
    config, session = demo.new_config(), demo.new_session()
    root = _root()
    policy = dict(demo.POLICY)

    def explode(_args):
        raise RuntimeError("bad policy")

    policy["stage_campaign"] = adapter.ToolPolicy("campaign.stage", context=explode)
    backend = demo.DemoBackend(config)
    tools = adapter.guard_executor(_executor(backend, config, session), root, policy)
    held = asyncio.run(tools.execute("stage_campaign", {"name": "A", "budget": 100.0}))
    assert held.blocked == adapter.AUTHORITY_GATE
    assert "RuntimeError" in held.result_text
    assert backend.ledger.pending() == []
    assert [e["reason"] for e in root.audit_log().entries if e["event"] == "deny"] == ["no_authority"]


def _seed(backend, session) -> None:
    """Stage one change as the operator, so a delegate has something to try to present.

    :param backend: The store.
    :param session: The session context.
    :returns: ``None``.
    """
    from merchant_agent.changes import ChangeItem, ChangeKind
    from merchant_agent.types import ActorKind

    backend.ledger.stage(
        kind=ChangeKind.LISTING_UPDATE, summary="Rewrite the planter description",
        items=[ChangeItem(target="L-202", field="short_description",
                          before="Matte ceramic planter.", after="Matte ceramic planter, 6 inch.")],
        actor=session.operator, actor_kind=ActorKind.OPERATOR)
