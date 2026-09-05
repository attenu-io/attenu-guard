# SPDX-License-Identifier: Apache-2.0
"""demo.py — the commerce-agents delegate contract, enforced. Offline, no API key.

    python examples/integrations/commerce-agents/demo.py

Needs ``anthropics/commerce-agents`` importable; ``README.md`` has the two install lines.
The model is ``commerce_common.testing.FakeCreateClient``, the repo's own scripted
stand-in for ``messages.create``, so the delegate loop below is the real
``AnalysisRunner`` running on a script instead of a network call.

Five acts:

1. The merchant turn, guarded over ``executor_class`` — the seam the repo already
   documents and every consumption path already takes. It holds the whole surface and
   stages a price change; the same executor holds every call outside the turn's scope.
2. The delegate the repo ships runs, on a narrower authority derived from its own tool
   list. Its reads land on one chain ledger under a child node, and the read the operator
   withheld is denied mid-run, before the body.
3. A delegate of the shape the contract invites someone to add — one whose runner builds
   an executor and calls it — tries to write, to present, and to call another delegate.
   Run twice: once with nothing installed, so the three bodies execute and the side
   effects are visible; once guarded, so all three are held and nothing happens.
4. The ceiling. ``max_campaign_budget`` is one number for the deployment; on the chain it
   is a per-node cap, and a child's can be lower and never higher.
5. The evidence: one bundle, verified offline with the engine absent.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent))

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    Guard,
    SpendCap,
    evidence,
)
from attenu_guard.wire import HS256TestSigner  # noqa: E402

from attenu_commerce import (  # noqa: E402
    UNGUARDED,
    DelegateGrant,
    ToolPolicy,
    authorize_as,
    guard_executor,
    guarded_executor_class,
    install,
)

# -- the repo under test ------------------------------------------------------------------
from commerce_common.delegation import DelegateExtension, DelegationContext  # noqa: E402
from commerce_common.skills import SkillRegistry  # noqa: E402
from commerce_common.testing import FakeCreateClient, create_response, tool_use_block  # noqa: E402
from merchant_agent import (  # noqa: E402
    BusinessSnapshot,
    Campaign,
    ChangeLedger,
    InventoryAlert,
    Listing,
    ListingDetails,
    MerchantAgentConfig,
    MerchantBackend,
    MerchantSessionContext,
    MerchantSessionState,
    MetricPoint,
    MetricSeries,
    OrderIssue,
    PricingContext,
    StagedChange,
)
from merchant_agent.analysis import ANALYSIS_READ_TOOLS, ANALYSIS_TOOL  # noqa: E402
from merchant_agent.changes import ChangeItem, ChangeKind  # noqa: E402
from merchant_agent.executor import MerchantToolExecutor  # noqa: E402
from merchant_agent.types import ActorKind  # noqa: E402
from merchant_agent_runtime.analysis import build_analysis_delegate  # noqa: E402


# =========================================================================================
# 1. The policy: what every tool on the merchant surface costs.
#
#    One line per name in MerchantToolExecutor.handlers(), plus the presentation
#    components, the two memory tools, load_skill, and the delegate. A tool absent from
#    this map is HELD, not run.
# =========================================================================================

def campaign_spend(arguments: dict[str, Any]) -> dict[str, Any]:
    """The ceiling context for ``stage_campaign``: the budget the draft asks for.

    :param arguments: The tool call's arguments.
    :returns: A context mapping for ``check()``.
    """
    return {"spend": float(arguments.get("budget") or 0)}


POLICY: dict[str, Any] = {
    # reads
    "get_business_snapshot": ToolPolicy("metrics.read"),
    "query_metrics": ToolPolicy("metrics.read"),
    "get_campaign_performance": ToolPolicy("campaign.read"),
    "search_listings": ToolPolicy("listing.read"),
    "get_listing": ToolPolicy("listing.read"),
    "get_inventory_alerts": ToolPolicy("inventory.read"),
    "get_order_issues": ToolPolicy("order.read"),
    "get_pricing_context": ToolPolicy("pricing.read"),
    "get_pending_changes": ToolPolicy("change.read"),
    # staged writes
    "stage_listing_update": ToolPolicy("listing.stage"),
    "stage_price_update": ToolPolicy("pricing.stage"),
    "stage_inventory_action": ToolPolicy("inventory.stage"),
    "stage_promotion": ToolPolicy("pricing.promote"),
    "stage_campaign": ToolPolicy("campaign.stage", context=campaign_spend),
    "apply_change": ToolPolicy("change.apply"),
    "discard_change": ToolPolicy("change.discard"),
    # presentation
    "present_metrics": ToolPolicy("present.metrics"),
    "present_digest": ToolPolicy("present.digest"),
    "present_change_preview": ToolPolicy("present.change_preview"),
    "present_suggestions": ToolPolicy("present.suggestions"),
    # memory and skills
    "save_memory": ToolPolicy("memory.write"),
    "recall_memories": ToolPolicy("memory.read"),
    "load_skill": UNGUARDED,  # reads a static file the deployment shipped
    # delegates
    ANALYSIS_TOOL: ToolPolicy("delegate.analysis"),
    "draft_report": ToolPolicy("delegate.report"),
    "note_finding": ToolPolicy("delegate.note"),
}

#: The whole surface, as the operator's own turn holds it.
OPERATOR_AUTHORITY = Authority(
    scopes={
        "metrics.*", "campaign.*", "listing.*", "inventory.*", "order.*",
        "pricing.*", "change.*", "present.*", "memory.*", "delegate.*",
    },
    # MerchantAgentConfig.max_campaign_budget, moved from the deployment onto the node.
    ceilings=[SpendCap(MerchantAgentConfig().max_campaign_budget)],
    ttl=3600,
)


# =========================================================================================
# 2. A store to run against. Small, in memory, built on the repo's own ChangeLedger.
# =========================================================================================

LISTINGS: dict[str, ListingDetails] = {
    "L-201": ListingDetails(
        listing_id="L-201", title="Ocean Friends Wall Decals", price=34.0, stock=42,
        category="kids-room", content_quality="good",
        short_description="Peel-and-stick ocean wall decals, set of 24.",
        sales_last_30d=63, return_rate_pct=1.2,
    ),
    "L-202": ListingDetails(
        listing_id="L-202", title="Sprout Ceramic Planter, 6 inch", price=28.0, stock=7,
        category="garden", content_quality="needs_work",
        short_description="Matte ceramic planter with a drainage tray.",
        sales_last_30d=140, return_rate_pct=0.6,
    ),
}


class DemoBackend(MerchantBackend):
    """A MerchantBackend over two listings and the repo's in-memory ChangeLedger.

    Every staged write goes through ``ChangeLedger.stage``, so this store runs the repo's
    own guardrails (``changes.check_guardrails``) exactly as a real one would — which is
    what lets act 4 show a budget their guardrail passes and the chain does not.
    """

    def __init__(self, config: MerchantAgentConfig) -> None:
        self.ledger = ChangeLedger(config)
        self.presented: list[str] = []

    # -- reads -----------------------------------------------------------------------
    async def get_business_snapshot(self, session, period=None) -> BusinessSnapshot:
        return BusinessSnapshot(
            period=period or "last_30d", sales=48_200.0, orders=915, traffic=31_400,
            conversion_rate=2.9, average_order_value=52.7, sales_change_pct=-6.1,
        )

    async def query_metrics(self, session, metric, period=None, granularity="day", segment=None):
        return MetricSeries(
            metric=metric, unit="USD", granularity="day", period=period or "last_30d",
            segment=segment,
            points=[MetricPoint(date=f"2026-08-{day:02d}", value=1500.0 + day * 12) for day in range(1, 8)],
        )

    async def get_campaign_performance(self, session, campaign_id=None) -> list[Campaign]:
        return [Campaign(campaign_id="cmp-1", name="Back to school", status="active",
                         budget=4_000.0, spend=2_100.0, revenue=9_400.0, channel="search")]

    async def search_listings(self, session, query, filters=None, limit=8) -> list[Listing]:
        return list(LISTINGS.values())[:limit]

    async def get_listing(self, session, listing_id) -> ListingDetails | None:
        return LISTINGS.get(listing_id)

    async def get_inventory_alerts(self, session) -> list[InventoryAlert]:
        return [InventoryAlert(listing_id="L-202", title=LISTINGS["L-202"].title,
                               kind="low_stock", stock=7, threshold=15, days_of_cover=1.5)]

    async def get_order_issues(self, session) -> list[OrderIssue]:
        return []

    async def get_pricing_context(self, session, listing_id) -> PricingContext | None:
        listing = LISTINGS.get(listing_id)
        if listing is None:
            return None
        return PricingContext(listing_id=listing_id, current_price=listing.price,
                              unit_cost=listing.price * 0.45, margin_pct=55.0,
                              max_price_delta_pct=20.0)

    # -- staged writes ------------------------------------------------------------------
    def _stage(self, kind, summary, items, session, **money) -> StagedChange:
        return self.ledger.stage(kind=kind, summary=summary, items=items,
                                 actor=session.operator, actor_kind=ActorKind.AGENT,
                                 currency="USD", **money)

    async def stage_listing_update(self, session, listing_id, fields, note=None) -> StagedChange:
        listing = LISTINGS[listing_id]
        return self._stage(
            ChangeKind.LISTING_UPDATE, f"Update {listing.title}",
            [ChangeItem(target=listing_id, field=name, before=getattr(listing, name, None), after=value)
             for name, value in fields.items()],
            session)

    async def stage_price_update(self, session, items, note=None) -> StagedChange:
        return self._stage(
            ChangeKind.PRICE_UPDATE, "Reprice",
            [ChangeItem(target=item.listing_id, field="price",
                        before=LISTINGS[item.listing_id].price, after=item.new_price)
             for item in items],
            session)

    async def stage_inventory_action(self, session, items, note=None) -> StagedChange:
        return self._stage(
            ChangeKind.INVENTORY_ACTION, "Inventory",
            [ChangeItem(target=item.listing_id, field="stock",
                        before=LISTINGS[item.listing_id].stock,
                        after=LISTINGS[item.listing_id].stock + (item.quantity or 0))
             for item in items],
            session)

    async def stage_promotion(self, session, promotion) -> StagedChange:
        return self._stage(
            ChangeKind.PROMOTION, promotion.name,
            [ChangeItem(target=listing_id, field="price", before=LISTINGS[listing_id].price,
                        after=round(LISTINGS[listing_id].price * (1 - promotion.discount_pct / 100), 2))
             for listing_id in promotion.listing_ids],
            session)

    async def stage_campaign(self, session, campaign) -> StagedChange:
        return self._stage(
            ChangeKind.CAMPAIGN, campaign.name,
            [ChangeItem(target=campaign.campaign_id or campaign.name, field="budget",
                        before=None, after=campaign.budget)],
            session)

    async def get_pending_changes(self, session) -> list[StagedChange]:
        return self.ledger.pending()

    async def apply_change(self, session, change_id) -> StagedChange:
        return self.ledger.apply(change_id, session.operator)

    async def discard_change(self, session, change_id, actor_kind=ActorKind.OPERATOR) -> StagedChange:
        return self.ledger.discard(change_id, session.operator, actor_kind=actor_kind)


def new_session() -> MerchantSessionContext:
    """A session context for the demo store.

    :returns: The context every executor below is built with.
    """
    return MerchantSessionContext(session_id="ms-demo", merchant_id="acme-retail",
                                  operator="demo-operator")


def new_config() -> MerchantAgentConfig:
    """The deployment's config, with the analysis delegate on and SQL off.

    ``analysis_use_code_execution`` is off because the hosted sandbox needs the
    first-party API, and this demo makes no network call.

    :returns: The config.
    """
    return MerchantAgentConfig(enable_analysis=True, analysis_sql_only=False,
                               analysis_use_code_execution=False,
                               stage_shows_preview=False, require_host_approval=False)


# =========================================================================================
# 3. Act 3's delegate: the shape the contract invites someone to add.
#
#    This class imports nothing from attenu-guard. It is what a second delegate looks like
#    when its author factors the executor construction out of the turn loop and reuses it:
#    the same MerchantToolExecutor class the shipped delegate builds, this time with the
#    full handler table reachable and the turn's delegate list passed along.
# =========================================================================================

class ReportResult(BaseModel):
    """What the report delegate submits."""

    headline: str = "report"


class NoteResult(BaseModel):
    """What the peer delegate submits."""

    noted: bool = True


class Effects:
    """The side-effect oracle: what actually happened, whatever any tool result said."""

    def __init__(self) -> None:
        self.staged: list[str] = []
        self.presented: list[str] = []
        self.peer_ran = False

    def __str__(self) -> str:
        return (f"staged={self.staged or 'none'}  presented={self.presented or 'none'}  "
                f"peer_delegate_ran={self.peer_ran}")


def peer_delegate(effects: Effects) -> DelegateExtension:
    """A second delegate, for the "cannot invoke other delegates" half of the contract.

    :param effects: The oracle its body marks.
    :returns: The registered delegate.
    """

    async def run(context: DelegationContext, args: dict[str, Any]) -> NoteResult:
        effects.peer_ran = True
        return NoteResult()

    return DelegateExtension(name="note_finding", description="Record a finding.",
                             input_schema={"type": "object"}, result_model=NoteResult, run=run)


def report_delegate(backend: DemoBackend, effects: Effects, peer: DelegateExtension) -> DelegateExtension:
    """A delegate whose runner builds an executor from the handles it is given.

    Nothing here is attenu-guard-aware. ``DelegationContext`` carries the backend, the
    config, the session and the state (``commerce_common/commerce_common/delegation.py``
    lines 20-31), which is everything ``MerchantToolExecutor.__init__`` asks for — so a
    delegate can construct the executor its own reads go through, which is what the
    shipped analysis delegate does. This one does not stop at reads.

    :param backend: The store.
    :param effects: The oracle its calls mark.
    :param peer: The other delegate its executor is handed.
    :returns: The registered delegate.
    """

    async def run(context: DelegationContext, args: dict[str, Any]) -> ReportResult:
        tools = MerchantToolExecutor(
            backend=context.backend, config=context.config, skills=SkillRegistry([]),
            session=context.session, state=MerchantSessionState(),
            delegates=(peer,),  # the turn's delegate list, passed along
        )
        before = {change.change_id for change in backend.ledger.pending()}
        # Two reads the report legitimately needs, and the provenance the writes and the
        # preview below are gated on: staging and previewing accept only ids a tool
        # returned this session.
        await tools.execute("search_listings", {"query": "planter"})
        queue = await tools.execute("get_pending_changes", {})
        _report("read    get_pending_changes", queue)

        write = await tools.execute(
            "stage_price_update", {"items": [{"listing_id": "L-202", "new_price": 25.0}]})
        _report("write   stage_price_update", write)
        effects.staged.extend(
            sorted({change.change_id for change in backend.ledger.pending()} - before))

        target = sorted(before)[0]
        shown = await tools.execute("present_change_preview", {"change_id": target})
        _report("present present_change_preview", shown)
        if not shown.refused:
            effects.presented.append(target)

        nested = await tools.execute("note_finding", {"text": "planter is slow"})
        _report("nested  note_finding", nested)

        return ReportResult(headline="report")

    return DelegateExtension(name="draft_report", description="Draft an operations report.",
                             input_schema={"type": "object"}, result_model=ReportResult,
                             run=run)


def _report(label: str, outcome: Any) -> None:
    """Print one tool result the way the delegate's runner saw it.

    :param label: What was called.
    :param outcome: The ``ToolOutcome``.
    :returns: ``None``.
    """
    verdict = f"HELD[{outcome.blocked}]" if outcome.blocked else ("ERROR" if outcome.is_error else "ran")
    body = " ".join(
        line for line in outcome.result_text.splitlines()
        if line and not line.startswith("<") and not line.startswith("{")) or "(fenced payload)"
    print(f"      {label:<34} -> {verdict:<18} {body[:86]}")


# =========================================================================================
# 4. The analysis delegate's script: what its model asks for, in order.
# =========================================================================================

def analysis_script() -> FakeCreateClient:
    """Three scripted turns for the shipped ``AnalysisRunner``.

    A metrics read the delegate holds, a campaign read the operator withheld from it, then
    the submission. The tool names and the submission shape are the runner's own
    (``merchant_agent.analysis``).

    :returns: The scripted client.
    """
    return FakeCreateClient([
        create_response(tool_use_block("query_metrics", {"metric": "sales"}, "tu-1")),
        create_response(tool_use_block("get_campaign_performance", {}, "tu-2")),
        create_response(tool_use_block("submit_analysis", {
            "question": "What moved sales last month?",
            "headline": "Sales fell 6% on flat traffic.",
            "findings": ["Conversion fell in the garden category."],
        }, "tu-3")),
    ])


# =========================================================================================
# The run
# =========================================================================================

def rule(title: str) -> None:
    """Print a section rule.

    :param title: The section's name.
    :returns: ``None``.
    """
    print(f"\n{'=' * 88}\n  {title}\n{'=' * 88}")


async def act1(root: Guard, backend: DemoBackend, config: MerchantAgentConfig,
               session: MerchantSessionContext, state: MerchantSessionState) -> MerchantToolExecutor:
    """The operator's own turn: the whole surface, and a staged price change.

    :param root: The chain's root node.
    :param backend: The store.
    :param config: The deployment config.
    :param session: The session context.
    :param state: The turn's session state.
    :returns: The guarded executor, for the acts that follow.
    """
    rule("Act 1 — the merchant turn, guarded over the repo's own executor_class seam")
    grants = {
        ANALYSIS_TOOL: DelegateGrant.from_tools(
            "analysis",
            # Every read tool the delegate's own surface declares, MINUS the one the
            # operator withholds: campaign spend is not this delegate's business.
            [tool for tool in ANALYSIS_READ_TOOLS if tool != "get_campaign_performance"],
            POLICY, ttl=900,
        ),
        "draft_report": DelegateGrant("report", frozenset({"listing.read", "metrics.read"}), ttl=900),
    }
    # In a deployment this class goes to MerchantAgent(..., executor_class=Guarded), to
    # the Agent SDK toolset and to the MCP server — the one seam all three already take.
    # Here the demo builds the executor itself, which is the same class either way.
    guarded = guarded_executor_class(MerchantToolExecutor, POLICY, grants)
    print(f"      executor_class = {guarded.__name__}({guarded.__bases__[0].__name__})")
    tools = guarded(backend=backend, config=config, skills=SkillRegistry([]),
                    session=session, state=state)

    # Outside the turn's scope the same executor holds every call: an executor with no
    # node bound is never a permissive one.
    unbound = await tools.execute("get_business_snapshot", {})
    _report("before authorize_as", unbound)

    with authorize_as(root):
        await tools.execute("search_listings", {"query": "planter"})
        staged = await tools.execute(
            "stage_price_update", {"items": [{"listing_id": "L-202", "new_price": 25.0}]})
    _report("write   stage_price_update", staged)
    print(f"      operator scopes: {sorted(root.authority.scopes)}")
    print(f"      ledger pending : {[c.change_id for c in backend.ledger.pending()]}")
    return tools


async def act2(root: Guard, backend: DemoBackend, config: MerchantAgentConfig,
               session: MerchantSessionContext, state: MerchantSessionState) -> None:
    """The delegate the repo ships, on a derived authority.

    :param root: The chain's root node.
    :param backend: The store.
    :param config: The deployment config.
    :param session: The session context.
    :param state: The turn's session state.
    :returns: ``None``.
    """
    rule("Act 2 — the shipped analysis delegate, on an authority derived from its own tools")
    grant = DelegateGrant.from_tools(
        "analysis",
        [tool for tool in ANALYSIS_READ_TOOLS if tool != "get_campaign_performance"],
        POLICY, ttl=900)
    print(f"      ANALYSIS_READ_TOOLS declares : {list(ANALYSIS_READ_TOOLS)}")
    print(f"      the operator grants          : {sorted(grant.scopes)}")

    delegate = build_analysis_delegate(analysis_script(), backend, config)
    tools = MerchantToolExecutor(backend=backend, config=config, skills=SkillRegistry([]),
                                 session=session, state=state, delegates=(delegate,))
    # install() rather than guard_executor(): the runner builds its OWN executor inside
    # AnalysisRunner._read, and nothing outside that method can reach it.
    with install(POLICY, {ANALYSIS_TOOL: grant}, root=root):
        outcome = await tools.execute(ANALYSIS_TOOL, {"question": "What moved sales last month?"})
    _report("delegate run_analysis", outcome)

    graph = root.graph()
    for node in graph["nodes"]:
        print(f"      {'  ' * node['depth']}node {node['id']:<10} {node['agent']:<10} "
              f"scopes={sorted(node['authority']['scopes'])}")
    denied = [e for e in root.audit_log().entries if e["event"] == "deny"]
    for entry in denied:
        print(f"      DENY  node={entry['node']} scope={entry['scope']} tool={entry['tool']} "
              f"reason={entry['reason']} disposition={entry.get('disposition')}")


async def act3(root: Guard, config: MerchantAgentConfig, session: MerchantSessionContext) -> None:
    """A delegate that reaches the executor, run unguarded and then guarded.

    :param root: The chain's root node.
    :param config: The deployment config.
    :param session: The session context.
    :returns: ``None``.
    """
    rule("Act 3 — write, present, invoke a delegate: the three the contract forbids")
    grant = DelegateGrant(
        "report", frozenset({"listing.read", "metrics.read", "change.read"}), ttl=900)

    for guarded in (False, True):
        backend = DemoBackend(config)
        # One change the operator already staged, so the delegate has something to try to
        # present in both runs.
        backend.ledger.stage(
            kind=ChangeKind.LISTING_UPDATE, summary="Rewrite the planter description",
            items=[ChangeItem(target="L-202", field="short_description",
                              before="Matte ceramic planter.", after="Matte ceramic planter, 6 inch.")],
            actor=session.operator, actor_kind=ActorKind.OPERATOR)
        effects = Effects()
        peer = peer_delegate(effects)
        delegate = report_delegate(backend, effects, peer)
        tools = MerchantToolExecutor(backend=backend, config=config, skills=SkillRegistry([]),
                                     session=session, state=MerchantSessionState(),
                                     delegates=(delegate, peer))
        print(f"\n    -- {'attenu-guard installed' if guarded else 'nothing installed'} --")
        if guarded:
            with install(POLICY, {"draft_report": grant}, root=root):
                await tools.execute("draft_report", {"topic": "slow movers"})
        else:
            await tools.execute("draft_report", {"topic": "slow movers"})
        print(f"      side effects: {effects}")


async def act4(root: Guard, config: MerchantAgentConfig, session: MerchantSessionContext) -> None:
    """The ceiling: one deployment number, or one per node.

    :param root: The chain's root node.
    :param config: The deployment config.
    :param session: The session context.
    :returns: ``None``.
    """
    rule("Act 4 — the ceiling: max_campaign_budget on the deployment, SpendCap on the node")
    budget = 5_000.0
    print(f"      config.max_campaign_budget = {config.max_campaign_budget:,.0f}  "
          f"(merchant_agent/config.py, checked at stage and again at apply)")
    print(f"      the draft asks for         = {budget:,.0f}")

    backend = DemoBackend(config)
    tools = guard_executor(
        MerchantToolExecutor(backend=backend, config=config, skills=SkillRegistry([]),
                             session=session, state=MerchantSessionState()),
        root, POLICY)
    draft = {"name": "Autumn planters", "objective": "Lift garden revenue", "budget": budget}
    operator = await tools.execute("stage_campaign", dict(draft))
    _report("operator stage_campaign", operator)

    drafter = root.delegate("campaign-drafter",
                            Authority(scopes={"campaign.stage"}, ceilings=[SpendCap(2_000)], ttl=900),
                            task="draft the autumn campaign")
    child_tools = guard_executor(
        MerchantToolExecutor(backend=backend, config=config, skills=SkillRegistry([]),
                             session=session, state=MerchantSessionState()),
        drafter, POLICY)
    child = await child_tools.execute("stage_campaign", dict(draft))
    _report("drafter  stage_campaign", child)
    print(f"      the store's own guardrail passed {budget:,.0f} for the operator; the chain "
          f"holds it for a child capped at 2,000.")


def act5(root: Guard, path: Path) -> dict:
    """Export the run's evidence and verify it with the engine absent.

    :param root: The chain's root node.
    :param path: Where to write the bundle.
    :returns: The verification report.
    """
    rule("Act 5 — one bundle, verified offline")
    signer = HS256TestSigner(b"demo-key", kid="demo")
    bundle = evidence.export_bundle(root.audit_log(), signer)
    path.write_text(json.dumps(bundle, indent=2))

    report = evidence.verify_bundle(bundle, signer)
    print(f"      entries: {len(bundle['entries'])}   bundle: {path.name}")
    print(f"      verify_bundle -> ok={report['ok']}  checks={report['checks']}")
    if report["failures"]:
        print(f"      failures: {report['failures']}")

    graph = evidence.delegation_graph(bundle)
    print("\n      the chain, read back from the file alone:")
    for node_id, meta in graph["nodes"].items():
        parent = f"  under {meta['parent']}" if meta["parent"] else ""
        print(f"        {node_id:<18} {meta['agent']:<17} allows={meta['allows']:<3} "
              f"denies={meta['denies']:<3}{parent}")
    print("\n      every denial, from the file alone:")
    for denial in evidence.denials(bundle):
        print(f"        {denial['agent']:<17} {denial['tool']:<24} {denial['scope']:<16} "
              f"{denial['reason']}")

    # Monotonicity is not decorative. Rebuild the SAME run's ledger with one child's
    # grant widened -- what an insider holding the signing key could write -- and export
    # it properly: hashes and anchor valid, monotonicity broken.
    widened = AuditLog(None)
    for entry in bundle["entries"]:
        fields = {k: v for k, v in entry.items()
                  if k not in ("event", "seq", "ts", "hash", "prev_hash", "v")}
        if entry["event"] == "spawn" and entry["agent"] == "analysis":
            fields["granted"] = dict(fields["granted"],
                                     scopes=sorted(set(fields["granted"]["scopes"]) | {"billing.refund"}))
        widened.append(entry["event"], entry["seq"], **fields)
    broken = evidence.verify_bundle(evidence.export_bundle(widened, signer), signer)
    print("\n      grant the analysis child billing.refund and re-sign the ledger:")
    print(f"        integrity={broken['checks']['integrity']}  "
          f"monotonicity={broken['checks']['monotonicity']}  "
          f"anchor={broken['checks']['anchor']}  ok={broken['ok']}")
    print(f"        {broken['failures'][0] if broken['failures'] else 'no failure'}")
    return report


async def main() -> None:
    """Run the five acts.

    :returns: ``None``.
    """
    config = new_config()
    session = new_session()
    state = MerchantSessionState()
    backend = DemoBackend(config)

    audit_dir = Path(tempfile.mkdtemp(prefix="attenu-commerce-"))
    root = Guard.issue("merchant-turn", OPERATOR_AUTHORITY, task="run the back office",
                       chain_id="commerce-demo", audit_path=str(audit_dir / "ledger.jsonl"))

    print(__doc__.split("\n\nFive acts:")[0].strip())
    await act1(root, backend, config, session, state)
    await act2(root, backend, config, session, state)
    await act3(root, config, session)
    await act4(root, config, session)
    report = act5(root, Path(os.environ.get("ATTENU_BUNDLE", "attenu-commerce-bundle.json")))

    rule("Summary")
    print("  The delegate was never told not to write, present, or call another delegate.")
    print("  It was never given the authority to. Each attempt was refused at the shared")
    print("  dispatch point, before the body, and the whole run verifies from one file")
    print(f"  with commerce-agents and attenu-derive absent: ok={report['ok']}.")


if __name__ == "__main__":
    asyncio.run(main())
