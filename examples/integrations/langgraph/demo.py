"""Runnable end-to-end demo: attenu-guard x LangGraph, fully offline.

    python examples/integrations/langgraph/demo.py

No API key, no network. This is a recipe for `attenu_guard.adapters.langgraph`
specifically -- the SHIPPED node-wrapping adapter, LangGraph 1.x's reference
wiring for this library. (The LangChain 1.x agent-loop middleware,
`attenu_guard.adapters.langchain`, is a DIFFERENT module with its own recipe:
see `../langgraph/subagent_middleware/`.)

The story it tells is the canonical "poisoned summarizer":

  1. An `orchestrator` Guard holds broad authority and delegates a summary job
     to a `summarizer` Guard -- strictly narrower, minted with `.delegate(...)`
     the same way you would at the point you wire up a graph node.
  2. `guard_node`/`add_guarded_node` wrap two LangGraph node functions with
     the summarizer's Guard: `summarize` (in scope) and `export` (out of
     scope -- the poisoned step).
  3. `graph.invoke()` runs `summarize`'s body, then raises `AuthorityDenied`
     out of the graph BEFORE `export`'s body ever runs.
  4. That same run closes a REAL execution-binding record: the `summarize`
     node's ledger entry carries `authorized_params_hash == invoked_params_hash`
     -- proof the arguments authorized are the arguments invoked, not just
     that a check passed.
  5. Revoking the summarizer's subtree cuts off a call that was legal a
     moment earlier -- called directly, no graph needed (`guard_node`'s
     wrapper is a plain callable; LangGraph is not required to use it).
  6. The ledger, checked without this process: a signed evidence bundle is
     exported and verified offline via the packaged `attenu-guard verify`
     command.

Run it twice mentally: the "BASELINE" section at the end re-runs the same
two node functions with no guard installed at all, and the export runs.

Exit code 0 if every expectation below held, 1 otherwise -- this script is
not just a transcript, it is its own assertion.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from attenu_guard import (
    AuditLog, Authority, AuthorityDenied, EgressRank, Guard, RowLimit, evidence,
)
from attenu_guard.adapters.langgraph import add_guarded_node, guard_node
from attenu_guard.cli import main as attenu_guard_cli
from attenu_guard.reasons import Capture
from attenu_guard.wire import Ed25519Signer

BAR = "=" * 72
ORCHESTRATOR = "orchestrator"
SUMMARIZER = "summarizer"

EXECUTED: list[str] = []


def rule(title: str) -> None:
    print(f"\n{BAR}\n  {title}\n{BAR}")


class State(TypedDict):
    expected_rows: int
    note: str


# ---------------------------------------------------------------------------
# The graph nodes. Each appends to EXECUTED, so "did the body run?" is
# observable independent of what the node happens to return.
# ---------------------------------------------------------------------------
def _make_nodes(guard: Guard):
    @guard_node(guard, "crm.read", context_fn=lambda state: {"rows": state["expected_rows"]})
    def summarize(state: State) -> dict:
        EXECUTED.append(f"summarize(rows={state['expected_rows']})")
        return {"note": f"summarised {state['expected_rows']} rows"}

    def export_impl(state: State) -> dict:
        EXECUTED.append("export")                # <- must NEVER happen
        return {"note": "exported"}

    return summarize, export_impl


def build_graph(guard: Guard):
    summarize, export_impl = _make_nodes(guard)
    g = StateGraph(State)
    g.add_node("summarize", summarize)
    add_guarded_node(g, "export", guard, "crm.export", export_impl,
                     context_fn=lambda state: {"egress": "any"}, tool="export")
    g.add_edge(START, "summarize")
    g.add_edge("summarize", "export")
    g.add_edge("export", END)
    return g.compile(), summarize


def main() -> int:
    rule("1. The authority the orchestrator holds")
    root = Guard.issue(
        ORCHESTRATOR,
        Authority(
            scopes={"crm.*", "mail.send"},
            ceilings=[RowLimit(100_000), EgressRank("any")],
            ttl=3600,
        ),
        task="deliver the Q3 pipeline summary",
        schema_version=2,  # required for the execution-binding capture below
    )
    print(f"  orchestrator  {root.authority!r}")

    summarizer_authority = Authority(
        scopes={"crm.read"},
        ceilings=[RowLimit(5_000), EgressRank("none")],
        ttl=900,
    )
    summarizer = root.delegate(SUMMARIZER, summarizer_authority, task="summarize Q3 pipeline")
    print(f"  will delegate {summarizer_authority!r}")
    print(f"  summarizer.is_narrower_than(orchestrator): {summarizer.is_narrower_than(root)}")

    rule("2. What a greedy delegation request gets (met down, never up)")
    greedy = Authority(
        scopes={"crm.*", "mail.send", "payments.transfer"},
        ceilings=[RowLimit(10_000_000), EgressRank("any")],
        ttl=999_999,
    )
    probe = root.delegate("greedy-probe", greedy, task="try to escalate")
    print(f"  requested  {greedy!r}")
    print(f"  granted    {probe.authority!r}")
    print(f"  narrower than parent? {probe.is_narrower_than(root)}")
    print(f"  'payments.transfer' granted? {'payments.transfer' in probe.authority.scopes}")
    root.revoke(probe.node_id)

    rule("3. Running the graph: crm_query allowed, crm_export denied before its body runs")
    app, summarize_fn = build_graph(summarizer)
    try:
        app.invoke({"expected_rows": 4200, "note": ""})
        print("  !! no denial -- unexpected")
        export_denied = False
    except AuthorityDenied as exc:
        print(f"    ok      node 'summarize' ran")
        print(f"    DENIED  node 'export'    {exc}")
        export_denied = True
    print(f"\n  node bodies that actually ran: {EXECUTED}")
    print("  -> AuthorityDenied propagates straight out of graph.invoke(); the")
    print("     LangGraph run never reaches export's body.")
    export_body_ran = any(e == "export" for e in EXECUTED)

    rule("4. Execution binding: genuine WRAPPER_SYNC, no attestation flag")
    entries = root.audit_log().entries
    summarize_allow = next(e for e in entries if e.get("tool") == "summarize" and e["event"] == "allow")
    summarize_outcome = next(e for e in entries if e.get("call_id") == summarize_allow.get("call_id")
                             and e["event"] == "outcome")
    print(f"  capture: {summarize_allow['capture']}")
    print(f"  authorized_params_hash == invoked_params_hash: "
          f"{summarize_allow['authorized_params_hash'] == summarize_outcome['invoked_params_hash']}")
    print("  This proves the ARGUMENTS authorized are the arguments invoked -- it does not")
    print("  prove anything about what summarize() did with them, and it says nothing about")
    print("  a call path that reaches crm_query without going through this node at all.")
    capture_is_wrapper_sync = summarize_allow["capture"] == Capture.WRAPPER_SYNC
    hashes_match = summarize_allow["authorized_params_hash"] == summarize_outcome["invoked_params_hash"]

    rule("5. Revocation: a call that was legal a moment ago, denied")
    print(f"  before revoke: summarize({{'expected_rows': 10}}) allowed? "
          f"{bool(summarizer.would_allow('crm.read', context={'rows': 10}))}")
    root.revoke(summarizer.node_id)
    revoked_denied = False
    try:
        summarize_fn({"expected_rows": 10, "note": ""})   # a direct call -- no graph needed
        print("  !! ran after revocation -- unexpected")
    except AuthorityDenied as exc:
        print(f"    DENIED  {exc}")
        revoked_denied = True
    print("  -> guard_node's wrapper is a plain callable: LangGraph was never required")
    print("     to exercise it, on this call or on the graph run above.")

    rule("6. The ledger, checked without this process")
    entries = root.audit_log().entries
    for e in entries:
        line = f"  seq={e['seq']:>2} {e['event']:<12}"
        if e.get("tool"):
            line += f" tool={e['tool']:<12}"
        if e.get("scope"):
            line += f" scope={e['scope']:<12}"
        if e.get("reason"):
            line += f" reason={e['reason']}"
        print(line)
    chain_ok, chain_err = AuditLog.verify(entries)
    print(f"\n  {len(entries)} events, hash chain: {chain_ok}" + (f" ({chain_err})" if chain_err else ""))

    workdir = Path(tempfile.mkdtemp(prefix="attenu-guard-langgraph-recipe-"))
    signer = Ed25519Signer.generate(kid="recipe-demo")
    pubkey = signer.public_bytes_raw().hex()
    bundle = evidence.export_bundle(root.audit_log(), signer)
    bundle_path = workdir / "evidence-bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))
    print(f"\n  bundle: {bundle_path}")
    print("  verifying it with the packaged command:")
    print(f"    attenu-guard verify {bundle_path.name} --pubkey {pubkey[:16]}…")
    try:
        verify_rc = attenu_guard_cli(["verify", str(bundle_path), "--pubkey", pubkey])
    except SystemExit as exc:
        # A bare sys.exit() carries code=None, which Python treats as success (exit status 0)
        # -- mirror that here so the `ok` check below agrees with process exit semantics.
        verify_rc = 0 if exc.code is None else (exc.code if isinstance(exc.code, int) else 1)
    reviewer_graph = evidence.delegation_graph(bundle)
    print(f"  reviewer view: {len(reviewer_graph['nodes'])} nodes")

    rule("7. BASELINE: the same two node functions, no guard installed")
    EXECUTED.clear()

    class UnguardedState(TypedDict):
        expected_rows: int
        note: str

    def summarize_unguarded(state: UnguardedState) -> dict:
        EXECUTED.append(f"summarize(rows={state['expected_rows']})")
        return {"note": "summarised"}

    def export_unguarded(state: UnguardedState) -> dict:
        EXECUTED.append("export")
        return {"note": "exported"}

    g = StateGraph(UnguardedState)
    g.add_node("summarize", summarize_unguarded)
    g.add_node("export", export_unguarded)
    g.add_edge(START, "summarize")
    g.add_edge("summarize", "export")
    g.add_edge("export", END)
    g.compile().invoke({"expected_rows": 4200, "note": ""})
    print(f"  node bodies that actually ran: {EXECUTED}")
    exfiltrated = any(e == "export" for e in EXECUTED)
    print(
        f"\n  CRM exported without a guard installed? {exfiltrated}\n"
        "  LangGraph itself carries no authority across a node call: a plain\n"
        "  callable node runs whatever its body says, with no relation at all\n"
        "  to what any other node in the graph is allowed to do."
    )

    ok = (
        export_denied
        and not export_body_ran
        and summarizer.is_narrower_than(root)
        and capture_is_wrapper_sync
        and hashes_match
        and revoked_denied
        and chain_ok
        and verify_rc in (0, None)
        and exfiltrated  # the baseline's whole point: it DOES leak, unguarded
    )
    print("\nRESULT:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
