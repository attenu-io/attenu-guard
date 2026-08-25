"""What an MCP server can check today — the attenu-guard MCP example.

Offline, in-memory transport, no API key. Exit 0 = every expectation held · 1 = failed ·
3 = the MCP SDK now carries a first-class agent-authority field (the premise changed; the check still works).

  [1] control: an unguarded server runs whatever it is asked.
  [2] guarded: the exporter's chain (root → exporter, crm.export) is verified offline and the export runs;
      the reader's chain (root → reader, crm.read only) is denied before the body runs; a SPLICED chain
      (reader → exporter-leaf) fails the parent-hash linkage; a FORGED leaf fails its signature; no chain = deny.
  [3] the server's ledger verifies.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

from mcp.shared.memory import create_connected_server_and_client_session as connect
from mcp.types import CallToolRequestParams

from attenu_guard import AuditLog, Authority, EgressRank, Guard, RowLimit
from attenu_guard.wire import HS256TestSigner

sys.path.insert(0, str(Path(__file__).resolve().parent))
import client as cl  # noqa: E402
import server as sv  # noqa: E402

EXIT_OK, EXIT_FAIL, EXIT_PREMISE_CHANGED = 0, 1, 3
ROOT = Authority(scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600)
READER = Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)
EXPORTER = Authority(scopes={"crm.export"}, ceilings=[EgressRank("any")], ttl=900)


def premise_changed() -> bool:
    """MCP's roadmap (2026-08-22) names sub-agent authority as future work; today the request carries none."""
    fields = set(CallToolRequestParams.model_fields)
    return bool({"authority", "delegation", "delegation_chain", "agent_authority"} & fields)


def agents(signer):
    root = Guard.issue("orchestrator", ROOT, task="serve")
    reader = root.delegate("reader", READER, task="summarise")
    exporter = root.delegate("exporter", EXPORTER, task="export")
    return root, reader, exporter


async def run(audit_path=None):
    signer = HS256TestSigner(b"issuer-secret", kid="issuer-1")
    root, reader, exporter = agents(signer)
    out: dict = {}

    sink0: list = []
    async with connect(sv.build_server(None, sink0)) as s:               # [1] control
        await cl.call(s, "crm_export", {"destination": "https://exfil.example"}, chain=None)
    out["control_ran"] = sink0 == [("crm_export", "https://exfil.example")]

    sink: list = []
    verifier = sv.ChainVerifier(signer, root_key_ids=["issuer-1"], audit_path=audit_path)
    server = sv.build_server(verifier, sink); sv.require_guard(server)
    async with connect(server) as s:                                     # [2] guarded
        ok = await cl.call(s, "crm_export", {"destination": "https://partner.example"}, cl.chain_for(exporter, signer))
        deny = await cl.call(s, "crm_export", {"destination": "https://exfil.example"}, cl.chain_for(reader, signer))
        # a real splice: the reader's full chain with the exporter's leaf appended — the leaf's parent hash
        # points at the root, not at the reader, so the chain must fail linkage
        spliced = cl.chain_for(reader, signer) + cl.chain_for(exporter, signer)[-1:]
        splice = await cl.call(s, "crm_export", {"destination": "https://exfil.example"}, spliced)
        # a forged leaf: the exporter's leaf token with one payload byte changed — the signature must fail
        forged_chain = cl.chain_for(exporter, signer); h, b, sig = forged_chain[-1].split(".")
        forged_chain[-1] = ".".join([h, b[:-2] + ("AA" if b[-2:] != "AA" else "BB"), sig])
        forged = await cl.call(s, "crm_export", {"destination": "https://exfil.example"}, forged_chain)
        nochain = await cl.call(s, "crm_export", {"destination": "https://exfil.example"}, None)
        read_ok = await cl.call(s, "crm_query", {"rows": 100}, cl.chain_for(reader, signer))
    out.update(exporter_allowed=ok.get("exported_to") == "https://partner.example",
               reader_denied=deny.get("error") == "authority_denied",
               splice_refused=splice.get("error") == "chain_invalid",
               forged_refused=forged.get("error") == "chain_invalid",
               nochain_denied=nochain.get("error") == "no_delegation_chain",
               reader_read_allowed=read_ok.get("rows_returned") == 100,
               side_effects=sink)
    entries = verifier.audit.entries
    out["ledger_ok"], _ = AuditLog.verify(entries)
    out["ledger_events"] = [(e["event"], e.get("tool")) for e in entries]
    return out, root, reader, exporter, verifier


def main() -> int:
    if premise_changed():
        print("the MCP SDK now carries an agent-authority field — the story premise changed; the check still works")
        return EXIT_PREMISE_CHANGED
    with tempfile.TemporaryDirectory() as td:
        out, *_ = asyncio.run(run(Path(td) / "server-audit.jsonl"))
    print("[1] unguarded control server ran the export:", out["control_ran"])
    print("[2] guarded server:")
    for k in ("exporter_allowed", "reader_denied", "splice_refused", "forged_refused", "nochain_denied", "reader_read_allowed"):
        print(f"    {k}: {out[k]}")
    print(f"    tool bodies that ran: {out['side_effects']}")
    print(f"[3] server ledger verifies: {out['ledger_ok']} — {out['ledger_events']}")
    expected_sink = [("crm_export", "https://partner.example"), ("crm_query", 100)]
    ok = all(out[k] for k in ("control_ran", "exporter_allowed", "reader_denied", "splice_refused", "forged_refused",
                              "nochain_denied", "reader_read_allowed", "ledger_ok")) and out["side_effects"] == expected_sink
    print("RESULT:", "OK" if ok else "FAIL")
    return EXIT_OK if ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
