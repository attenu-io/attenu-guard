"""Regenerate the three sample bundles in this directory (deterministic; stdlib only).

    python examples/verify/make_samples.py

clean.bundle.json      a real run: root → reader (narrowed) → analyst (narrower); one denial mid-chain
tampered.bundle.json   the same bundle with a denial rewritten into an allow — integrity fails
widened.bundle.json    a consistent, correctly signed ledger in which a child was granted MORE than its parent
                       (what an insider holding the key could write) — integrity passes, monotonicity fails
Verifier key for all three (HS256 test signer): secret hex 73616d706c652d6b6579 ("sample-key"), kid "sample".
"""
from __future__ import annotations

import json
from pathlib import Path

from attenu_guard import AuditLog, Authority, EgressRank, Guard, RowLimit, evidence
from attenu_guard.wire import HS256TestSigner

HERE = Path(__file__).resolve().parent
SECRET, KID = b"sample-key", "sample"


def clean() -> dict:
    signer = HS256TestSigner(SECRET, kid=KID)
    root = Guard.issue("orchestrator", Authority(scopes={"crm.*", "mail.send"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600), task="quarterly review")
    reader = root.delegate("reader", Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900), task="summarise pipeline")
    analyst = reader.delegate("analyst", Authority(scopes={"crm.read"}, ceilings=[RowLimit(500)], ttl=600), task="top accounts")
    reader.check("crm.read", context={"rows": 4_200}, tool="crm_query")           # allow
    analyst.check("crm.read", context={"rows": 120}, tool="crm_query")            # allow
    analyst.check("crm.read", context={"rows": 9_000}, tool="crm_query")          # deny: row ceiling
    reader.check("crm.export", context={"egress": "any"}, tool="crm_export")      # deny: scope not held (mid-chain)
    return evidence.export_bundle(root.audit_log(), signer)


def tampered(bundle: dict) -> dict:
    import copy
    b = copy.deepcopy(bundle)
    d = next(e for e in b["entries"] if e["event"] == "deny")
    d["event"] = "allow"                                                          # the classic rewrite
    return b


def widened() -> dict:
    """A ledger an insider with the key could produce: hashes and anchor all valid, but a child holds more than its parent."""
    signer = HS256TestSigner(SECRET, kid=KID)
    log = AuditLog(None)
    parent_auth = Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)
    child_auth = Authority(scopes={"crm.read", "crm.export"}, ceilings=[EgressRank("any")], ttl=900)   # ⊄ parent
    log.append("root", 1, chain_id="chain", node="n0", agent="orchestrator", authority=parent_auth.to_wire())
    log.append("spawn", 2, chain_id="chain", node="n1", parent="n0", agent="exporter", granted=child_auth.to_wire())
    log.append("allow", 3, chain_id="chain", node="n1", agent="exporter", scope="crm.export", tool="crm_export", context={"egress": "any"})
    return evidence.export_bundle(log, signer)


def main() -> None:
    c = clean()
    (HERE / "clean.bundle.json").write_text(json.dumps(c, indent=1, sort_keys=True))
    (HERE / "tampered.bundle.json").write_text(json.dumps(tampered(c), indent=1, sort_keys=True))
    (HERE / "widened.bundle.json").write_text(json.dumps(widened(), indent=1, sort_keys=True))
    signer = HS256TestSigner(SECRET, kid=KID)
    for name in ("clean", "tampered", "widened"):
        rep = evidence.verify_bundle(json.loads((HERE / f"{name}.bundle.json").read_text()), signer)
        print(f"{name:9s} ok={rep['ok']} {rep['checks']}")


if __name__ == "__main__":
    main()
