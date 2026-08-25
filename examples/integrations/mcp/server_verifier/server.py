"""An MCP server that checks the delegation chain before it runs a tool.

The chain (attenu-guard Delegation Tokens, `attenu_guard.wire`) rides in the request's `_meta`
(`meta={"attenu_chain": [...]}` on `ClientSession.call_tool`) — out-of-band of the tool arguments,
where MCP's own roadmap places agent identity and authority. The server:

  1. loads the chain offline (`wire.load`): signatures, parent hashes, depth, and child ⊆ parent at
     every hop — no authorization server in the path;
  2. checks the LEAF authority against the tool's scope and request context (`VerifiedChain.permits`);
  3. records allow/deny on a hash-chained audit log BEFORE running the body; if it cannot record, it
     does not run the body (fail closed);
  4. returns the denial-contract response on deny, and only then runs the tool.

Trust boundary: the check lives at the MCP boundary. Code that calls the underlying Python function
directly is outside it (the test proves it), as is any other route to the resource behind the tool.
"""
from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import Context, FastMCP

from attenu_guard import AuditLog, wire
from attenu_guard.reasons import Disposition

TOOL_SCOPES: dict[str, tuple[str, Callable[[dict], dict]]] = {
    "crm_query":  ("crm.read",   lambda a: {"rows": int(a.get("rows", 0))}),
    "crm_export": ("crm.export", lambda a: {"egress": "any"}),
}


class ChainVerifier:
    """The enforcement point: verifier key(s) + a ledger. One per server."""

    def __init__(self, signer, *, root_key_ids=None, audit_path=None):
        self.signer, self.root_key_ids = signer, root_key_ids
        self.audit = AuditLog(audit_path)
        self._seq = 0

    def _append(self, event: str, **fields) -> None:
        self._seq += 1
        self.audit.append(event, self._seq, **fields)          # raises if the ledger cannot be written

    def decide(self, tool: str, args: dict, meta) -> dict | None:
        """None = allowed (and recorded). A dict = the denial-contract response (and recorded)."""
        scope, ctx_of = TOOL_SCOPES[tool]
        tokens = _chain_from_meta(meta)
        if not tokens:
            self._append("deny", tool=tool, scope=scope, reason="no_delegation_chain", disposition=Disposition.UNRESOLVED)
            return _denial(tool, scope, "no_delegation_chain", "no delegation chain presented; default deny")
        try:
            vc = wire.load(list(tokens), self.signer, root_key_ids=self.root_key_ids)
        except wire.WireError as exc:
            self._append("deny", tool=tool, scope=scope, reason="chain_invalid", detail=str(exc)[:160])
            return _denial(tool, scope, "chain_invalid", str(exc))
        decision = vc.permits(scope, ctx_of(args))
        leaf = vc.payloads[-1]
        if decision:
            self._append("allow", tool=tool, scope=scope, chain_depth=vc.depth, leaf=leaf.get("sub"))
            return None
        reasons = [r.code for r in decision.reasons]
        self._append("deny", tool=tool, scope=scope, chain_depth=vc.depth, leaf=leaf.get("sub"),
                     reasons=reasons, disposition=Disposition.OUT_OF_AUTHORITY)
        return _denial(tool, scope, "authority_denied", "; ".join(reasons), disposition=Disposition.OUT_OF_AUTHORITY)


def _chain_from_meta(meta) -> list[str]:
    if meta is None:
        return []
    if isinstance(meta, dict):
        return list(meta.get("attenu_chain") or [])
    extra = getattr(meta, "model_extra", None) or {}
    return list(extra.get("attenu_chain") or getattr(meta, "attenu_chain", None) or [])


def _denial(tool: str, scope: str, error: str, detail: str, disposition: str | None = None) -> dict:
    out = {"error": error, "tool": tool, "scope": scope, "detail": detail}
    if disposition:
        out["disposition"] = disposition
    return out


def require_guard(server: FastMCP) -> ChainVerifier:
    """Fail closed: refuse to serve unless the verifier is attached."""
    v = getattr(server, "_attenu_verifier", None)
    if v is None:
        raise RuntimeError("attenu-guard: no ChainVerifier attached to this MCP server — refusing to serve unguarded")
    return v


def build_server(verifier: ChainVerifier | None, sink: list, *, name: str = "crm") -> FastMCP:
    """`sink` records every tool BODY that actually ran — the side-effect oracle."""
    mcp = FastMCP(name)
    mcp._attenu_verifier = verifier  # type: ignore[attr-defined]

    def gate(tool: str, args: dict, ctx: Context) -> dict | None:
        if verifier is None:                                    # the unguarded control server
            return None
        return verifier.decide(tool, args, ctx.request_context.meta)

    @mcp.tool()
    def crm_query(rows: int, ctx: Context) -> dict:
        """Read `rows` rows from the CRM."""
        denied = gate("crm_query", {"rows": rows}, ctx)
        if denied:
            return denied
        sink.append(("crm_query", rows)); return {"rows_returned": rows}

    @mcp.tool()
    def crm_export(destination: str, ctx: Context) -> dict:
        """Export the CRM dataset to `destination`."""
        denied = gate("crm_export", {"destination": destination}, ctx)
        if denied:
            return denied
        sink.append(("crm_export", destination)); return {"exported_to": destination}

    return mcp
