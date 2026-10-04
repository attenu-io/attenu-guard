"""Client side: mint a chain for the calling agent and present it in `_meta`."""
from __future__ import annotations

import json
from typing import Any

from attenu_guard import Guard, wire


def chain_for(guard: Guard, signer) -> list[str]:
    """Root → this agent, as Delegation Tokens (offline-verifiable by anyone holding the verifier key)."""
    return wire.serialize_chain(guard, signer)


def result_field(result, name: str, v1_name: str):
    """A `CallToolResult` field on either SDK: mcp 2.x snake-cased the names (`is_error`), 1.x has `isError`."""
    return getattr(result, name) if hasattr(result, name) else getattr(result, v1_name)


async def call(session, tool: str, args: dict[str, Any], chain: list[str] | None) -> dict:
    """`session` is a `ClientSession`, or an mcp 2.x `Client`: both take `meta=` on `call_tool`."""
    res = await session.call_tool(tool, args, meta={"attenu_chain": chain} if chain is not None else None)
    structured = result_field(res, "structured_content", "structuredContent")
    if structured:
        return dict(structured.get("result", structured))
    text = "".join(getattr(c, "text", "") for c in res.content)
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return {"raw": text, "isError": result_field(res, "is_error", "isError")}
