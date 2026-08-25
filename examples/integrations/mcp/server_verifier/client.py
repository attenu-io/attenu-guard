"""Client side: mint a chain for the calling agent and present it in `_meta`."""
from __future__ import annotations

import json
from typing import Any

from mcp import ClientSession

from attenu_guard import Guard, wire


def chain_for(guard: Guard, signer) -> list[str]:
    """Root → this agent, as Delegation Tokens (offline-verifiable by anyone holding the verifier key)."""
    return wire.serialize_chain(guard, signer)


async def call(session: ClientSession, tool: str, args: dict[str, Any], chain: list[str] | None) -> dict:
    res = await session.call_tool(tool, args, meta={"attenu_chain": chain} if chain is not None else None)
    if res.structuredContent:
        return dict(res.structuredContent.get("result", res.structuredContent))
    text = "".join(getattr(c, "text", "") for c in res.content)
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return {"raw": text, "isError": res.isError}
