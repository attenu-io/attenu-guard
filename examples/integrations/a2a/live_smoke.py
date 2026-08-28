"""
attenu-guard x A2A — the same story over a real HTTP hop.

`demo.py` runs both halves in one process over an in-process `ClientTransport`. This runs them
over the wire: a Starlette + uvicorn A2A server on localhost, reached by a real `ClientFactory`
client that resolves the agent card over HTTP, negotiates the JSON-RPC binding, sends the
`A2A-Extensions` header and posts `message:send`. Still no model and no API key — the remote
agent's plan is scripted, as in the demo.

    RUN_LIVE=1 python examples/integrations/a2a/live_smoke.py

Needs the SDK's HTTP server extras:

    pip install 'a2a-sdk[http-server]' uvicorn

Point it at an agent someone else is running instead, in which case only the CLIENT half runs
(the chain is attached and sent; what that agent does with it is its own business):

    RUN_LIVE=1 A2A_AGENT_URL=http://localhost:9999 python examples/integrations/a2a/live_smoke.py

Exit 0 = the story held. Exit 2 = skipped (no RUN_LIVE, or the extras are missing).
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo  # noqa: E402  - the shared story: permissions, tools, executor, agent card

from attenu_guard import evidence  # noqa: E402
from attenu_guard.adapters.a2a import (  # noqa: E402
    DelegationInterceptor,
    GuardedAgentExecutor,
    delegating_guard_for,
    verify_hop,
)


def _skip(reason: str) -> int:
    print(f"SKIPPED: {reason}")
    return 2


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _build_app(handler, card):
    from starlette.applications import Starlette

    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes

    return Starlette(routes=[
        *create_agent_card_routes(card),
        *create_jsonrpc_routes(handler, "/"),
    ])


@contextlib.contextmanager
def _serving(app, port: int):
    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(200):
            if server.started:
                break
            threading.Event().wait(0.05)
        if not server.started:
            raise RuntimeError("the A2A server did not start")
        yield
    finally:
        server.should_exit = True
        thread.join(timeout=10)


async def _run_against(url: str, *, executor=None) -> int:
    import httpx

    from a2a.client.client import ClientConfig
    from a2a.client.client_factory import ClientFactory
    from a2a.helpers.proto_helpers import new_text_message
    from a2a.types.a2a_pb2 import Role, SendMessageRequest

    orchestrator = demo.Guard.issue(
        "orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="summarise Q3 pipeline",
        chain_id="orchestrator-live",
    )
    interceptor = DelegationInterceptor(
        guard_for=delegating_guard_for(
            orchestrator, authority_for=lambda card, task: demo.SUMMARISER_REQUEST,
        ),
        signer=demo.signer(),
    )

    async with httpx.AsyncClient(timeout=30) as http:
        factory = ClientFactory(ClientConfig(streaming=False, httpx_client=http))
        client = await factory.create_from_url(url, interceptors=[interceptor])
        request = SendMessageRequest(
            message=new_text_message("summarise the Q3 pipeline", role=Role.ROLE_USER),
        )
        reply = None
        async for event in client.send_message(request):
            reply = event
        await client.close()

    print(f"  card resolved and message sent over HTTP to {url}")
    print(f"  chain on the wire: {len(interceptor.sent[-1][1])} Delegation Tokens")
    if reply is not None and reply.HasField("message"):
        for line in demo.text_of(reply.message).splitlines():
            print(f"  {line}")

    if executor is None:
        print("  external agent: only the client half was exercised")
        return 0

    if not executor.guards:
        print(f"  FAILED: the server refused the hop: {executor.denials}")
        return 1

    task_id, served = next(iter(executor.guards.items()))
    print(f"  server served {served.agent_id} with {sorted(served.authority.scopes)}")
    print(f"  tool bodies that actually ran: {demo.WORLD['bodies_run']}")
    print(f"  data exported anywhere:        {demo.WORLD['exported_to'] or 'nothing'}")

    report = verify_hop(
        interceptor.sent[-1][1], demo.signer(),
        client_bundle=evidence.export_bundle(orchestrator.audit_log(), demo.signer()),
        server_bundle=executor.bundle_for_task(task_id, demo.signer()),
    )
    print(f"  offline verification: {report['checks']}")
    for failure in report["failures"]:
        print(f"  - {failure}")

    ok = (
        demo.WORLD["bodies_run"] == [("crm_query", 1_800)]
        and demo.WORLD["exported_to"] is None
        and sorted(served.authority.scopes) == ["crm.read"]
        and report["ok"]
    )
    return 0 if ok else 1


def main() -> int:
    if os.environ.get("RUN_LIVE") != "1":
        return _skip("set RUN_LIVE=1 to run this")

    external = os.environ.get("A2A_AGENT_URL")
    if external:
        print(f"attenu-guard x A2A — live against {external}")
        return asyncio.run(_run_against(external))

    try:
        import starlette  # noqa: F401
        import uvicorn    # noqa: F401
    except ImportError:
        return _skip("install 'a2a-sdk[http-server]' and uvicorn, or set A2A_AGENT_URL")

    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.tasks import InMemoryTaskStore

    demo.reset_world()
    port = _free_port()
    card = demo.summariser_card()
    card.supported_interfaces[0].url = f"http://127.0.0.1:{port}/"
    executor = GuardedAgentExecutor(
        demo.SummariserExecutor(),
        agent_id="summariser",
        authority_for=lambda agent_id, task: demo.REMOTE_TASK_AUTHORITY,
        signer=demo.signer(),
        root_key_ids=(demo.KID,),
    )
    handler = DefaultRequestHandler(
        agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card,
    )

    print(f"attenu-guard x A2A — live over HTTP on 127.0.0.1:{port}")
    with _serving(_build_app(handler, card), port):
        rc = asyncio.run(_run_against(f"http://127.0.0.1:{port}", executor=executor))

    print(f"\nRESULT: {'OK' if rc == 0 else 'FAILED'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
