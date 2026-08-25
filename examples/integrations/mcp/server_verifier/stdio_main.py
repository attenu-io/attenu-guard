"""Entry point for the stdio variant (used by live_smoke.py): the guarded server over stdio."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server as sv  # noqa: E402
from attenu_guard.wire import HS256TestSigner  # noqa: E402

secret = os.environ.get("ATTENU_VERIFIER_SECRET", "").encode()
verifier = sv.ChainVerifier(HS256TestSigner(secret, kid="issuer-1"), root_key_ids=["issuer-1"])
sink: list = []
server = sv.build_server(verifier, sink)
sv.require_guard(server)
server.run(transport="stdio")
