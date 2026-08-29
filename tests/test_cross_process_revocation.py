"""Cross-process revocation is invisible to the offline verifier. This test PROVES the limit
rather than papering over it, so a composition layer can map it as a negative case.

Sequence (requested by a VATE reviewer on Discussion #7, 2026-08-29):

  1. the CALLER process mints a chain and serializes the leaf's tokens;
  2. the caller REVOKES the node in its own process (`Guard.revoke`);
  3. a SEPARATE RECEIVING process (a fresh interpreter) loads the tokens with the
     `revocation_check` seam UNWIRED;
  4. `wire.load` succeeds and the tool body is reached.

`wire.load` does not consult a Token Status List (draft {{verify}} step 7 is out of scope
for the wire format; see wire.py). Revocation lives in the caller's in-process chain and
never reaches the wire, so the receiving side cannot see it. Within attenu-guard's A2A
receiver, `revocation_check=` is the supplied seam for a status source. A composition
layer may enforce current revocation evidence earlier at admission. The second case
below models the receiver seam and shows the same tokens refused; the real
`GuardedAgentExecutor` path is covered in `tests/integrations/test_a2a.py`.

stdlib only. The receiving process is real (`subprocess`), not a thread: the point is
that no in-memory state crosses the boundary.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import Authority, Guard, RowLimit, wire  # noqa: E402

SECRET = b"cross-process-revocation-test-secret"
KID = "revocation-test"

# The receiving process. It knows the tokens, the verification key, and optionally a
# path to a revocation status file. It knows nothing about the caller's chain object.
RECEIVER = r'''
import json, sys
from attenu_guard import wire

args = json.load(sys.stdin)
signer = wire.HS256TestSigner(bytes.fromhex(args["secret_hex"]), kid=args["kid"])
verified = wire.load(args["tokens"], signer, now=0)          # step 4a: offline verification
leaf = verified.payloads[-1]

# Model the `revocation_check` contract without importing the optional A2A SDK: it is
# called on the verified leaf payload, and a non-empty reason refuses the hop.
revocation_check = None
if args.get("status_path"):
    revoked = set(json.load(open(args["status_path"]))["revoked_jti"])
    revocation_check = lambda payload: "revoked" if payload.get("jti") in revoked else None

reason = revocation_check(leaf) if revocation_check else None
if reason:
    print("DENIED:" + reason)
    sys.exit(0)

def tool_body():                                              # step 4b: the inner executor
    return "REACHED"

print(tool_body())
'''


def _mint_and_revoke() -> tuple[list[str], str]:
    """Steps 1-2, in the caller process. Returns the serialized tokens and the leaf jti."""
    root = Guard.issue(
        "orchestrator",
        Authority(scopes={"crm.*"}, ceilings=[RowLimit(1000)], ttl=3600),
        max_depth=3,
    )
    worker = root.delegate(
        "worker", Authority(scopes={"crm.read"}, ceilings=[RowLimit(100)], ttl=900), task="t"
    )
    signer = wire.HS256TestSigner(SECRET, kid=KID)
    tokens = wire.serialize_chain(worker, signer)             # step 1
    leaf_jti = json.loads(wire.b64url_decode(tokens[-1].split(".")[1]))["jti"]
    revoked = root.revoke(worker.node_id)                      # step 2: in THIS process only
    assert worker.node_id in revoked and worker.is_revoked
    return tokens, leaf_jti


def _receive(tokens: list[str], status_path: str | None) -> str:
    """Step 3: a fresh interpreter. Nothing from the caller's memory crosses this line."""
    payload = json.dumps({
        "secret_hex": SECRET.hex(), "kid": KID, "tokens": tokens, "status_path": status_path,
    })
    src = str(Path(__file__).resolve().parents[1] / "src")
    out = subprocess.run(
        [sys.executable, "-c", RECEIVER], input=payload, capture_output=True, text=True,
        env={"PYTHONPATH": src, "PATH": "/usr/bin:/bin"}, check=True,
    )
    return out.stdout.strip()


class CrossProcessRevocation(unittest.TestCase):

    def test_revocation_is_invisible_to_an_unwired_receiver(self):
        """The documented limit: revoked in the caller, verifies at the receiver, body reached."""
        tokens, _ = _mint_and_revoke()
        self.assertEqual(_receive(tokens, status_path=None), "REACHED")

    def test_wired_revocation_check_refuses_the_same_tokens(self):
        """The seam that closes it: a status source the caller wrote, consulted by the receiver."""
        tokens, leaf_jti = _mint_and_revoke()
        with tempfile.TemporaryDirectory() as d:
            status = Path(d) / "status.json"
            status.write_text(json.dumps({"revoked_jti": [leaf_jti]}))
            self.assertEqual(_receive(tokens, status_path=str(status)), "DENIED:revoked")

if __name__ == "__main__":
    unittest.main(verbosity=2)
