"""
Hash-chained audit log — the open, verifiable record of every authority decision.

Each event is appended as one JSON line whose `hash` covers the event plus the
previous line's hash. Any insertion, deletion, or reordering breaks the chain
and is detectable offline by anyone, with no vendor in the loop. This is the
free/open core of the evidence ledger; the commercial product adds signing with
customer-held keys, external anchoring, and regulator-shaped exports.

Schema is versioned and published in schema/agent-audit.schema.json so other
tools (SIEMs, observability) can ingest it. The schema is the standard we seed.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from . import canonical

SCHEMA_VERSION = 1
GENESIS = "0" * 64


def _canonical(obj: dict) -> bytes:
    return canonical.dumps(obj)


def _hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(_canonical(payload))
    return h.hexdigest()


@dataclass
class AuditLog:
    """Append-only, hash-chained decision log.

    Timestamps are injected by the caller (default: a monotonic counter) so the
    log stays deterministic in tests and reproducible in replay. In production
    the runtime supplies a trusted timestamp.
    """

    path: Path | None = None
    sinks: tuple = ()                 # local-file sinks (see sinks.py); each gets every entry after the file write
    _prev: str = GENESIS
    _seq: int = 0
    _entries: list[dict] = None  # in-memory mirror

    def __post_init__(self):
        self._entries = []
        # One lock per log: `append` reads prev_hash/seq, hashes, then writes
        # both — an unsynchronised interleaving from two threads (frameworks
        # run parallel tool calls on thread pools) forks the chain and makes
        # `verify()` reject the library's OWN log. RLock: `verify`/`entries`
        # never take it, so there is no re-entrancy today, but it is cheap.
        self._lock = threading.RLock()
        if self.path:
            self.path = Path(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("")  # fresh log

    def append(self, event: str, ts: str | int, **fields) -> dict:
        with self._lock:
            payload = {
                "v": SCHEMA_VERSION,
                "c14n": "JCS",
                "seq": self._seq,
                "ts": ts,
                "event": event,
                **fields,
                "prev_hash": self._prev,
            }
            payload["hash"] = _hash(self._prev, payload)
            self._prev = payload["hash"]
            self._seq += 1
            self._entries.append(payload)
            if self.path:
                with self.path.open("a") as f:
                    f.write(canonical.dumps(payload).decode("utf-8") + "\n")
            for sink in self.sinks:                    # local files only — never the network (see sinks.py)
                sink.write(payload)
            return payload

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    # Ergonomics (adapters kept writing `.entries()`): iterate/len the log
    # directly. `entries` stays a property — the wire-published contract.
    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    # ---- verification --------------------------------------------------
    def head(self) -> tuple[int, str]:
        """(seq, hash) of the last entry — the chain head. (-1, GENESIS) for an empty log."""
        with self._lock:
            if not self._entries:
                return (-1, GENESIS)
            last = self._entries[-1]
            return (last["seq"], last["hash"])

    def anchor(self, signer, ts: str | int = 0) -> dict:
        """A signed external COMMITMENT to the chain head (ADR-14). Publish it out-of-band; a later
        `verify_anchor` then catches a log that was fully rewritten and re-hashed — plain `verify` cannot,
        because a consistent rewrite reproduces its own hashes. The signed head hash is the fixed point."""
        seq, head = self.head()
        body = {
            "v": SCHEMA_VERSION,
            "c14n": "JCS",
            "chain_id": self._chain_id_hint(),
            "seq": seq,
            "head": head,
            "ts": ts,
        }
        signing_input = canonical.dumps(body)
        return {**body, "kid": getattr(signer, "kid", None), "sig": signer.sign(signing_input).hex()}

    def _chain_id_hint(self) -> str:
        for e in self._entries:
            if e.get("chain_id"):
                return e["chain_id"]
        return "chain"

    @staticmethod
    def verify_anchor(entries: list[dict], anchor: dict, signer) -> tuple[bool, str | None]:
        """The chain reproduces AND its head matches a SIGNED anchor. Catches a consistent full rewrite."""
        if anchor.get("c14n") != "JCS":
            return False, "anchor canonicalization is not JCS"
        try:
            body = {k: anchor[k] for k in ("v", "c14n", "chain_id", "seq", "head", "ts")}
        except KeyError as exc:
            return False, f"anchor missing field {exc.args[0]}"
        signing_input = canonical.dumps(body)
        try:
            sig = bytes.fromhex(anchor.get("sig", ""))
        except ValueError:
            return False, "anchor signature not hex"
        if not signer.verify(signing_input, sig, anchor.get("kid")):
            return False, "anchor signature invalid"
        ok, err = AuditLog.verify(entries)
        if not ok:
            return False, err
        if not entries:
            return (anchor["seq"] == -1), None
        if entries[-1]["hash"] != anchor["head"] or entries[-1]["seq"] != anchor["seq"]:
            return False, "anchor head does not match the ledger head (ledger rewritten?)"
        return True, None

    @staticmethod
    def verify(entries: list[dict]) -> tuple[bool, str | None]:
        """Recompute the chain. Returns (ok, first_bad_reason)."""
        prev = GENESIS
        expected_seq = 0
        for e in entries:
            if e.get("c14n") != "JCS":
                return False, f"canonicalization is not JCS at seq {expected_seq}"
            if e.get("seq") != expected_seq:
                return False, f"seq gap at {expected_seq} (got {e.get('seq')})"
            stored = e.get("hash")
            payload = {k: v for k, v in e.items() if k != "hash"}
            if payload.get("prev_hash") != prev:
                return False, f"prev_hash mismatch at seq {expected_seq}"
            if _hash(prev, payload) != stored:
                return False, f"hash mismatch at seq {expected_seq}"
            prev = stored
            expected_seq += 1
        return True, None

    @classmethod
    def load(cls, path: str | Path) -> list[dict]:
        lines = Path(path).read_text().splitlines()
        return [json.loads(ln) for ln in lines if ln.strip()]
