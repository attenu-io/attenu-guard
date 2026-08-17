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
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1
GENESIS = "0" * 64


def _canonical(obj: dict) -> bytes:
    # Deterministic serialisation so hashes are reproducible across machines.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


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
    _prev: str = GENESIS
    _seq: int = 0
    _entries: list[dict] = None  # in-memory mirror

    def __post_init__(self):
        self._entries = []
        if self.path:
            self.path = Path(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("")  # fresh log

    def append(self, event: str, ts: str | int, **fields) -> dict:
        payload = {
            "v": SCHEMA_VERSION,
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
                f.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    # ---- verification --------------------------------------------------
    @staticmethod
    def verify(entries: list[dict]) -> tuple[bool, str | None]:
        """Recompute the chain. Returns (ok, first_bad_reason)."""
        prev = GENESIS
        expected_seq = 0
        for e in entries:
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
