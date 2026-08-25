"""
Sinks — where `AuditLog` copies each entry AFTER writing its own file.

Local files only: the network never enters `AuditLog.append` (a slow or failed upload must never touch
enforcement). `SpoolSink` is the write-ahead spool an uploader drains later; it is a SEPARATE file with its own
lifecycle (the AuditLog file is truncated when a log is constructed — a spool must never share that), bounded
(on overflow it stops writing and counts what it dropped; the ledger file remains the log of record), fsync'd
every N lines and on `flush()`, and it carries the ingest idempotency key on every line:

    {"boot_id": ..., "chain_id": ..., "seq": ..., "hash": ..., "entry": {...}}

together with the installation the uploader authenticates as, that is (installation, boot, chain, seq, hash)
— two processes running the same workload emit identical hashes from GENESIS, so the hash alone is not a key.
Stdlib only.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

__all__ = ["SpoolSink"]


class SpoolSink:
    def __init__(self, path, *, boot: str | None = None, max_bytes: int = 64 * 1024 * 1024, fsync_every: int = 64):
        from attenu_guard.identity import boot_id
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.boot = boot or boot_id()
        self.max_bytes = max_bytes
        self.fsync_every = max(1, fsync_every)
        self._lock = threading.Lock()
        self._fh = self.path.open("a", encoding="utf-8")          # append: a new sink never truncates an existing spool
        self._size = self.path.stat().st_size
        self._since_sync = 0
        self.written = 0
        self.dropped = 0
        self.overflowed = False
        self._offset_file = self.path.with_suffix(self.path.suffix + ".offset")

    # ---- AuditLog sink protocol ---------------------------------------------
    def write(self, entry: dict) -> None:
        line = json.dumps({"boot_id": self.boot, "chain_id": entry.get("chain_id"), "seq": entry.get("seq"),
                           "hash": entry.get("hash"), "entry": entry},
                          sort_keys=True, separators=(",", ":")) + "\n"
        data = line.encode("utf-8")
        with self._lock:
            if self.overflowed or self._size + len(data) > self.max_bytes:
                self.overflowed = True
                self.dropped += 1                                  # bounded: the ledger file stays the log of record
                return
            self._fh.write(line)
            self._fh.flush()                                   # out of the process on every line (a process crash loses nothing);
            self._size += len(data)                            # fsync (power-loss durability) every N lines and on flush()
            self.written += 1
            self._since_sync += 1
            if self._since_sync >= self.fsync_every:
                self._sync()

    def _sync(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._since_sync = 0

    def flush(self) -> None:
        with self._lock:
            self._sync()

    # ---- uploader side: resumable read + ack --------------------------------
    def _offset(self) -> int:
        return int(self._offset_file.read_text()) if self._offset_file.exists() else 0

    def read_pending(self, max_n: int = 500) -> list[dict]:
        """The next `max_n` un-acked lines (each with the idempotency key + the entry)."""
        with self._lock:
            self._fh.flush()
            lines = self.path.read_text(encoding="utf-8").splitlines()
        start = self._offset()
        return [json.loads(ln) for ln in lines[start:start + max_n] if ln.strip()]

    def ack(self, n: int) -> None:
        """Advance the durable offset by `n` lines (after the server confirmed them)."""
        self._offset_file.write_text(str(self._offset() + n))

    def close(self) -> None:
        with self._lock:
            try:
                self._sync()
            finally:
                self._fh.close()
