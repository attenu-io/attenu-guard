"""
Identity without a key — a process boot id, a product discovered from `.attenu/product.json`, and where its
ledgers and spools live.

A product has an identity BEFORE it has a key or a cloud — the way a git repository has an identity before
it has a remote. Several products on one machine are several directories, each with its own `product.json`;
a running process is an *installation* of one product, distinguished by a random per-process boot id.

Why the boot id matters for the ledger: two processes running the same workload produce byte-identical hash
chains from GENESIS (seq 0, counter timestamps), so the entry hash alone is NOT unique across processes. The
boot id is what keeps their ledgers distinct on disk and forms part of the ingest idempotency key
(installation, boot, chain, seq, hash). Stdlib only; nothing here ever touches the network.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

__all__ = ["boot_id", "new_chain_id", "find_product_dir", "load_product", "ledger_path", "spool_path"]

_BOOT: str | None = None


def boot_id() -> str:
    """Random per-process nonce (16 hex chars), constant for the life of the process."""
    global _BOOT
    if _BOOT is None:
        _BOOT = secrets.token_hex(8)
    return _BOOT


def new_chain_id(prefix: str = "chain") -> str:
    """An ASSIGNED chain id (`<prefix>-<8 hex>`) — never inferred from the entries."""
    return f"{prefix}-{secrets.token_hex(4)}"


def find_product_dir(start: Path | None = None) -> Path | None:
    """The directory holding `.attenu/product.json`: `ATTENU_PRODUCT_DIR` if set (and valid), else the
    nearest ancestor of `start` (default: cwd). None when not inside any product — that is not an error."""
    env = os.environ.get("ATTENU_PRODUCT_DIR")
    if env:
        p = Path(env)
        return p if (p / ".attenu" / "product.json").exists() else None
    cur = Path(start or Path.cwd()).resolve()
    for d in (cur, *cur.parents):
        if (d / ".attenu" / "product.json").exists():
            return d
    return None


def load_product(start: Path | None = None) -> dict | None:
    d = find_product_dir(start)
    if d is None:
        return None
    return json.loads((d / ".attenu" / "product.json").read_text())


def ledger_path(product_dir: Path, chain_id: str, boot: str | None = None) -> Path:
    """`<product>/.attenu/ledger/<boot>/<chain_id>.jsonl` — one file per chain, one directory per process."""
    return Path(product_dir) / ".attenu" / "ledger" / (boot or boot_id()) / f"{chain_id}.jsonl"


def spool_path(product_dir: Path, boot: str | None = None) -> Path:
    """`<product>/.attenu/spool/<boot>.ndjson` — the write-ahead spool an uploader drains later."""
    return Path(product_dir) / ".attenu" / "spool" / f"{boot or boot_id()}.ndjson"
