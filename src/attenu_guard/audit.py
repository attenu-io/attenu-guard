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
import math
import threading
from dataclasses import dataclass
from pathlib import Path

from . import canonical
from ._display import shown as _shown

SCHEMA_VERSION = 1
GENESIS = "0" * 64


def _integral(value):
    """`value` as the integer it is, or None when it is not one.

    The rule for every `seq` and `v` this package reads off a ledger, a bundle or an envelope:
    an integral number that is not a bool, as the schema's `integer` type defines it (JSON
    Schema 2020-12, schema/agent-audit.schema.json). `1.0` is 1 and `-0.0` is 0, and RFC 8785
    writes both as the integer, so they hash alike. A bool is not a number here although
    Python's `bool` is an `int` (`True == 1`), and neither is a string, null, or a number that
    is fractional or not finite."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value == int(value):
        return int(value)
    return None


def _int_or(value):
    """`value` as a message prints it: the integer when it is integral (`_integral`) and inside
    the I-JSON safe range, so `1.0` reads 1 as it does in every other implementation, and the
    value unchanged otherwise. Past ±(2**53 - 1) a number is not exact across implementations,
    and it is left as Python prints it."""
    integral = _integral(value)
    if integral is None or abs(integral) > canonical.MAX_SAFE_INTEGER:
        return value
    return integral


def _canonical(obj: dict) -> bytes:
    return canonical.dumps(obj)


def _hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(_canonical(payload))
    return h.hexdigest()


class CommittedAuditError(RuntimeError):
    """Raised by `AuditLog.append` when the entry was committed to the in-memory chain but
    persisting it afterward (the audit-path file write, or a sink) raised.

    The entry IS committed — it is in `entries`/`head()` and every later `hash`/`prev_hash`
    is computed on top of it. Callers must not retry the operation that produced this entry
    merely because this was raised: retrying would record it a second time. The original
    exception is chained as `__cause__`.
    """

    def __init__(self, entry: dict, cause: BaseException):
        self.entry = entry
        super().__init__(
            f"entry seq={entry.get('seq')} was committed to the audit log, but persisting it "
            f"failed: {cause!r}"
        )


@dataclass
class AuditLog:
    """Append-only, hash-chained decision log.

    Timestamps are injected by the caller (default: a monotonic counter) so the
    log stays deterministic in tests and reproducible in replay. In production
    the runtime supplies a trusted timestamp.
    """

    path: Path | None = None
    sinks: tuple = ()                 # local-file sinks (see sinks.py); each gets every entry after the file write
    overwrite: bool = False           # False: refuse to silently erase a pre-existing non-empty ledger at `path`
    schema_version: int = SCHEMA_VERSION   # 0.9.0: per-chain, stated on `v` of every entry (see guard.py's
                                            # `schema_version=` on Guard.issue — chains never mix versions)
    _prev: str = GENESIS
    _seq: int = 0
    _entries: list[dict] = None  # in-memory mirror

    def __post_init__(self):
        if self.schema_version not in (1, 2):
            raise ValueError(f"unsupported schema_version {self.schema_version!r}; expected 1 or 2")
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
            if self.path.exists() and self.path.stat().st_size > 0 and not self.overwrite:
                raise FileExistsError(
                    f"{self.path} already has a ledger; use a new audit_path, or pass "
                    "audit_overwrite=True to Guard.issue (overwrite=True to AuditLog) to replace it "
                    "(this permanently discards the existing entries)"
                )
            self.path.write_text("")  # fresh log

    def append(self, event: str, ts: str | int, **fields) -> dict:
        with self._lock:
            payload = {
                "v": self.schema_version,
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
            self._entries.append(payload)          # committed: the entry now exists in the chain
            try:
                if self.path:
                    with self.path.open("a") as f:
                        f.write(canonical.dumps(payload).decode("utf-8") + "\n")
                for sink in self.sinks:                # local files only — never the network (see sinks.py)
                    sink.write(payload)
            except Exception as exc:
                raise CommittedAuditError(payload, exc) from exc
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
            "v": self.schema_version,
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
        try:
            for key in ("v", "chain_id", "seq", "head", "ts"):
                anchor[key]
        except KeyError as exc:
            return False, f"anchor missing field {exc.args[0]}"
        body = {k: v for k, v in anchor.items() if k not in ("kid", "sig", "verified")}
        try:
            signing_input = canonical.dumps(body)
        except canonical.UnsafeIntegerError:
            # An integer past 2**53 has no RFC 8785 form, so no signer produced an anchor carrying
            # one (`anchor()` refuses to): what arrived is not a signed anchor, and the verdict is
            # that its signature does not verify. Raising here crashed the verifier on input from
            # the bundle. Signing still raises, in `anchor()` and `evidence.export_bundle`.
            return False, "anchor signature invalid"
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
            return (_integral(anchor["seq"]) == -1), None
        entry_chain_id = next((e["chain_id"] for e in entries if e.get("chain_id")), None)
        if anchor["chain_id"] != entry_chain_id:
            return False, "anchor chain_id does not match the ledger entries"
        if (entries[-1]["hash"] != anchor["head"]
                or _integral(entries[-1]["seq"]) != _integral(anchor["seq"])):
            return False, "anchor head does not match the ledger head (ledger rewritten?)"
        return True, None

    @staticmethod
    def verify(entries: list[dict]) -> tuple[bool, str | None]:
        """Recompute the chain. Returns (ok, first_bad_reason)."""
        prev = GENESIS
        expected_seq = 0
        for e in entries:
            seq = e.get("seq")
            # An integral number and never a bool (`_integral`): `True == 1` in Python, so a
            # re-hashed chain carrying `"seq": true` at index 1 used to verify with no failure.
            # `1.0` is 1, as the schema's integer type and RFC 8785 both have it.
            if _integral(seq) != expected_seq:
                # `seq` is the entry's own value, which a forged ledger chooses: printed by the
                # one rule (`_display.shown`) so it cannot end the reader's line and start another,
                # and an integral one as its integer.
                return False, f"seq gap at {expected_seq} (got {_shown(_int_or(seq))})"
            stored = e.get("hash")
            payload = {k: v for k, v in e.items() if k != "hash"}
            if payload.get("prev_hash") != prev:
                return False, f"prev_hash mismatch at seq {expected_seq}"
            try:
                computed = _hash(prev, payload)
            except canonical.UnsafeIntegerError:
                # An integer past 2**53 has no RFC 8785 form, so this entry cannot be the one its
                # hash was computed over (`append` refuses to write one): the chain does not
                # reproduce here, which is the existing finding, at this entry. Raising crashed
                # the verifier on input from the bundle; writing still raises.
                return False, f"hash mismatch at seq {expected_seq}"
            if computed != stored:
                return False, f"hash mismatch at seq {expected_seq}"
            prev = stored
            expected_seq += 1
        return True, None

    @classmethod
    def load(cls, path: str | Path) -> list[dict]:
        lines = Path(path).read_text().splitlines()
        return [json.loads(ln) for ln in lines if ln.strip()]
