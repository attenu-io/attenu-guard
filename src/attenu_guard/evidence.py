"""
Offline evidence bundle + verifier (attenu-derive T33a). The delegation ledger is only worth as much as an
auditor's ability to check it WITHOUT the engine that produced it. This module exports a self-contained bundle
(the hash-chained ledger + a signed anchor) and verifies three invariants from that bundle ALONE:

  integrity     the hash chain reproduces AND matches the out-of-band signed anchor (a consistent full rewrite,
                which `AuditLog.verify` alone cannot catch, fails here — the anchor's head is the fixed point);
  monotonicity  every delegation is child ⊆ parent (the granted authority on each `spawn` is narrower than the
                parent node's authority) — Attenu's core claim, re-checked offline;
  containment   every `allow` action's scope was within the acting node's authority — the ledger is internally
                consistent, no action was authorised outside what the node held.

    from attenu_guard import evidence
    bundle = evidence.export_bundle(guard.audit_log(), signer)     # publish this + verify the anchor out-of-band
    rep = evidence.verify_bundle(bundle, signer)                   # {"ok", "checks": {...}, "failures": [...],
                                                                   #  "failure_details": [...]}

`failures` is the human-readable list (its strings are a published contract — other implementations
parse them); `failure_details` is its machine-readable twin, one dict per string, same order, same
count: `{"reason", "seq", "node", "call_id", "detail"}`. It exists so a conformance suite can assert
WHICH check failed and WHERE, not merely that something did — see tests/vectors/bundles/.

Stdlib-only; `signer` is any `wire` signer (Ed25519 in production). No engine state is consulted — the bundle
is the whole input, which is the point.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from attenu_guard import canonical
from attenu_guard.audit import SCHEMA_VERSION, AuditLog, GENESIS as _GENESIS, _hash as _rehash
from attenu_guard.authority import Authority
from attenu_guard.ceilings import describe as _describe_ceiling
from attenu_guard.reasons import Capture, BodyState
from attenu_guard.params import ParamsHashReason

__all__ = ["export_bundle", "verify_bundle", "delegation_graph", "denials", "redaction_report", "EvidenceLeakError", "LEDGER_FIELDS",
           "SUPPORTED_BUNDLE_VERSIONS"]

# Bundle schema versions this build knows how to verify. A bundle (or anchor) declaring anything
# else is rejected rather than verified against a schema this code doesn't actually understand.
# 2 (0.9.0): execution binding — call_id, capture/adapter, outcome events, params commitments.
# v1 bundles verify exactly as before; `execution_binding` reports "not applicable" for them
# (docs/execution-binding spec section 9).
SUPPORTED_BUNDLE_VERSIONS = frozenset({1, 2})

# The COMPLETE set of top-level ledger field names the shim emits. Custody guarantee (A2b): an exported bundle may
# carry ONLY these — an unknown field is exactly where a raw tool argument would be smuggled, so it is a leak, not a
# curiosity. This is a test, not a habit: `export_bundle(strict=True)` raises on any field outside this set.
LEDGER_FIELDS = frozenset({
    "v", "c14n", "seq", "ts", "event", "prev_hash", "hash", "chain_id", "node", "parent", "agent", "task",
    "scope", "tool", "context", "reason", "reasons", "authority", "requested", "granted", "target",
    "revoked", "strikes", "mode", "disposition",
    # 0.9.0 execution binding (schema_version=2 chains): every field named in the spec.
    "call_id", "capture", "adapter", "authorized_params_hash", "params_hash_reason", "params_salt",
    "body_state", "error_code", "invoked_params_hash", "duration_ms", "receipt", "pending_at_kill",
})
# `task` is free text (a delegated prompt) and `context` is a dict; both are redacted for transport (see below).


class EvidenceLeakError(RuntimeError):
    """Raised by export_bundle(strict=True) when a bundle would carry a field or context key outside the allow-list —
    i.e. potential customer data the custody contract says must not leave the premises."""


class _FailureLog:
    """The verifier's failure list, kept in two shapes that cannot drift apart.

    `messages` is the string list `verify_bundle` has always returned as `failures`; those exact
    strings are a published contract (other implementations parse them), so they are never
    reworded here. `details` is the structured twin of each one, appended in the same call:

        {"reason": <stable token, the text before the first ':' in `detail`>,
         "seq":    <the offending entry's own seq, or None for a chain-level failure>,
         "node":   <the offending entry's node, or None>,
         "call_id":<the call this failure is about, or None>,
         "detail": <the string, verbatim>}

    Every failure in this module goes through `add()`, so a new check cannot add a message
    without its twin: tests/test_bundle_vectors.py greps this file for a direct append to a
    failure list and fails on one, and asserts the two lists stay in step at every site."""

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.details: list[dict] = []

    def add(self, reason: str, detail: str, *, seq=None, node=None, call_id=None) -> None:
        self.messages.append(detail)
        self.details.append({"reason": reason, "seq": seq, "node": node,
                             "call_id": call_id, "detail": detail})

    def extend(self, other: "_FailureLog") -> None:
        self.messages += other.messages
        self.details += other.details

    def __len__(self) -> int:
        return len(self.messages)


def _redact_task(t):
    import hashlib
    if not t:
        return t
    return f"redacted:len={len(str(t))}:h={hashlib.sha256(str(t).encode()).hexdigest()[:12]}"


def redaction_report(entries: list[dict], *, context_allowlist=None) -> dict:
    """Every top-level field must be in LEDGER_FIELDS; if `context_allowlist` is given, every context key must be in it.
    Returns {ok, violations:[{event_index, field|context_key, ...}]}. `task` free-text is allowed structurally but is
    redacted by export_bundle(redact_task=True) for transport (its raw value is the caller's, not the shim's, to keep)."""
    violations = []
    for i, e in enumerate(entries):
        for f in e:
            if f not in LEDGER_FIELDS:
                violations.append({"event_index": i, "event": e.get("event"), "field": f})
        if context_allowlist is not None:
            for k in (e.get("context") or {}):
                if k not in context_allowlist:
                    violations.append({"event_index": i, "event": e.get("event"), "context_key": k})
    return {"ok": not violations, "violations": violations}


def _chain_id(entries: list[dict]) -> str:
    for e in entries:
        if e.get("chain_id"):
            return e["chain_id"]
    return "chain"


def _bundle_version(entries: list[dict]) -> int:
    """The chain's declared schema version, read off the `root` entry (falls back to
    SCHEMA_VERSION for an empty/rootless list — the historical default)."""
    for e in entries:
        if e.get("event") == "root" and "v" in e:
            return e["v"]
    return SCHEMA_VERSION


def _anchor_for(entries: list[dict], signer, ts: int = 0) -> dict:
    """A signed commitment to the head of `entries` (mirrors AuditLog.anchor, but over a plain list — used by
    export and by tests that re-anchor a rewritten bundle)."""
    if not entries:
        seq, head = -1, "GENESIS"
    else:
        seq, head = entries[-1].get("seq", len(entries) - 1), entries[-1]["hash"]
    body = {
        "v": _bundle_version(entries),
        "c14n": "JCS",
        "chain_id": _chain_id(entries),
        "seq": seq,
        "head": head,
        "ts": ts,
    }
    signing_input = canonical.dumps(body)
    return {**body, "kid": getattr(signer, "kid", None), "sig": signer.sign(signing_input).hex()}


def export_bundle(audit_log: AuditLog, signer, ts: int = 0, *, context_allowlist=None, redact_task: bool = False,
                  strict: bool = False) -> dict:
    """A self-contained evidence bundle: the full ledger + a signed anchor over its head.

    Custody (A2b): with `redact_task=True`, free-text `task` fields are replaced by a length+hash marker BEFORE the
    anchor is computed, so the transported bundle carries no raw prompt text yet still verifies. With `strict=True`
    the bundle is checked against LEDGER_FIELDS (and `context_allowlist` if given) and an `EvidenceLeakError` is
    raised on any field/context key outside the allow-list — the flywheel transport ships nothing unvetted."""
    import copy
    entries = copy.deepcopy(audit_log.entries)
    if redact_task:
        for e in entries:
            if "task" in e:
                e["task"] = _redact_task(e["task"])
        # re-hash the chain so the redacted form is what the anchor covers (redaction is not tampering: it only ever removes)
        prev = _GENESIS
        for e in entries:
            e["prev_hash"] = prev
            payload = {k: v for k, v in e.items() if k != "hash"}
            e["hash"] = _rehash(prev, payload); prev = e["hash"]
    report = redaction_report(entries, context_allowlist=context_allowlist)
    if strict and not report["ok"]:
        raise EvidenceLeakError(f"{len(report['violations'])} field(s) outside the ledger allow-list: {report['violations'][:5]}")
    anchor = _anchor_for(entries, signer, ts)
    from attenu_guard import AuditLog as _AL
    anchor["verified"] = _AL.verify_anchor(entries, anchor, signer)[0]
    return {"v": _bundle_version(entries), "c14n": "JCS", "chain_id": _chain_id(entries), "entries": entries,
            "anchor": anchor, "redaction": report,
            "note": "offline-verifiable: attenu_guard.evidence.verify_bundle(bundle, signer)"}


def _node_authorities(entries: list[dict]) -> tuple[dict, dict, _FailureLog, dict]:
    """(node -> Authority, node -> parent, failures, node -> defining entry) reconstructed from
    root/spawn events, no engine state.

    The fourth element is the `root`/`spawn` entry each node was DEFINED by, so a node-level
    failure (monotonicity) can name the seq of the delegation that caused it, not only the node.
    These two failures are the one place where the historical string does not start with a
    reason token — it names the node — so their `reason` is stated explicitly rather than parsed
    out of the message."""
    auth: dict[str, Authority] = {}; parent: dict[str, str] = {}; fail = _FailureLog()
    defined_by: dict[str, dict] = {}
    for e in entries:
        ev = e.get("event")
        if ev == "root":
            defined_by[e.get("node")] = e
            try: auth[e["node"]] = Authority.from_wire(e["authority"])
            except Exception as exc: fail.add("unreadable_authority", f"root {e.get('node')}: unreadable authority ({exc})", seq=e.get("seq"), node=e.get("node"))  # noqa: BLE001
        elif ev == "spawn":
            defined_by[e.get("node")] = e
            parent[e["node"]] = e.get("parent")
            try: auth[e["node"]] = Authority.from_wire(e["granted"])
            except Exception as exc: fail.add("unreadable_granted", f"spawn {e.get('node')}: unreadable granted ({exc})", seq=e.get("seq"), node=e.get("node"))  # noqa: BLE001
    return auth, parent, fail, defined_by


def _monotonicity_detail(child: Authority, parent: Authority) -> str:
    """Why `child` is not ⊆ `parent`, rendered for the monotonicity failure message.

    Called only once `Authority.is_narrower_than` has already returned False, and it walks the
    dimensions in the ORDER that relation compares them — scopes, then ceilings by key, then ttl
    — so the message names the dimension that actually failed. Every dimension the relation can
    fail on has a branch here:

      scopes    a scope the parent does not cover (wildcard-aware);
      ceilings  a key the parent bounds and the child does not (child unbounded there, so MORE
                powerful), or one the child bounds more loosely than the parent;
      ttl       a child that never expires under a parent that does, or one that outlives it.

    Reports the FIRST failing dimension: one message per unsound delegation, as before. The
    final fallback can only be reached if a future dimension is added to `is_narrower_than`
    without a branch here, and exists so that such a dimension cannot fail SILENTLY.
    """
    # Unchanged since 0.4.0, byte for byte. A scope failure always leaves this list non-empty:
    # a scope literally present in the parent's set is covered by it, so anything the parent
    # does not cover is also absent from that set.
    if not all(parent.covers_scope(s) for s in child.scopes):
        return f"child scopes {sorted(set(child.scopes) - set(parent.scopes))} not held by parent"

    child_by_key = {c.key: c for c in child.ceilings}
    for key, parent_ceiling in sorted(((c.key, c) for c in parent.ceilings), key=lambda kv: kv[0]):
        child_ceiling = child_by_key.get(key)
        if child_ceiling is None:
            return f"ceiling {key} unbounded, parent holds {_describe_ceiling(parent_ceiling)}"
        if not parent_ceiling.subsumes(child_ceiling):
            return (f"ceiling {_describe_ceiling(child_ceiling)} looser than parent "
                    f"{_describe_ceiling(parent_ceiling)}")

    if parent.ttl is not None:
        if child.ttl is None:
            return f"ttl unbounded, parent {parent.ttl}"
        if child.ttl > parent.ttl:
            return f"ttl {child.ttl} > parent {parent.ttl}"

    return "child not narrower than parent"


def delegation_graph(bundle: dict) -> dict:
    """A view of the chain from the bundle: each node with its agent, task, authority, parent, and per-node action
    counts (allow/deny) — what a reviewer or a UI renders. Derived from the ledger alone."""
    entries = bundle.get("entries") or []
    auth, parent, _fail, _defined_by = _node_authorities(entries)
    meta: dict[str, dict] = {}
    for e in entries:
        ev = e.get("event"); n = e.get("node")
        if ev in ("root", "spawn"):
            meta[n] = {"agent": e.get("agent"), "task": e.get("task"), "parent": e.get("parent"),
                       "scopes": sorted(auth[n].scopes) if n in auth else [], "allows": 0, "denies": 0, "revoked": False, "complete": False,
                       "denials_by_disposition": {}}
        elif ev == "allow" and n in meta: meta[n]["allows"] += 1
        elif ev == "deny" and n in meta:
            meta[n]["denies"] += 1
            d = e.get("disposition") or e.get("reason") or "unstated"     # a deny without a disposition is named by its reason (revoked, ceiling_exceeded…)
            meta[n]["denials_by_disposition"][d] = meta[n]["denials_by_disposition"].get(d, 0) + 1
        elif ev == "done" and n in meta: meta[n]["complete"] = True
        elif ev == "kill":
            for r in (e.get("revoked") or []):
                if r in meta: meta[r]["revoked"] = True
    return {"chain_id": bundle.get("chain_id"), "nodes": meta,
            "edges": [{"parent": p, "child": c} for c, p in parent.items() if p]}


def denials(bundle: dict) -> list[dict]:
    """Deny events grouped by (node, tool, scope, disposition) — the rows a Decisions queue renders: "should this
    agent be allowed to <tool>?" with how often it asked and why it was refused. A pure fold over the ledger; no
    engine, no state. Ordered by first occurrence."""
    entries = bundle.get("entries") or []
    agent_of = {e.get("node"): e.get("agent") for e in entries if e.get("event") in ("root", "spawn")}
    rows: dict[tuple, dict] = {}
    for e in entries:
        if e.get("event") != "deny":
            continue
        key = (e.get("node"), e.get("tool"), e.get("scope"), e.get("disposition"))
        r = rows.get(key)
        if r is None:
            rows[key] = {"node": e.get("node"), "agent": agent_of.get(e.get("node")), "tool": e.get("tool"),
                         "scope": e.get("scope"), "disposition": e.get("disposition"), "reason": e.get("reason"),
                         "count": 1, "first_seq": e.get("seq"), "last_seq": e.get("seq")}
        else:
            r["count"] += 1; r["last_seq"] = e.get("seq")
    return sorted(rows.values(), key=lambda r: r["first_seq"])


# =========================================================================
# Execution binding (0.9.0): offline checks over call_id/allow/outcome, from
# the ledger alone — docs/execution-binding spec section 5. Schema_version=2
# chains only; a v1 bundle's execution_binding is {"status": "not applicable"}.
# =========================================================================

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _present_but_null(e: dict, field: str) -> bool:
    """True when `field` is EXPLICITLY present with a JSON null value — distinct from the key
    being absent entirely. A conditional field (authorized_params_hash, capture, ...) must be
    either a valid value or ABSENT; an explicit null is neither, and `dict.get` alone cannot
    tell the two apart (both return None)."""
    return field in e and e[field] is None


def _valid_call_id(e: dict) -> str | None:
    if _present_but_null(e, "call_id"):
        return "call_id is explicitly null (must be a valid call_id or absent)"
    cid = e.get("call_id")
    if not isinstance(cid, str) or not _HEX32.match(cid):
        return f"call_id missing or malformed ({cid!r})"
    return None


def _valid_hash_field(e: dict, field: str) -> str | None:
    if _present_but_null(e, field):
        return f"{field} is explicitly null (must be a valid hash or absent)"
    v = e.get(field)
    if v is None:
        return None
    if not isinstance(v, str) or not _HEX64.match(v):
        return f"{field} malformed ({v!r})"
    return None


def _valid_params_hash_reason(e: dict, hash_field: str) -> str | None:
    if _present_but_null(e, "params_hash_reason"):
        return "params_hash_reason is explicitly null (must be a valid reason or absent)"
    reason = e.get("params_hash_reason")
    if reason is not None and reason not in ParamsHashReason.ALL:
        return f"params_hash_reason {reason!r} not a known value"
    if reason is not None and e.get(hash_field) is not None:
        return f"params_hash_reason present alongside {hash_field} (illegal conditional field)"
    return None


_ALLOW_ONLY_FIELDS = frozenset({"capture", "adapter", "authorized_params_hash", "params_hash_reason"})


def _validate_allow(e: dict) -> str | None:
    err = _valid_call_id(e)
    if err:
        return err
    if _present_but_null(e, "capture"):
        return "capture is explicitly null (must be a valid Capture value)"
    if _present_but_null(e, "adapter"):
        return "adapter is explicitly null (must be a valid adapter object)"
    capture = e.get("capture")
    adapter = e.get("adapter")
    # Mandatory on every v2 allow (not merely paired with each other): a bare check() with no
    # wrapper is ITSELF pre_hook_only observation, and Guard.check() supplies that truthfully —
    # there is no honest reason for a v2 allow to lack capture/adapter, so absence is now
    # invalid, not "no claim made" (Codex review item 4).
    if capture is None:
        return "capture is required on every v2 allow"
    if capture not in Capture.ALL:
        return f"capture {capture!r} not a known value"
    if adapter is None:
        return "adapter is required alongside capture on every v2 allow"
    if not isinstance(adapter, Mapping):
        return "adapter must be an object with module/version/hook_path"
    for k in ("module", "version", "hook_path"):
        if not isinstance(adapter.get(k), str) or not adapter.get(k):
            return f"adapter[{k!r}] must be a non-empty string"
    err = _valid_hash_field(e, "authorized_params_hash")
    if err:
        return err
    return _valid_params_hash_reason(e, "authorized_params_hash")


def _validate_deny(e: dict) -> str | None:
    err = _valid_call_id(e)
    if err:
        return err
    leaked = sorted(_ALLOW_ONLY_FIELDS & e.keys())
    if leaked:
        return f"deny carries allow-only field(s) {leaked}"
    return None


def _validate_outcome(e: dict) -> str | None:
    err = _valid_call_id(e)
    if err:
        return err
    if _present_but_null(e, "body_state"):
        return "body_state is explicitly null"
    body_state = e.get("body_state")
    if body_state not in BodyState.ALL:
        return f"body_state {body_state!r} not a known value"
    if _present_but_null(e, "error_code"):
        return "error_code is explicitly null (must be a non-empty string or absent)"
    error_code = e.get("error_code")
    if body_state == BodyState.RAISED:
        if not isinstance(error_code, str) or not error_code:
            return "error_code required when body_state == raised"
    elif error_code is not None:
        return "error_code present but body_state != raised (illegal conditional field)"
    if _present_but_null(e, "duration_ms"):
        return "duration_ms is explicitly null"
    duration = e.get("duration_ms")
    if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
        return f"duration_ms invalid ({duration!r})"
    err = _valid_hash_field(e, "invoked_params_hash")
    if err:
        return err
    err = _valid_params_hash_reason(e, "invoked_params_hash")
    if err:
        return err
    if _present_but_null(e, "receipt"):
        return "receipt is explicitly null (must be a valid receipt or absent)"
    receipt = e.get("receipt")
    if receipt is not None:
        if not isinstance(receipt, Mapping):
            return "receipt must be an object with type/ref/digest"
        for k in ("type", "ref"):
            if not isinstance(receipt.get(k), str) or not receipt.get(k):
                return f"receipt[{k!r}] must be a non-empty string"
        digest = receipt.get("digest")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            return "receipt['digest'] must be a lowercase-hex SHA-256 digest (64 hex characters)"
    return None


def _validate_root(e: dict) -> str | None:
    """v2 root only: params_salt is MANDATORY (spec section 4 — the whole chain's argument
    commitments are computed against it) and must be 32 lowercase hex characters (16 raw bytes)."""
    if _present_but_null(e, "params_salt"):
        return "params_salt is explicitly null"
    salt = e.get("params_salt")
    if not isinstance(salt, str) or not re.fullmatch(r"[0-9a-f]{32}", salt):
        return f"params_salt missing or malformed on the v2 root entry ({salt!r})"
    return None


def _validate_kill(e: dict) -> str | None:
    """v2 kill only: pending_at_kill, when present, must be a list of call_id-shaped strings."""
    if _present_but_null(e, "pending_at_kill"):
        return "pending_at_kill is explicitly null (must be a list or absent)"
    pending = e.get("pending_at_kill")
    if pending is None:
        return None
    if not isinstance(pending, list) or any(
            not isinstance(c, str) or not _HEX32.match(c) for c in pending):
        return f"pending_at_kill must be a list of call_id-shaped strings ({pending!r})"
    return None


def _params_coverage(allows: dict, outcomes: dict, invalid_allow_ids: set) -> str:
    """`complete | partial | none`, from how many calls carry both hashes — computed over EVERY
    valid allow (spec section 5: "how many calls carry both hashes"), not only calls that already
    have an outcome: a call still pending necessarily lacks invoked_params_hash and so correctly
    counts against coverage, not merely outside the sample."""
    total = both = 0
    for cid, allow_e in allows.items():
        if cid in invalid_allow_ids:
            continue
        total += 1
        oc = outcomes.get(cid)
        if allow_e.get("authorized_params_hash") and oc is not None and oc.get("invoked_params_hash"):
            both += 1
    if total == 0 or both == 0:
        return "none"
    return "complete" if both == total else "partial"


# Every field the shim ever writes only under schema_version=2 (spec sections 1-7). A
# schema_version=1 chain must carry NONE of them — including call_id: v1 never allocates one.
_V2_ONLY_FIELDS = frozenset({
    "call_id", "capture", "adapter", "authorized_params_hash", "params_hash_reason",
    "params_salt", "body_state", "error_code", "invoked_params_hash", "duration_ms",
    "receipt", "pending_at_kill",
})


def _v2_field_leaks_on_v1(entries: list[dict]) -> _FailureLog:
    """Every v2-only field found on any entry of a schema_version=1 bundle — mixed-version data,
    invalid regardless of which field it is (Codex review item 4/(c))."""
    failures = _FailureLog()
    for e in entries:
        leaked = sorted(_V2_ONLY_FIELDS & e.keys())
        if leaked:
            failures.add("v2_field_on_v1",
                         f"v2_field_on_v1: seq={e.get('seq')} event={e.get('event')!r} "
                         f"carries v2-only field(s) {leaked} on a schema_version=1 entry",
                         seq=e.get("seq"), node=e.get("node"))
    return failures


def _execution_binding(entries: list[dict], bundle_v) -> tuple[dict, _FailureLog]:
    """(the `execution_binding` report, its failures as a `_FailureLog`).

    The report's own `failures` key keeps its historical list-of-strings shape — the structured
    twins ride alongside it rather than inside it, so this sub-report's published shape is
    unchanged."""
    if bundle_v == 1:
        leaked = _v2_field_leaks_on_v1(entries)
        if leaked:
            return {"status": "not applicable", "failures": leaked.messages}, leaked
        return {"status": "not applicable"}, _FailureLog()
    if bundle_v != 2:
        return {"status": "not applicable"}, _FailureLog()

    failures = _FailureLog()
    seen_call_ids: dict[str, tuple] = {}     # call_id -> (event, node, seq) — first sighting, allow OR deny
    allows: dict[str, dict] = {}
    outcomes: dict[str, dict] = {}
    invalid_allow_ids: set = set()
    nodes: set = set()
    finalized_nodes: set = set()
    revoked_nodes: set = set()

    for e in entries:
        ev = e.get("event")
        if ev == "root":
            nodes.add(e.get("node"))
            err = _validate_root(e)
            if err:
                failures.add("invalid_root", f"invalid_root: {err} (seq {e.get('seq')})",
                             seq=e.get("seq"), node=e.get("node"))
        elif ev == "spawn":
            nodes.add(e.get("node"))
        elif ev == "done":
            finalized_nodes.add(e.get("node"))
        elif ev == "kill":
            revoked_nodes.update(e.get("revoked") or [])
            err = _validate_kill(e)
            if err:
                failures.add("invalid_kill", f"invalid_kill: {err} (seq {e.get('seq')})",
                             seq=e.get("seq"), node=e.get("node"))

        if ev in ("allow", "deny"):
            cid = e.get("call_id")
            if cid is not None:
                prior = seen_call_ids.get(cid)
                if prior is not None:
                    # Positioned on the SECOND sighting: the entry that re-used a call_id is the
                    # offending record, the first one having been legitimate when it was written.
                    failures.add("duplicate_call_id",
                                 f"duplicate_call_id: call_id {cid} on seq {e.get('seq')} ({ev}) "
                                 f"already used at seq {prior[2]} ({prior[0]})",
                                 seq=e.get("seq"), node=e.get("node"), call_id=cid)
                else:
                    seen_call_ids[cid] = (ev, e.get("node"), e.get("seq"))
            validator = _validate_allow if ev == "allow" else _validate_deny
            err = validator(e)
            if err:
                failures.add(f"invalid_{ev}", f"invalid_{ev}: {err} (seq {e.get('seq')})",
                             seq=e.get("seq"), node=e.get("node"), call_id=cid)
                if ev == "allow" and cid is not None:
                    invalid_allow_ids.add(cid)
                continue
            if ev == "allow" and cid is not None:
                allows[cid] = e
        elif ev == "outcome":
            cid = e.get("call_id")
            err = _validate_outcome(e)
            if err:
                failures.add("invalid_outcome", f"invalid_outcome: {err} (seq {e.get('seq')})",
                             seq=e.get("seq"), node=e.get("node"), call_id=cid)
                continue
            if cid in outcomes:
                failures.add("duplicate_outcome",
                             f"duplicate_outcome: call_id {cid} at seq {e.get('seq')} "
                             f"(first at seq {outcomes[cid].get('seq')})",
                             seq=e.get("seq"), node=e.get("node"), call_id=cid)
                continue
            outcomes[cid] = e

    # Bind each outcome to its allow: outcome_without_allow / cross_ref / outcome_before_allow / params_mismatch.
    # `bound_ok`: call_ids whose outcome exists AND passed identity+order binding (node match,
    # seq after the allow) — spec's "observed (an outcome exists, bound correctly)". Failing
    # params_mismatch does NOT itself un-bind a call: the call plainly WAS observed, only its
    # recorded content disagrees with what was authorized (spec: "parameter equality is
    # established only for calls where both hashes are present; elsewhere only identity and
    # order binding was checked" — params_mismatch is that separate concern).
    # Every failure in this loop is about a PAIR, and is positioned on the `outcome` entry: the
    # allow was a complete, valid record when it was written, and it is the outcome that fails to
    # bind to it (or reports different arguments than were authorized).
    bound_ok: set = set()
    for cid, oc in outcomes.items():
        allow_e = allows.get(cid)
        if allow_e is None:
            failures.add("outcome_without_allow",
                         f"outcome_without_allow: call_id {cid} at seq {oc.get('seq')} has no allow in this chain",
                         seq=oc.get("seq"), node=oc.get("node"), call_id=cid)
            continue
        node_ok = allow_e.get("node") == oc.get("node")
        if not node_ok:
            failures.add("cross_ref",
                         f"cross_ref: call_id {cid} allow on node {allow_e.get('node')!r} "
                         f"but outcome on node {oc.get('node')!r}",
                         seq=oc.get("seq"), node=oc.get("node"), call_id=cid)
        order_ok = (oc.get("seq") is not None and allow_e.get("seq") is not None
                   and oc["seq"] > allow_e["seq"])
        if not order_ok:
            failures.add("outcome_before_allow",
                         f"outcome_before_allow: call_id {cid} outcome seq {oc.get('seq')} "
                         f"not after allow seq {allow_e.get('seq')}",
                         seq=oc.get("seq"), node=oc.get("node"), call_id=cid)
        ah, ih = allow_e.get("authorized_params_hash"), oc.get("invoked_params_hash")
        if ah is not None and ih is not None and ah != ih:
            failures.add("params_mismatch",
                         f"params_mismatch: call_id {cid} authorized_params_hash {ah} != invoked_params_hash {ih}",
                         seq=oc.get("seq"), node=oc.get("node"), call_id=cid)
        if node_ok and order_ok:
            bound_ok.add(cid)

    # Per-call observation + per-node pending, from valid allows only.
    per_call: dict[str, str] = {}
    node_pending: dict[str, list] = {}
    for cid, allow_e in allows.items():
        if cid in invalid_allow_ids:
            continue
        # Spec order matters: "observed" (an outcome exists, BOUND CORRECTLY) is checked FIRST —
        # not merely "a call_id-matching outcome exists somewhere", which a cross_ref'd or
        # misordered outcome would satisfy despite being wrong. Only once no correctly-bound
        # outcome exists does capture decide unobserved (none was promised) vs unaccounted (one
        # was, and none arrived correctly).
        if cid in bound_ok:
            per_call[cid] = "observed"
            continue
        capture = allow_e.get("capture")
        if capture is None or capture == Capture.PRE_HOOK_ONLY:
            per_call[cid] = "unobserved"
        else:
            per_call[cid] = "unaccounted"
            node_pending.setdefault(allow_e.get("node"), []).append(cid)

    # Per-node lifecycle. "revoked" (clean kill, nothing pending) is not one of the spec's three
    # named states (finalized/in_progress/revoked_with_pending) — it names the gap those three
    # leave for a cleanly-killed node, distinct from revoked_with_pending, and never escalates
    # the aggregate (a smallest-honest addition; see the 0.9.0 implementation report).
    lifecycle: dict[str, str] = {}
    for n in nodes:
        if n in finalized_nodes:
            lifecycle[n] = "finalized"
        elif n in revoked_nodes:
            lifecycle[n] = "revoked_with_pending" if node_pending.get(n) else "revoked"
        else:
            lifecycle[n] = "in_progress"

    # Aggregate: clean < incomplete < failed: never downgrade once escalated.
    order = {"clean": 0, "incomplete": 1, "failed": 2}
    aggregate = "clean"

    def escalate(level: str) -> None:
        nonlocal aggregate
        if order[level] > order[aggregate]:
            aggregate = level

    if failures:
        # Any binding failure or invalid record is a genuine inconsistency, not a benign gap —
        # worse than "incomplete", which spec reserves for gaps that are no producer fault.
        escalate("failed")
    for n, state in lifecycle.items():
        if state == "finalized" and node_pending.get(n):
            escalate("failed")            # an unaccounted call in a finalized node (spec section 5)
        elif state in ("in_progress", "revoked_with_pending"):
            escalate("incomplete")
    if any(s == "unobserved" for s in per_call.values()):
        escalate("incomplete")

    return {
        "aggregate": aggregate,
        "params_coverage": _params_coverage(allows, outcomes, invalid_allow_ids),
        "per_call": per_call,
        "per_node_lifecycle": lifecycle,
        "failures": failures.messages,
    }, failures


def _integrity_position(entries: list[dict]) -> tuple:
    """(seq, node) of the FIRST entry the hash chain does not reproduce at — position only.

    `AuditLog.verify` stays the authority on WHETHER the chain is broken and on the message this
    module reports; this walk exists so the structured twin of that message can say WHERE, which
    the message's own text does not expose in a parseable form. Mirrors `AuditLog.verify`'s walk
    exactly (same seq/prev_hash/hash order). (None, None) when nothing entry-local is wrong — a
    consistently re-hashed ledger fails against the signed anchor, not here, and that failure is
    chain-level."""
    prev = _GENESIS
    for i, e in enumerate(entries):
        payload = {k: v for k, v in e.items() if k != "hash"}
        try:
            broken = (e.get("seq") != i or payload.get("prev_hash") != prev
                      or _rehash(prev, payload) != e.get("hash"))
        except Exception:  # noqa: BLE001 - an unhashable payload is itself the break, at this entry
            return e.get("seq"), e.get("node")
        if broken:
            return e.get("seq"), e.get("node")
        prev = e["hash"]
    return None, None


def verify_bundle(bundle: dict, signer=None, *, expected_anchor: dict | None = None,
                  expected_head: tuple | None = None) -> dict:
    """Verify integrity, monotonicity and containment from the bundle alone. Returns
    {ok, checks, failures, failure_details, ...}.

    `signer` is the verifier for the bundle's signed anchor (a public key, or the test signer). With `signer=None`
    the hash chain, monotonicity and containment are still checked, but the anchor signature is NOT — the report
    says so (`checks["anchor"] == "not checked"`), and `ok` then means "consistent, unverified by key": a consistent
    full rewrite by someone holding the key cannot be excluded without the key.

    Verifying against ONLY the bundle's own enclosed anchor detects tampering since that anchor, nothing earlier —
    a fully rewritten bundle whose attacker also controls (or omits) the anchor is invisible to that check alone
    (spec section 5). `expected_anchor` (a full anchor dict, e.g. one retained from an earlier `export_bundle`) or
    `expected_head` (a bare `(seq, hash)` tuple) let a caller supply an INDEPENDENTLY RETAINED reference point;
    when given, the bundle's actual (seq, hash, chain_id, v) must equal it exactly, or `checks["expected_anchor"]`
    reports `"FAILED"` and the mismatch lands in `failures`. `report["verified_against"]` names which mode ran.

    `failure_details` is the structured twin of `failures`: same order, same count, one
    `{"reason", "seq", "node", "call_id", "detail"}` dict per string, so a conformance suite can
    assert the reason AND the position of every failure instead of matching prose.
    """
    entries = bundle.get("entries") or []
    anchor = bundle.get("anchor") or {}
    checks = {"integrity": False, "monotonicity": False, "containment": False, "anchor": "not checked",
              "version": False, "chain_id": False, "root": False, "expected_anchor": "not checked"}
    log = _FailureLog()

    # (0) version: the bundle must declare a schema version this build understands, and — when an
    # anchor is present — the anchor must be anchoring THAT version, not a different one.
    bundle_v = bundle.get("v")
    version_ok = bundle_v in SUPPORTED_BUNDLE_VERSIONS
    if not version_ok:
        log.add("unsupported_version",
                f"unsupported_version: bundle v={bundle_v!r} not in {sorted(SUPPORTED_BUNDLE_VERSIONS)}")
    if anchor and anchor.get("v") != bundle_v:
        version_ok = False
        log.add("anchor_version_mismatch",
                f"anchor_version_mismatch: anchor v={anchor.get('v')!r} != bundle v={bundle_v!r}")

    # (0a) exactly one root: a rootless bundle (or one splicing in a second root) would otherwise
    # sail through monotonicity/containment trivially — there is nothing to anchor those checks to.
    root_events = [e for e in entries if e.get("event") == "root"]
    checks["root"] = len(root_events) == 1
    if not checks["root"]:
        log.add("missing_root",
                f"missing_root: bundle has {len(root_events)} root event(s), expected exactly 1")
    root_entry = root_events[0] if len(root_events) == 1 else None

    # 0.9.0: a chain is created at ONE schema version and never mixes (spec section 9) — the root
    # entry's v must equal the bundle's declared v, and no OTHER entry may carry a different v.
    if root_entry is not None and root_entry.get("v") != bundle_v:
        version_ok = False
        log.add("root_version_mismatch",
                f"root_version_mismatch: root v={root_entry.get('v')!r} != bundle v={bundle_v!r}",
                seq=root_entry.get("seq"), node=root_entry.get("node"))
    mixed_entries = [e for e in entries if e.get("v") != bundle_v]
    mixed = sorted({e.get("v") for e in mixed_entries})
    if mixed:
        version_ok = False
        # One aggregate message over every offending entry (unchanged); the twin is positioned on
        # the first of them, which is where a reader looks.
        log.add("mixed_entry_versions",
                f"mixed_entry_versions: entries declare v in {mixed}, bundle v={bundle_v!r}",
                seq=mixed_entries[0].get("seq"), node=mixed_entries[0].get("node"))
    checks["version"] = version_ok

    # (0c) independently retained expected anchor/head: verified against the BUNDLE's actual
    # computed head, never against its own (possibly forged) enclosed anchor.
    if expected_anchor is not None or expected_head is not None:
        actual_seq, actual_head = (len(entries) - 1, entries[-1]["hash"]) if entries else (-1, _GENESIS)
        ok = True
        if expected_head is not None:
            exp_seq, exp_hash = expected_head
            if actual_seq != exp_seq or actual_head != exp_hash:
                ok = False
                log.add("expected_head_mismatch",
                    f"expected_head_mismatch: bundle head is (seq={actual_seq}, hash={actual_head}) but the "
                    f"independently retained expected head is (seq={exp_seq}, hash={exp_hash})")
        if expected_anchor is not None:
            if (expected_anchor.get("seq") != actual_seq or expected_anchor.get("head") != actual_head
                    or expected_anchor.get("chain_id") != bundle.get("chain_id")
                    or expected_anchor.get("v") != bundle_v):
                ok = False
                log.add("expected_anchor_mismatch",
                    "expected_anchor_mismatch: the bundle's actual (seq, head, chain_id, v) does not match "
                    "the independently retained expected anchor")
        checks["expected_anchor"] = "verified" if ok else "FAILED"

    # (0b) chain identity: the bundle, every entry, and — when an anchor is present — the anchor
    # must all name the SAME chain. Without this a correctly-signed, internally-consistent bundle
    # for a DIFFERENT chain could be handed to a verifier who believes it is checking this one.
    bundle_chain_id = bundle.get("chain_id")
    foreign = next((e for e in entries if e.get("chain_id") != bundle_chain_id), None)
    entries_ok = foreign is None
    if not entries_ok:
        log.add("chain_id_mismatch",
                f"chain_id_mismatch: an entry does not carry chain_id={bundle_chain_id!r}",
                seq=foreign.get("seq"), node=foreign.get("node"))
    anchor_chain_ok = not anchor or anchor.get("chain_id") == bundle_chain_id
    if not anchor_chain_ok:
        log.add("chain_id_mismatch",
                f"chain_id_mismatch: anchor chain_id={anchor.get('chain_id')!r} != bundle chain_id={bundle_chain_id!r}")
    checks["chain_id"] = entries_ok and anchor_chain_ok

    # (1) integrity: hash chain (+ the signed anchor, when a verifier key is given)
    ok_chain, err = AuditLog.verify(entries)
    if not ok_chain:
        bad_seq, bad_node = _integrity_position(entries)
        log.add("integrity", f"integrity: {err}", seq=bad_seq, node=bad_node)
    if signer is not None:
        ok_anchor, aerr = AuditLog.verify_anchor(entries, anchor, signer)
        checks["anchor"] = "verified" if ok_anchor else "FAILED"
        # Chain-level by construction: the anchor commits to the head of the WHOLE ledger, so a
        # consistently re-hashed chain has no single offending entry to point at.
        if not ok_anchor: log.add("integrity(anchor)", f"integrity(anchor): {aerr}")
        checks["integrity"] = bool(ok_chain and ok_anchor)
    else:
        checks["integrity"] = bool(ok_chain)

    auth, parent, afail, defined_by = _node_authorities(entries)
    log.extend(afail)

    # (2) monotonicity: every child ⊆ its parent
    mono = True
    for node, pid in parent.items():
        if pid is None or pid not in auth or node not in auth:
            continue
        # 0.11.x: the subsumption relation ALONE decides. This used to be gated on a literal,
        # non-wildcard-aware scope difference, which silently accepted a delegation that widened
        # only ttl or a ceiling whenever the child's scopes happened to be literally a subset of
        # the parent's — the child was more powerful and the bundle verified clean. The relation
        # already compares every dimension; `_monotonicity_detail` names the one that failed.
        if not auth[node].is_narrower_than(auth[pid]):
            mono = False
            spawn_e = defined_by.get(node) or {}
            log.add("monotonicity",
                    f"monotonicity: {node} not ⊆ parent {pid} ({_monotonicity_detail(auth[node], auth[pid])})",
                    seq=spawn_e.get("seq"), node=node)
    checks["monotonicity"] = mono and not afail

    # (3) containment: every allow action's scope within the acting node's authority
    contained = True; actions = 0
    for e in entries:
        if e.get("event") != "allow":
            continue
        actions += 1
        node = e.get("node"); scope = e.get("scope"); ctx = e.get("context") or {}
        a = auth.get(node)
        if a is None:
            contained = False
            log.add("containment", f"containment: allow on unknown node {node}",
                    seq=e.get("seq"), node=node, call_id=e.get("call_id"))
            continue
        if not a.permits(scope, ctx):
            contained = False
            log.add("containment",
                    f"containment: allow of {scope!r} on {node} outside its authority {sorted(a.scopes)}",
                    seq=e.get("seq"), node=node, call_id=e.get("call_id"))
    checks["containment"] = contained

    execution_binding, eb_failures = (_execution_binding(entries, bundle_v) if version_ok
                                      else ({"status": "not applicable"}, _FailureLog()))
    if execution_binding.get("failures"):
        log.extend(eb_failures)

    excluded = ("anchor", "expected_anchor")
    return {"ok": all(v for k, v in checks.items() if k not in excluded) and not log,
            "checks": checks, "failures": log.messages, "failure_details": log.details,
            "nodes": len(auth), "actions_checked": actions, "chain_id": bundle.get("chain_id"),
            "execution_binding": execution_binding,
            "verified_against": "expected_anchor" if (expected_anchor is not None or expected_head is not None)
                                else "bundle_anchor"}
