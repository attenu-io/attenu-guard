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
    rep = evidence.verify_bundle(bundle, signer)                   # {"ok", "checks": {...}, "failures": [...]}

Stdlib-only; `signer` is any `wire` signer (Ed25519 in production). No engine state is consulted — the bundle
is the whole input, which is the point.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from attenu_guard import canonical
from attenu_guard.audit import SCHEMA_VERSION, AuditLog, GENESIS as _GENESIS, _hash as _rehash
from attenu_guard.authority import Authority
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


def _node_authorities(entries: list[dict]) -> tuple[dict, dict, list]:
    """(node -> Authority, node -> parent, failures) reconstructed from root/spawn events, no engine state."""
    auth: dict[str, Authority] = {}; parent: dict[str, str] = {}; fail = []
    for e in entries:
        ev = e.get("event")
        if ev == "root":
            try: auth[e["node"]] = Authority.from_wire(e["authority"])
            except Exception as exc: fail.append(f"root {e.get('node')}: unreadable authority ({exc})")  # noqa: BLE001
        elif ev == "spawn":
            parent[e["node"]] = e.get("parent")
            try: auth[e["node"]] = Authority.from_wire(e["granted"])
            except Exception as exc: fail.append(f"spawn {e.get('node')}: unreadable granted ({exc})")  # noqa: BLE001
    return auth, parent, fail


def delegation_graph(bundle: dict) -> dict:
    """A view of the chain from the bundle: each node with its agent, task, authority, parent, and per-node action
    counts (allow/deny) — what a reviewer or a UI renders. Derived from the ledger alone."""
    entries = bundle.get("entries") or []
    auth, parent, _ = _node_authorities(entries)
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


def _valid_call_id(e: dict) -> str | None:
    cid = e.get("call_id")
    if not isinstance(cid, str) or not _HEX32.match(cid):
        return f"call_id missing or malformed ({cid!r})"
    return None


def _valid_hash_field(e: dict, field: str) -> str | None:
    v = e.get(field)
    if v is None:
        return None
    if not isinstance(v, str) or not _HEX64.match(v):
        return f"{field} malformed ({v!r})"
    return None


def _validate_allow(e: dict) -> str | None:
    err = _valid_call_id(e)
    if err:
        return err
    capture = e.get("capture")
    if capture is not None and capture not in Capture.ALL:
        return f"capture {capture!r} not a known value"
    if capture is not None:
        adapter = e.get("adapter")
        if not isinstance(adapter, Mapping) or any(k not in adapter for k in ("module", "version", "hook_path")):
            return "adapter missing module/version/hook_path alongside capture"
    err = _valid_hash_field(e, "authorized_params_hash")
    if err:
        return err
    reason = e.get("params_hash_reason")
    if reason is not None and reason not in ParamsHashReason.ALL:
        return f"params_hash_reason {reason!r} not a known value"
    if reason is not None and e.get("authorized_params_hash") is not None:
        return "params_hash_reason present alongside authorized_params_hash (illegal conditional field)"
    return None


def _validate_deny(e: dict) -> str | None:
    return _valid_call_id(e)


def _validate_outcome(e: dict) -> str | None:
    err = _valid_call_id(e)
    if err:
        return err
    body_state = e.get("body_state")
    if body_state not in BodyState.ALL:
        return f"body_state {body_state!r} not a known value"
    error_code = e.get("error_code")
    if body_state == BodyState.RAISED:
        if not isinstance(error_code, str) or not error_code:
            return "error_code required when body_state == raised"
    elif error_code is not None:
        return "error_code present but body_state != raised (illegal conditional field)"
    duration = e.get("duration_ms")
    if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
        return f"duration_ms invalid ({duration!r})"
    err = _valid_hash_field(e, "invoked_params_hash")
    if err:
        return err
    reason = e.get("params_hash_reason")
    if reason is not None and reason not in ParamsHashReason.ALL:
        return f"params_hash_reason {reason!r} not a known value"
    if reason is not None and e.get("invoked_params_hash") is not None:
        return "params_hash_reason present alongside invoked_params_hash (illegal conditional field)"
    receipt = e.get("receipt")
    if receipt is not None:
        if not isinstance(receipt, Mapping) or any(k not in receipt for k in ("type", "ref", "digest")):
            return "receipt malformed (expected type/ref/digest)"
    return None


def _params_coverage(allows: dict, outcomes: dict) -> str:
    """`complete | partial | none`, from how many calls that have BOTH an allow and an outcome
    carry both hashes (spec section 5). No comparable calls at all -> "none" (no coverage shown)."""
    total = both = 0
    for cid, oc in outcomes.items():
        a = allows.get(cid)
        if a is None:
            continue
        total += 1
        if a.get("authorized_params_hash") and oc.get("invoked_params_hash"):
            both += 1
    if total == 0 or both == 0:
        return "none"
    return "complete" if both == total else "partial"


def _execution_binding(entries: list[dict], bundle_v) -> dict:
    if bundle_v != 2:
        return {"status": "not applicable"}

    failures: list[str] = []
    seen_call_ids: dict[str, tuple] = {}     # call_id -> (event, node, seq) — first sighting, allow OR deny
    allows: dict[str, dict] = {}
    outcomes: dict[str, dict] = {}
    invalid_allow_ids: set = set()
    nodes: set = set()
    finalized_nodes: set = set()
    revoked_nodes: set = set()

    for e in entries:
        ev = e.get("event")
        if ev in ("root", "spawn"):
            nodes.add(e.get("node"))
        elif ev == "done":
            finalized_nodes.add(e.get("node"))
        elif ev == "kill":
            revoked_nodes.update(e.get("revoked") or [])

        if ev in ("allow", "deny"):
            cid = e.get("call_id")
            if cid is not None:
                prior = seen_call_ids.get(cid)
                if prior is not None:
                    failures.append(f"duplicate_call_id: call_id {cid} on seq {e.get('seq')} ({ev}) "
                                    f"already used at seq {prior[2]} ({prior[0]})")
                else:
                    seen_call_ids[cid] = (ev, e.get("node"), e.get("seq"))
            validator = _validate_allow if ev == "allow" else _validate_deny
            err = validator(e)
            if err:
                failures.append(f"invalid_{ev}: {err} (seq {e.get('seq')})")
                if ev == "allow" and cid is not None:
                    invalid_allow_ids.add(cid)
                continue
            if ev == "allow" and cid is not None:
                allows[cid] = e
        elif ev == "outcome":
            cid = e.get("call_id")
            err = _validate_outcome(e)
            if err:
                failures.append(f"invalid_outcome: {err} (seq {e.get('seq')})")
                continue
            if cid in outcomes:
                failures.append(f"duplicate_outcome: call_id {cid} at seq {e.get('seq')} "
                                f"(first at seq {outcomes[cid].get('seq')})")
                continue
            outcomes[cid] = e

    # Bind each outcome to its allow: outcome_without_allow / cross_ref / outcome_before_allow / params_mismatch.
    for cid, oc in outcomes.items():
        allow_e = allows.get(cid)
        if allow_e is None:
            failures.append(f"outcome_without_allow: call_id {cid} at seq {oc.get('seq')} has no allow in this chain")
            continue
        if allow_e.get("node") != oc.get("node"):
            failures.append(f"cross_ref: call_id {cid} allow on node {allow_e.get('node')!r} "
                            f"but outcome on node {oc.get('node')!r}")
        if not (oc.get("seq") is not None and allow_e.get("seq") is not None and oc["seq"] > allow_e["seq"]):
            failures.append(f"outcome_before_allow: call_id {cid} outcome seq {oc.get('seq')} "
                            f"not after allow seq {allow_e.get('seq')}")
        ah, ih = allow_e.get("authorized_params_hash"), oc.get("invoked_params_hash")
        if ah is not None and ih is not None and ah != ih:
            failures.append(f"params_mismatch: call_id {cid} authorized_params_hash {ah} != invoked_params_hash {ih}")

    # Per-call observation + per-node pending, from valid allows only.
    per_call: dict[str, str] = {}
    node_pending: dict[str, list] = {}
    for cid, allow_e in allows.items():
        if cid in invalid_allow_ids:
            continue
        capture = allow_e.get("capture")
        if capture is None or capture == Capture.PRE_HOOK_ONLY:
            per_call[cid] = "unobserved"
        elif cid in outcomes:
            per_call[cid] = "observed"
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
        "params_coverage": _params_coverage(allows, outcomes),
        "per_call": per_call,
        "per_node_lifecycle": lifecycle,
        "failures": failures,
    }


def verify_bundle(bundle: dict, signer=None) -> dict:
    """Verify integrity, monotonicity and containment from the bundle alone. Returns {ok, checks, failures, ...}.

    `signer` is the verifier for the bundle's signed anchor (a public key, or the test signer). With `signer=None`
    the hash chain, monotonicity and containment are still checked, but the anchor signature is NOT — the report
    says so (`checks["anchor"] == "not checked"`), and `ok` then means "consistent, unverified by key": a consistent
    full rewrite by someone holding the key cannot be excluded without the key.
    """
    entries = bundle.get("entries") or []
    anchor = bundle.get("anchor") or {}
    checks = {"integrity": False, "monotonicity": False, "containment": False, "anchor": "not checked",
              "version": False, "chain_id": False}
    failures: list[str] = []

    # (0) version: the bundle must declare a schema version this build understands, and — when an
    # anchor is present — the anchor must be anchoring THAT version, not a different one.
    bundle_v = bundle.get("v")
    version_ok = bundle_v in SUPPORTED_BUNDLE_VERSIONS
    if not version_ok:
        failures.append(f"unsupported_version: bundle v={bundle_v!r} not in {sorted(SUPPORTED_BUNDLE_VERSIONS)}")
    if anchor and anchor.get("v") != bundle_v:
        version_ok = False
        failures.append(f"anchor_version_mismatch: anchor v={anchor.get('v')!r} != bundle v={bundle_v!r}")
    # 0.9.0: a chain is created at ONE schema version and never mixes (spec section 9) — the root
    # entry's v must equal the bundle's declared v, and no OTHER entry may carry a different v.
    root_entry = next((e for e in entries if e.get("event") == "root"), None)
    if root_entry is not None and root_entry.get("v") != bundle_v:
        version_ok = False
        failures.append(f"root_version_mismatch: root v={root_entry.get('v')!r} != bundle v={bundle_v!r}")
    mixed = sorted({e.get("v") for e in entries if e.get("v") != bundle_v})
    if mixed:
        version_ok = False
        failures.append(f"mixed_entry_versions: entries declare v in {mixed}, bundle v={bundle_v!r}")
    checks["version"] = version_ok

    # (0b) chain identity: the bundle, every entry, and — when an anchor is present — the anchor
    # must all name the SAME chain. Without this a correctly-signed, internally-consistent bundle
    # for a DIFFERENT chain could be handed to a verifier who believes it is checking this one.
    bundle_chain_id = bundle.get("chain_id")
    entries_ok = all(e.get("chain_id") == bundle_chain_id for e in entries)
    if not entries_ok:
        failures.append(f"chain_id_mismatch: an entry does not carry chain_id={bundle_chain_id!r}")
    anchor_chain_ok = not anchor or anchor.get("chain_id") == bundle_chain_id
    if not anchor_chain_ok:
        failures.append(f"chain_id_mismatch: anchor chain_id={anchor.get('chain_id')!r} != bundle chain_id={bundle_chain_id!r}")
    checks["chain_id"] = entries_ok and anchor_chain_ok

    # (1) integrity: hash chain (+ the signed anchor, when a verifier key is given)
    ok_chain, err = AuditLog.verify(entries)
    if not ok_chain: failures.append(f"integrity: {err}")
    if signer is not None:
        ok_anchor, aerr = AuditLog.verify_anchor(entries, anchor, signer)
        checks["anchor"] = "verified" if ok_anchor else "FAILED"
        if not ok_anchor: failures.append(f"integrity(anchor): {aerr}")
        checks["integrity"] = bool(ok_chain and ok_anchor)
    else:
        checks["integrity"] = bool(ok_chain)

    auth, parent, afail = _node_authorities(entries)
    failures += afail

    # (2) monotonicity: every child ⊆ its parent
    mono = True
    for node, pid in parent.items():
        if pid is None or pid not in auth or node not in auth:
            continue
        if not auth[node].is_narrower_than(auth[pid]) and set(auth[node].scopes) - set(auth[pid].scopes):
            mono = False; failures.append(f"monotonicity: {node} not ⊆ parent {pid} (child scopes {sorted(set(auth[node].scopes) - set(auth[pid].scopes))} not held by parent)")
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
            contained = False; failures.append(f"containment: allow on unknown node {node}"); continue
        if not a.permits(scope, ctx):
            contained = False; failures.append(f"containment: allow of {scope!r} on {node} outside its authority {sorted(a.scopes)}")
    checks["containment"] = contained

    execution_binding = _execution_binding(entries, bundle_v) if version_ok else {"status": "not applicable"}
    if execution_binding.get("failures"):
        failures += execution_binding["failures"]

    return {"ok": all(v for k, v in checks.items() if k != "anchor") and not failures, "checks": checks, "failures": failures,
            "nodes": len(auth), "actions_checked": actions, "chain_id": bundle.get("chain_id"),
            "execution_binding": execution_binding}
