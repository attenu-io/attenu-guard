"""
tests/vectors/generate_bundles.py — deterministic, language-neutral test vectors for the
EVIDENCE BUNDLE verifier (`attenu_guard.evidence.verify_bundle`), the offline-verifiable
half of the claim: an auditor checks a delegation chain from the published bundle ALONE,
with no engine, no service and no vendor in the loop.

This is a SEPARATE, bundle-level suite from `tests/vectors/generate.py`'s Delegation TOKEN
vectors. Those pin the wire format and the token-chain verification algorithm; these pin the
LEDGER checks — hash-chain integrity against a signed anchor, monotonicity, containment, and
the schema-v2 execution-binding rules (call_id uniqueness, allow -> outcome binding and order,
one outcome per call, authorized vs invoked argument commitments).

The file it writes is scored differently from the token vectors, because a bundle-level
verifier reports a LIST of failures rather than one reject reason. Each rejecting case declares
`expect_failures`: the MINIMAL set of `{reason, seq, node}` that MUST appear. A conformant
verifier MAY report more (one broken record often makes a second check unsatisfiable); it may
never report fewer, and never at a different position.

stdlib-only, runnable with bare `python3`, no network:

    python3 tests/vectors/generate_bundles.py

Deterministic — the same bytes on every run, on every machine. Two things a real chain draws
from the OS CSPRNG (`params_salt` and every `call_id`) are drawn here from a fixed,
counter-derived byte stream instead, for the duration of generation only; nothing else in the
ledger is time- or randomness-dependent (audit `ts` is a monotonic counter, node ids are
counter-derived). A change in this library that adds, removes or reorders a CSPRNG draw changes
these vectors and is meant to: CI regenerates them and fails on the diff.

Like `generate.py`, this module is the SINGLE writer for BOTH copies of its output — this
directory (which the README and docs cite by path) and `src/attenu_guard/vectors/bundles/`,
which ships inside the installed package so an independent implementation can score itself with
nothing but `pip install attenu-guard`. One serialisation, written twice, so neither copy can
lag the other.

See README.md in this directory ("Evidence bundle vectors") for the file format, the
minimal-set rule, and how an independent implementation scores itself.
"""
from __future__ import annotations   # `Path | None` in a signature, on Python 3.9

import copy
import hashlib
import itertools
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import Authority, Guard, RowLimit  # noqa: E402
from attenu_guard import evidence, wire  # noqa: E402
from attenu_guard.audit import AuditLog, GENESIS, _hash as _entry_hash  # noqa: E402
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

BUNDLES_DIRNAME = "bundles"
VECTORS_FILENAME = "bundle_vectors_v1.json"
VECTORS_VERSION = "bundle_vectors_v1"
# Cases are ADDED to this file, never changed or removed, so `version` is the compatibility
# contract and stays put: an implementation that scored `bundle_vectors_v1` still scores it.
# `revision` is the additive counter — it moves whenever a case is appended, so a reader can
# tell which corpus they ran without diffing case lists.
VECTORS_REVISION = "bundle_vectors_v1.1"

VECTORS_DIR = Path(__file__).resolve().parent / BUNDLES_DIRNAME
# The shipped copy: package data, so `pip install attenu-guard` carries these vectors.
# See attenu_guard.vectors.load_bundle_vectors() for the accessor an installed consumer uses.
PACKAGE_VECTORS_DIR = _ROOT / "src" / "attenu_guard" / "vectors" / BUNDLES_DIRNAME

# A published, fixed, well-known secret — deliberately NOT a secret in any real sense (it is
# printed in this source file and in the emitted vector file). Same reasoning as the token
# vectors: HS256 is symmetric, so these vectors pin the bundle FORMAT and the verification
# ALGORITHM, not a production trust boundary, and they stay runnable with bare `python3`.
# Production anchoring uses Ed25519 (attenu_guard.wire.Ed25519Signer) or a KMS key.
SECRET = b"attenu-guard-bundle-vectors-v1-fixed-secret"
KID = "bundle-interop-v1"

CHAIN_ID = "vectors"
ANCHOR_TS = 0

# The adapter identity recorded on every allow in these vectors (module/version/hook_path is
# mandatory on a v2 allow; a fixed value keeps the vectors deterministic across releases).
ADAPTER = {"module": "attenu_guard.adapters.example", "version": "1.0.0", "hook_path": "wrap_tool"}

# A call_id shape-valid (32 lowercase hex) but present on no allow in the chain — the orphan
# terminal in reject_outcome_without_allow.
ORPHAN_CALL_ID = "0123456789abcdef0123456789abcdef"
# A hash shape-valid (64 lowercase hex) and different from every real commitment — the
# substituted argument hash in reject_params_mismatch.
SUBSTITUTED_PARAMS_HASH = "11" * 32

# A scope no node in this chain holds and no wildcard in it covers (the root holds crm.* and
# mail.send) — the scope the summarizer grants ITSELF in reject_widened_scope.
UNHELD_SCOPE = "pay.transfer"
# A scope the ROOT holds (covered by its crm.*) but never delegated to the summarizer, whose
# grant is exactly {crm.read} — the scope forged onto the summarizer's allow in
# reject_uncontained_allow, and the one its honest deny at seq 5 refuses.
UNDELEGATED_SCOPE = "crm.export"


def _signer() -> wire.HS256TestSigner:
    return wire.HS256TestSigner(SECRET, kid=KID)


class _fixed_entropy:
    """Replace the OS CSPRNG with a fixed, counter-derived byte stream for the duration of the
    `with` block, so the two values a real chain draws from it (the chain's `params_salt` and
    every `call_id`) are reproducible in a committed vector file. Restored on exit; used ONLY
    by this generator, never by the library."""

    def __enter__(self):
        counter = itertools.count()

        def stream(n: int) -> bytes:
            out = b""
            while len(out) < n:
                out += hashlib.sha256(b"attenu-guard-bundle-vectors-v1:"
                                      + str(next(counter)).encode()).digest()
            return out[:n]

        self._real = os.urandom
        os.urandom = stream
        return self

    def __exit__(self, *exc):
        os.urandom = self._real
        return False


# =========================================================================
# The chain every case is derived from
# =========================================================================

def _valid_bundle() -> dict:
    """A complete, honest schema-v2 chain: an orchestrator that delegates to a narrower
    summarizer, two authorized tool calls each observed to completion, one over-reach denied,
    both nodes finalized. Nine entries, seq 0..8:

        0 root      orchestrator            {crm.*, mail.send}, max_rows 100000
        1 spawn     summarizer              {crm.read}, max_rows 5000   (child ⊂ parent)
        2 allow     orchestrator mail.send  call A, authorized_params_hash
        3 outcome   orchestrator            call A, invoked_params_hash == authorized
        4 allow     summarizer   crm.read   call B, authorized_params_hash
        5 deny      summarizer   crm.export (over-reach, out_of_authority)
        6 outcome   summarizer              call B, invoked_params_hash == authorized
        7 done      summarizer
        8 done      orchestrator
    """
    with _fixed_entropy():
        root = Guard.issue("orchestrator",
                           Authority(scopes={"crm.*", "mail.send"}, ceilings=[RowLimit(100_000)], ttl=3600),
                           chain_id=CHAIN_ID, schema_version=2)
        child = root.delegate("summarizer",
                              Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900),
                              task="summarize Q3 pipeline")

        mail_params = {"to": "cfo@example.com", "subject": "Q3 pipeline"}
        d_mail = root.check("mail.send", tool="mail.send", authorized_params=mail_params,
                            capture=Capture.WRAPPER_SYNC, adapter=ADAPTER)
        root.record_outcome(d_mail.call_id, BodyState.RETURNED, invoked_params=mail_params,
                            duration_ms=12)

        read_params = {"limit": 120, "query": "pipeline"}
        d_read = child.check("crm.read", tool="crm.read", context={"rows": 120},
                             authorized_params=read_params,
                             capture=Capture.WRAPPER_SYNC, adapter=ADAPTER)
        child.check("crm.export", tool="crm.export", context={"rows": 120})   # denied: over-reach
        child.record_outcome(d_read.call_id, BodyState.RETURNED, invoked_params=read_params,
                             duration_ms=7)

        child.complete()
        root.complete()
        return evidence.export_bundle(root.audit_log(), _signer(), ts=ANCHOR_TS)


# =========================================================================
# Mutation helpers — every rejecting case is ONE change to the valid bundle
# =========================================================================

def _rehash_chain(entries: list) -> None:
    """Recompute `prev_hash`/`hash` down the whole ledger, in place, so the chain is internally
    self-consistent again after a mutation. This is what a competent forger does; it is exactly
    what the signed anchor exists to catch (the anchor commits to the head, and the head moves)."""
    prev = GENESIS
    for e in entries:
        e["prev_hash"] = prev
        payload = {k: v for k, v in e.items() if k != "hash"}
        e["hash"] = _entry_hash(prev, payload)
        prev = e["hash"]


def _renumber(entries: list) -> None:
    """`seq` = position, for the two cases that insert or transpose a record."""
    for i, e in enumerate(entries):
        e["seq"] = i


def _reanchor(bundle: dict) -> None:
    """Re-sign an anchor over the mutated ledger's new head, so the case isolates the check it
    is about rather than also tripping the anchor."""
    signer = _signer()
    anchor = evidence._anchor_for(bundle["entries"], signer, ANCHOR_TS)
    anchor["verified"] = AuditLog.verify_anchor(bundle["entries"], anchor, signer)[0]
    bundle["anchor"] = anchor


def _mutate(base: dict, mutate, *, rehash: bool = True, reanchor: bool = True) -> dict:
    """A deep copy of the valid bundle with exactly one thing changed. `rehash=False` leaves the
    hash chain broken at the mutation; `reanchor=False` leaves the ORIGINAL signed anchor in
    place, still committing to the head the ledger used to have."""
    bundle = copy.deepcopy(base)
    mutate(bundle["entries"])
    if rehash:
        _rehash_chain(bundle["entries"])
    if reanchor:
        _reanchor(bundle)
    return bundle


def _case(name: str, description: str, bundle: dict, *, expect: str,
          expect_failures: list | None = None) -> dict:
    return {
        "name": name,
        "description": description,
        "signer": {"alg": "HS256", "kid": KID, "secret_hex": SECRET.hex()},
        "bundle": bundle,
        "expect": expect,
        "expect_failures": expect_failures or [],
    }


def _fail(reason: str, seq, node) -> dict:
    return {"reason": reason, "seq": seq, "node": node}


# =========================================================================
# The cases
# =========================================================================

def gen_cases() -> list:
    base = _valid_bundle()
    n0, n1 = f"{CHAIN_ID}:n0", f"{CHAIN_ID}:n1"
    cases = []

    cases.append(_case(
        "valid_bundle_v2",
        "A complete, honest schema_version=2 evidence bundle: an orchestrator delegates to a "
        "strictly narrower summarizer (scopes {crm.*, mail.send} -> {crm.read}; max_rows 100000 "
        "-> 5000; ttl 3600 -> 900), each node makes one authorized tool call that is observed to "
        "completion with matching authorized/invoked argument commitments, one over-reach "
        "(crm.export on the summarizer) is denied, and both nodes are finalized. Every check MUST "
        "pass: the hash chain reproduces and matches the signed anchor, every delegation is a "
        "subset of its parent, every allowed scope was inside the acting node's authority, and "
        "every call_id is unique with exactly one correctly-ordered outcome on the same node. "
        "This is the bundle every rejecting case below is derived from by exactly one change.",
        base, expect="accept"))

    cases.append(_case(
        "reject_params_mismatch",
        "The outcome at seq 3 reports an invoked_params_hash that is not the "
        "authorized_params_hash its allow (seq 2) committed to: the arguments actually passed to "
        "the tool were not the arguments that were authorized. The ledger is otherwise perfect — "
        "the chain was re-hashed and a fresh anchor signed over it — so a verifier that checks "
        "only integrity, monotonicity and containment accepts this bundle. Substitution between "
        "authorization and invocation is visible ONLY because both commitments exist and are "
        "compared.",
        _mutate(base, lambda es: es[3].__setitem__("invoked_params_hash", SUBSTITUTED_PARAMS_HASH)),
        expect="reject", expect_failures=[_fail("params_mismatch", 3, n0)]))

    cases.append(_case(
        "reject_outcome_without_allow",
        "The outcome at seq 6 carries a call_id that no allow in this chain ever issued (the "
        "orphan terminal). A tool call was reported as having run under an authorization that "
        "does not exist in the ledger. Chain re-hashed and re-anchored, so nothing else fails. "
        "Consequentially the summarizer's real call (call B, allowed at seq 4) is left with no "
        "outcome and the node is finalized anyway, which a verifier reports as an unaccounted "
        "call in its execution-binding aggregate, not as a separate failure.",
        _mutate(base, lambda es: es[6].__setitem__("call_id", ORPHAN_CALL_ID)),
        expect="reject", expect_failures=[_fail("outcome_without_allow", 6, n1)]))

    def _transpose_allow_and_outcome(es):
        es[2], es[3] = es[3], es[2]
        _renumber(es)

    cases.append(_case(
        "reject_outcome_before_allow",
        "The orchestrator's allow and its outcome are transposed: the outcome now sits at seq 2 "
        "and the allow that authorized it at seq 3, so the call is reported as finished before it "
        "was ever authorized. Each record keeps its own contents (including its original ts); "
        "only ledger POSITION is normative for this check, and the two seq fields follow their "
        "new positions. Chain re-hashed and re-anchored: ordering is the only thing wrong.",
        _mutate(base, _transpose_allow_and_outcome),
        expect="reject", expect_failures=[_fail("outcome_before_allow", 2, n0)]))

    def _duplicate_outcome(es):
        es.insert(4, copy.deepcopy(es[3]))
        _renumber(es)

    cases.append(_case(
        "reject_duplicate_outcome",
        "The orchestrator's outcome record is duplicated: the same call_id reports a terminal "
        "state twice, at seq 3 and again at seq 4 (every later entry shifts up by one seq). "
        "Exactly one outcome per call_id is the rule that makes 'observed' mean anything — a "
        "second one is either a double-counted invocation or a replayed record. Chain re-hashed "
        "and re-anchored; the duplicate is a byte-for-byte copy, ts included, so nothing but the "
        "duplication itself is detectable.",
        _mutate(base, _duplicate_outcome),
        expect="reject", expect_failures=[_fail("duplicate_outcome", 4, n0)]))

    def _duplicate_call_id(es):
        es[2]["call_id"] = es[4]["call_id"]

    cases.append(_case(
        "reject_duplicate_call_id",
        "One call_id on two allows: the orchestrator's allow at seq 2 is re-issued with the "
        "call_id the summarizer's allow at seq 4 already uses. A call_id is the only thing that "
        "binds an authorization to the invocation that followed it, so a collision makes the "
        "binding ambiguous by construction — which is why uniqueness is checked before any "
        "binding is attempted. The required failure is duplicate_call_id at seq 4, the second "
        "sighting. This bundle also necessarily leaves the orchestrator's outcome at seq 3 with "
        "no allow of its own call_id, which our verifier additionally reports as "
        "outcome_without_allow at seq 3; that consequence is not required of a conformant "
        "verifier, which may stop at the collision. Chain re-hashed and re-anchored.",
        _mutate(base, _duplicate_call_id),
        expect="reject", expect_failures=[_fail("duplicate_call_id", 4, n1)]))

    def _restate_duration(es):
        es[3]["duration_ms"] = 999

    cases.append(_case(
        "reject_rehashed_chain",
        "The outcome at seq 3 is edited (duration_ms 12 -> 999) and then EVERY later hash is "
        "recomputed, so the ledger is perfectly self-consistent: recomputing the chain from "
        "GENESIS reproduces every stored hash. This is the rewrite that a hash chain alone cannot "
        "catch, and the reason the anchor exists — the anchor here is the ORIGINAL one, signed "
        "over the head this ledger used to have, and it no longer matches. Note the bundle's own "
        "anchor still carries \"verified\": true: that field is the producer's claim about itself, "
        "never evidence, and a verifier MUST re-check the signature and the head rather than read "
        "it. The failure is chain-level — the whole ledger was rewritten, so there is no single "
        "offending entry to point at. Our verifier reports it as integrity(anchor) with seq and "
        "node null; an implementation that names its own equivalent chain-level integrity failure "
        "with no position is conformant. It is the same edit as reject_tampered_entry, differing "
        "only in whether the forger bothered to re-hash.",
        _mutate(base, _restate_duration, rehash=True, reanchor=False),
        expect="reject", expect_failures=[_fail("integrity(anchor)", None, None)]))

    cases.append(_case(
        "reject_tampered_entry",
        "The same edit as reject_rehashed_chain (duration_ms 12 -> 999 on the outcome at seq 3), "
        "with neither the chain re-hashed nor the anchor re-signed: the crude tamper. The stored "
        "hash at seq 3 no longer covers the entry's own contents, so the chain check fails AT "
        "that entry — a verifier must report the position, not merely that something is wrong. "
        "Our verifier also reports integrity(anchor) here, because the anchor's signature is "
        "intact but the ledger under it does not reproduce; only the positioned integrity failure "
        "is required.",
        _mutate(base, _restate_duration, rehash=False, reanchor=False),
        expect="reject", expect_failures=[_fail("integrity", 3, n0)]))

    # ---- delegation containment (added in revision v1.1) -----------------
    # The first two independent runs of this file both reported the same gap: every rejecting
    # case above exercises integrity or execution binding, and none exercises the two checks
    # the library exists for — that a delegation narrows, and that an authorization stayed
    # inside what the acting node held. These two close that gap, one rule each.

    def _widen_granted_scopes(es):
        es[1]["granted"]["scopes"] = sorted(["crm.read", UNHELD_SCOPE])

    cases.append(_case(
        "reject_widened_scope",
        "The delegation at seq 1 grants the summarizer a scope its parent does not hold: "
        f"{{crm.read}} becomes {{crm.read, {UNHELD_SCOPE}}}, and the orchestrator's authority is "
        "{crm.*, mail.send}, which covers neither literally nor by wildcard. This is the "
        "violation the whole library exists to make impossible — authority growing across a "
        "handoff — and a bundle is where an auditor catches it after the fact, with no engine "
        "in the loop. Nothing else is touched: the chain was re-hashed and a fresh anchor "
        "signed over it, both tool calls still bind to their outcomes, and the allow at seq 4 "
        "is still crm.read, so containment holds. The failure is positioned on the SPAWN that "
        "granted too much (seq 1), not on any later action, because the spawn is where the "
        "authority was created. Its node is the child, the node whose grant is unsound.",
        _mutate(base, _widen_granted_scopes),
        expect="reject", expect_failures=[_fail("monotonicity", 1, n1)]))

    def _forge_allow_scope(es):
        es[4]["scope"] = UNDELEGATED_SCOPE

    cases.append(_case(
        "reject_uncontained_allow",
        f"The summarizer's allow at seq 4 authorizes {UNDELEGATED_SCOPE}, which is outside the "
        "{crm.read} it was granted at seq 1. Note what this is NOT: the orchestrator holds "
        f"crm.* and could legitimately have delegated {UNDELEGATED_SCOPE}, so the chain root is "
        "not over-reaching — the acting node is, against its own recorded grant, which is the "
        "point of checking containment separately from monotonicity. The same bundle still "
        f"carries the honest deny of {UNDELEGATED_SCOPE} on the same node at seq 5, so the "
        "ledger contradicts itself in a way a reader can see. Only the allow's `scope` is "
        "changed: its call_id, capture, adapter and authorized_params_hash are untouched, the "
        "outcome at seq 6 still binds to it with matching arguments, the chain was re-hashed "
        "and re-anchored, and the delegation at seq 1 is still strictly narrower, so "
        "monotonicity holds. The failure is positioned on the allow itself.",
        _mutate(base, _forge_allow_scope),
        expect="reject", expect_failures=[_fail("containment", 4, n1)]))

    return cases


def _document(cases: list) -> dict:
    return {
        "version": VECTORS_VERSION,
        "revision": VECTORS_REVISION,
        "description": (
            "Bundle-level offline-verification vectors for attenu-guard evidence bundles "
            "(schema_version=2, with execution binding). Each case is a complete bundle plus the "
            "signer material for its anchor. `expect` is \"accept\" or \"reject\". For a rejecting "
            "case, `expect_failures` is the MINIMAL set of failures that MUST appear, each with "
            "the exact reason and the exact position (`seq`/`node`, null when the failure is "
            "chain-level); a conformant verifier MAY report additional failures — one broken "
            "record often makes a second check unsatisfiable — but never fewer, and never at a "
            "different position. Every rejecting bundle is derived from `valid_bundle_v2` by "
            "exactly one change, so each case isolates one rule. `version` is the compatibility "
            "contract and does not move when cases are appended; `revision` does. Verify an anchor as "
            "hex(HMAC-SHA256(secret, JCS(anchor without kid/sig/verified))) and each entry as "
            "hex(SHA-256(prev_hash_ascii || JCS(entry without hash))); see "
            "tests/vectors/README.md."),
        "cases": cases,
    }


def generate_all(out_dir: Path = VECTORS_DIR,
                 package_dir: Path | None = PACKAGE_VECTORS_DIR) -> dict:
    """Write the vector file to `out_dir` AND, unless `package_dir` is None, to the packaged
    copy; return the document so callers (tests/test_bundle_vectors.py) can self-check without
    re-reading from disk. Serialised ONCE and written to both destinations, so the two are
    byte-identical by construction. Deterministic: calling this twice writes identical bytes."""
    document = _document(gen_cases())
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    for d in [out_dir] + ([package_dir] if package_dir is not None else []):
        d.mkdir(parents=True, exist_ok=True)
        for stale in d.glob("*.json"):
            if stale.name != VECTORS_FILENAME:
                stale.unlink()
        (d / VECTORS_FILENAME).write_text(text)
    return document


def check_case(case: dict) -> tuple[bool, str]:
    """Score ONE case against this build's own `verify_bundle` — exactly what an independent
    implementation does with its own verifier. Returns (ok, human-readable outcome)."""
    signer = wire.HS256TestSigner(bytes.fromhex(case["signer"]["secret_hex"]),
                                  kid=case["signer"]["kid"])
    report = evidence.verify_bundle(case["bundle"], signer)
    got = "accept" if report["ok"] else "reject"
    if got != case["expect"]:
        return False, f"expected={case['expect']} got={got} failures={report['failures']}"
    seen = [{"reason": d["reason"], "seq": d["seq"], "node": d["node"]}
            for d in report["failure_details"]]
    missing = [f for f in case["expect_failures"] if f not in seen]
    if missing:
        return False, f"expected={case['expect']} got={got} but MISSING {missing} (reported {seen})"
    extra = [f for f in seen if f not in case["expect_failures"]]
    note = f" (+{len(extra)} further reported)" if extra else ""
    return True, f"expected={case['expect']} got={got}, {len(case['expect_failures'])} required failure(s) present{note}"


def _self_check(document: dict) -> bool:
    """Verify every case against THIS build's evidence.verify_bundle immediately after
    generating it, so this generator can never emit a vector its own reference implementation
    would score differently than the file declares."""
    ok = True
    for case in document["cases"]:
        passed, detail = check_case(case)
        ok = ok and passed
        print(f"  self-check {case['name']}: {detail}  [{'OK' if passed else 'MISMATCH'}]")
    return ok


def main() -> int:
    document = generate_all()
    rel_out = VECTORS_DIR.relative_to(_ROOT)
    rel_pkg = PACKAGE_VECTORS_DIR.relative_to(_ROOT)
    print(f"wrote {VECTORS_FILENAME} ({len(document['cases'])} cases) to {rel_out}/ and {rel_pkg}/")
    print("\nself-checking against this build's attenu_guard.evidence.verify_bundle ...")
    ok = _self_check(document)
    print("\nALL BUNDLE VECTORS SELF-CONSISTENT" if ok else "\nBUNDLE VECTOR SELF-CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
