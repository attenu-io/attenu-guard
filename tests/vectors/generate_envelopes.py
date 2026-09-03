"""
tests/vectors/generate_envelopes.py — deterministic, language-neutral test vectors for the
OBSERVER ENVELOPE layer (envelope v1): a witness's signature over the identity of one committed
ledger entry, carried beside the ledger in a bundle's top-level `envelopes` array.

This is the THIRD suite in this directory, and the narrowest. `generate.py` pins the delegation
TOKEN wire format; `generate_bundles.py` pins the LEDGER checks; this one pins the single
question neither of those can answer — was this delegation event signed by something OUTSIDE
the process that wrote it? An envelope is never required. An absent one is the status quo and
changes nothing, and every entry of a bundle without envelopes reports `process-asserted`. A
PRESENT one has to verify: a broken envelope lands in the same failure list as the chain-level
checks and the bundle rejects.

The bundle every case is built on is the same nine-entry chain as `bundle_vectors_v1.json`'s
`valid_bundle_v2` — imported from `generate_bundles`, not restated here, so the two files can
never describe different ledgers. Envelope-covered entries are therefore `spawn` at seq 1
(node `vectors:n1`) and `allow` at seq 2 (`vectors:n0`) and seq 4 (`vectors:n1`); envelope v1
defines a subject for `spawn` and `allow` and for no other event.

stdlib-only, runnable with bare `python3`, no network:

    python3 tests/vectors/generate_envelopes.py

Deterministic — the same bytes on every run, on every machine. The chain's own two CSPRNG draws
are fixed by `generate_bundles._fixed_entropy`; the three Ed25519 witness keys are derived from
fixed, published seed strings below; Ed25519 signing is itself deterministic (RFC 8032: the
nonce comes from the key and the message, never from a CSPRNG), so the signatures are the same
64 bytes whether `cryptography` is installed or the stdlib fallback in `attenu_guard._ed25519`
produced them.

MEMBER ORDER. This file is written with every object's members sorted, exactly as
`bundle_vectors_v1.json` is — with ONE deliberate exception, the envelope of case 3
(`valid_jcs_reorder`), whose members are scrambled on purpose. That case is the positive
control for canonicalization: the same envelope, in a different SOURCE order, still verifies,
and the row carries the exact JCS bytes the signature covers so a verifier can be scored on the
bytes it produced and not only on its verdict. A writer that sorted that object would delete
the only thing the case tests.

Like the other two generators, this module is the SINGLE writer for BOTH copies of its output —
this directory and `src/attenu_guard/vectors/envelopes/`, which ships inside the installed
package so an independent implementation can score itself with nothing but
`pip install attenu-guard`. One serialisation, written twice, so neither copy can lag the other.

See README.md in this directory ("Observer envelope vectors") for the file format, the
minimal-set rule, and the two scoring rules that bind where a failure may land.
"""
from __future__ import annotations   # `Path | None` in a signature, on Python 3.9

import copy
import hashlib
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from attenu_guard import canonical, evidence  # noqa: E402

import generate_bundles  # tests/vectors/generate_bundles.py — the shared chain  # noqa: E402
from generate_bundles import ANCHOR_TS, CHAIN_ID, KID, SECRET, _fail, _reanchor  # noqa: E402

ENVELOPES_DIRNAME = "envelopes"
VECTORS_FILENAME = "envelope_vectors_v1.json"
# Cases are ADDED to this file, never changed or removed, so `version` is the compatibility
# contract and stays put: an implementation that scored `envelope_vectors_v1` still scores it.
# `revision` is the additive counter — it moves whenever a case is appended, so a reader can
# tell which corpus they ran without diffing case lists. Same discipline as the bundle file,
# which grew its `revision` only at its first addition; this one carries it from the start.
VECTORS_VERSION = "envelope_vectors_v1"
VECTORS_REVISION = "envelope_vectors_v1.0"

VECTORS_DIR = Path(__file__).resolve().parent / ENVELOPES_DIRNAME
# The shipped copy: package data, so `pip install attenu-guard` carries these vectors.
# See attenu_guard.vectors.load_envelope_vectors() for the accessor an installed consumer uses.
PACKAGE_VECTORS_DIR = _ROOT / "src" / "attenu_guard" / "vectors" / ENVELOPES_DIRNAME

# Published, fixed witness seeds — deliberately NOT secrets (they are printed in this source
# file, and the public halves they derive are printed in the emitted vector file). Unlike the
# bundle anchors' HS256 secret, these are ASYMMETRIC: a scorer holds only the public keys the
# file carries and still cannot forge an envelope, which is what makes rows 8 and 15 checkable
# from the file alone. Production witnesses use a real key; these pin the FORMAT and the
# verification ALGORITHM.
_SEED_PREFIX = b"attenu-guard-envelope-vectors-v1:"


def _seed(name: str) -> bytes:
    return hashlib.sha256(_SEED_PREFIX + name.encode()).digest()


# The witness whose kid every case names, and whose key every case trusts.
WITNESS_KID = "witness-interop-v1"
# A SECOND trusted key. Row 8 signs with this one while still naming the first, so the only
# thing wrong with that envelope is the signature — a signature that verifies under some other
# trusted key is not witness-signed.
WITNESS_KID_B = "witness-interop-v1-b"
# A key NO case trusts: row 15's envelope names it, and it is absent from every `witness_keys`.
WITNESS_KID_UNLISTED = "witness-interop-v1-unlisted"

SEEDS = {WITNESS_KID: _seed("witness-a"),
         WITNESS_KID_B: _seed("witness-b"),
         WITNESS_KID_UNLISTED: _seed("witness-unlisted")}
# The trust set carried on EVERY case, identical throughout: the first two keys, never the third.
TRUSTED_KIDS = (WITNESS_KID, WITNESS_KID_B)

# Fixed observation metadata. `at` is the moment the witness says it looked and `method` names
# how; the signature covers both and no verifier decision turns on either.
OBSERVED_AT = "2026-09-01T11:00:00Z"
OBSERVED_METHOD = "sidecar:ledger-tail"

# The seq the four chain-mutation rows (6, 12, 13, 14) all edit, and the one the rest of the
# rejecting rows carry an envelope for: the `spawn`, node vectors:n1.
SPAWN_SEQ = 1
# The next envelope-eligible hop after it: the orchestrator's `allow`, node vectors:n0. It is
# the covered hop M in the sparse row, where coverage skips the mutated entry.
ALLOW_SEQ = 2
# What the mutated `ts` becomes. `ts` is the one member no check in this contract reads — not
# monotonicity, not containment, not execution binding — so a row that edits it isolates the
# envelope layer. The corpus ledger's `ts` is a monotonic counter, and this value breaks that
# ordering; a verifier that additionally reports a timestamp-ordering finding is inside the
# minimal-set rule, which permits more than the declared set but never fewer.
MUTATED_TS = 99


def _public_hex(kid: str) -> str:
    _sign, _verify, public = evidence._ed25519_backend()
    return public(SEEDS[kid]).hex()


def witness_keys() -> list:
    """The `witness_keys` array every case carries: the Ed25519 public keys a verifier trusts
    for that case, `public_key_hex` being the raw 32-byte key in lowercase hex."""
    return [{"kid": kid, "alg": evidence.ENVELOPE_ALG, "public_key_hex": _public_hex(kid)}
            for kid in TRUSTED_KIDS]


# =========================================================================
# The chain, and the envelopes over it
# =========================================================================

def _base_bundle() -> dict:
    """The accepting nine-entry chain every case is built on — `valid_bundle_v2`'s own ledger,
    imported rather than restated. No `envelopes` member: adding one is what each case does."""
    return generate_bundles._valid_bundle()


def _envelope(entries: list, seq: int, *, kid: str = WITNESS_KID, result: str = "matched") -> dict:
    """One honest envelope over the entry at `seq`, signed by `kid`'s key."""
    return evidence.sign_envelope(entries, seq, SEEDS[kid], kid=kid, result=result,
                                  at=OBSERVED_AT, method=OBSERVED_METHOD)


def _resign(envelope: dict, kid: str = WITNESS_KID) -> dict:
    """Re-sign an envelope after a change to it. The convention of this file: unless a row says
    otherwise the witness re-signs after the change, so `envelope_bad_signature` is NOT what
    fails. Row 8 is the only row where it is."""
    sign, _verify, _public = evidence._ed25519_backend()
    envelope = {k: v for k, v in envelope.items() if k != "sig"}
    envelope["sig"] = sign(SEEDS[kid], evidence.envelope_signing_input(envelope)).hex()
    return envelope


def _mutate_ts(bundle: dict, *, reanchor: bool) -> dict:
    """The chain edit rows 6, 12, 13 and 14 share: the `ts` of the entry at SPAWN_SEQ is
    restated and EVERY later hash recomputed, so the ledger is perfectly self-consistent. With
    `reanchor=False` the ORIGINAL anchor stays, still committing to the head the ledger used to
    have, which is what makes the chain-level failure assertable."""
    bundle = copy.deepcopy(bundle)
    bundle["entries"][SPAWN_SEQ]["ts"] = MUTATED_TS
    generate_bundles._rehash_chain(bundle["entries"])
    if reanchor:
        _reanchor(bundle)
    return bundle


# =========================================================================
# Case construction
# =========================================================================

def _case(name: str, description: str, bundle: dict, *, expect: str, witness_signed=(),
          expect_failures: list | None = None, signer: bool = True, **extra) -> dict:
    """One case. `witness_signed` is the set of seqs whose entry a verifying envelope covers;
    `expect_states` is derived from it and covers EVERY entry in the chain, not only the covered
    ones, so an accepting row asserts a state rather than merely the absence of a failure."""
    signed = set(witness_signed)
    states = {str(e.get("seq")): (evidence.WITNESS_SIGNED if e.get("seq") in signed
                                  else evidence.PROCESS_ASSERTED)
              for e in bundle["entries"]}
    case = {
        "name": name,
        "description": description,
        # Row 14 is the only case with no signer: it carries no anchor either, so no
        # bundle-level anchor check runs and the envelope is the only thing left that can fail.
        "signer": {"alg": "HS256", "kid": KID, "secret_hex": SECRET.hex()} if signer else None,
        "witness_keys": witness_keys(),
        "bundle": bundle,
        "expect": expect,
        "expect_states": states,
        "expect_failures": expect_failures or [],
    }
    case.update(extra)
    return case


def gen_cases() -> list:
    base = _base_bundle()
    entries = base["entries"]
    n0, n1 = f"{CHAIN_ID}:n0", f"{CHAIN_ID}:n1"
    spawn_envelope = _envelope(entries, SPAWN_SEQ)
    allow_envelope = _envelope(entries, ALLOW_SEQ)

    def with_envelopes(bundle: dict, envelopes: list) -> dict:
        bundle = copy.deepcopy(bundle)
        bundle["envelopes"] = copy.deepcopy(envelopes)
        return bundle

    cases = []

    # ---- valid ----------------------------------------------------------
    cases.append(_case(
        "valid_spawn_envelope",
        "One honest envelope over the `spawn` at seq 1: a witness outside the process that "
        "wrote the ledger signed the IDENTITY of that entry — chain_id, node, seq, entry_hash "
        "and event — and nothing about its contents, which the entry's own hash already covers. "
        "Every check MUST pass, and the entry at seq 1 MUST report witness-signed while every "
        "other entry reports process-asserted: coverage is explicit, never assumed dense. The "
        "report line for seq 1 is `witness-signed (matched)`. This is the case the rejecting "
        "rows below are derived from by exactly one change, unless their description names "
        "another.",
        with_envelopes(base, [spawn_envelope]),
        expect="accept", witness_signed=[SPAWN_SEQ]))

    cases.append(_case(
        "valid_allow_envelope",
        "The same, over an `allow` instead: the orchestrator's authorization at seq 2, whose "
        "subject carries `call_id` alongside the five members a spawn subject carries. An allow "
        "never creates a node of its own, which is why the ENTRY and not the node is the unit a "
        "state is reported for. Every check MUST pass; seq 2 reports witness-signed, every "
        "other entry process-asserted.",
        with_envelopes(base, [allow_envelope]),
        expect="accept", witness_signed=[ALLOW_SEQ]))

    reordered = _reorder_envelope(spawn_envelope)
    cases.append(_case(
        "valid_jcs_reorder",
        "The positive control for canonicalization. Byte for byte the same envelope as "
        "valid_spawn_envelope — the same subject, the same signature — with its members, and "
        "its subject's, observed's and witness's members, written in a different SOURCE order. "
        "JCS sorts them, so it still verifies and seq 1 still reports witness-signed. Score "
        "this row on both halves: it accepts, AND the bytes the verifier canonicalized equal "
        "`canonical_hex`, which is the exact JCS preimage the signature covers — the envelope "
        "without its `sig` member, as bytes, not a digest over them. Accepting while producing "
        "different bytes fails the row. Every other object in this file is written with its "
        "members sorted; this envelope is the one deliberate exception, and a generator that "
        "sorted it would delete what the case tests.",
        with_envelopes(base, [reordered]),
        expect="accept", witness_signed=[SPAWN_SEQ],
        canonical_hex=canonical.dumps({k: v for k, v in spawn_envelope.items()
                                       if k != "sig"}).hex()))

    cases.append(_case(
        "absent_envelope",
        "No envelopes at all: the bundle carries no top-level `envelopes` member, which is "
        "every bundle written before this contract existed and every bundle written by a "
        "deployment that runs no witness. It MUST verify exactly as it does today, and every "
        "entry MUST report process-asserted. process-asserted covers two facts a bundle does "
        "not separate — a hop nobody undertook to cover, and a hop a witness undertook to cover "
        "and never did — and v1 takes the weaker of the two readings and stops there. Nothing "
        "in this row is a failure.",
        copy.deepcopy(base),
        expect="accept"))

    cases.append(_case(
        "indeterminate_result",
        "valid_spawn_envelope with `observed.result` set to `indeterminate`: a witness that "
        "looked and could not settle the question in either direction. It is carried, it "
        "verifies, and it is NOT a failure. The result never changes the state — a verifying "
        "envelope is witness-signed whatever the witness concluded — so seq 1 reports "
        "witness-signed and the report line is `witness-signed (indeterminate)`. This is the "
        "residual state of the three: `not_matched` requires evidence that CONTRADICTS the "
        "event, and thin or absent evidence is indeterminate, never not_matched.",
        with_envelopes(base, [_envelope(entries, SPAWN_SEQ, result="indeterminate")]),
        expect="accept", witness_signed=[SPAWN_SEQ]))

    # ---- coverage, and the two chain-mutation rows that bracket it -------
    cases.append(_case(
        "reject_rehashed_chain_sparse",
        f"Sparse coverage. The entry at seq {SPAWN_SEQ} has its `ts` restated and every later "
        "hash recomputed, so the ledger is perfectly self-consistent; the anchor is the "
        "ORIGINAL one, over the head this ledger used to have. Coverage SKIPS the mutated "
        f"entry: the only envelope is over seq {ALLOW_SEQ}, the next covered hop, whose hash "
        "moved with the rehash. Two failures are required and they come from different layers: "
        "`integrity(anchor)` at chain level, with no position, because the anchor genuinely no "
        f"longer matches; and `envelope_subject_mismatch` at seq {ALLOW_SEQ}, the covered hop. "
        f"The envelope failure lands at seq {ALLOW_SEQ} and NEVER at seq {SPAWN_SEQ}, because "
        "no envelope covers that entry — position is only ever as fine as coverage. Every entry "
        "reports process-asserted.",
        with_envelopes(_mutate_ts(base, reanchor=False), [allow_envelope]),
        expect="reject",
        expect_failures=[_fail("integrity(anchor)", None, None),
                         _fail("envelope_subject_mismatch", ALLOW_SEQ, n0)]))

    # ---- reject: the envelope itself ------------------------------------
    def _subject_change(envelope: dict, member: str, value) -> dict:
        envelope = copy.deepcopy(envelope)
        envelope["subject"][member] = value
        return _resign(envelope)

    nibbled = spawn_envelope["subject"]["entry_hash"]
    nibbled = nibbled[:-1] + ("0" if nibbled[-1] != "0" else "1")
    cases.append(_case(
        "reject_subject_mismatch",
        "The binding member, altered by one nibble: the subject's `entry_hash` names an entry "
        "that is not the one at its `seq`, and the envelope was re-signed afterwards so the "
        "signature is sound and only the claim is wrong. `entry_hash` is the ONLY subject "
        "member that is evidence of which entry the witness signed; the rest are locators. A "
        "verifier finds the entry at `seq`, recomputes its hash from the bundle, and compares. "
        "Required: `envelope_subject_mismatch` at the seq and node of the entry the envelope "
        "covers. The ledger is untouched, so nothing else fails.",
        with_envelopes(base, [_subject_change(spawn_envelope, "entry_hash", nibbled)]),
        expect="reject",
        expect_failures=[_fail("envelope_subject_mismatch", SPAWN_SEQ, n1)]))

    cases.append(_case(
        "reject_bad_signature",
        f"Signed by {WITNESS_KID_B!r}, whose key IS in `witness_keys`, while `witness.kid` "
        f"still names {WITNESS_KID!r}. Everything else is correct: the subject matches the "
        "entry, the member sets are right, the version is known and the witness is trusted, so "
        "the signature is the only thing wrong. A signature that verifies under some OTHER "
        "trusted key is not witness-signed — the kid names the key, and that is the key it has "
        "to verify under. This is the only row in this file where `envelope_bad_signature` is "
        "what fails; every other row is re-signed after its change. Required: "
        "`envelope_bad_signature` at the seq and node of the entry the envelope covers.",
        with_envelopes(base, [_resign(spawn_envelope, WITNESS_KID_B)]),
        expect="reject",
        expect_failures=[_fail("envelope_bad_signature", SPAWN_SEQ, n1)]))

    bumped = copy.deepcopy(spawn_envelope)
    bumped["v"] = 2
    cases.append(_case(
        "reject_unknown_version",
        "`v: 2`, re-signed, and everything else untouched. The version commits the exact signed "
        "member set of the whole envelope, the subject included, so a verifier that meets a "
        "version it does not know refuses rather than reading the members it recognises and "
        "ignoring the rest. The signature is valid, which is the point: a verifier that checks "
        "the signature first still has to refuse. Required: `envelope_unknown_version` at the "
        "seq and node of the entry the envelope covers. A different `typ` is the same failure, "
        "for the same reason — it is a different contract.",
        with_envelopes(base, [_resign(bumped)]),
        expect="reject",
        expect_failures=[_fail("envelope_unknown_version", SPAWN_SEQ, n1)]))

    raw, non_canonical = _non_canonical_envelope(spawn_envelope)
    cases.append(_case(
        "reject_non_canonical",
        "The same envelope serialized non-canonically and signed over THOSE bytes. The "
        "non-canonicality is an escape that does not survive a parse — the `typ` value's first "
        "character is written as a `\\u0064` escape — so a verifier handed the parsed object "
        "alone cannot see it. That is why the row supplies the bytes as received, in `raw_hex`: "
        "the invariant under test is that the received bytes equal JCS of what they parse to, "
        "which is separate from the signature. The signature itself is always over "
        "`JCS(envelope minus sig)`, so a verifier that recomputes that preimage ALSO gets "
        "`envelope_bad_signature` here and may report it; that is an extra, permitted by the "
        "minimal-set rule. The required failure is `envelope_non_canonical` at the seq and node "
        "of the entry the envelope covers, because scoring it must not depend on whether a "
        "deployment kept the bytes.",
        with_envelopes(base, [non_canonical]),
        expect="reject",
        expect_failures=[_fail("envelope_non_canonical", SPAWN_SEQ, n1)],
        raw_hex=raw.hex()))

    widened = copy.deepcopy(spawn_envelope)
    widened["subject"]["agent"] = "summarizer"
    cases.append(_case(
        "reject_member_without_bump",
        "A member added to the subject with no version bump, re-signed: `agent`, taken "
        "truthfully off the very entry the subject covers, so the added member states nothing "
        "false. It is still a reject. A member added anywhere in the envelope changes what the "
        "witness signs, and by the contract that is a new version — which this envelope does "
        "not declare, so the digest would widen silently. Required: `envelope_unknown_member` "
        "at the seq and node of the entry the envelope covers. Note the direction: a member "
        "ADDED is unknown_member, while a subject MISSING a member its event requires is "
        "`envelope_subject_mismatch`.",
        with_envelopes(base, [_resign(widened)]),
        expect="reject",
        expect_failures=[_fail("envelope_unknown_member", SPAWN_SEQ, n1)]))

    cases.append(_case(
        "reject_masked_bundle_mutation",
        f"The entry the envelope covers, the `spawn` at seq {SPAWN_SEQ}, has its `ts` mutated "
        "on the BUNDLE side after the envelope was signed. The chain is re-hashed and a FRESH "
        "anchor signed over it, so the ledger is internally perfect and the anchor matches: a "
        "verifier that checks integrity, monotonicity, containment and execution binding "
        "accepts this bundle and reports nothing. The envelope itself still verifies — its "
        "signature is untouched and sound — and the entry no longer matches what it says. "
        "Required: `envelope_subject_mismatch` at the seq and node of the hop that carried it, "
        "and that is the whole minimal set. No chain-level integrity failure is raised here, "
        "and none may be: that failure comes from a real anchor mismatch and from nothing else.",
        with_envelopes(_mutate_ts(base, reanchor=True), [spawn_envelope]),
        expect="reject",
        expect_failures=[_fail("envelope_subject_mismatch", SPAWN_SEQ, n1)]))

    cases.append(_case(
        "reject_rehashed_chain_anchored",
        "reject_rehashed_chain_sparse with the mutated entry COVERED. The same `ts` mutation at "
        f"seq {SPAWN_SEQ}, the same rehash of every later entry, the same original anchor; the "
        "one difference is that an envelope now covers the mutated entry as well as the hop "
        "after it. Required: `integrity(anchor)` at chain level, and "
        f"`envelope_subject_mismatch` at seq {SPAWN_SEQ}, which is where the sparse row could "
        f"not point. This build also reports the mismatch at seq {ALLOW_SEQ}, whose hash moved "
        "with the same rehash; that is an extra on a covered hop, inside the minimal-set rule. "
        "Every entry reports process-asserted.",
        with_envelopes(_mutate_ts(base, reanchor=False), [spawn_envelope, allow_envelope]),
        expect="reject",
        expect_failures=[_fail("integrity(anchor)", None, None),
                         _fail("envelope_subject_mismatch", SPAWN_SEQ, n1)]))

    unanchored = _mutate_ts(base, reanchor=False)
    del unanchored["anchor"]
    cases.append(_case(
        "reject_rehashed_chain_unanchored",
        f"The same `ts` mutation at seq {SPAWN_SEQ}, every later entry rehashed, and NO anchor "
        "at all: the case carries `\"signer\": null`, the only one in this file that does, so "
        "no bundle-level anchor check runs. The chain re-hashes cleanly, monotonicity and "
        "containment hold, execution binding holds. Required: `envelope_subject_mismatch` at "
        f"seq {SPAWN_SEQ}, and it is the ONLY check that fails. This is the row that fails only "
        "if the envelope check exists — a verifier without one accepts this bundle.",
        with_envelopes(unanchored, [spawn_envelope]),
        expect="reject", signer=False,
        expect_failures=[_fail("envelope_subject_mismatch", SPAWN_SEQ, n1)]))

    cases.append(_case(
        "reject_unknown_witness",
        f"Signed by {WITNESS_KID_UNLISTED!r}, whose kid is not in `witness_keys` and whose "
        "public key this file never carries. The signature is genuine and the subject is "
        "correct; there is simply no reason to trust it. Required: "
        "`envelope_unknown_witness` at the seq and node of the entry the envelope covers. This "
        "row and reject_bad_signature are the two the `witness_keys` array exists to make "
        "checkable from the file alone: one names a key the file trusts and fails on the "
        "signature, the other carries a good signature from a key the file does not trust.",
        with_envelopes(base, [_envelope(entries, SPAWN_SEQ, kid=WITNESS_KID_UNLISTED)]),
        expect="reject",
        expect_failures=[_fail("envelope_unknown_witness", SPAWN_SEQ, n1)]))

    # ---- appended at @safal207's proposal (A2A #1575) --------------------
    cases.append(_case(
        "reject_locator_mismatch",
        f"The ledger and `entry_hash` are untouched; `subject.node` is the only change, set to "
        f"{n0!r} — another node in the same chain, so a verifier that looks the entry up by "
        f"node lands on a real entry that is the WRONG one. The envelope is re-signed. Required: "
        "`envelope_subject_mismatch` at the FOUND entry's seq and node, which is the entry "
        f"`seq` locates ({n1} at seq {SPAWN_SEQ}) and not the node the subject names. `seq` is "
        "the lookup key and there is nothing to compare it against; the locators are checked "
        "against the entry it found, and one that disagrees is this failure at that position. "
        "This pins the position rule for a disagreeing locator on its own, since "
        "reject_subject_mismatch only exercises the hash.",
        with_envelopes(base, [_subject_change(spawn_envelope, "node", n0)]),
        expect="reject",
        expect_failures=[_fail("envelope_subject_mismatch", SPAWN_SEQ, n1)]))

    return cases


def _reorder_envelope(envelope: dict) -> dict:
    """The same envelope with every object's members in REVERSE canonical order, at every level.

    Reverse-of-sorted rather than any other permutation, because it is guaranteed different from
    the canonical order for every object with more than one member — a hand-picked permutation
    can accidentally BE the canonical order for a two-member object like `witness`, and then
    that level tests nothing. Same members, same values, same signature: only the source order
    moves, which is exactly what JCS exists to make irrelevant."""
    def reverse(value):
        if isinstance(value, dict):
            return {k: reverse(value[k]) for k in sorted(value, reverse=True)}
        return value
    return reverse(envelope)


def _non_canonical_envelope(envelope: dict) -> tuple:
    """(bytes as received, the envelope those bytes parse to).

    The received bytes are canonical in every respect but one: the `typ` value's leading `d` is
    written as a `\\u0064` escape. Escaping does not survive a parse, so the parsed object alone
    carries no trace of it — which is the whole reason the case has to supply the bytes. The
    producer signed those bytes, so the signature is over a preimage a verifier recomputing
    `JCS(envelope minus sig)` will not reproduce."""
    escaped = (b'"delegation-event-observation"', b'"\\u0064elegation-event-observation"')
    sign, _verify, _public = evidence._ed25519_backend()
    body = {k: v for k, v in envelope.items() if k != "sig"}
    preimage = canonical.dumps(body).replace(*escaped)
    assert preimage != canonical.dumps(body), "the escape did not change the preimage"
    signed = dict(body, sig=sign(SEEDS[WITNESS_KID], preimage).hex())
    raw = canonical.dumps(signed).replace(*escaped)
    assert raw != canonical.dumps(signed), "the escape did not change the received bytes"
    return raw, json.loads(raw)


# =========================================================================
# Serialisation
# =========================================================================

def _document(cases: list) -> dict:
    return {
        "version": VECTORS_VERSION,
        "revision": VECTORS_REVISION,
        "description": (
            "Observer-envelope vectors (envelope v1) for attenu-guard evidence bundles. An "
            "envelope is a witness's Ed25519 signature over the IDENTITY of one committed "
            "ledger entry — `chain_id`, `node`, `seq`, `entry_hash`, `event`, and `call_id` on "
            "an allow — carried beside the ledger in the bundle's top-level `envelopes` array. "
            "It is never required: an absent envelope is the status quo and every entry of a "
            "bundle without them reports `process-asserted`. A present one must verify, and a "
            "broken one lands in the same failure list as the chain-level checks. Each case "
            "carries `witness_keys`, the Ed25519 public keys a verifier trusts for it "
            "(`public_key_hex` is the raw 32-byte key, lowercase hex; `alg` is EdDSA), and "
            "`expect_states`, the per-entry state for EVERY entry in the chain, "
            "`witness-signed` or `process-asserted`. `expect` is \"accept\" or \"reject\"; for "
            "a rejecting case `expect_failures` is the MINIMAL set of failures that MUST "
            "appear, each with the exact reason and the exact position (`seq`/`node`, null "
            "when the failure is chain-level). A conformant verifier MAY report more, never "
            "fewer, and never at a different position — subject to two rules: an envelope "
            "failure lands only on the hop that envelope covers, never on a hop coverage "
            "skipped; and no chain-level integrity failure is ever raised because an envelope "
            "failed. `sig` is over JCS(envelope minus its \"sig\" member), lowercase hex over "
            "the raw signature bytes; `entry_hash` is the entry's hash recomputed from the "
            "bundle as hex(SHA-256(prev_hash_ascii || JCS(entry without hash))). `version` is "
            "the compatibility contract and does not move when cases are appended; `revision` "
            "does. See tests/vectors/README.md."),
        "cases": cases,
    }


def _deep_sorted(value):
    """Every object's members sorted, at every depth — what `json.dumps(sort_keys=True)` would
    do, applied ahead of serialisation so that ONE object can be exempted from it."""
    if isinstance(value, dict):
        return {k: _deep_sorted(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_deep_sorted(v) for v in value]
    return value


def _serialise(document: dict) -> str:
    """Sorted everywhere except `valid_jcs_reorder`'s envelope, which is restored scrambled
    after the sort. That case's whole point is a non-canonical SOURCE order, and a writer that
    sorted it would leave nothing to test."""
    reordered = document["cases"][2]["bundle"]["envelopes"][0]
    assert document["cases"][2]["name"] == "valid_jcs_reorder", document["cases"][2]["name"]
    document = _deep_sorted(document)
    document["cases"][2]["bundle"]["envelopes"][0] = reordered
    return json.dumps(document, indent=2, sort_keys=False) + "\n"


def generate_all(out_dir: Path = VECTORS_DIR,
                 package_dir: Path | None = PACKAGE_VECTORS_DIR) -> dict:
    """Write the vector file to `out_dir` AND, unless `package_dir` is None, to the packaged
    copy; return the document so callers (tests/test_envelope_vectors.py) can self-check without
    re-reading from disk. Serialised ONCE and written to both destinations, so the two are
    byte-identical by construction. Deterministic: calling this twice writes identical bytes."""
    document = _document(gen_cases())
    text = _serialise(document)
    for d in [out_dir] + ([package_dir] if package_dir is not None else []):
        d.mkdir(parents=True, exist_ok=True)
        for stale in d.glob("*.json"):
            if stale.name != VECTORS_FILENAME:
                stale.unlink()
        (d / VECTORS_FILENAME).write_text(text)
    return json.loads(text)


def check_case(case: dict) -> tuple:
    """Score ONE case against this build's own `verify_bundle` — exactly what an independent
    implementation does with its own verifier. Returns (ok, human-readable outcome)."""
    signer = None
    if case["signer"] is not None:
        from attenu_guard import wire
        signer = wire.HS256TestSigner(bytes.fromhex(case["signer"]["secret_hex"]),
                                      kid=case["signer"]["kid"])
    raw = case.get("raw_hex")
    envelope_bytes = [bytes.fromhex(raw)] if raw is not None else None
    report = evidence.verify_bundle(case["bundle"], signer, witness_keys=case["witness_keys"],
                                    envelope_bytes=envelope_bytes)
    got = "accept" if report["ok"] else "reject"
    if got != case["expect"]:
        return False, f"expected={case['expect']} got={got} failures={report['failures']}"
    states = {str(seq): state for seq, state in report["envelopes"]["states"].items()}
    if states != case["expect_states"]:
        return False, f"expected={case['expect']} got={got} but STATES {states} != {case['expect_states']}"
    seen = [{"reason": d["reason"], "seq": d["seq"], "node": d["node"]}
            for d in report["failure_details"]]
    missing = [f for f in case["expect_failures"] if f not in seen]
    if missing:
        return False, f"expected={case['expect']} got={got} but MISSING {missing} (reported {seen})"
    if "canonical_hex" in case:
        produced = evidence.envelope_signing_input(case["bundle"]["envelopes"][0]).hex()
        if produced != case["canonical_hex"]:
            return False, (f"expected={case['expect']} got={got} but canonicalized {produced} "
                           f"!= canonical_hex {case['canonical_hex']}")
    extra = [f for f in seen if f not in case["expect_failures"]]
    note = f" (+{len(extra)} further reported)" if extra else ""
    return True, (f"expected={case['expect']} got={got}, {len(case['expect_failures'])} required "
                  f"failure(s) present, states as declared{note}")


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
    print("\nALL ENVELOPE VECTORS SELF-CONSISTENT" if ok else "\nENVELOPE VECTOR SELF-CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
