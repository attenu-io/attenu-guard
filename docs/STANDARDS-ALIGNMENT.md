# Standards Alignment & IETF Strategy — Agent Delegation Authorization

*Verified against primary IETF sources, August 17, 2026. This document decides
what we reuse, what we invent, where we take it, and how we get it adopted.
Companion to the Internet-Draft [draft-asor-wimse-agent-delegation-chain-00](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/) (individual submission, posted 2026-08-27; source `draft-asor-wimse-agent-delegation-chain-00.md`)
and the DevX review (`DEVX-REVIEW.md`).*

## The one thing to internalize

We are **not** first, and that is the good news. Enforced, monotonic,
offline-verifiable attenuation across agent delegation chains is one of the most
active corners of the IETF right now — roughly sixteen individual drafts, two of
them near-twins of our design, and a multi-vendor umbrella draft
(`draft-klrc-aiagent-auth`, authored across Defakto/AWS/Zscaler/Ping/OpenAI/Okta)
heading for WIMSE adoption. **None is WG-adopted yet**, so the mechanism slot is
still open. The failure mode is not "nobody cares" — it is "you are the
seventeenth redundant capability-token draft and the working group ignores you."
The winning move is **convergence plus one narrow, well-justified differentiator
backed by running code**, not a fresh standalone land-grab. Everything below
serves that.

## What we reuse vs. what we invent (the whole strategy in one table)

An IETF reviewer rejects anything that reinvents crypto or overlaps existing
work. So we invent exactly **one** thing and profile everything else.

| Layer | We REUSE (don't touch) | Standard |
|---|---|---|
| Token container | JWT + JWS; parallel CWT/COSE binding via a CDDL model | RFC 7519 / 7515; 8392 / 9052 / 8949 / 8610 |
| Access-token profile | `at+jwt` claim discipline (`iss`,`exp`,`aud`,`sub`,`iat`,`jti`) | RFC 9068 |
| Authority representation | `authorization_details` as a top-level claim | RFC 9396 (Rich Authorization Requests) |
| Holder binding / PoP | `cnf` confirmation claim + DPoP proof; mTLS optional | RFC 7800 / 8747; 9449; 8705 |
| Delegation *identity/history* | `act` / `may_act` / `actor_token` | RFC 8693 (Token Exchange) |
| Cross-**org** hop | Identity Chaining (Token Exchange + JWT assertion) | draft-ietf-oauth-identity-chaining (RFC-Ed queue) |
| Revocation at scale | Token Status List + short TTL; RFC 7009 endpoint optional | draft-ietf-oauth-status-list; RFC 7009 |
| Signatures | Ed25519 mandatory, ES256 alternate, ML-DSA permitted; fully-specified algs | RFC 8032/8037; 9864; 9964 |
| Identity substrate | WIT / WPT (workload identity + proof tokens); SPIFFE | draft-ietf-wimse-workload-creds, -wpt |
| **We INVENT (only this)** | **the cryptographically-linked, subsumption-enforced, offline, multi-hop attenuation chain + its verification algorithm** | *our draft* |

The invented layer is legitimate to invent because **RFC 8693 provably cannot do
it**: its nested `act` chain is *informational history only* ("a consumer MUST
only consider the top-level claims and the current actor"), so it cannot enforce
that hop *N*'s authority ⊆ hop *N−1*'s, offline, at depth ≥ 2. That single
sentence — "8693 can't do it, here is the minimal addition" — is our cleanest
gap argument and the spine of the draft's introduction.

## The competitive draft map (know your neighbors)

Convergence requires knowing exactly who is already here. All individual, none
adopted, as of Aug 2026:

- **`draft-niyikiza-oauth-attenuating-agent-tokens` (Tenuo)** — our near-twin.
  JWT + RFC 9396 + `par_hash` (SHA-256 of the parent JWS Signing Input) chaining
  + `del_depth`/`del_max_depth` + `cnf`/DPoP + monotonic attenuation, offline.
  Rust reference impl ("warrants"). **This is prior art we must cite and a
  co-authorship target — not something to silently duplicate.**
- **`draft-coetzee-oauth-spt-txn-tokens` (SPT-Txn)** — the most complete rival.
  CAT→CT→TXN tiers; **five invariants** (monotonic scope, chain intersection,
  monotonic TTL, bounded depth, full-chain byte-commitment against splicing);
  intent binding via SHA-256 over RFC 8785 JCS; Token Status List revocation;
  PQ agility. **Study its five invariants; our invariants must match or exceed
  and our delta must be explicit.**
- **`draft-klrc-aiagent-auth` (the umbrella)** — a composition BCP (the "AIMS"
  stack) reusing WIMSE + OAuth primitives, multi-vendor, heading for WIMSE
  adoption as the anchor document. **Align hardest here: become the attenuation
  mechanism this umbrella points to. Fighting it is fatal; complementing it is
  the fast path.**
- **`draft-reece-wimse-cross-org-delegation`** — a *requirements* draft whose
  R1 literally mandates recursive attenuation ("each hop conveys a subset… no
  hop exceeds its predecessor"). **Our single best anchoring hook: position the
  draft as "the mechanism that satisfies Reece R1."**
- **`draft-sweeney-wimse-credential-delegation`** — enforces subset at an
  *online* Delegation Server. **Our differentiator vs. Sweeney is explicit:
  offline, issuer-free chain verification. Do not undercut it by mandating
  online infrastructure.**
- **`draft-munoz-wimse-authorization-evidence`** ("Permit" records, SCITT COSE),
  **`draft-nennemann-wimse-ect`** (execution-history DAG), **`draft-ni-wimse-
  ai-agent-identity`** (agent↔owner identity binding) — all **complementary
  layers we plug into, not compete with**: evidence/audit, execution history,
  and identity respectively.
- **`draft-prakash-aip`** — puts **Biscuit** (protobuf + Datalog) at the IETF as
  a chained-capability option. Forces us to explicitly justify a **JOSE-native**
  format over Biscuit's wire format (we do: reviewer familiarity + no new
  envelope; see the draft's rationale).

## The review bar we must clear (already on the record)

The OAuth WG's critique of the attenuation approach (Neil Madden, June 2026) is
the exact bar. Our Security Considerations pre-empt every point:

1. **"Why not just use macaroons?"** — because macaroons verify with the root
   *secret* (symmetric HMAC), so every enforcement point must hold the minting
   key; no public/offline verification at an untrusted edge. We use public-key
   signatures (Ed25519), verifiable with only the root public key.
2. **"Nothing is removed when deriving a token, so the parent stays valid."** —
   the sharpest attack. Attenuation produces a *new* child token but does not
   invalidate the parent; a holder of the parent still has the parent. We
   address it three ways: (a) parent tokens are short-TTL and holder-bound
   (`cnf`), so a leaked parent is both time-boxed and non-replayable without the
   key; (b) chain **byte-commitment** (child commits to the parent's exact bytes)
   makes splicing a different parent detectable; (c) Token Status List lets an
   issuer revoke a parent (and, by policy, its subtree) early.
3. **Intermediate-token replay / PoP gaps.** — every hop is `cnf`-bound and
   requires a per-request DPoP proof; a captured intermediate token is unusable
   without its bound key.
4. **RFC 2693 (SDSI/SPKI) precedent.** — we cite it as the standards-track
   ancestor and explain what we reuse from the modern stack instead.

Plus the SPT-Txn-class concerns we adopt proactively: **chain splicing** (bound by
byte-commitment), **unbounded depth** (hard `del_max_depth`), and **confused
deputy** (each hop's authority is the *meet*, and tool audience is pinned).

## Where it goes: WIMSE, on OAuth primitives

**Primary WG home: WIMSE** (Workload Identity in Multi-System Environments,
Security Area). It is the gravity well for agent identity/authz, it is about to
adopt `draft-klrc-aiagent-auth` as its anchor, it hosts the Reece requirements
draft we answer, and it owns the WIT/WPT identity substrate our tokens bind to.
**Coordinate with OAuth**, whose primitives (RAR, Token Exchange, Status List,
DPoP) we normatively reference and where the two twin drafts live. Concrete
shape: **a WIMSE profile that normatively references OAuth primitives**,
socialized on both lists.

**Avoid:** the `agentproto` BoF (it explicitly scoped authorization *out*), GNAP
(RFC 9635 — richer but near-zero deployment; building on it signals NIH), and
opening a new BoF (unnecessary with two live homes).

## The five moves that most increase acceptance

1. **Ship running code + interop, matching the bar already set.** A permissively
   licensed reference verifier, **published offline-verification test vectors**
   (canonicalized per RFC 8785 JCS), and a **second independent implementation**.
   Tenuo has a Rust impl; the A2A project already runs cross-implementation CI
   vectors. `attenu-guard` is our reference implementation — this is why it
   exists and why it must be excellent.
2. **Profile, don't reinvent** (the table above). Every layer cites the standard
   it reuses; we invent only the chain + verification algorithm.
3. **Anchor to existing consensus artifacts.** Frame the draft as *"the
   mechanism satisfying `draft-reece-wimse-cross-org-delegation` R1"* and *"the
   attenuation companion to `draft-klrc-aiagent-auth`."* Recruit a WIMSE
   chair/AD champion early (Responsible AD: Charles Eckel).
4. **Converge with incumbents.** Reach out to Niyikiza (Tenuo), Coetzee
   (SPT-Txn), Sweeney, and the klrc authors *before* submitting. A merged,
   multi-implementer draft is dramatically more adoptable than a parallel one —
   multi-vendor co-authorship is precisely the pattern that got Txn-Tokens and
   Identity Chaining through.
5. **Enter the process cleanly and narrowly.** Post to the WIMSE + OAuth lists
   now; request a **WIMSE interim before IETF 127**; submit a tight **-00 before
   the Nov 2, 2026 I-D cutoff**; request a WG slot (by Oct 2, 2026) for **IETF
   127, San Francisco, week of Nov 14, 2026**; bring a one-slide gap analysis vs.
   Txn-Tokens/RAR/Identity-Chaining and a **live offline-verify demo**.

## What repels a working group (do not do)

A boil-the-ocean mega-draft (identity + attestation + delegation + revocation +
PQ in one) — WGs adopt narrow composable documents; keep our normative core to
**chain construction + verification algorithm + revocation binding**. NIH /
overlap — do not re-solve cross-domain chaining, context propagation, revocation
lists, or the composition umbrella. Vendor-branded framing — neutral terminology
(no "Attenu" claims, no company-named tokens), full IPR disclosure, BSD/MIT
reference code. Mandating online infrastructure — it contradicts our
offline-verification differentiator. Weak Security Considerations — replay, PoP,
splicing, depth, confused-deputy, revocation latency each addressed head-on.
Cold-dropping the draft — socialize on the lists first, then submit.

## Timeline

- **Now (Aug–Sep 2026):** finalize the -00, ship the reference verifier + test
  vectors + second impl, open contact with Tenuo/klrc authors, post to WIMSE +
  OAuth lists.
- **BoF proposals close Sep 18, 2026; WG session requests close Oct 2, 2026;
  I-D submission cutoff Nov 2, 2026.**
- **Ask WIMSE chairs for an interim before IETF 127** (they offered).
- **IETF 127, San Francisco, week of Nov 14, 2026** — present with running code.
- **Realistic individual-draft → RFC: ~2–4 years** even when healthy. Adoption
  (becoming `draft-ietf-wimse-…`) is the near-term win that matters commercially
  — it is the "we are the standard" proof for customers and acquirers, and it is
  achievable in the 2027 timeframe if convergence works.
