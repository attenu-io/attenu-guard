---
title: "Verifiable Attenuated Delegation for AI Agent Chains"
abbrev: "Agent Delegation Chain"
docname: draft-asor-wimse-agent-delegation-chain-01
category: std
ipr: trust200902
area: Security
workgroup: WIMSE
keyword: [agent, delegation, attenuation, authorization, capability]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  -
    ins: R. Asor
    name: Rafael Asor
    organization: Attenu
    email: rafael.asor@gmail.com
    uri: https://attenu.io/
normative:
  RFC2119:
  RFC5234:  # ABNF
  RFC7515:  # JWS
  RFC7519:  # JWT
  RFC7800:  # PoP cnf
  RFC8032:  # EdDSA
  RFC8037:  # CFRG curves in JOSE
  RFC8174:
  RFC8785:  # JCS
  RFC9068:  # JWT access-token profile
  RFC9396:  # Rich Authorization Requests
  RFC9449:  # DPoP
  RFC9864:  # Fully-specified algorithms
  I-D.ietf-oauth-status-list:
informative:
  RFC2693:  # SDSI/SPKI
  RFC7009:  # Token Revocation
  RFC8693:  # Token Exchange
  RFC8705:  # mTLS-bound tokens
  RFC9964:  # ML-DSA for JOSE/COSE
  I-D.ietf-oauth-identity-chaining:
  I-D.reece-wimse-cross-org-delegation:
  I-D.klrc-aiagent-auth:
  I-D.niyikiza-oauth-attenuating-agent-tokens:
  I-D.coetzee-oauth-spt-txn-tokens:
  I-D.sweeney-wimse-credential-delegation:
  I-D.hamr-oauth-agent-delegation:
  Macaroons:
    title: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"
    date: 2014
    seriesinfo: NDSS 2014
  Biscuit:
    title: "Biscuit Authorization Token Specification, v3"
    target: https://doc.biscuitsec.org/reference/specifications.html
--- abstract

AI agents increasingly delegate tasks to other agents. Each delegation should
convey only a subset of the delegating party's authority, that subset should be
bounded in scope, magnitude, and time, and any enforcement point should be able
to verify -- offline, with no call to an authorization server -- that a token
presented at hop N carries authority no greater than the token at hop N-1, back
to a trusted root. OAuth 2.0 Token Exchange (RFC 8693) models two-party
delegation and records prior actors in a nested "act" claim, but that claim is
informational only and cannot enforce attenuation across a chain of depth two or
more. This document defines the Agent Delegation Chain: a profile of OAuth 2.0
JWT access tokens (RFC 9068) that carries authority as Rich Authorization
Requests (RFC 9396), links each delegation to its parent by a cryptographic
byte-commitment, and specifies a deterministic offline verification algorithm
that enforces monotonic attenuation, bounded depth, and monotonic expiry. It
reuses existing JOSE, proof-of-possession (RFC 9449), and status-list machinery (the OAuth Status List draft) and introduces no new cryptography.

--- middle

# Introduction

An AI agent that receives a task from a user or another agent frequently
decomposes it and delegates sub-tasks to further agents or tools. In production
deployments this produces delegation chains of depth greater than two. The
security requirement is a single invariant: the authority exercised at any hop
MUST be a subset of the authority granted at the hop that delegated to it, and
this MUST be verifiable by the enforcement point that ultimately honors a tool
call, without that point contacting an authorization server.

## The gap in existing mechanisms

OAuth 2.0 Token Exchange {{RFC8693}} defines delegation and impersonation
semantics and a nestable "act" claim. However, {{RFC8693}} Section 4.1 states
that a recipient considers only the top-level claims and the current (outermost)
actor; the nested chain is history for audit, not enforced authority. Token
Exchange also normally contacts the authorization server at each hop. Neither
property supports offline, enforced, depth >= 2 attenuation.

Cross-domain identity chaining (see {{I-D.ietf-oauth-identity-chaining}}) and
transaction tokens address related but distinct problems (crossing trust domains
and propagating immutable context within one domain, respectively) and
explicitly do not provide chained cryptographic attenuation.

Capability systems that do provide offline attenuation -- macaroons
{{Macaroons}}, Biscuit {{Biscuit}} -- either verify with a shared secret
(macaroons: symmetric HMAC, so every verifier holds the minting key) or use a
non-IETF wire format (Biscuit: protocol buffers with an embedded Datalog engine).
The historical standards-track ancestor is SDSI/SPKI {{RFC2693}}.

This document fills the gap by reusing the JOSE/OAuth stack and adding only the
chain linkage and the subsumption-enforcing verification algorithm. It is
designed as the attenuation mechanism satisfying requirement R1 of
{{I-D.reece-wimse-cross-org-delegation}} and as a companion to
{{I-D.klrc-aiagent-auth}}. It shares its approach with, and is intended to
converge with, {{I-D.niyikiza-oauth-attenuating-agent-tokens}} and
{{I-D.coetzee-oauth-spt-txn-tokens}}. Its offline verification model is
complementary to the online Delegation Server and synchronous revocation model
in {{I-D.sweeney-wimse-credential-delegation}}. The two are halves of one
design, separated by a single axis: whether a server is in the path. The
in-token mechanisms this document requires -- constraints carried in the token,
parent-hash verification, and a child expiry bounded by its parent's -- are how
a verifier with no network reconstructs what such a server would otherwise know
first-hand; where a server is in every hop, they are redundant rather than
absent.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Delegation Token (DT):
: An OAuth 2.0 JWT access token {{RFC9068}} profiled by this document, carrying
  the authority granted to one agent at one hop of a chain.

Delegation Chain:
: An ordered sequence of Delegation Tokens DT_0, DT_1, ... DT_n, where DT_0 is
  the root, and each DT_i (i > 0) is linked to DT_{i-1} by the mechanism in
  {{chain-linkage}}.

Authority:
: The set of permitted scope values carried by an "agent_delegation"
  authorization detail in the "authorization_details" claim {{RFC9396}},
  together with the constraints in {{constraints}}.

Attenuation:
: The construction of a child Delegation Token whose Authority is a subset of
  its parent's, per the subsumption rules in {{subsumption}}.

Enforcement Point:
: The component that verifies a Delegation Chain and permits or denies an action.

# Token Format {#token-format}

A Delegation Token is a JWT {{RFC7519}} signed with JWS {{RFC7515}} using a
fully-specified algorithm {{RFC9864}}. Implementations MUST support Ed25519
{{RFC8032}} {{RFC8037}} and MAY support ES256 and, for post-quantum readiness,
ML-DSA {{RFC9964}}. The token uses the "application/at+jwt" header type of
{{RFC9068}} and includes its required claims (iss, exp, aud, sub, iat, jti).
The protected header SHOULD contain "c14n": "JCS" as an informational label.
Verifiers MUST NOT rely on this field. The canonicalization of the protected
header and payload JSON is the JSON Canonicalization Scheme (JCS) {{RFC8785}}:
producers MUST serialize both with JCS before base64url encoding, and verifiers
MUST reject either decoded byte string unless it is exactly the JCS
serialization of the parsed object. Verifiers MUST also reject duplicate object
member names, non-finite numbers, and lone UTF-16 surrogates.

In addition, a Delegation Token contains:

authorization_details:
: REQUIRED. An array of authorization detail objects {{RFC9396}} expressing the
  Authority. See {{authority}}.

cnf:
: REQUIRED. A confirmation claim {{RFC7800}} binding the token to the holder's
  key, proven per DPoP {{RFC9449}}. See {{binding}}.

del_depth:
: REQUIRED. A non-negative integer; the position of this token in the chain.
  DT_0 has del_depth 0.

del_max_depth:
: REQUIRED in DT_0. A positive integer; the maximum permitted chain length.
  MUST NOT be increased by any child (see {{subsumption}}).

par_hash:
: REQUIRED in every DT_i with i > 0; MUST be absent in DT_0. The base64url-encoded
  SHA-256 digest of the parent token's JWS Signing Input ({{RFC7515}} Section 5.1),
  i.e. of the exact bytes "ASCII(BASE64URL(parent JOSE Header)) || '.' ||
  ASCII(BASE64URL(parent JWS Payload))". This is the byte-commitment that binds a
  child to one specific parent and prevents chain splicing.

# Authority Representation {#authority}

For this profile, Authority is expressed by an authorization detail object
{{RFC9396}} whose "type" is "agent_delegation". The object contains a REQUIRED
"scopes" member: an array of strings, where each string names one permitted
operation. An empty array conveys no permitted operation. Numeric and
enumerated bounds ("ceilings") that {{RFC9396}} does not standardize are carried
in the "constraints" member defined here.

## Scope Syntax and Wildcards {#scopes}

Each member of "scopes" MUST match the following ABNF {{RFC5234}}:

~~~
lower          = %x61-7A
digit          = %x30-39
segment        = lower *(lower / digit / "_" / "-")
literal-scope  = segment "." segment *("." segment)
wildcard-scope = segment *("." segment) ".*"
scope          = literal-scope / wildcard-scope
~~~

Thus, scope values are lowercase, dot-separated names with at least two
segments. A wildcard is permitted only as the complete final segment following
a dot. The bare value `*`, partial-segment forms such as `crm.re*`, and
non-terminal forms such as `crm.*.read` are invalid. A producer MUST NOT emit
an invalid scope. A verifier that encounters one MUST reject the Delegation
Token as malformed before evaluating subsumption.

A parent literal scope covers only an identical child scope. A parent wildcard
scope covers any child scope whose value begins with the parent value after
removing only the final `*` and retaining the dot. Therefore `crm.*` covers
"crm.read", "crm.x.y.z", and `crm.x.*`; it does not cover the bare name "crm"
or the adjacent namespace "crmx.read". Wildcard coverage is segment-bounded and
extends to any depth below the named prefix.

This wildcard-covering rule applies only to the "scopes" member of the
"agent_delegation" authorization detail type defined in {{authority}}; other
authorization detail types, if defined, specify their own scope semantics.

## Constraint Vocabulary {#constraints}

The "constraints" member is an array of objects. Each object contains a
REQUIRED "key" member identifying the constrained dimension and one typed
constraint value. This document defines:

- "max" : a number. The value of the associated quantity MUST NOT exceed it
  (e.g. {"key": "max_rows", "max": 5000}).
- "min" : a number. The value of the associated quantity MUST NOT be less than
  it (e.g. {"key": "tenure_years", "min": 2}). Where "max" carries a ceiling
  tightened downward, "min" carries a floor tightened upward.
- "one_of" : an array. The associated value MUST be a member.
- "not_one_of" : an array. The associated value MUST NOT be a member.
- "prefix" : a string. The associated value MUST have it as a prefix.
- "rank" : used for ordered enumerations (e.g. egress none < internal < any);
  the value's rank MUST NOT exceed the constraint's.

The registry in {{iana}} allows new constraint types. A verifier that encounters
an unknown constraint type MUST treat the action as denied (fail-closed), never
as unconstrained.

## Subsumption Rules {#subsumption}

An Authority C is subsumed by an Authority P (written C <= P) if and only if all
of the following hold:

1. Every scope in C's "agent_delegation" detail is covered by at least one
   scope in P's "agent_delegation" detail according to {{scopes}}, and
2. for every constraint present in P, a corresponding constraint is present in C
   whose admissible set is a subset of P's (e.g. C.max <= P.max; C.min >= P.min;
   C.one_of subset of P.one_of; C.rank <= P.rank), and
3. a constraint present in P MUST NOT be absent in C (absence means unbounded,
   which is not a subset), and
4. C.exp <= P.exp (monotonic expiry), and
5. C.del_max_depth <= P.del_max_depth.

Attenuation is the construction of C as the greatest lower bound (meet) of P and
a request R under these rules. Because the meet can only narrow, C <= P holds by
construction for every R.

# Chain Linkage {#chain-linkage}

Each child token commits to its parent by "par_hash" ({{token-format}}). This
binds the child to the parent's exact serialized bytes, so a child cannot be
re-parented onto a different (e.g. broader) token: doing so changes the parent's
Signing Input and thus its SHA-256 digest, which no longer matches the child's
"par_hash". The digest is over the already-serialized JWS Signing Input; the
protected header and payload that form that input are JCS {{RFC8785}} as required
by {{token-format}}.

# Offline Verification Algorithm {#verify}

An Enforcement Point presented with a Delegation Chain DT_0 ... DT_n and an
attempted action A, and holding the trusted root public key(s), MUST perform the
following, denying on the first failure:

1. Verify the JWS signature of every DT_i using a fully-specified algorithm
   {{RFC9864}}. DT_0 MUST verify under a trusted root key.
2. For each i > 0, compute SHA-256 of DT_{i-1}'s JWS Signing Input and compare,
   in constant time, to DT_i's "par_hash". Any mismatch: deny.
3. Check del_depth: DT_0.del_depth == 0; DT_i.del_depth == i; n <
   DT_0.del_max_depth. Otherwise deny.
4. For each i > 0, verify DT_i.Authority <= DT_{i-1}.Authority per {{subsumption}}.
   Any violation: deny.
5. Check time: for every i, nbf (if present) <= now <= exp, and exp is monotonic
   non-increasing along the chain. Otherwise deny.
6. Verify holder binding: the presenter proves possession of the key in DT_n.cnf
   via a valid DPoP proof {{RFC9449}} bound to this request. Otherwise deny.
7. Check revocation: consult the Token Status List {{I-D.ietf-oauth-status-list}}
   reference in each DT_i (if present) against a cached list; if any is revoked,
   deny (and, by local policy, treat the whole subtree as revoked).
8. Authorize A against DT_n.Authority (scope and every constraint in
   {{constraints}}). Permit only if A is within it.

The algorithm is deterministic, side-effect free, and requires no network call
except the (cacheable, offline-checkable) status list of step 7.

# Holder Binding {#binding}

Every Delegation Token is sender-constrained by a "cnf" claim {{RFC7800}}
carrying the JWK thumbprint of the holder's key, proven per request with DPoP
{{RFC9449}}. mTLS-bound tokens {{RFC8705}} MAY be used where the transport is
controlled end-to-end. A captured token is therefore unusable without its bound
private key, which mitigates replay of intermediate tokens.

# Revocation {#revocation}

Delegation Tokens are RECOMMENDED to be short-lived (seconds to minutes for leaf
and execution tokens), so that expiry is the common revocation path. For earlier
revocation of longer-lived delegations, each token MAY carry a Token Status List
{{I-D.ietf-oauth-status-list}} reference; revoking a token's status entry, and
by local policy the entries of its descendants, revokes a delegation or a whole
sub-chain while preserving offline verification (the status list is itself
cacheable and offline-checkable). An online revocation endpoint {{RFC7009}} MAY
additionally be offered.

Deployments that require synchronous cascading revocation MAY issue and
exercise Delegation Tokens through an online Delegation Server as specified by
{{I-D.sweeney-wimse-credential-delegation}}. The server can evaluate current
delegation-tree state and refuse a revoked root or descendant immediately. This
online bridge complements, and does not replace, the offline verification
algorithm in {{verify}}: an Enforcement Point that receives a chain MUST still
verify its signatures, linkage, attenuation, depth, and expiry.

# Security Considerations {#security}

## Parent tokens remain valid after attenuation

Attenuation produces a new child token but does not, by itself, invalidate the
parent. A party holding the parent still holds the parent's (broader) authority.
This is mitigated by three mechanisms that MUST be considered together: (a)
tokens are short-lived and holder-bound ({{binding}}), so a leaked parent is both
time-boxed and non-replayable without its key; (b) the "par_hash" byte-commitment
({{chain-linkage}}) prevents splicing a child onto a different parent; and (c)
status-list revocation ({{revocation}}) allows early invalidation of a parent and
its subtree. Deployments that require immediate parent invalidation on delegation
MUST use short TTLs and status lists accordingly.

## Chain splicing

Without the byte-commitment, an attacker could present a valid child together
with a broader token as its purported parent. Step 2 of {{verify}} prevents this:
the child's "par_hash" digests the parent's exact Signing Input, so only the
intended parent verifies.

## Confused deputy and over-broad delegation

Because each hop's authority is the meet of parent and request ({{subsumption}}),
a child cannot be induced (e.g. by prompt injection) to exercise authority the
parent lacked.

## Unbounded depth and fan-out

"del_max_depth" (checked in step 3) bounds chain length; deployments SHOULD set
it low (e.g. 5). Fan-out (a parent delegating to many children) is not limited by
the token format and MUST be bounded by the issuing infrastructure if required.

## Offline verification vs. revocation latency

Offline verification means an enforcement point may honor a token that has been
revoked but whose status-list update it has not yet fetched. Deployments trade
this window against TTL: shorter TTLs bound the exposure. This is the standard
status-list trade-off and MUST be documented for each deployment.

## Why not macaroons; algorithm agility

Macaroons {{Macaroons}} verify with the root secret, precluding public offline
verification at an untrusted edge; this document uses public-key signatures.
Algorithms are fully specified {{RFC9864}} and agile via the JOSE "alg" registry,
with a migration path to ML-DSA {{RFC9964}}.

# IANA Considerations {#iana}

This document requests registration, in the JSON Web Token Claims registry, of:
"del_depth", "del_max_depth", and "par_hash" (with the semantics in
{{token-format}}). It requests a new "Agent Delegation Constraint Types" registry
(initial entries: "max", "min", "one_of", "not_one_of", "prefix", "rank"; registration
policy Specification Required; unknown types fail closed per {{constraints}}). It
requests an "authorization_details" type value for delegated agent authority,
coordinated with {{I-D.niyikiza-oauth-attenuating-agent-tokens}} to avoid
divergence.

--- back

# Acknowledgments

This work builds directly on, and seeks convergence with,
{{I-D.niyikiza-oauth-attenuating-agent-tokens}},
{{I-D.coetzee-oauth-spt-txn-tokens}},
{{I-D.sweeney-wimse-credential-delegation}}, {{I-D.klrc-aiagent-auth}}, and the
requirements of {{I-D.reece-wimse-cross-org-delegation}}. The capability-token
lineage of {{Macaroons}}, {{Biscuit}}, and {{RFC2693}} is gratefully
acknowledged. The "min" constraint type was added after Amr Hassan, author of
{{I-D.hamr-oauth-agent-delegation}}, observed that -00 had no comparator for a
floor tightened upward; the duration-typed "tenureMin" axis of that document is
the motivating example.

# Reference Implementation and Test Vectors

A permissively licensed reference implementation (the "attenu-guard" library)
and a set of offline-verification test vectors (chains that MUST verify and
adversarial chains that MUST be rejected) accompany this draft. Separating
vectors cover scope and ceiling widening, parent splicing, depth and expiry
violations, wildcard errors, RFC 8785 number and string forms, non-finite values,
duplicate member names, and the informational "c14n" label, including a valid
JCS token without that label. They are intended for interoperability testing
across independent implementations.
