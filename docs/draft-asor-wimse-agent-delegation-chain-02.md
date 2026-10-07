---
title: "Verifiable Attenuated Delegation for AI Agent Chains"
abbrev: "Agent Delegation Chain"
docname: draft-asor-wimse-agent-delegation-chain-02
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
  RFC6749:  # OAuth 2.0 (scope-token ABNF)
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
  RFC9728:  # Protected Resource Metadata
  RFC9864:  # Fully-specified algorithms
  I-D.ietf-oauth-status-list:
informative:
  RFC2693:  # SDSI/SPKI
  RFC7009:  # Token Revocation
  RFC7942:  # Implementation Status section
  RFC8693:  # Token Exchange
  RFC8705:  # mTLS-bound tokens
  RFC9964:  # ML-DSA for JOSE/COSE
  I-D.ietf-oauth-identity-chaining:
  I-D.ietf-wimse-aims:
  I-D.ietf-wimse-identifier:
  I-D.reece-wimse-cross-org-delegation:
  I-D.jackson-wimse-evaluation:
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
  BoundedCounters:
    title: "Extending Eventually Consistent Cloud Databases for Enforcing Numeric Invariants"
    author:
      -
        ins: V. Balegas
      -
        ins: D. Serra
      -
        ins: S. Duarte
      -
        ins: C. Ferreira
      -
        ins: R. Rodrigues
      -
        ins: N. Preguica
      -
        ins: M. Shapiro
      -
        ins: M. Najafzadeh
    date: 2015
    seriesinfo: arXiv 1503.09052
--- abstract

AI agents increasingly delegate tasks to other agents. Each delegation should
convey only a subset of the delegating party's authority, that subset should be
bounded in scope, magnitude, and time, and any enforcement point should be able
to verify -- offline, with no call to an authorization server -- that a token
presented at hop N carries authority no greater than the token at hop N-1, back
to a trusted root, and that every hop acts under the same accountable
principal. OAuth 2.0 Token Exchange (RFC 8693) models two-party delegation and
records prior actors in a nested "act" claim, but that claim is informational
only and cannot enforce attenuation across a chain of depth two or more. This
document defines the Agent Delegation Chain: a profile of OAuth 2.0 JWT access
tokens (RFC 9068) that carries authority as Rich Authorization Requests (RFC
9396), binds the chain to one principal and names the agent acting at each hop,
links each delegation to its parent by a cryptographic byte-commitment, and
specifies a deterministic offline verification algorithm that enforces
monotonic attenuation, bounded depth, monotonic expiry, and principal
invariance. It reuses existing JOSE, proof-of-possession (RFC 9449), and
status-list machinery (the OAuth Status List draft) and introduces no new
cryptography.

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
chain linkage, the principal binding, and the subsumption-enforcing verification
algorithm. It is designed as the attenuation mechanism satisfying requirements
R1 and R5 of {{I-D.reece-wimse-cross-org-delegation}} and as a companion to
{{I-D.ietf-wimse-aims}}, whose placement of the acting agent in "client_id" and
the on-behalf-of party in "sub" this profile follows. It shares its approach
with, and is intended to converge with,
{{I-D.niyikiza-oauth-attenuating-agent-tokens}} and
{{I-D.coetzee-oauth-spt-txn-tokens}}. Its offline verification model is
complementary to the online Delegation Server and synchronous revocation model
in {{I-D.sweeney-wimse-credential-delegation}}. The two are halves of one
design, separated by a single axis: whether a server is in the path. The
in-token mechanisms this document requires -- constraints carried in the token,
parent-hash verification, and a child expiry bounded by its parent's -- are how
a verifier with no network reconstructs what such a server would otherwise know
first-hand; where a server is in every hop, they are redundant rather than
absent. The verifier-side evaluation rules of {{I-D.jackson-wimse-evaluation}}
describe the receiving half of the same problem; this document cites that work
informatively, and no requirement here depends on it.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Delegation Token (DT):
: An OAuth 2.0 JWT access token {{RFC9068}} profiled by this document, carrying
  the authority granted to one agent at one hop of a chain.

Delegation Chain:
: An ordered sequence of Delegation Tokens DT_0, DT_1, ... DT_n, where DT_0 is
  the root, and each DT_i (i > 0) is linked to DT_{i-1} by the mechanism in
  {{chain-linkage}}. A chain is one path. An agent that holds tokens issued
  along several paths holds several chains; see {{several-chains}}.

Principal:
: The party accountable for the chain: the party whose grant every token in
  the chain acts under. Carried in "sub", identical at every hop
  ({{token-format}}).

Acting Agent:
: The agent that holds, and acts under, one Delegation Token. Carried in
  "client_id", and different at each hop.

Authority:
: The set of permitted scope values carried by an "agent_delegation"
  authorization detail in the "authorization_details" claim {{RFC9396}},
  together with the constraints in {{constraints}}.

Attenuation:
: The construction of a child Delegation Token whose Authority is a subset of
  its parent's, per the subsumption rules in {{subsumption}}.

Enforcement Point:
: The component that verifies a Delegation Chain and permits or denies an action.

Verifier:
: Any component that runs the algorithm of {{verify}}, whether or not it is
  presented with an action. An Enforcement Point is a Verifier that is
  presented with an action and decides it.

# Token Format {#token-format}

A Delegation Token is a JWT {{RFC7519}} signed with JWS {{RFC7515}} using a
fully-specified algorithm {{RFC9864}}. Implementations MUST support Ed25519
{{RFC8032}} {{RFC8037}} and MAY support ES256 and, for post-quantum readiness,
ML-DSA {{RFC9964}}. The token uses the "application/at+jwt" header type of
{{RFC9068}} and includes the claims that profile requires: "iss", "exp", "aud",
"sub", "client_id", "iat", and "jti". The protected header SHOULD contain
"c14n": "JCS" as an informational label. Verifiers MUST NOT rely on this field.
The canonicalization of the protected header and payload JSON is the JSON
Canonicalization Scheme (JCS) {{RFC8785}}: producers MUST serialize both with
JCS before base64url encoding, and verifiers MUST reject either decoded byte
string unless it is exactly the JCS serialization of the parsed object.
Verifiers MUST also reject duplicate object member names, non-finite numbers,
and lone UTF-16 surrogates.

The {{RFC9068}} claims carry the following meaning in a Delegation Token:

sub:
: REQUIRED. The Principal. {{RFC9068}} Section 2.2 makes "sub" the resource
  owner where one exists; in a Delegation Chain the resource owner is the party
  whose grant the chain acts under, and the same value MUST appear in every
  DT_i of the chain. A verifier denies a chain in which any DT_i carries a
  "sub" that differs from DT_0's ({{verify}}, step 3). A chain whose DT_0
  carries no "sub", or a "sub" that is not a non-empty string, is malformed.

client_id:
: REQUIRED. The Acting Agent at this hop, as a string. It identifies which
  software exercised the authority; "sub" identifies whose grant it exercised.
  The value MAY be a workload identifier as defined by
  {{I-D.ietf-wimse-identifier}}; this document places no requirement on its
  format beyond being a string.

aud:
: REQUIRED. The audience, as {{RFC7519}} Section 4.1.3 defines it: a string,
  or an array of one or more strings. A token whose "aud" is absent, null, or
  an empty array is malformed. The Enforcement Point applies the audience check
  of {{RFC9068}} Section 4 to DT_n ({{verify}}, step 8); this document places
  no requirement on the audience of DT_i for i < n beyond presence and shape.

iss, exp, iat, jti:
: REQUIRED, as in {{RFC9068}}. "exp" is additionally subject to the monotonic
  expiry rule of {{subsumption}}. "jti" identifies the token instance for the
  purposes of {{chain-linkage}} and of per-lifetime constraints
  ({{constraints}}).

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

## Principal and Acting Agent {#principal}

A Delegation Chain answers two questions that a holder key alone does not: who
is accountable for what the chain does, and which agents took part. The first
is answered by "sub", which names the Principal and is invariant along the
chain: a child token is issued under the same grant as its parent, so it names
the same Principal, and a token that names a different one is not a member of
the chain. The second is answered by "client_id", which names the Acting Agent
at each hop and therefore changes at each hop. Together they make a chain
auditable as well as verifiable.

The "par_hash" commitment ({{chain-linkage}}) already prevents a child from
being re-parented onto a different token. It does not, by itself, prevent a
child from carrying a different "sub" than its parent, because the child is a
new token with its own payload. The invariance check in step 3 of {{verify}} is
what closes that gap, and it is a comparison of two strings, not new
machinery.

# Authority Representation {#authority}

For this profile, Authority is expressed by an authorization detail object
{{RFC9396}} whose "type" is "agent_delegation". A Delegation Token MUST carry
exactly one authorization detail object of that type. The object contains a
REQUIRED "scopes" member: an array of strings, where each string names one
permitted operation. An empty array conveys no permitted operation. Numeric and
enumerated bounds ("ceilings") that {{RFC9396}} does not standardize are carried
in the "constraints" member defined here. The object MUST NOT carry members
other than "type", "scopes", and "constraints"; a verifier that encounters
another member MUST reject the token as malformed, because it would otherwise
report success on a detail it had not fully read.

## Scope Syntax and Wildcards {#scopes}

Each member of "scopes" MUST match the following ABNF {{RFC5234}}:

~~~
lower          = %x61-7A
digit          = %x30-39
segment        = lower *(lower / digit / "_" / "-")
literal-scope  = segment "." segment *("." segment)
wildcard-scope = segment *("." segment) ".*"
opaque-scope   = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )
scope          = literal-scope / wildcard-scope / opaque-scope
~~~

The "opaque-scope" form is the "scope-token" of {{RFC6749}} Section 3.3 with
the asterisk (%x2A) removed. It exists so that a chain can carry a scope string
issued by an OAuth authorization server under that server's own naming, which
the two structured forms do not admit.

A verifier classifies each scope value by its bytes alone, trying the forms in
this order: a value that matches "literal-scope" is a literal scope; otherwise,
a value that matches "wildcard-scope" is a wildcard scope; otherwise, a value
that matches "opaque-scope" is an opaque scope. A value that matches none of
the three, for example one that contains an asterisk anywhere other than as a
complete final segment following a dot, is invalid. Thus `crm.read` is a
literal scope, `crm.*` is a wildcard scope, `User.Read` and `openid` are opaque
scopes, and the bare value `*`, the partial-segment form `crm.re*`, and the
non-terminal form `crm.*.read` are invalid. A producer MUST NOT emit an invalid
scope. A verifier that encounters one MUST reject the Delegation Token as
malformed before evaluating subsumption. There is no case folding: `User.Read`
and `user.read` are two different scopes.

The covering relation between a parent scope and a child scope is:

- A parent literal scope covers only an identical child scope.
- A parent wildcard scope covers any child scope, literal or wildcard, whose
  value begins with the parent value after removing only the final `*` and
  retaining the dot. Therefore `crm.*` covers "crm.read", "crm.x.y.z", and
  `crm.x.*`; it does not cover the bare name "crm" or the adjacent namespace
  "crmx.read". Wildcard coverage is segment-bounded and extends to any depth
  below the named prefix, and a wildcard covers a narrower wildcard under its
  prefix.
- A parent opaque scope covers only a byte-identical child scope. No wildcard
  scope covers an opaque scope, and an opaque scope covers no wildcard scope.

One consequence of classifying by bytes alone is stated here so that
deployments can plan for it: a scope string issued by an authorization server
that happens to match "literal-scope" is treated as a literal scope, and a
wildcard over its prefix covers it. A deployment that needs such a scope to
match exactly SHOULD NOT grant a wildcard over its prefix; doing so also gives
up wildcard coverage for every other scope under that prefix. This document
provides no registry by which a verifier could tell a dotted provider string
from a structured literal, and does not add one.

This covering relation belongs to the "agent_delegation" authorization detail
type; see {{detail-types}} for how the relation is bound to the type.

## Constraint Vocabulary {#constraints}

The "constraints" member is an array of objects. Each object contains a
REQUIRED "key" member, a string identifying the constrained dimension, and
exactly one typed constraint value, whose member name is the constraint type.
This document defines:

- "max" : a number. The value of the associated quantity in one authorized
  action MUST NOT exceed it (e.g. {"key": "max_rows", "max": 5000}). It is
  measured per action: nothing in this type aggregates across actions, tokens,
  siblings, or a subtree.
- "max_lifetime" : a number. The sum of the associated quantity over every
  action authorized under the token carrying it, identified by "jti", MUST NOT
  exceed it (e.g. {"key": "max_calls", "max_lifetime": 50}). It is measured per
  token lifetime. A re-issued token ({{chain-linkage}}) is a new "jti" and
  starts a new total; an issuer that needs a bound to span re-issuance issues
  the new token with the bound reduced by the amount already consumed.
- "max_subtree" : a number. The sum of the associated quantity over every
  action authorized under the token carrying it and under every token
  descended from it MUST NOT exceed it. It is measured per subtree. Enforcing
  it requires accounting across tokens; see {{fanout}} for what an offline
  verifier can and cannot do with it.
- "min" : a number. The value of the associated quantity in one authorized
  action MUST NOT be less than it (e.g. {"key": "tenure_years", "min": 2}).
  Where "max" carries a ceiling tightened downward, "min" carries a floor
  tightened upward.
- "one_of" : an array. The associated value MUST be a member.
- "not_one_of" : an array. The associated value MUST NOT be a member.
- "prefix" : a string. The associated value MUST have it as a prefix.
- "rank" : a string naming a position in an ordered enumeration. The constraint
  object additionally carries an "order" member: an array of two or more
  distinct strings listing the enumeration from least to most permissive, of
  which "rank" MUST be one (e.g. {"key": "egress", "rank": "internal", "order":
  ["none", "internal", "any"]}). The associated value MUST be a member of
  "order" whose position does not exceed that of "rank". The ordering travels
  with the constraint so that a verifier needs no registry entry per key; a
  constraint of type "rank" that lacks "order", or whose "rank" is not a member
  of "order", is malformed.

The three measurement scopes -- per action, per token lifetime, per subtree --
are distinct constraint types because they are enforced by different machinery:
a per-action bound is decided from the request alone, a per-lifetime bound
needs a running total held by the component that authorizes actions under that
token, and a per-subtree bound needs a total that spans tokens. A producer MUST
NOT emit a cumulative bound under the "max" type.

Within one authorization detail object, the pair (key, type) identifies a
constraint. A detail MUST NOT carry two constraints with the same key and the
same type, and a verifier MUST reject a token that does as malformed, rather
than choosing one of them. Two constraints with the same key and different
types (for example a "min" and a "max" on one quantity, forming a range) are
permitted and are evaluated independently.

The registry in {{iana}} allows new constraint types. A verifier that encounters
an unknown constraint type MUST treat the action as denied (fail-closed), never
as unconstrained.

## Subsumption Rules {#subsumption}

An Authority C is subsumed by an Authority P (written C <= P) if and only if all
of the following hold:

1. Every scope in C's "agent_delegation" detail is covered by at least one
   scope in P's "agent_delegation" detail according to {{scopes}}, and
2. for every constraint (key, type) present in P, a constraint with the same
   key and the same type is present in C whose admissible set is a subset of
   P's: for "max", "max_lifetime", and "max_subtree", C.value <= P.value; for
   "min", C.value >= P.value; for "one_of", C's array is a subset of P's; for
   "not_one_of", C's array is a superset of P's; for "prefix", C's string
   begins with P's; for "rank", C's "order" is identical to P's, element for
   element, and the position of C's "rank" in it does not exceed the position
   of P's, and
3. a constraint (key, type) present in P MUST NOT be absent in C (absence means
   unbounded, which is not a subset), and
4. C.exp <= P.exp (monotonic expiry), and
5. C.del_max_depth <= P.del_max_depth.

No inference is made across constraint types: a "max_lifetime" in C does not
satisfy a "max" in P, and a "max" in C does not satisfy a "max_lifetime" in P,
whatever their values. A verifier that does not implement the type of a
constraint present in P cannot evaluate rule 2 for it; it MUST treat the chain
as not subsumed unless C carries a constraint with the same key and type whose
JCS serialization {{RFC8785}} is byte-identical to P's, and even then the action
is denied at step 8 of {{verify}} under the fail-closed rule of {{constraints}}.

Attenuation is the construction of C as the greatest lower bound (meet) of P and
a request R under these rules. Because the meet can only narrow, C <= P holds by
construction for every R.

## Authorization Detail Types and the Verifier {#detail-types}

{{RFC9396}} does not maintain a registry of authorization detail type values;
its Section 2.1 recommends that an API designer use a collision-resistant
namespace under the designer's control, such as a URI. The type value
"agent_delegation" is the one this document and its test vectors use; whether
a later revision moves it to a URI-form value under such a namespace is an open
question, and the wire value is unchanged by this revision.

The covering relation a verifier applies at step 4 of {{verify}} is specified
per authorization detail type. For "agent_delegation" it is the relation in
{{scopes}} together with the constraint rules of {{subsumption}}. Another
authorization detail type, if defined, specifies its own relation, and that
relation is what a verifier applies to details of that type. The type selects
the relation.

A verifier MUST evaluate every authorization detail object in every DT_i, or
reject the token. A detail whose type the verifier does not implement is one it
cannot evaluate, and the token MUST be rejected as malformed; a verifier that
skips a detail it does not understand has reported success on a token it did
not read. For a chain carrying details of more than one type, subsumption is
evaluated per type: for each type present in DT_i, DT_{i-1} MUST carry a detail
of that type and that type's covering relation MUST hold between them. A
resource server SHOULD declare the types it implements in the
"authorization_details_types_supported" member of its protected resource
metadata ({{RFC9728}}, Section 2), so that an issuer can learn which chains it will accept.
{{I-D.jackson-wimse-evaluation}} states the same process-every-entry-or-refuse
rule from the verifier's side; the requirement here stands on its own.

Which chains a verifier accepts across deployments is a trust decision the
verifier already makes by the root keys it holds ({{verify}}, step 1); two
verifiers that both implement "agent_delegation" apply the same covering
relation to the same chain.

## Open Issue: Scope Vocabulary {#vocabulary}

Subsumption is syntactic. Two deployments that both implement
"agent_delegation", and attach different meanings to the same scope verbs, both
verify the same chain clean and read it differently, because nothing in the
token says what "crm.read" permits. A profile or registry of common operation
verbs would close that gap. This document states the limit and supplies
neither.

A companion document that does supply one is expected to take the result of
the native verification in {{verify}} as an input rather than re-implement it;
to map a scope family to an action definition explicitly; and, where a mapping
is ambiguous, to refuse rather than resolve. A companion document is cited from
this one when it is an Internet-Draft, so that every reader can cite it by a
stable name.

# Chain Linkage {#chain-linkage}

Each child token commits to its parent by "par_hash" ({{token-format}}). This
binds the child to the parent's exact serialized bytes, so a child cannot be
re-parented onto a different (e.g. broader) token: doing so changes the parent's
Signing Input and thus its SHA-256 digest, which no longer matches the child's
"par_hash". The digest is over the already-serialized JWS Signing Input; the
protected header and payload that form that input are JCS {{RFC8785}} as required
by {{token-format}}.

The commitment is to a parent token instance, not to a parent identity. A
child's chain carries the parent instance the child commits to. When a parent
is re-issued -- for example refreshed before expiry with a new "jti", "iat",
and "exp" -- the re-issued token is a different token, outside the chain of any
child issued under the previous instance. Re-issuing a parent therefore does
not invalidate its existing children: they continue to verify with the instance
they were issued under until that instance expires or a token in their chain is
revoked ({{revocation}}), and a child presented together with a re-issued
parent instead of the instance it commits to is denied at step 2 of
{{verify}}. The operational consequence for the refresh rate is in
{{latency}}. A parent identity that survives re-issuance is not defined by this
document.

# Offline Verification Algorithm {#verify}

An Enforcement Point presented with a Delegation Chain DT_0 ... DT_n and an
attempted action A, and holding the trusted root public key(s), MUST perform the
following, denying on the first failure:

1. Verify the JWS signature of every DT_i using a fully-specified algorithm
   {{RFC9864}}. The verifier MUST hold a local list of accepted algorithms, and
   MUST deny the chain if the "alg" of any DT_i is not on that list, even where
   the signature verifies. The verifier MUST take the algorithm from its own
   configuration for the key, and MUST deny if the "alg" header names a
   different one. DT_0 MUST verify under a trusted root key.
2. For each i > 0, compute SHA-256 of DT_{i-1}'s JWS Signing Input and compare,
   in constant time, to DT_i's "par_hash". Any mismatch: deny.
3. Check chain shape. Depth: DT_0.del_depth == 0; DT_i.del_depth == i; n <
   DT_0.del_max_depth. Principal: DT_0.sub is a non-empty string, and for every
   i, DT_i.sub is identical to DT_0.sub. Otherwise deny.
4. For each i > 0, verify DT_i.Authority <= DT_{i-1}.Authority per {{subsumption}},
   having first confirmed per {{detail-types}} that every authorization detail
   in DT_i is of a type the verifier implements. Any violation: deny.
5. Check time: for every i, nbf (if present) <= now <= exp, and exp is monotonic
   non-increasing along the chain. Otherwise deny.
6. Verify holder binding: the presenter proves possession of the key in DT_n.cnf
   via a valid DPoP proof {{RFC9449}} bound to this request. Otherwise deny.
7. Check revocation: consult the Token Status List {{I-D.ietf-oauth-status-list}}
   reference in each DT_i (if present) against a cached list. A cached status
   answer is trusted for its time to live, so the window in which a revoked
   token is still honored is that time to live and no longer. A status
   reference that is present but whose list cannot be fetched, or whose cached
   answer has outlived its time to live and cannot be refreshed, is UNKNOWN,
   and the verifier MUST deny: unknown is not not-revoked. If any DT_i is
   revoked, deny (and, by local policy, treat the whole subtree as revoked). A
   token issued with no status reference is a choice made at issuance
   ({{revocation}}) and is not denied on that account.
8. Authorize A against DT_n: confirm that the Enforcement Point is identified by
   DT_n's "aud" as {{RFC9068}} Section 4 requires; then check A against
   DT_n.Authority, its scope and every per-action constraint ("max", "min",
   "one_of", "not_one_of", "prefix", "rank"), and, where the Enforcement Point
   holds the running total for DT_n, every "max_lifetime" constraint. Permit
   only if A is within it.

The algorithm is deterministic, side-effect free, and requires no network call
except the (cacheable, offline-checkable) status list of step 7. The order of
steps 1 to 5 is the order in which a chain presented without an action can be
checked ({{without-request}}); steps 6 and 8 need the request, and step 7 needs
the status list.

## What Verification Establishes {#without-request}

A Verifier is not always an Enforcement Point. An auditor re-checking a
recorded chain, an issuer validating a parent before minting a child, or a
component that holds a chain but no request, can run steps 1 to 5 and, if a
status list is available, step 7. {{table-conclusions}} states what such a
Verifier may and may not conclude.

| Property | Chain alone (steps 1-5, 7) | With the request (steps 6, 8) |
|---|---|---|
| Every token is well-formed, JCS-canonical, and signed under an accepted algorithm | yes | yes |
| DT_0 is signed under a trusted root key | yes | yes |
| Each child commits to the parent instance presented with it | yes | yes |
| Depth is bounded and the Principal is unchanged along the chain | yes | yes |
| Each hop's Authority is a subset of its parent's | yes | yes |
| Every token is within its validity window at the instant checked | yes | yes |
| No token in the chain is revoked, within the status list's time to live | yes, if the list is reachable | yes, if the list is reachable |
| The presenter holds the key DT_n is bound to | no | yes |
| A specific action is permitted | no | yes |
| A per-lifetime total is within bound | no | only where the total is held |
| A per-subtree total is within bound | no | no ({{fanout}}) |
{: #table-conclusions title="What a Verifier may conclude, by the steps it performed"}

A Verifier that has not performed step 6 has established that the chain is
valid, not that the party presenting it is its holder, and MUST NOT report the
chain as authorizing anything. A Verifier that has not performed step 8 has
established the leaf Authority as a set and MUST NOT report any action as
permitted. Such a Verifier SHOULD report its result as the chain's validity
together with the steps it did not perform.

## Verification Outcomes {#outcomes}

Independent implementations are compared by their outcomes on shared test
vectors ({{vectors}}), and the comparison is only as good as the agreement on
how a denial is named. A verifier SHOULD report a denial under the name that
{{table-outcomes}} gives for the check that failed, which is the vocabulary the
test vectors declare; since the algorithm denies on the first failure, one
denial carries one name. A verifier MAY add detail of its own beside the name. The names are
not carried in any token and have no effect on the wire.

| Name | Step | Meaning |
|---|---|---|
| malformed | parse | a token is not three base64url parts, a claim this document requires is absent or of the wrong shape, a scope is invalid, a constraint is malformed or repeated, a detail carries an unknown member, or a detail type is not implemented |
| non_canonical | parse | a decoded header or payload is not the JCS serialization of what it parses to |
| duplicate_member | parse | a JSON object repeats a member name |
| non_finite | parse | a number is not finite or cannot be represented in JCS |
| signature_invalid | 1 | a signature does not verify, the algorithm is not on the verifier's list, the algorithm differs from the one configured for the key, or DT_0 is not under a trusted root key |
| par_hash_mismatch | 2 | a child's commitment does not match the parent presented with it |
| depth_invalid | 3 | a del_depth is out of sequence or the chain exceeds del_max_depth |
| principal_altered | 3 | a token's "sub" differs from DT_0's |
| not_narrower | 4 | a child's Authority is not subsumed by its parent's |
| expired | 5 | a token is outside its validity window or its expiry exceeds its parent's |
| holder_binding_failed | 6 | the proof of possession is absent or invalid for this request |
| revoked | 7 | a token in the chain is revoked |
| status_unknown | 7 | a status reference is present and its current status cannot be established |
| audience_mismatch | 8 | DT_n's "aud" does not identify the Enforcement Point |
| scope_not_granted | 8 | the action's scope is not covered by DT_n's scopes |
| ceiling_exceeded | 8 | the action violates a constraint of DT_n |
| unknown_constraint | 8 | DT_n carries a constraint of a type the verifier does not implement |
{: #table-outcomes title="Verification outcome names"}

## Several Chains Reaching One Agent {#several-chains}

This document defines the verification of one chain. An agent may hold
Delegation Tokens issued along more than one path from one or more roots, and
so hold more than one chain. For each request the presenter presents one chain,
the Enforcement Point verifies that chain alone, and the action is permitted
only if that chain permits it. An Enforcement Point MUST NOT combine the
Authority of tokens from different chains, and a chain that fails verification
has no effect on the evaluation of another chain the same agent presents. A
presenter holding several valid chains chooses which to present; one valid
chain that permits the action suffices.

## Open Issue: Trust-Anchor Provenance {#provenance}

Step 1 assumes the verifier already holds the trusted root key or keys. This
document says nothing about how a verifier comes to hold that key, how the key
is bound to the party it is trusted as, or under which algorithm that binding
was made; the algorithm rule of step 1 reaches every token in the chain and
stops at the root key. A chain can be post-quantum at every hop and still rest
on a root key whose provenance the verifier cannot check. That is a property of
every delegation chain design, not of this one, and the author's view is that
it belongs to the working group rather than to this document. It is recorded
here as open and is not solved here.

# Holder Binding {#binding}

Every Delegation Token is sender-constrained by a "cnf" claim {{RFC7800}}
carrying the JWK thumbprint of the holder's key, proven per request with DPoP
{{RFC9449}}. mTLS-bound tokens {{RFC8705}} MAY be used where the transport is
controlled end-to-end. A captured token is therefore unusable without its bound
private key, which mitigates replay of intermediate tokens. The "cnf" claim is
present in every token of a chain, and a Verifier that sees no request
({{without-request}}) checks its presence and shape but cannot perform step 6.

# Revocation {#revocation}

Delegation Tokens are RECOMMENDED to be short-lived (seconds to minutes for leaf
and execution tokens), so that expiry is the common revocation path. For earlier
revocation of longer-lived delegations, each token MAY carry a Token Status List
{{I-D.ietf-oauth-status-list}} reference; revoking a token's status entry, and
by local policy the entries of its descendants, revokes a delegation or a whole
sub-chain while preserving offline verification (the status list is itself
cacheable and offline-checkable). An online revocation endpoint {{RFC7009}} MAY
additionally be offered.

Whether a token carries a status reference is decided at issuance. A token
issued without one can be revoked only by expiry. A token issued with one is
subject to step 7 of {{verify}} as stated there: a cached answer is trusted for
its time to live and no longer, and an answer that cannot be obtained or
refreshed is unknown, which denies. A deployment chooses between the two at
issuance with that consequence in view.

Short lifetimes mean re-issuance. A parent that is re-issued is a new token
instance ({{chain-linkage}}); its existing children are not invalidated by the
re-issuance, and a deployment that wants them invalidated revokes the previous
instance. The rate at which this happens is an operational property that
{{latency}} states.

Deployments that require synchronous cascading revocation MAY issue and
exercise Delegation Tokens through an online Delegation Server as specified by
{{I-D.sweeney-wimse-credential-delegation}}. The server can evaluate current
delegation-tree state and refuse a revoked root or descendant immediately. This
online bridge complements, and does not replace, the offline verification
algorithm in {{verify}}: an Enforcement Point that receives a chain MUST still
verify its signatures, linkage, attenuation, depth, principal, and expiry.

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
intended parent verifies. The same check is what denies a child presented with
a re-issued parent rather than the instance it was issued under
({{chain-linkage}}).

## Confused deputy and over-broad delegation

Because each hop's authority is the meet of parent and request ({{subsumption}}),
a child cannot be induced (e.g. by prompt injection) to exercise authority the
parent lacked. The principal invariance check (step 3 of {{verify}}) adds that a
child cannot be induced to act under a different grant than its parent: a
token that names another Principal is not a member of the chain.

## Unbounded depth, fan-out, and aggregate budgets {#fanout}

"del_max_depth" (checked in step 3) bounds chain length; deployments SHOULD set
it low (e.g. 5). Fan-out (a parent delegating to many children) is not limited by
the token format and MUST be bounded by the issuing infrastructure if required.

Quantity constraints compose across siblings, and subsumption is checked per
edge. A "max" constraint bounds one authorized action and nothing else
({{constraints}}). A parent holding {"key": "max_spend", "max": 100} can mint
any number of children each carrying max_spend 100; every parent-child edge
satisfies C <= P, and a subtree of N children can spend N x 100. The same holds
at a single enforcement point and across several: against a root ceiling of
100, two valid children can each authorize 60 at two different gateways; both
chains verify, each gateway sees a request within bound, and the combined
spend is 120. Individually permitted delegations compose into an outcome
nobody permitted. The "max_subtree" type names that total, and a chain-only
verifier checks only that a child's "max_subtree" is no wider than its
parent's; verification is side-effect free by design, so a signed ceiling
names a limit while nothing in verifying it reserves against that limit or
sees another gateway's balance. A signed ceiling alone provides none of the
protection an aggregate budget needs.

An aggregate budget over a consequential resource therefore needs machinery
outside the token, and that machinery has two separable parts. Allocation --
deciding how much of a parent's budget each child may consume -- requires
coordination: an allocator that splits a budget at delegation time only keeps
the total under bound if it is a single writer, since two issuers allocating
offline from the same budget can each allocate the same units. Spending
afterwards does not require coordination once allocations are disjoint: each
enforcement point debits its own durable balance for the allocation it holds
and contacts no shared service per action. Two deployment shapes follow, and a
deployment that enforces aggregate budgets uses one of them:

- Shared accounting: one ledger, consulted by every enforcement point, that
  checks and debits atomically at authorization time. A ledger that is read at
  authorization and debited afterwards, or debited by more than one writer
  without coordination, does not close the hole; the check and the debit are
  one operation or the budget is not enforced.
- Coordinated allocation with local enforcement: a single-writer allocator
  reserves disjoint allocations for the children (for example 60 units to the
  child acting at gateway A and 40 to the child acting at gateway B, leaving
  none at the parent, since allocating to a child reduces what remains
  available to the parent), and each enforcement point enforces its own
  allocation locally against a durable balance. This path has to protect
  against three hazards that a signed ceiling does not: duplicate allocation of
  the same units to two children; local rollback, where an enforcement point
  loses or reverts a debit it has already honored; and premature reuse of
  allocated units before the action that consumed them is settled. The
  bounded-counter construction of {{BoundedCounters}} is one treatment of the
  local-enforcement half of this shape.

Either way, the division is the one this document is built on: the offline
chain bounds each action and produces the audit trail; the online half holds
the aggregates.

## Offline verification vs. revocation latency {#latency}

Offline verification means an enforcement point may honor a token that has been
revoked but whose status-list update it has not yet fetched. Deployments trade
this window against TTL: shorter TTLs bound the exposure, and step 7 of
{{verify}} fixes the window at the cached answer's time to live. This is the
standard status-list trade-off and MUST be documented for each deployment.

The lifetimes {{revocation}} recommends have a second cost, which is on the
issuing side rather than the verifying side. A token that lives for seconds to
minutes and is still needed must be re-issued, so a platform with many live
agent instances sustains a refresh rate proportional to the number of live
instances, continuously, not only at startup. That rate is a property of the
deployment and a deployment MUST size its authorization server for it, and for
the resynchronisation case in which many instances refresh at once after an
outage of the issuer or of the network between them. Offline verification is
preserved under these lifetimes; offline operation is not, because an agent
whose issuer is unreachable stops receiving tokens when its current ones
expire.

The refresh rate counts every token in a chain, not only the roots, and grows
with fan-out. Rule 4 of {{subsumption}} and step 5 of {{verify}} cap a child's
"exp" at its parent's when the child is issued, so at the recommended
lifetimes every child that keeps working is re-issued at least once per parent
lifetime, whichever instance of the parent it commits to ({{chain-linkage}}).
A deployment that revokes the previous parent instance at refresh adds a burst
on top of that rate: every child of that instance at once. Both the sustained
rate and the burst belong in the sizing above, and the fan-out bound of
{{fanout}} is what bounds them.

## Why not macaroons; algorithm agility

Macaroons {{Macaroons}} verify with the root secret, precluding public offline
verification at an untrusted edge; this document uses public-key signatures.
Algorithms are fully specified {{RFC9864}} and agile via the JOSE "alg" registry,
with a migration path to ML-DSA {{RFC9964}}. The algorithm list of step 1 in
{{verify}} is the agility mechanism on the verifying side. A deployment that
retires an algorithm, for example a quantum-vulnerable one after a transition
date, removes it from the verifier's list, and chains that still use it are
then denied whatever their remaining lifetime. Because every hop's "alg" sits
in a protected header that the child's "par_hash" covers, a verifier holding
the full chain sees every hop's algorithm, and a parent whose algorithm was
swapped after the fact no longer matches its child's commitment.

## Root issuance is the policy decision point {#root-issuance}

DT_0's Authority is asserted by whoever holds the root key. Every guarantee in
this document begins downstream of that minting: each child is a deterministic
attenuation of DT_0, and verification can establish that no hop exceeded the
root, never that the root was right. Approval policy therefore belongs at root
issuance. A deployment that requires a human decision before an agent may act
with consequential authority places that decision where DT_0 is minted, not at
a later hop, because no later hop can widen what DT_0 granted and no
verification step can tighten it. The Principal named in DT_0's "sub" is the
party that decision is taken on behalf of, and the "client_id" of each hop
records which agent acted under it.

# IANA Considerations {#iana}

This document requests registration, in the JSON Web Token Claims registry, of:
"del_depth", "del_max_depth", and "par_hash" (with the semantics in
{{token-format}}). The claims "sub", "client_id", "aud", and "cnf" are already
registered and are used with their registered meanings as profiled in
{{token-format}}.

It requests a new "Agent Delegation Constraint Types" registry with the
following initial entries, each recorded with its measurement scope:
"max" (per action), "max_lifetime" (per token lifetime), "max_subtree" (per
subtree), "min" (per action), "one_of" (per action), "not_one_of" (per action),
"prefix" (per action), and "rank" (per action). The registration policy is
Specification Required; a registration states the type's value shape, its
measurement scope, and its subsumption rule in the form of {{subsumption}}.
Unknown types fail closed per {{constraints}}.

This document does not request registration of an "authorization_details" type
value. {{RFC9396}} maintains no registry of type values, and recommends a
collision-resistant namespace under the designer's control; see
{{detail-types}}.

# Implementation Status

This section records the status of known implementations of this document at
the time of its posting, as described in {{RFC7942}}. The description of
implementations here is intended to assist the IETF in its decision processes
in progressing drafts to RFCs. It is not an endorsement of any implementation,
and the listing is not a claim that any implementation conforms to this
revision in full. Please note that this section is to be removed before this
document is published as an RFC.

Two reference implementations are maintained by the author under the Apache
License 2.0: "attenu-guard", in Python, which mints Delegation Tokens and runs
the verification algorithm of {{verify}}, and "attenu-guard-ts", in TypeScript,
which runs the verification algorithm and mints nothing. At the time of
posting, both implement steps 1 to 5 of the algorithm as the previous revision
of this document stated them, under a single-signer trust model, and neither
implements step 6 (holder binding) or step 7 (status list), which both document
as not performed. Of the changes this revision makes
({{changes}}), the principal invariance check of step 3 is implemented in the
Python library on a development branch; the algorithm list of step 1, the
opaque scope form, the two new constraint types, the "order" member of "rank",
the per-type detail rule, and the audience check are not implemented in either
library at the time of posting. The Python library ships the test vectors of
{{vectors}} and regenerates them on every test run; the TypeScript library
runs them in its test suite.

Two implementations independent of the author's code have run the twenty test
vectors of the previous revision and published their results, as reported by
their authors: the conformance harness of the Cred delegation protocol, which
reported 17 of 20 with three declared gaps at a pinned commit of its SDK, and a
standalone Node.js verifier that imports no code from either reference
implementation, which reported 20 of 20 with verdicts and declared reasons both
matching. Neither
result is reproduced here, and neither author has reported a run against the
vectors of this revision.

--- back

# Acknowledgments

This work builds directly on, and seeks convergence with,
{{I-D.niyikiza-oauth-attenuating-agent-tokens}},
{{I-D.coetzee-oauth-spt-txn-tokens}},
{{I-D.sweeney-wimse-credential-delegation}}, {{I-D.ietf-wimse-aims}}, and the
requirements of {{I-D.reece-wimse-cross-org-delegation}}. The capability-token
lineage of {{Macaroons}}, {{Biscuit}}, and {{RFC2693}} is gratefully
acknowledged. The "min" constraint type was added after Amr Hassan, author of
{{I-D.hamr-oauth-agent-delegation}}, observed that -00 had no comparator for a
floor tightened upward; the duration-typed "tenureMin" axis of that document is
the motivating example.

The following contributions were made on the WIMSE mailing list in review of
the -01 and shaped this revision. Naming a contributor records where their
contribution landed; it does not imply that they endorse this document.

Wes Jackson: the binding of the chain to an accountable Principal in "sub",
distinct from the holder key, and the naming of the Acting Agent at each hop
in "client_id" ({{token-format}}, {{principal}}); the observation that
quantity constraints compose across siblings while subsumption is checked per
edge, that "max" is therefore per token, and that per-action, per-lifetime,
and per-subtree limits are enforced by different machinery and belong in
distinct registered types ({{constraints}}, {{fanout}}); the atomic
check-and-debit requirement on shared accounting and the single-writer
constraint on delegation-time allocation ({{fanout}}); root issuance as the
policy decision point ({{root-issuance}}); the scope-vocabulary limit
({{vocabulary}}); and the questions that led to the process-every-detail rule
and the per-type interoperability statement ({{detail-types}}).

Iman Schrock: the two-gateway example in which two verified chains overspend a
root ceiling, the distinction between allocation, which needs coordination,
and spending within disjoint allocations, which does not, the two deployment
shapes and the three hazards of the allocation path ({{fanout}}), the
compatibility point that led the scope grammar to keep structured literals as
their own form, and the request to state the residual ambiguity of that
grammar beside it ({{scopes}}).

Girish Konda: the sustained refresh rate implied by the recommended lifetimes
and the sizing it requires of the authorization server, and the requirement
that a verifier tell a fresh status answer from a stale one ({{latency}},
{{verify}} step 7).

Jijie Wei: the question of what "par_hash" commits to when a parent is
re-issued, answered in {{chain-linkage}}, and the counting of child
re-issuance in the refresh rate ({{latency}}).

Kieran Sweeney: the proposal to admit scope strings issued by OAuth providers,
which became the opaque scope form ({{scopes}}); the observation that a
chain-only verifier cannot see a running total, stated in {{constraints}} and
{{without-request}}; and the observation that a rank's ordering has to travel
on the wire or in a registry, answered by the "order" member ({{constraints}}).

Venkata Karunakar Uppalapati: the rule that a verifier rejects a chain carrying
an algorithm outside its local policy even where the signature verifies, now
step 1 of {{verify}} and the agility text in {{security}}, and the
trust-anchor provenance gap recorded in {{provenance}}.

# Reference Implementation and Test Vectors {#vectors}

A permissively licensed reference implementation (the "attenu-guard" library)
and a set of offline-verification test vectors (chains that MUST verify and
adversarial chains that MUST be rejected, each with the outcome name of
{{outcomes}} it is expected to produce) accompany this draft. They are intended
for interoperability testing across independent implementations.

The twenty vector files published with the -01 are unchanged by this revision
and remain available under their -01 names: independent implementations have
vendored them, and a byte-stable set is worth more than a corrected one. They
do not conform to this revision: their tokens carry no "cnf" and no
"client_id", and their "aud" is null. A second, separately named vector set
accompanies this revision. It carries "cnf", "client_id", and a well-formed
"aud" on every token, and adds vectors for: a chain in which a child's "sub"
differs from the root's (principal_altered); a child presented with a
re-issued parent rather than the instance it commits to (par_hash_mismatch),
contributed by Jijie Wei; a wildcard scope over an opaque child scope and an
opaque scope over a wildcard child, both not_narrower, and an opaque scope
covering a byte-identical child, which verifies, contributed by Kieran Sweeney;
a detail carrying two constraints with the same key and type (malformed); a
"rank" whose "order" differs from its parent's (not_narrower); a "max_lifetime"
under a parent "max" of the same key (not_narrower, by the no-cross-type rule);
a token whose "alg" is not on the verifier's list (signature_invalid); and a
token carrying an authorization detail of a type the verifier does not
implement (malformed). The -01 set's coverage of scope and ceiling widening,
parent splicing, depth and expiry violations, wildcard errors, RFC 8785 number
and string forms, non-finite values, duplicate member names, and the
informational "c14n" label is re-minted in the new set under this revision's
claim layout.

# Changes Since -01 {#changes}

- "sub" is defined as the Principal, identical at every hop; "client_id" is
  added to the required claims as the Acting Agent at each hop; and step 3 of
  the verification algorithm denies a chain in which any token's "sub" differs
  from the root's. A new subsection explains the split.
- "aud" is required to be a string or non-empty array of strings; null is
  malformed. The audience check of RFC 9068 Section 4 is applied to the leaf
  token in step 8.
- Step 1 requires a verifier-held list of accepted algorithms, denies any
  token whose "alg" is not on it even where the signature verifies, and takes
  the algorithm from the verifier's configuration for the key rather than from
  the header. The algorithm agility text says how an algorithm is retired.
- The scope grammar gains a third form, "opaque-scope", the RFC 6749 scope
  token without the asterisk, so that provider-issued scope strings can be
  carried; classification is by bytes alone in a stated order; an opaque scope
  covers only a byte-identical child and no wildcard covers it; the residual
  ambiguity for dotted provider strings is stated beside the grammar.
- Two constraint types are added, "max_lifetime" and "max_subtree", so that
  per-action, per-lifetime, and per-subtree bounds are distinct registered
  types; "max" is defined as per action only; no inference is made across
  types; a chain-only verifier checks only that a child's cumulative bounds
  are no wider than its parent's.
- The "rank" type carries its ordering on the wire in an "order" member, and
  a child's ordering must be identical to its parent's.
- A detail may not carry two constraints with the same key and type; a
  verifier rejects a token that does.
- The covering relation is bound to the authorization detail type; a verifier
  must evaluate every detail or reject the token, and an unimplemented type is
  a rejection; a resource server is pointed to RFC 9728 to declare the types it
  supports.
- The IANA request for an "authorization_details" type value is withdrawn,
  since RFC 9396 keeps no such registry; whether the type value becomes a URI
  is recorded as open.
- The scope-vocabulary limit is recorded as an open issue in its own
  subsection, with the interface a companion document is expected to meet and
  the rule under which such a document is cited.
- The chain linkage section states that "par_hash" commits to a parent token
  instance, and what that means for re-issued parents and their children.
- Step 7 states that a cached status answer is trusted for its time to live,
  that an unobtainable or unrefreshable status is unknown and denies, and that
  a token issued without a status reference is a choice made at issuance.
- A table states what a verifier that sees no request may and may not
  conclude, and a table names the verification outcomes the test vectors use.
- Several chains reaching one agent are addressed: each chain is verified
  alone and never combined with another.
- Trust-anchor provenance is recorded as an open issue.
- The fan-out security consideration gains the sibling and two-gateway
  examples, the allocation/spending distinction, the two deployment shapes for
  aggregate budgets, and the three hazards of the allocation path.
- The revocation-latency security consideration gains the sustained refresh
  rate, the resynchronisation case, the sizing requirement, the counting of
  child re-issuance, and the revoke-at-refresh burst.
- Root issuance is stated as the policy decision point in a new security
  consideration.
- draft-klrc-aiagent-auth, now replaced, is re-pointed to draft-ietf-wimse-aims
  in the introduction and the acknowledgments; draft-jackson-wimse-evaluation,
  draft-ietf-wimse-identifier, RFC 6749, RFC 7942, RFC 9728, and the
  bounded-counter paper are added as references.
- An Implementation Status section is added.
- The test-vector appendix records that the -01 set stays byte-stable and does
  not conform to this revision, and describes the second set that does.
