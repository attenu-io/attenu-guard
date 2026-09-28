# Compared with

*Dated 2026-09-28. Every quotation below was taken from the cited page on that date; the pages are numbered
[S1] to [S24] and listed at the end. Every statement about attenu-guard describes release v0.18.0. Where a
number comes from a run, the run's output is in this repository and named.*

This is the long form of the README's "Compared with" section: what each alternative does at a handoff
between agents, in its own words, and where attenu-guard differs. Concessions come first in each entry.
What attenu-guard does is one thing: at a handoff the child gets the permissions you declare for its task,
never more than the parent holds, and every `check()`, allowed or denied, lands on a hash-chained log you
verify offline. The limits of that log are stated in [THREAT-MODEL.md](THREAT-MODEL.md): it is an
authorization and lifecycle record, not an execution record, and a call that bypasses the hook leaves it
silent.

## 0. The baseline runs behind the framework rows

One question, asked of each framework with nothing of ours in the process: when a parent hands work to a
sub-agent, can the child run a tool the parent never held? The scripts under
[`../examples/baselines/`](../examples/baselines/) run offline with a scripted model, no API key, and no
`attenu_guard` import. Pinned outputs from 2026-09-02 sit beside each script; the 2026-09-28 re-run against
the releases current on that date is in `output-2026-09-28.txt` in the same directories.

| Framework, version on 2026-09-28 | Child declared a tool the parent lacks. Did its body run? | Changed since 2026-09-02? |
|---|---|---|
| Deep Agents 0.7.19 / LangChain 1.4.2 | Yes. `web_search` ran. With the twelve-line `BoundedByParent` middleware, `write_brief` alone ran | No |
| CrewAI 1.15.22 | Yes. The coworker ran `crm_export`; a tool-less coworker did not inherit `crm_query` | No |
| OpenAI Agents SDK 0.22.3 | Yes. The handoff target and `as_tool()` both ran `crm_export`; an emptied `input_filter` did not stop it | No |
| Google ADK 2.10.0 | Yes. The transfer target and `AgentTool` both ran `crm_export` | Yes. A peer transfer with `disallow_transfer_to_peers=True` now fails with `WorkflowDataError: Cannot transfer from 'a_agent' to peer agent 'b_agent': disallow_transfer_to_peers is set.` |

## 1. Framework-native sub-agent permissions

### Deep Agents / LangGraph

- **Does well.** Path-level allow and deny rules for its built-in filesystem tools, and a per-spec tool list
  for each sub-agent.
- **In its own words** [S1]: a sub-agent's `tools` field "Inherits from main agent by default. When specified,
  overrides the inherited tools entirely." Its permissions page [S2] states that "Custom tools and MCP tools
  that access the filesystem are not covered." The `graph.py` docstring in the released package says a
  sub-agent's permissions field "replaces the parent's rules entirely".
- **Run.** Deep Agents 0.7.19: the sub-agent's `web_search` body ran under a supervisor that never held it.
- **Contrast.** A Deep Agents sub-agent spec replaces the parent's tools and rules. attenu-guard gives the
  child what it declares for the task, never more than the parent holds. The twelve-line `BoundedByParent`
  middleware in the same baseline directory shows the intersection done natively.

### CrewAI

- **Does well.** A pre-call veto exists [S3]: "raise HookAborted(reason, source) to block the call".
- **In its own words** [S4]: "When `allow_delegation=True`, agents automatically gain access to powerful
  collaboration tools." The page states no rule relating a coworker's tools to the delegator's.
- **Recorded.** Ordinary exceptions raised inside a tool hook let the tool continue; the documented veto
  stopped it. That is a hook trap, not a missing veto.
- **Run.** CrewAI 1.15.22: the coworker ran `crm_export`, absent from the delegator's set.
- **Contrast.** attenu-guard bounds the coworker by the delegator, through CrewAI's own hooks.

### OpenAI Agents SDK

- **Does well.** Per-tool checks wrap `FunctionTool` instances and "let you validate or block calls to those
  tools before and after execution" [S5]. A handoff can be switched off with `is_enabled`.
- **In its own words** [S6]: "When a handoff occurs, it's as though the new agent takes over the
  conversation". `input_filter` rewrites `HandoffInputData`, which is conversation history; the run shows it
  carries no tools field.
- **Run.** OpenAI Agents SDK 0.22.3: the handoff target ran `crm_export`, a tool the source agent lacked,
  even after `input_filter` emptied the history; `as_tool()` behaved the same way.
- **Contrast.** attenu-guard checks the target's calls against the source's authority.

### Google ADK

- **Does well.** Its safety guide [S7] recommends callbacks and plugins that "Validate model and tool calls
  before or after execution, checking parameters against agent state or external policies."
- **In its own words** [S8]: transfer is routed through `transfer_to_agent` and the `disallow_transfer_*`
  flags. The pages state no rule that a sub-agent's tools are bounded by its parent's.
- **Changed.** 2.10.0 raises `WorkflowDataError` on a peer transfer when `disallow_transfer_to_peers=True`.
  That is a check on who may transfer, not on what authority passes.
- **Run.** ADK 2.10.0: a transfer target and an `AgentTool` both ran `crm_export`, a tool the coordinator
  never held.
- **Contrast.** attenu-guard bounds both by the coordinator, through ADK's own callbacks.

### Two more a reader will name

- **Pydantic AI.** Delegation "threads usage limits" and a shared cancellation token "cancels a whole tree of
  runs at once" [S9]. Its own page says: "Generally the delegate agent needs to either have the same
  dependencies as the calling agent, or dependencies which are a subset" and, in the same paragraph, "there's
  nothing to stop you initializing dependencies within a tool call". We have no widening baseline run for
  Pydantic AI; the row rests on its documentation. attenu-guard bounds the delegate's authority the way
  Pydantic AI bounds its usage.
- **Claude Code / Claude Agent SDK.** "Subagents inherit the built-in tools and MCP tools available in the
  main conversation, narrowed by two filters" [S10]. Since v2.1.267, "A subagent that declares
  bypassPermissions keeps the main conversation's mode instead." Still open by its own page: "When the main
  conversation is in default, dontAsk, or plan mode, the subagent runs in the permission mode you set,
  except bypassPermissions." On 2026-09-02, live, the CLI refused a child whose one tool was outside the
  parent's pool (`../examples/baselines/claude_code/output-live-2026-09-02.txt`). Claude Code caps a
  subagent's tools at the parent's pool; what attenu-guard adds there is the record, see the
  [hooks recipe](../examples/integrations/claude_code/hooks_receipt/README.md).

## 2. OAuth token exchange (RFC 8693) and RFC 9396

- **Does well.** OAuth scopes are the universal format [S11]. RFC 9396 "specifies a new parameter
  authorization_details that is used to carry fine-grained authorization data in OAuth messages" [S12].
- **In its own words** [S13], RFC 8693 §4.1: "Prior actors identified by any nested "act" claims are
  informational only and are not to be considered in access control decisions."
- **Contrast.** Under RFC 8693 the delegation history in `act` is informational. attenu-guard's Delegation
  Tokens (`attenu_guard.wire`) carry the chain and verify each hop's subset relation offline, with no
  authorization server in the path. A Cedar or OAuth decision can be the root grant; the chain below it is
  what attenu-guard checks.

## 3. SPIFFE / SPIRE

- **Does well.** "a set of open-source standards for securely identifying software systems in dynamic and
  heterogeneous environments" [S14].
- **In its own words** [S15]: "SPIFFE and SPIRE do not provide a means to implement authorization policies,
  only authentication policies."
- **Contrast.** SPIFFE says who a workload is and states that it does not do authorization. attenu-guard
  decides what each agent inside the workload may do, and records the decision.

## 4. Macaroons and Biscuit

- **Macaroons, in the paper's own words** [S16]: they "embed caveats that attenuate and contextually confine
  when, where, by who, and for what purpose a target service should authorize requests" and "support
  decentralized delegation between principals". They "are bearer credentials", verified with a shared HMAC
  root key. This is the origin of the idea.
- **Biscuit, in its own words** [S17]: "Biscuit also supports offline attenuation (like Macaroons)" and "The
  token can only be restricted, it will never gain more rights." It is public-key based, with a Datalog policy
  language.
- **Contrast.** Both already do offline attenuation, and nothing scopes either away from agents. What
  attenu-guard adds is on top of that idea, not instead of it: typed ceilings (`RowLimit`, `SpendCap`,
  `CallLimit`, `EgressRank`, `Allow`, `Deny`, `Prefix`, or your own) joined by a meet that can only shrink; a
  JOSE wire format with 20 published vectors that another language scores with `pip install attenu-guard`;
  the per-call hash-chained log; and the framework adapters. Biscuit could serve as a token format under the
  same idea.

## 5. OPA, Cedar, Casbin

- **OPA** [S18] "unifies policy enforcement across the stack" and "OPA accepts arbitrary structured data as
  input." A parent/child delegation relation exists only if you model it in input or data and write the
  Rego rule.
- **Cedar** [S19] is "a language for writing authorization policies and making authorization decisions based
  on those policies"; a policy states "who (the principal) is allowed to perform which actions, on which
  resources, and in what context". A delegation chain would be entities you supply.
- **Casbin** [S20] is "an efficient, open-source access control library that enforces authorization and
  supports multiple access control models". Its "What Casbin Does Not Do" section lists authentication and
  user or role management; it says nothing about agent delegation either way.
- **Contrast.** Each answers one request against one policy, and a delegation bound is a rule you write and
  maintain. In attenu-guard child ⊆ parent is the built-in invariant of `delegate()`; the three compose with
  it, since any of them can decide the root grant.

## 6. Keel and Tenuo

### Keel

- **In its own words** [S21]: "A **permit chain** is a per-project lineage of Permit objects bound by
  parent-child references, where each child permit's `authority_envelope` is mechanically constrained to be a
  subset of its parent's." Artifacts "are verifiable without contacting the issuer". The spec does not
  specify "A runtime, gateway, or proxy." Its table names the reference code as "keel-api (Keel-internal, not
  publicly readable)"; the spec and schemas are public.
- **Contrast.** Keel offers child ⊆ parent and offline verification too. The difference is where the code
  runs: attenu-guard's enforcement and verifier are both Apache-2.0 and run in your process.

### Tenuo

The closest neighbour, and we say so up front.

- **In its own words** [S22]: "Tenuo gives each task only the authority it needs. That authority travels
  with the work, can only shrink when handed off, and is checked where the action runs." "Verified offline."
  "No delegated warrant can exceed its parent." "Signed authorization receipts are opt-in". The Rust SDK
  includes "an observe mode". Its token format is "being standardized as
  draft-niyikiza-oauth-attenuating-agent-tokens-01". Apache-2.0, "v0.2 - Production/Stable".
- **Same invariant.** Tenuo and attenu-guard enforce the same rule at a handoff: the child's authority is a
  subset of the parent's, checked without a server. We claim no capability gap.
- **Differences that are true and sourced.**
  - Footprint. The tenuo 0.3.1 Python package requires `pyyaml` and `pydantic` and ships compiled abi3 wheels
    [S23]. attenu-guard has zero runtime dependencies and is pure Python; PyPI 0.18.0 lists only optional
    extras.
  - Proof artefact. Tenuo's primitive is a signed, holder-bound warrant checked per call, with receipts
    opt-in. attenu-guard's primary artefact is a hash-chained log of every check, allowed or denied, exported
    as a bundle a third party verifies with the vendor absent; three verifiers sharing no code with this
    repository have scored the published corpora, pinned in [`../tests/vectors/README.md`](../tests/vectors/README.md).
    attenu-guard also has signed tokens (`attenu_guard.wire`).
  - Coverage, stated for our side. attenu-guard ships adapters for 19 frameworks and the A2A protocol, each
    hooking the framework's public API ([INTEGRATIONS.md](INTEGRATIONS.md)). Tenuo's README lists its own
    runtime surfaces; we do not score the two lists against each other.
- **Relationship.** The draft its format names is a neighbouring draft we cite and hope to converge with.
  That is the whole of it.

## 7. IETF neighbours, not compared

All four are individual submissions, as ours is; none is a working-group document. Our draft cites the first two; the third cites ours.

| Draft | In its own words | What it scopes out, in its own words |
|---|---|---|
| draft-sweeney-wimse-credential-delegation-00 [S24] | this "protocol keeps the Delegation Server in the loop at every hop in exchange for synchronous revocation" | "This document does not define new token formats" |
| draft-niyikiza-oauth-attenuating-agent-tokens-01 [S24] | "A token holder authorized to delegate can derive a token offline with equal or narrower authority" | "this document does not define a transport binding" |
| draft-jackson-wimse-evaluation-01 [S24] | verifier-side evaluation rules; "It is complementary to chain-format documents such as [DELEGATION-CHAIN]", which is ours | "This document does not define a chain format, a token envelope, or a policy language" |
| draft-schrock-canonical-action-identifier-04 [S24] | a typed, canonical action identifier | "CAID carries no trust semantics. It does not establish identity, authority, authorization, execution, safety, or legal reliance." |

The trade-off the first row names is real and we state our side of it: attenu-guard verifies offline with
no authorization server, and revocation is in-process (`revoke()` a subtree). Without a server there is no
synchronous revocation across processes; the A2A adapter takes a `revocation_check=` seam for that. A public
harness from the Cred protocol scored our 20 Delegation Token vectors 17 of 20 with 3 declared gaps, each a
stated design choice on its side.

## What this file does not claim

- Not "first", not "only", not "unique". Attenuation that can only shrink, and offline verification, are
  described by macaroons, Biscuit, Keel, Tenuo and the attenuating-agent-tokens draft. The differences
  above are footprint, proof artefact and framework coverage, nothing wider.
- No exploit claims. Every framework row is a scripted-model run in this repository showing a tool body
  executing; none is a report of a live compromise, and each framework offers hooks that can stop it.
- No adoption claims. Nobody named here has adopted, embedded or endorsed attenu-guard; third-party
  verifier runs are corpus scores at a pin, and their authors said so.
- No execution claims. The ledger proves authorization and lifecycle; `allow` means authorized, not
  executed. See [THREAT-MODEL.md](THREAT-MODEL.md) and the two documented limitations in
  [RED-TEAM.md](RED-TEAM.md).
- No silence read as a negative. Hosted enforcement platforms are not listed: their public pages do not
  address sub-agent delegation one way or the other.
- No characterisation of any private conversation. Everything quoted is a public page, a public commit or
  a public comment.
- If a quotation above no longer matches its page, open an issue with the page and the date; the row is
  corrected, not argued.

## Sources, all read on 2026-09-28

- [S1] Deep Agents, subagents: https://docs.langchain.com/oss/python/deepagents/subagents
- [S2] Deep Agents, permissions: https://docs.langchain.com/oss/python/deepagents/permissions
- [S3] CrewAI, tool hooks: https://docs.crewai.com/en/learn/tool-hooks
- [S4] CrewAI, collaboration: https://docs.crewai.com/en/concepts/collaboration
- [S5] OpenAI Agents SDK, per-tool checks: https://openai.github.io/openai-agents-python/guardrails/ <!-- lint:allow -->
- [S6] OpenAI Agents SDK, handoffs: https://openai.github.io/openai-agents-python/handoffs/
- [S7] Google ADK, safety: https://adk.dev/safety/
- [S8] Google ADK, LLM agents: https://adk.dev/agents/llm-agents/
- [S9] Pydantic AI, multi-agent applications: https://pydantic.dev/docs/ai/guides/multi-agent-applications/
- [S10] Claude Code, subagents: https://code.claude.com/docs/en/sub-agents
- [S11] RFC 6749 §3.3: https://www.rfc-editor.org/rfc/rfc6749.txt
- [S12] RFC 9396: https://www.rfc-editor.org/rfc/rfc9396.txt
- [S13] RFC 8693: https://www.rfc-editor.org/rfc/rfc8693.txt
- [S14] SPIFFE overview: https://spiffe.io/docs/latest/spiffe-about/overview/
- [S15] SPIRE comparisons: https://spiffe.io/docs/latest/spire-about/comparisons/
- [S16] Macaroons paper page: https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/
- [S17] Biscuit introduction: https://doc.biscuitsec.org/getting-started/introduction
- [S18] OPA: https://www.openpolicyagent.org/docs
- [S19] Cedar: https://docs.cedarpolicy.com/
- [S20] Casbin overview: https://casbin.org/docs/overview
- [S21] Keel permit chain: https://github.com/keelapi/keel-permit (README and `spec/permit-chain-v1.md`)
- [S22] Tenuo README: https://github.com/tenuo-ai/tenuo
- [S23] tenuo on PyPI, 0.3.1 metadata: https://pypi.org/project/tenuo/
- [S24] IETF Datatracker: https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/ , https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/ , https://datatracker.ietf.org/doc/draft-jackson-wimse-evaluation/ , https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/
