# Compared with

*Dated 2026-09-28. The attenu-guard column describes release v0.18.0. Every cell about another project is
a quotation from its own page, marked [S1] to [S24] and listed at the end, or the result of a run in this
repository. Legend: **✓** stated on its own pages or shown by a run · **✗** its own pages or a run say no ·
**—** not stated on the pages read; silence is not read as a no.*

Two projects enforce the same handoff rule we do, Tenuo and Keel, and they come first. What differs is
footprint, the proof artefact and framework coverage, nothing wider.

## 1. Delegation and enforcement

| | attenu-guard | Tenuo | Keel | Framework hooks ¹ | OPA · Cedar · Casbin |
|---|---|---|---|---|---|
| Every tool call checked, in your process | ✓ | ✓ "checked where the action runs" [S22] | ✗ the spec "does not specify a runtime, gateway, or proxy" [S21] | ✓ [S1] [S3] [S5] [S7] | ✓ one request against one policy [S18] [S19] [S20] |
| Child holds no more than its parent, enforced at the handoff | ✓ `delegate()` takes the meet; 4,000 random trees per invariant, run 2026-09-28 | ✓ "No delegated warrant can exceed its parent" [S22] | ✓ "mechanically constrained to be a subset of its parent's" [S21] | ✗ a sub-agent ran a tool its parent never held, all four, run 2026-09-28 (§4) | you write the rule; no parent relation unless you model it [S18] [S19] |
| Holds down a chain of any depth | ✓ every node stays inside the root; `del_max_depth` | — | ✓ "a per-project lineage of Permit objects bound by parent-child references" [S21] | ✗ no parent relation | — |
| Revoke a parent, every descendant denies at once | ✓ `revoke()` on a subtree | — | — | — | — |
| Limits with units that only shrink (rows, spend, calls) | ✓ `RowLimit`, `SpendCap`, `CallLimit`, `EgressRank`, or your own | — | — | — | — |
| Every allow and deny on a hash-chained log | ✓ one line per `check()` | receipts: "Signed authorization receipts are opt-in" [S22] | — | — | — |
| Verified offline, no server in the path | ✓ `attenu-guard verify bundle.json` | ✓ "Verified offline" [S22] | ✓ "verifiable without contacting the issuer" [S21] | — | n/a, a decision engine |
| Observe mode: record everything, block nothing | ✓ | ✓ the Rust SDK "includes an observe mode" [S22] | — | — | — |
| Test vectors scored by verifiers that share no code with the project | ✓ three, pinned in [`tests/vectors/README.md`](../tests/vectors/README.md) | — | — | n/a | n/a |
| Agent-framework adapters | 19 + A2A ([INTEGRATIONS.md](INTEGRATIONS.md)) | listed in its README [S22] | — | n/a | — |
| Python runtime dependencies | none | `pyyaml`, `pydantic`; compiled wheels [S23] | n/a, a spec | n/a | — |
| Code you can run | Apache-2.0: enforcement and verifier | Apache-2.0 [S22] | spec and verifier public; reference server "Keel-internal, not publicly readable" [S21] | n/a | Apache-2.0, all three [S18] [S19] [S20] |
| Wire format | draft-asor-wimse-agent-delegation-chain-01, individual I-D | draft-niyikiza-oauth-attenuating-agent-tokens-01, individual I-D [S22] | its own spec v1 [S21] | n/a | n/a |

¹ Deep Agents, CrewAI, the OpenAI Agents SDK and Google ADK, each through its own hook API. The runs are in §4.

## 2. Tokens, identity, and where the idea comes from

| | attenu-guard | OAuth token exchange and RAR (RFC 8693, RFC 9396) | SPIFFE / SPIRE | Macaroons · Biscuit |
|---|---|---|---|---|
| Says who the caller is | n/a, pair it with an identity | ✓ | ✓ "securely identifying software systems" [S14] | ✗ "bearer credentials" [S16] |
| Decides what a caller may do, per call | ✓ | scopes and `authorization_details` on the token [S11] [S12] | ✗ "do not provide a means to implement authorization policies, only authentication policies" [S15] | ✓ caveats checked at the target [S16] |
| Bounds each hop by the previous holder | ✓ | ✗ nested `act` claims "are informational only and are not to be considered in access control decisions" [S13] | n/a | ✓ "The token can only be restricted, it will never gain more rights" [S17] |
| Attenuates offline, no issuer in the path | ✓ | ✗ the authorization server issues each exchanged token [S13] | n/a | ✓ "offline attenuation" [S17] |
| Limits with units and a meet | ✓ | RAR carries structured details [S12]; shrinking across hops — | n/a | caveats, any predicate [S16] [S17] |
| Every decision on a hash-chained log | ✓ | — | — | — |
| Agent-framework adapters | 19 + A2A | — | — | — |
| What attenu-guard does with it | | does not replace it: a root grant still comes from an issuer | does not replace it: identity is upstream | the idea's origin; attenu-guard adds the framework hooks, the typed meet and the per-call log |

## 3. Each one, in its own words

| | What it is, in its own words | Where attenu-guard differs |
|---|---|---|
| Tenuo | "gives each task only the authority it needs. That authority travels with the work, can only shrink when handed off, and is checked where the action runs." Apache-2.0, "v0.2 - Production/Stable" [S22] | Same invariant. Zero runtime dependencies against `pyyaml` and `pydantic` [S23]; a hash-chained log of every check, exported as a bundle a third party verifies, against opt-in receipts; 19 adapters and A2A, each on the framework's public API. |
| Keel | "each child permit's `authority_envelope` is mechanically constrained to be a subset of its parent's"; artifacts "are verifiable without contacting the issuer" [S21] | Same invariant. Keel's reference server is "Keel-internal, not publicly readable"; attenu-guard's enforcement and verifier are both Apache-2.0 and run in your process. |
| Deep Agents / LangGraph | a sub-agent's `tools` field "overrides the inherited tools entirely" [S1]; on permissions, "Custom tools and MCP tools that access the filesystem are not covered" [S2] | The child gets what it declares for its task, never more than the parent holds. The twelve-line `BoundedByParent` middleware in [`../examples/baselines/`](../examples/baselines/) shows the intersection done natively. |
| CrewAI | "When `allow_delegation=True`, agents automatically gain access to powerful collaboration tools" [S4]; a pre-call veto exists: "raise HookAborted(reason, source) to block the call" [S3] | Bounds the coworker by the delegator, through CrewAI's own hooks. |
| OpenAI Agents SDK | "When a handoff occurs, it's as though the new agent takes over the conversation" [S6]; per-tool checks "let you validate or block calls to those tools before and after execution" [S5] | Checks the target's calls against the source's authority. |
| Google ADK | callbacks and plugins that "Validate model and tool calls before or after execution, checking parameters against agent state or external policies" [S7]; on 2.10.0 a peer transfer with `disallow_transfer_to_peers=True` raises `WorkflowDataError` (§4) | That flag gates who may transfer, not what authority passes. attenu-guard bounds a transfer target and an `AgentTool` by the coordinator, through ADK's own callbacks. |
| Pydantic AI | delegation "threads usage limits"; "Generally the delegate agent needs to either have the same dependencies as the calling agent, or dependencies which are a subset", and "there's nothing to stop you initializing dependencies within a tool call" [S9] | Bounds the delegate's authority the way Pydantic AI bounds its usage. No widening run exists for it; this row rests on its docs. |
| Claude Code / Claude Agent SDK | "Subagents inherit the built-in tools and MCP tools available in the main conversation, narrowed by two filters"; since v2.1.267, "A subagent that declares bypassPermissions keeps the main conversation's mode instead" [S10] | Claude Code already caps a subagent's tools at the parent's pool (live, 2026-09-02: `../examples/baselines/claude_code/output-live-2026-09-02.txt`). attenu-guard adds the record: the [hooks recipe](../examples/integrations/claude_code/hooks_receipt/README.md). |
| OPA | "unifies policy enforcement across the stack"; "OPA accepts arbitrary structured data as input" [S18] | One request against one policy; child ⊆ parent is a rule you write and maintain there, and `delegate()`'s built-in invariant here. Any of the three can decide the root grant. |
| Cedar | "a language for writing authorization policies and making authorization decisions based on those policies"; a policy states "who (the principal) is allowed to perform which actions, on which resources, and in what context" [S19] | As OPA. |
| Casbin | "an efficient, open-source access control library that enforces authorization and supports multiple access control models" [S20] | As OPA. |
| OAuth 2.0 token exchange and RAR | RFC 8693: nested `act` claims "are informational only and are not to be considered in access control decisions" [S13]; RFC 9396 "specifies a new parameter authorization_details that is used to carry fine-grained authorization data in OAuth messages" [S12] | Delegation Tokens (`attenu_guard.wire`) carry the chain and verify each hop's subset relation offline, with no authorization server in the path. The root grant still comes from an issuer. |
| SPIFFE / SPIRE | "SPIFFE and SPIRE do not provide a means to implement authorization policies, only authentication policies" [S15] | Identity is upstream. attenu-guard decides what each agent inside the workload may do, and records it. |
| Macaroons | "embed caveats that attenuate and contextually confine when, where, by who, and for what purpose a target service should authorize requests"; "bearer credentials" [S16] | The origin of the idea. attenu-guard adds typed ceilings joined by a meet, a JOSE wire format with 20 published vectors, the per-call log and the framework adapters. |
| Biscuit | "Biscuit also supports offline attenuation (like Macaroons)"; "The token can only be restricted, it will never gain more rights" [S17] | As Macaroons. Biscuit could serve as a token format under the same idea. |
| draft-sweeney-wimse-credential-delegation-00 | "keeps the Delegation Server in the loop at every hop in exchange for synchronous revocation"; "This document does not define new token formats" [S24] | attenu-guard verifies offline; revocation is in-process (`revoke()` a subtree), and without a server there is no synchronous revocation across processes. The A2A adapter takes a `revocation_check=` seam for that. |
| draft-niyikiza-oauth-attenuating-agent-tokens-01 | "A token holder authorized to delegate can derive a token offline with equal or narrower authority"; "this document does not define a transport binding" [S24] | The same rule. Our draft cites it. |
| draft-jackson-wimse-evaluation-01 | verifier-side evaluation rules, "complementary to chain-format documents such as [DELEGATION-CHAIN]", which is ours; "This document does not define a chain format, a token envelope, or a policy language" [S24] | It cites our draft; the two are meant to fit together. |
| draft-schrock-canonical-action-identifier-04 | "CAID carries no trust semantics. It does not establish identity, authority, authorization, execution, safety, or legal reliance." [S24] | An action identifier, not an authority model. |

All four drafts are individual submissions, as ours is; none is a working-group document.

## 4. The runs behind the framework rows

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

In CrewAI, ordinary exceptions raised inside a tool hook let the tool continue; the documented veto,
`HookAborted`, stopped it. That is a hook trap, not a missing veto.

## 5. What this page does not claim

- No adoption claims. Nobody named here has adopted, embedded or endorsed attenu-guard; third-party
  verifier runs are corpus scores at a pin, and their authors said so.
- No exploit claims. Every framework row is a scripted-model run in this repository showing a tool body
  executing, and each framework offers hooks that can stop it.
- No execution claims. The ledger proves authorization and lifecycle; `allow` means authorized, not
  executed ([THREAT-MODEL.md](THREAT-MODEL.md), and the two documented limitations in [RED-TEAM.md](RED-TEAM.md)).
- No silence read as a negative. Hosted enforcement platforms are not listed: their public pages do not
  address sub-agent delegation one way or the other.
- Not "first", not "only", not "unique". Attenuation that can only shrink, and offline verification, are
  described by macaroons, Biscuit, Keel, Tenuo and the attenuating-agent-tokens draft.
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
- [S18] OPA: https://www.openpolicyagent.org/docs (licence: github.com/open-policy-agent/opa)
- [S19] Cedar: https://docs.cedarpolicy.com/ (licence: github.com/cedar-policy/cedar)
- [S20] Casbin overview: https://casbin.org/docs/overview (licence: github.com/casbin/casbin)
- [S21] Keel permit chain: https://github.com/keelapi/keel-permit (README and `spec/permit-chain-v1.md`)
- [S22] Tenuo README: https://github.com/tenuo-ai/tenuo
- [S23] tenuo on PyPI, 0.3.1 metadata: https://pypi.org/project/tenuo/
- [S24] IETF Datatracker: https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/ , https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/ , https://datatracker.ietf.org/doc/draft-jackson-wimse-evaluation/ , https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/
