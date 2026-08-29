# attenu-guard

[attenu.io](https://attenu.io) · [Docs](docs/) · [Attenu Derive — what each agent may do, read from your app](https://github.com/attenu-io/attenu-derive) · [Internet-Draft](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/) · [Changelog](CHANGELOG.md)

**Works with** LangGraph · LangChain `create_agent` / deepagents · OpenAI Agents SDK · Google ADK · Pydantic AI · CrewAI · AutoGen · Claude Agent SDK · smolagents · AWS Strands · LlamaIndex · Semantic Kernel · Agno · Haystack · CAMEL-AI · Microsoft Agent Framework · AG2 — each integrated **unmodified**, each with an offline demo and tests ([matrix](docs/INTEGRATIONS.md)). Enforced live on real applications with Google ADK, CrewAI and LangGraph.

**Attenu Guard checks what an AI agent may do — and keeps it narrowing at every
handoff.** When one agent hands work to another, the child gets only the
permissions its task needs, never the parent's full set. Chains have hard
ceilings. Any subtree can be revoked in one call. Every decision lands on a
tamper-evident log you can verify offline. The alternative most teams live with
is handing an agent a person's credentials and reading the logs afterwards.

An open enforcement layer for [OWASP ASI07 (insecure inter-agent communication) and ASI08
(cascading failures)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):
delegated authority stays inside the parent's limits, and every decision the guard makes remains verifiable offline.

![attenu-guard demo — the poisoned summariser: one legitimate read allowed, the exfiltration blocked, the subtree revoked, the audit chain verified](https://raw.githubusercontent.com/attenu-io/attenu-guard/main/docs/assets/demo.gif)

```bash
pip install attenu-guard                 # zero runtime deps; gives you the `attenu-guard` command too
pip install 'attenu-guard[langgraph]'    # or crewai, google-adk, openai-agents, … — one extra per framework
```

> **Have a bundle to check?** `pipx run attenu-guard verify bundle.json` — integrity, child ⊆ parent and
> containment from the file alone, no account, no network; the [auditor's walkthrough](examples/verify/README.md)
> has three sample bundles (clean, tampered, widened) and takes a minute.

> **Just want to see it run?** From the repo root, no install needed:
> `python examples/poisoned_summarizer.py` — the examples bootstrap the
> `src/` path themselves. `python tests/run_properties.py` proves the
> invariants the same way.

```python
from attenu_guard import Authority, Guard, RowLimit, EgressRank

# The orchestrator holds broad authority.
orchestrator = Guard.issue("orchestrator", Authority(
    scopes={"crm.*", "mail.send"},
    ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

# It delegates a narrow task. The child gets the *meet* of what the parent
# held and what the task needs — computed and enforced, not suggested.
summarizer = orchestrator.delegate("summarizer", Authority(
    scopes={"crm.read"},
    ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
    task="summarize Q3 pipeline")

decision = summarizer.check("crm.read", context={"rows": 4_200})   # Decision(allowed=True)
if not decision:
    print(decision.explain())

summarizer.enforce("crm.export", context={"egress": "any"})        # raises AuthorityDenied
```

`check()` returns a rich **`Decision`** (with machine-readable reason codes for
your audit trail); `enforce()` is the hard-stop gate that raises; `would_allow()`
is a dry-run that writes nothing. The `crm.export` call is refused whatever the agent was talked into trying —
the sub-agent never held that permission, so an injected instruction has
nothing to widen. That is the default once permissions narrow at the handoff.

## What happens at a handoff today

In the frameworks we audited, the handoff itself is not something the system can
see: identity tokens describe two parties — user and agent — so "child ⊆ parent"
cannot be written down, and policy checks fire when a tool is invoked rather than
at the moment permissions are passed down. Verified against released code, and
pinned by tests that fail the day the behaviour changes:

| System | What it does at a handoff (verified against the released code — see [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md)) |
|---|---|
| OpenAI Agents SDK 0.21 | passes the **entire** conversation to the sub-agent (`Handoff.input_filter=None` by default: *"the new agent sees the entire conversation history"*); no parent/child relation exists, so nothing checks child ⊆ parent |
| LangChain `deepagents` 0.7 | a sub-agent's `permissions` **replace** the parent's rules entirely (`graph.py`) — a child can be granted what its parent is denied |
| Google ADK 2.7.1 | `disallow_transfer_to_peers` is enforced on the legacy `llm_flows` path since 2.7.1 ([#3850](https://github.com/google/adk-python/issues/3850), fix `fa18d26a`) — but the 2.x default workflow path (`workflow/utils/_transfer_utils.py`, sibling case) still carries no check: on 2.7.1 the peer transfer goes through (pinned by `tests/integrations/test_google_adk.py`, which fails the day it stops). Either way ADK checks *who may transfer*; it does not check *what authority passes*, and no record exists to verify afterwards |
| CrewAI 1.15 | a delegated coworker runs with its **own full tool list**; the tool-hook dispatcher swallows exceptions and runs the tool (**fail-open**) unless you raise its one blessed exception |
| AutoGen 0.7 | `Handoff` carries target/description/message only; the receiver offers the model its own full tool list |
| Microsoft Entra | child agent **inherits** the parent's scopes |
| MCP | scope flow is **accumulation**-biased (step-up unions) |
| A2A | authenticates the hop, carries **no** delegated authority |

attenu-guard makes child ⊆ parent a computed, enforced, offline-verifiable
invariant — in your framework, in your process — no proxy, and no network call in the deny path.

## What you get

- **`Authority`** — an immutable capability (scopes + a list of typed, extensible `Ceiling` bounds + TTL) with `meet`, the lattice operation that can only ever *shrink*, and `is_narrower_than`, the provable subsumption relation.
- **`Guard`** — `issue()` a root, `delegate()` a sub-agent with attenuated authority, `check()` → `Decision`, `enforce()` → raises, `would_allow()` → dry-run, `revoke()` a whole subtree.
- **Typed ceilings** — `RowLimit`, `SpendCap`, `CallLimit`, `EgressRank`, `Allow`, `Deny`, `Prefix`, or your own via `register_ceiling`. Unknown ceiling types **fail closed**, never silently unbounded.
- **Chain invariants** — depth, fanout, and aggregate budget ceilings; **cascade revocation** (revoke any node, every descendant denies immediately).
- **Hash-chained audit log** — an open, versioned [schema](schema/agent-audit.schema.json); `attenu-guard view log.jsonl` renders the tree and verifies it; tampering is provable offline. Every `deny` says **why** (`disposition`: `held_pending_grant` — waiting on a human · `withheld_tier2` · `unresolved` — no authority known for the tool · `out_of_authority` — real over-reach), so "held" never reads as "denied"; `evidence.export_bundle` / `verify_bundle` / `delegation_graph` / `denials` give an auditor an **offline-verifiable** bundle and the folds a console renders. `AuditLog(sinks=…)` copies entries to local **sinks** after the write (never the network) — `sinks.SpoolSink` is a bounded, fsync'd, resumable write-ahead spool carrying the ingest idempotency key `(boot_id, chain_id, seq, hash)`; [`attenu_guard.identity`](src/attenu_guard/identity.py) gives a product an identity before it has a key (`.attenu/product.json`, per-process `boot_id`, assigned chain ids).
- **Wire format** ([`attenu_guard.wire`](src/attenu_guard/wire.py)) — `serialize`/`load` the delegation chain as signed **Delegation Tokens** and verify child ⊆ parent **offline**, across services, with no authorization server in the path. This is the reference implementation of the current working Internet-Draft in [`docs/`](docs/draft-asor-wimse-agent-delegation-chain-01.md); 19 interop test vectors live in [`tests/vectors/`](tests/vectors/) and ship inside the installed package as `attenu_guard.vectors`, so an implementation in any language can score its own verifier with nothing but `pip install attenu-guard`.
- **Scenario harness** — declarative JSON/YAML authorization tests (`attenu-guard scenarios file.json`); see [`scenarios/`](scenarios/).
- **Adapters** — shipped, tested integrations for the major agent frameworks as [`attenu_guard.adapters.<name>`](src/attenu_guard/adapters/): LangGraph, LangChain `create_agent` / deepagents, OpenAI Agents SDK, Google ADK, Pydantic AI, CrewAI, AutoGen, Microsoft Agent Framework, AG2, Claude Agent SDK, smolagents, AWS Strands, LlamaIndex, Semantic Kernel, Agno, Haystack, CAMEL-AI — and, for the **A2A** protocol, a client interceptor plus a guarded `AgentExecutor` that carries the attenuated chain across a hop between processes. Each has an offline demo under [`examples/integrations/`](examples/integrations/); install one with `pip install 'attenu-guard[<extra>]'`. Hooks, versions and what each framework enforces itself: [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

## Canonicalization and compatibility

Versions 0.7 and later use [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) for every
signed or hash-linked artifact: Delegation Token protected headers and payloads,
parent commitments, integrity seals, audit entries, anchors, and evidence bundles.
Tokens and metadata-bearing artifacts emit `"c14n":"JCS"` as an informational
label. Verifiers enforce JCS from canonical bytes and hashes, not from that label;
non-canonical input, duplicate object member names, non-finite numbers, and lone
UTF-16 surrogates are rejected.

This is a deliberate wire-format break from versions through 0.6.1. Current versions have
no legacy or dual-format reader. Producers and verifiers in different languages must
move together; the 19 packaged [interop vectors](tests/vectors/README.md) pin the
required bytes and rejection reasons.

## Prove the safety claims yourself

```bash
python tests/run_properties.py      # 4,000 random delegation trees per invariant, zero deps
python tests/red_team.py            # 17 adversarial attacks, black- & white-box; 0 must break
python examples/poisoned_summarizer.py
attenu-guard demo
```

The property suite asserts — over thousands of random chains — that attenuation
never widens, holds transitively down a chain, that a revoked subtree authorizes
nothing, and that audit tampering is detected. The red-team harness (see
[`docs/RED-TEAM.md`](docs/RED-TEAM.md)) additionally tries to *break* the protocol
— privilege escalation, chain splicing, expired-grant reuse — and every genuine
finding is fixed and pinned as a regression. If you can break one, the core claim
is false; please [tell us](SECURITY.md).

## Standards

The protocol is designed to be IETF-acceptable: it reuses the OAuth/JOSE stack
(JWT, RFC 9396 authorization_details, DPoP, Token Status List) and invents only
the one missing piece — cryptographically-linked, subsumption-enforced, offline
multi-hop attenuation. See [`docs/STANDARDS-ALIGNMENT.md`](docs/STANDARDS-ALIGNMENT.md)
and the Internet-Draft [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/) (published revision `-00`, individual submission, WIMSE; working `-01` source in [`docs/`](docs/draft-asor-wimse-agent-delegation-chain-01.md)).

## What this is *not*

This library does **not** decide authority *for* you. You write the `Authority` for
each delegation — or you let [`attenu-derive`](https://github.com/attenu-io/attenu-derive),
the open engine, compute it from your app's declared structure (agents, roster, tools,
what each task calls) and approve it before it is enforced. The library is the
enforcement shim and the open schema; it is useful entirely on its own, forever, with
no account and no network. The [Attenu console](https://attenu.io) is optional: a
place to see denials, decide, and verify — never in the deny path.

## License

Apache-2.0. Contributions under the [DCO](CONTRIBUTING.md). Security policy in
[SECURITY.md](SECURITY.md).
