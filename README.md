# delegation-guard

**Enforced authority attenuation for multi-agent AI systems.** When one AI agent
hands work to another, the child inherits *only* what its task needs — never the
parent's full authority. Chains have hard ceilings. Any subtree can be revoked in
one call. Every decision lands on a tamper-evident log you can verify offline.

The open answer to [OWASP ASI07 (insecure inter-agent communication) and ASI08
(cascading failures)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) —
the two agentic risks that no framework or platform enforces today.

```bash
# From a clone (pre-publish): install in editable mode, zero runtime deps.
pip install -e .        # gives you the `dg` command too
# Once published to PyPI this becomes: pip install delegation-guard
```

> **Just want to see it run?** From the repo root, no install needed:
> `python examples/poisoned_summarizer.py` — the examples bootstrap the
> `src/` path themselves. `python tests/run_properties.py` proves the
> invariants the same way.

```python
from delegation_guard import Authority, Guard, RowLimit, EgressRank

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
is a dry-run that writes nothing. The `crm.export` call is refused no matter what
the agent was tricked into trying — because the sub-agent *physically lacks* the
authority. **No CVE required: this is default behaviour once authority is
attenuated at the handoff.**

## Why this doesn't exist anywhere else

Every framework and platform we audited stops one step short — because in each
of them **the delegation act is invisible**. Identity tokens top out at two
parties (user, agent), so "child ⊆ parent" can't even be *written down*; every
policy check fires at invocation time inside one vendor's perimeter, never at the
moment authority is handed down.

| System | What it does at a handoff |
|---|---|
| OpenAI Agents SDK | passes the **entire** conversation to the sub-agent |
| Microsoft Entra | child agent **inherits** the parent's scopes |
| Google ADK | ships a restriction flag that ["only influences the prompt"](https://github.com/google/adk-python/issues/3850) |
| MCP | scope flow is **accumulation**-biased (step-up unions) |
| A2A | authenticates the hop, carries **no** delegated authority |

delegation-guard makes child ⊆ parent a computed, enforced, offline-verifiable
invariant — in ten minutes, in your framework, with no proxy and no phone-home.

## What you get

- **`Authority`** — an immutable capability (scopes + a list of typed, extensible `Ceiling` bounds + TTL) with `meet`, the lattice operation that can only ever *shrink*, and `is_narrower_than`, the provable subsumption relation.
- **`Guard`** — `issue()` a root, `delegate()` a sub-agent with attenuated authority, `check()` → `Decision`, `enforce()` → raises, `would_allow()` → dry-run, `revoke()` a whole subtree.
- **Typed ceilings** — `RowLimit`, `SpendCap`, `CallLimit`, `EgressRank`, `Allow`, `Deny`, `Prefix`, or your own via `register_ceiling`. Unknown ceiling types **fail closed**, never silently unbounded.
- **Chain invariants** — depth, fanout, and aggregate budget ceilings; **cascade revocation** (revoke any node, every descendant denies immediately).
- **Hash-chained audit log** — an open, versioned [schema](schema/agent-audit.schema.json); `dg view log.jsonl` renders the tree and verifies it; tampering is provable offline.
- **Wire format** ([`delegation_guard.wire`](src/delegation_guard/wire.py)) — `serialize`/`load` the delegation chain as signed **Delegation Tokens** and verify child ⊆ parent **offline**, across services, with no authorization server in the path. This is the reference implementation of the Internet-Draft in [`docs/`](docs/draft-asor-wimse-agent-delegation-chain-00.md); interop test vectors live in [`tests/vectors/`](tests/vectors/).
- **Scenario harness** — declarative JSON/YAML authorization tests (`dg scenarios file.json`); see [`scenarios/`](scenarios/).
- **Adapters** — a LangGraph integration ([`delegation_guard.adapters.langgraph`](src/delegation_guard/adapters/langgraph.py)); MCP/FastAPI to follow.

## Prove the safety claims yourself

```bash
python tests/run_properties.py      # 4,000 random delegation trees per invariant, zero deps
python tests/red_team.py            # 17 adversarial attacks, black- & white-box; 0 must break
python examples/poisoned_summarizer.py
dg demo
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
and the [Internet-Draft](docs/draft-asor-wimse-agent-delegation-chain-00.md).

## What this is *not*

This library deliberately does **not** decide authority *for* you — you write the
`Authority` for each delegation. Automatically *deriving* the right authority from
a task, scoring plan-vs-action divergence, fleet management, and regulator-shaped
evidence exports are the commercial [Attenu](https://attenu.io) authority
plane. The library is the enforcement shim and the open schema; it is useful
entirely on its own, forever, with no account and no network.

## License

Apache-2.0. Contributions under the [DCO](CONTRIBUTING.md). Security policy in
[SECURITY.md](SECURITY.md).
