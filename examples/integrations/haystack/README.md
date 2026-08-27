# attenu-guard x Haystack

Enforced authority attenuation for deepset Haystack's `Agent` and `AgentTool`.
Tested against **haystack-ai 3.1.0** (Apache-2.0, requires Python >= 3.10).

A Haystack sub-agent keeps its own tool list. Nothing in the framework relates it to the
agent that delegated to it, so a sub-agent can hold permissions its caller never had. This
adapter adds the missing relation: a child's authority is the *meet* of what it asks for and
what its parent holds, and every tool call is checked against it before the tool body runs.

## What it hooks

| Hook point | API used |
|---|---|
| Child creation | The `AgentTool` call itself (`haystack/tools/agent_tool.py:46`). Haystack's delegation primitive is a `ComponentTool` wrapping a whole `Agent`, so the delegation moment *is* a tool invocation. A `ToolPolicy(delegates_to=..., grant=...)` mints the child with `parent.delegate(...)` after the check passes and before the sub-agent's first step. |
| Tool invocation | `Tool.invoke` / `Tool.invoke_async` (`haystack/tools/tool.py:283`, `:305`) via `guard_tools(...)`. These are the only paths from the Agent's run loop to a tool body (`components/agents/tool_calling.py:219`, `:256`), so a denial provably precedes the body. The guarded object is a subclass of the tool's *own* class, so `isinstance(tool, ComponentTool)` — which `_get_func_params` keys off — and `inputs_from_state` / `outputs_to_state` / `outputs_to_string` all keep working. |
| Tool invocation (alt) | `AttenuationStrategy`, a `ConfirmationStrategy` registered through Haystack's own `ConfirmationHook` at the `before_tool` hook point (`hooks/human_in_the_loop/hooks.py:19`, run at `agent.py:1003`, before `_run_tool` at `agent.py:1014`). A `ToolExecutionDecision(execute=False)` makes Haystack drop the call and answer the model with an error tool-result. Use it *instead of* the `Tool.invoke` gate for a given tool, never as well — each is a full check, and metered calls would be counted twice. |

Both tool hooks go through one `authorize_tool_call(...)`, so they cannot disagree.
Nothing is monkeypatched: the adapter subclasses `Tool` and implements the
`ConfirmationStrategy` protocol, which is how Haystack itself builds `ComponentTool`,
`AgentTool` and `BlockingConfirmationStrategy`.

Who counts as the parent is held in a `contextvars.ContextVar`, which is correct under
Haystack's own concurrency: a turn's tool calls each run under their own
`copy_context()` (`tool_calling.py:213`) or their own task (`:251`), so three `AgentTool`
calls in one model turn become three siblings of the same parent, never a chain.

## Run it

```bash
pip install 'attenu-guard[haystack]'
python examples/integrations/haystack/demo.py     # offline, no API key
pytest tests/integrations/test_haystack.py
```

## What you'll see

A coordinator (`crm.*`, `mail.send`, 100 000 rows, egress `any`) delegates through an
`AgentTool` to a researcher (`crm.read`, 5 000 rows, egress `none`, ttl 900) whose model has
been poisoned. Then: `crm_query(4200)` runs; `crm_export(...)` is **denied before its body**
(`ops.exported_to` stays `None`); a 90 000-row read is denied on the ceiling even though the
scope is granted; a delegation asking for more is met down; three delegations in one turn
land as siblings; revoking the sub-agent by name refuses the next delegation to it; and the
hash-chained audit log verifies and carries the deny with reason `scope_not_granted`.

A denial raises `AuthorityDeniedTool`, a subclass of Haystack's own `ToolInvocationError`.
That hands the outcome to the Agent's existing switch: with
`raise_on_tool_invocation_failure=False` (Haystack's default) the model is shown an error
tool-result saying it lacks the authority and the run continues; with `True` the run aborts.
The body never runs either way. `on_deny="raise"` raises `AuthorityDenied` instead — a stop
Haystack does not catch, whatever the Agent is configured to do.

## Trust boundary

The `Guard` lives in your process, next to the tool it is protecting; the check is a
function call, and no network is involved. What is enforced is structural, not persuasive:
the sub-agent is not told to avoid `crm_export`, it is never given the authority for it, so
a prompt injection has nothing to escalate.

The adapter is only as good as the two things you write: the `Authority` you issue and the
`ToolPolicy` map that says what each tool consumes. attenu-guard deliberately does not
decide those for you. A tool with no policy, and any call made outside
`with authority(guard): ...`, are denied and recorded — the fail-closed default.

Denials are recorded in a hash-chained log that anyone can verify offline, without
attenu-guard's help; the log is tamper-evident, so an alteration is detectable after the
fact rather than impossible.

Two limits worth knowing. A guarded tool is bound to a live `Guard`, so it refuses
`to_dict()`: serialize your pipeline with the unguarded tools and apply `guard_tools(...)`
after `from_dict()`. And the `before_tool` hook sees pending tool calls, not the sub-agent an
`AgentTool` is about to start, so it cannot mint a child `Guard` — guard `AgentTool`s with
`guard_tools(...)` even when leaf tools go through the strategy.
