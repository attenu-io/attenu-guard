# Integrations — delegation-guard inside real agent frameworks

Every row below is a **shipped, tested** integration: a thin adapter installed with the
package as `delegation_guard.adapters.<framework>` (enable its framework with
`pip install 'delegation-guard[<extra>]'`; the core stays zero-dependency — a framework is
imported only when you import its adapter), a runnable `demo.py` under
[`examples/integrations/<framework>/`](../examples/integrations/) that tells the
poisoned-summariser story end to end, and a pytest under
[`tests/integrations/`](../tests/integrations/) that runs **offline** — every
framework's own mock/scripted model, no LLM API key — and is skipped when the
framework isn't installed. CI runs each one against the exact version listed
(`integrations` job) and, weekly, against the latest release (`integrations-latest`).

The library itself was **not modified** for any of them: `Guard` / `Authority` /
`Decision` / `AuditLog` integrate through each framework's official hooks. Two hook
points are always needed — (1) the moment a parent hands off to / spawns a
sub-agent, where the child's attenuated `Guard` is minted with
`parent.delegate(...)`, and (2) the moment any agent invokes a tool, where
`guard.check(...)` runs *before* the tool body.

Versions and file:line references are as of **August 2026**; they will drift.

## The matrix

| Framework (version tested) | Delegation primitive | Hook (1) — mint the child Guard | Hook (2) — check before the tool body | Offline model used in the test | What the framework itself enforces about a sub-agent's authority | Fit |
|---|---|---|---|---|---|---|
| **LangGraph** 1.2 + LangChain `create_agent` | none in LangGraph itself (a sub-agent is another graph you call) | construction site / the `task` tool call (deepagents) | `ToolNode(wrap_tool_call=…)` / `AgentMiddleware.wrap_tool_call` (`langgraph/prebuilt/tool_node.py`, `langchain/agents/middleware/types.py`); the shipped `guard_node`/`DelegatedToolNode` for hand-written nodes | scripted `BaseChatModel` (`bind_tools` passthrough) | nothing; `create_agent` has no notion of parent/child | 5 |
| **deepagents** 0.7 (LangChain's multi-agent app) | `task(description, subagent_type)` tool → `subagent.invoke(...)` (`deepagents/middleware/subagents.py`) | the same `wrap_tool_call`, filtered on `task` | `wrap_tool_call` in the sub-agent | same | `SubAgent["tools"]` (leaky: every sub-agent also inherits the filesystem suite); `permissions` on a sub-agent **replace** the parent's rules entirely (`graph.py`, verified: a child wrote `/secrets/…` where its parent was denied) | 5 |
| **OpenAI Agents SDK** 0.21 | `handoffs=[…]`, `Agent.as_tool(...)` | `RunHooks.on_handoff` (`agents/lifecycle.py`; fires at `turn_resolution.py`) or `handoff(..., on_handoff=…)` | `FunctionTool.tool_input_guardrails` (`agents/tool.py`), executed *before* `on_tool_start` and the body (`tool_execution.py`) | `agents.testing.ScriptedModel` (shipped) | nothing relative to a parent — tool lists are independent per agent; handoff forwards the **entire** conversation by default; `RunHooks.on_tool_start` cannot deny; a handoff cannot be vetoed | 5 |
| **Google ADK** 2.7 | `sub_agents=[…]` + `transfer_to_agent`, `AgentTool`, `mode='task'` sub-agents | `BasePlugin.before_agent_callback` (covers all three primitives; `mode='task'` never fires a tool callback) | `BasePlugin.before_tool_callback` (`google/adk/plugins/base_plugin.py`; runs at `flows/llm_flows/functions.py` before the tool, a returned dict short-circuits) | custom `BaseLlm` scripted per agent | `disallow_transfer_to_*` shape the prompt + tool-schema enum only; the 2.x transfer path (`workflow/utils/_transfer_utils.py`) checks tree shape, not the flags; `tool_filter` is per-agent visibility, not parent-relative | 5 |
| **Pydantic AI** 2.31 | documented "agent delegation" (a tool calling `child.run(..., usage=ctx.usage)`) — no framework primitive | construction site: `ctx.deps.delegate(...)` inside the delegating tool | `AbstractCapability.before_tool_execute` (`pydantic_ai/capabilities/abstract.py`; the only path to `toolset.call_tool` — `tool_manager.py`) or `WrapperToolset.call_tool` | `FunctionModel` with scripted `ToolCallPart`s | nothing delegation-aware; `UsageLimits` count/cost only; `FilteredToolset`/`prepare` = visibility | 5 |
| **CrewAI** 1.15 | `allow_delegation=True` → `Delegate work to coworker` tool; hierarchical manager | the delegate tool call, inside the same before-tool hook | `crewai.hooks.register_before_tool_call_hook` on both dispatch paths (`utilities/tool_utils.py`, `agents/crew_agent_executor.py`) — must abort with `HookAborted`: **any other exception is swallowed and the tool runs** (`hooks/dispatch.py`) | `BaseLLM` subclass replaying ReAct / native tool-call text | nothing: the coworker runs with its **own full tool list** (`tools/agent_tools/base_agent_tools.py`), selected by fuzzy role-name match on model output; `guardrail=` validates task *output*; events/callbacks are post-hoc | 5 |
| **AutoGen** (`autogen-agentchat`) 0.7 | `Swarm` + `Handoff`, `AgentTool`/`TeamTool` | `Handoff.handoff_tool` override (`GuardedHandoff`) — handoffs bypass the workbench (`_assistant_agent.py`) | `StaticStreamWorkbench.call_tool` **and** `call_tool_stream` (the agent loop takes the stream branch) | `ReplayChatCompletionClient` with `FunctionCall`s (needs `ModelInfo(function_calling=True)`) | nothing: `Handoff` has target/description/name/message; receiver offers its own full tool list; intervention handlers cannot see tool calls | 4 |
| **Claude Agent SDK** 0.2 | subagents: `ClaudeAgentOptions(agents={…: AgentDefinition})`, invoked via the built-in `Agent` (né `Task`) tool | `SubagentStart` hook (+ the parent's `Agent` `PreToolUse`) | `PreToolUse` hook → `permissionDecision: "deny"`; `agent_id` on the tool event correlates the call to its subagent (the only framework here that ships that) | none exists (the SDK drives the Claude Code CLI); tests drive the hook functions with the CLI's real payload shapes; **live-verified** on a logged-in Claude Code session (see the example README) | **real, code-enforced** per-subagent tool allowlist (`AgentDefinition.tools`/`disallowedTools`) and absolute hook denies — but no argument-level ceilings, no child ⊆ parent relation, no revocation; `can_use_tool` is silently skipped for auto-approved tools; a parent in `bypassPermissions` overrides every subagent's mode | 5 |
| **smolagents** 1.26 | `managed_agents=[…]` (a managed agent is duck-typed into a tool; `MultiStepAgent.__call__`) | construction site (`DelegatedAgent` proxy in `managed_agents`) — no framework hook | `Tool.forward` via a `Tool` subclass (`GuardedTool`) — one hook covers `ToolCallingAgent` **and** `CodeAgent`'s sandbox; `step_callbacks` fire *after* the step | scripted `Model` returning `ChatMessageToolCall`s | nothing: managed agents keep their own tool list; only `additional_authorized_imports` (sandbox import allowlist, per-agent, not parent-relative) is code-enforced | 4 |
| **AWS Strands** 1.52 | agents-as-tools (`Agent.as_tool`), `Swarm` (`handoff_to_agent` injected into every node), `Graph` | `BeforeToolCallEvent` (agent-tool) / `BeforeNodeCallEvent` (swarm/graph) with `cancel_node` | `BeforeToolCallEvent` → `event.cancel_tool = reason` (checked before the executor runs the tool); also exposed as a Strands `InterventionHandler` | custom `Model` emitting scripted tool-use stream events | **real, code-enforced** per-agent tool registry, `interventions` (`Deny/Confirm/Guide/Transform`), Cedar policies — all per-agent/static; nothing relative to the caller; `Swarm` lets any node hand off to any node | 5 |
| **LlamaIndex** 0.14 | `AgentWorkflow(agents=[FunctionAgent(can_handoff_to=[…])])` with the injected `handoff` tool | wrap the `handoff` tool in `GuardedAgentWorkflow.get_tools()`; a refused delegation clears `next_agent` | `guarded_tool(fn, scope=…)` — a `FunctionTool` wrapper receiving the live `Context`; raises before the body; `_call_tool` turns it into `ToolOutput(is_error=True)` | `MockFunctionCallingLLM` with scripted `ToolCallBlock`s | `can_handoff_to` restricts *routing*, not authority; the target runs with its own tool list | 4 |
| **Semantic Kernel** 1.36 | `HandoffOrchestration` (`Handoff-transfer_to_<Target>` functions per edge), agent-as-plugin | `AUTO_FUNCTION_INVOCATION` filter on the transfer function (SK's own handoff idiom) | `FUNCTION_INVOCATION` filter — not awaiting `next(context)` provably stops the body; covers auto tool-calling **and** direct `kernel.invoke` | scripted `ChatCompletionClientBase` with `FunctionCallContent`s | nothing parent-relative; note `Kernel.clone()` deep-copies plugins *and* filters (filters must be closures; state must not live in plugins) | 4 |
| **Agno** 2.9 | `Team(members=[…])` — leader delegates via a generated `delegate_task_to_member` tool (hands over a task string) | `Team(tool_hooks=[…])` on the delegate function | `Agent(tool_hooks=[…])` — a hook that never calls `function_call(**args)` prevents the body (Agno sanitizes injected args *before* hooks "so a hook used as an authorization gate" is sound); `pre_hooks` are input guardrails, not tool gates | scripted `Model` returning tool calls | nothing: members keep their own tools, may hold **more** than the leader; leader `tool_hooks` don't propagate to members | 5 |

*Fit = how well the framework's official hooks carry an authorization decision (1–5). Twelve frameworks, twelve offline test suites, 213 tests; the Claude Agent SDK integration was additionally verified live.*

## Denial semantics — one decision every adapter makes

`Guard.check()` returns a `Decision`; the adapter decides what the *framework* sees:

- **Return the denial to the model as a failed tool result** (default in most adapters:
  `ToolMessage(status="error")`, `ToolFailed`, `reject_content`, `ToolResult(is_error=True)`,
  ADK's error dict): the run continues, the model is told *why* and can recover. The tool
  body still never runs.
- **Raise** (`AuthorityDenied` or the framework's own tripwire): the run aborts. Use for
  hard-stop policies. Every adapter exposes this as a one-word switch (`on_deny="raise"`).

Either way the denial lands on the hash-chained audit log with a reason code, and
`dg view` renders it in the delegation tree — that is the only place a *sub-agent's*
blocked call surfaces in frameworks (deepagents, AutoGen) that collapse the child's
transcript into a single message for the parent.

## What we learned that shaped the library (v0.3)

- `strict_metering=True` only refused an *entirely empty* context; a partial context that
  forgot one metered dimension silently skipped that ceiling. Now checked per ceiling
  (`ctx_field_of`, `is_metered` in `ceilings.py`).
- Adapters need to refuse things *upstream* of policy (an agent the chain never delegated
  to, an unmapped tool). `ReasonCode.NO_AUTHORITY` + `Guard.record_denial(...)` put those on
  the same audit trail.
- `Guard.agent_id`, `Guard.is_revoked`, `Guard.is_expired` — read-only state every registry
  and UI wanted.
- **`revoke()` was node-scoped**: a framework that re-hands-off to a revoked agent (swarm
  ping-pong, a second `as_tool()` call) minted it a fresh, clean child from the still-valid
  parent; two adapters had to keep their own "revoked names" set. `Guard.revoke_agent(agent_id)`
  revokes the principal chain-wide (every node it holds, plus a grow-only ban that makes any
  later `delegate()` to it fail with `agent_banned`) in one auditable event.
- `Guard.would_delegate(agent_id, request)` — dry-run of the delegation preconditions
  (revoked/expired parent, banned agent, depth/fanout) with no node created and no audit write,
  so a hook can pre-flight a handoff before it cancels a whole swarm.
- The tool→scope map is the integrator's job and the only real work (~10 minutes once you
  know your tools). Adapters default to **fail-closed** on an unmapped tool.
- Frameworks run parallel tool calls on thread pools (smolagents, ADK): concurrent `check()`s
  could interleave the hash-chain append and make `verify()` reject the library's own log.
  The audit log, sequence clock and chain mutations are now serialised per chain
  (`ts` and `seq` advance together).
- `Ceiling.describe()` / `Authority.describe()` and `ReasonCode.{CHAIN_REVOKED, AGENT_BANNED,
  TTL_EXPIRED, MAX_DEPTH, MAX_FANOUT, CHAIN_CEILING}` — every adapter demo had re-invented the
  first; every adapter had a lookup table for the second.

## Running one

```bash
pip install -e '.[openai-agents]'             # extras: langchain, deepagents, openai-agents, google-adk,
                                              # pydantic-ai, crewai, autogen, claude-agent-sdk, smolagents,
                                              # strands, llama-index, semantic-kernel, agno
python examples/integrations/openai_agents/demo.py
python -m pytest -q tests/integrations/test_openai_agents.py
```

```python
from delegation_guard.adapters.openai_agents import GuardRegistry, DelegationGuardHooks, guarded_tool
```

Each directory's `README.md` lists the exact hooks, the version tested, and an
env-gated `live_smoke.py` (`RUN_LIVE=1` + your provider key) that replays the same
story against a real model.
