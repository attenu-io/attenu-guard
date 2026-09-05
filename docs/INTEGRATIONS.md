# Integrations — attenu-guard inside real agent frameworks

Every row below is a **shipped, tested** integration: a thin adapter installed with the
package as `attenu_guard.adapters.<framework>` (enable its framework with
`pip install 'attenu-guard[<extra>]'`; the core stays zero-dependency — a framework is
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
| **Pydantic AI** 2.31 | documented "agent delegation" (a tool calling `child.run(..., usage=ctx.usage)`) — no framework primitive | construction site: `ctx.deps.delegate(...)` inside the delegating tool | `GuardedToolsetCapability` — an `AbstractCapability` contributing one `WrapperToolset` (`pydantic_ai/toolsets/wrapper.py`) ordered `position="innermost"`, so its `call_tool` is the innermost check in the toolset chain; or `AbstractCapability.wrap_tool_execute` (`pydantic_ai/capabilities/abstract.py`; the only path to `toolset.call_tool` — `tool_manager.py`), which stops the body on a denial but sits above every wrapper toolset | `FunctionModel` with scripted `ToolCallPart`s | nothing delegation-aware; `UsageLimits` count/cost only; `FilteredToolset`/`prepare` = visibility | 5 |
| **CrewAI** 1.15 | `allow_delegation=True` → `Delegate work to coworker` tool; hierarchical manager | the delegate tool call, inside the same before-tool hook | `crewai.hooks.register_before_tool_call_hook` on both dispatch paths (`utilities/tool_utils.py`, `agents/crew_agent_executor.py`) — must abort with `HookAborted`: **any other exception is swallowed and the tool runs** (`hooks/dispatch.py`) | `BaseLLM` subclass replaying ReAct / native tool-call text | nothing: the coworker runs with its **own full tool list** (`tools/agent_tools/base_agent_tools.py`), selected by fuzzy role-name match on model output; `guardrail=` validates task *output*; events/callbacks are post-hoc | 5 |
| **AutoGen** (`autogen-agentchat`) 0.7 | `Swarm` + `Handoff`, `AgentTool`/`TeamTool` | `Handoff.handoff_tool` override (`GuardedHandoff`) — handoffs bypass the workbench (`_assistant_agent.py`) | `StaticStreamWorkbench.call_tool` **and** `call_tool_stream` (the agent loop takes the stream branch) | `ReplayChatCompletionClient` with `FunctionCall`s (needs `ModelInfo(function_calling=True)`) | nothing: `Handoff` has target/description/name/message; receiver offers its own full tool list; intervention handlers cannot see tool calls | 4 |
| **Microsoft Agent Framework** 1.15 (the AutoGen + Semantic Kernel successor) | `Agent.as_tool()`; `handoff_to_<target>` tools in handoff orchestration; workflow `AgentExecutor` participants | the same function middleware, on the delegating tool — `as_tool` returns a plain `FunctionTool` (`_agents.py:718`) whose body starts the sub-agent (`:694`); handoff edges are `handoff_to_<id>` tools (`agent_framework_orchestrations/_handoff.py:124`) and their own `_AutoHandoffMiddleware` is *appended* (`:269`), so the guard runs first | `FunctionMiddleware.process` — the body is reachable only through `final_wrapper` in `FunctionMiddlewarePipeline.execute` (`_middleware.py:1126-1163`); one registration covers the non-streaming (`_tools.py:3174`) and streaming (`:3337`) loops, which share one pipeline (`:3628-3634`) | none shipped — a `ScriptedChatClient` composing `FunctionInvocationLayer`/`ChatMiddlewareLayer` over `BaseChatClient`, as the real providers do (`agent_framework_openai/_chat_client.py:3430-3434`) | nothing parent-relative: a sub-agent keeps its own tool list and may hold more than its parent; `approval_mode="always_require"` is per-tool and static; `security.py` is information-flow labelling, not authority; **middleware does not propagate into sub-agents** — install the guard on every agent | 5 |
| **AG2** 1.0 (the AutoGen fork; package `ag2`, a rewrite) | `Agent.as_tool()` → `task_<agent>`; `tasks=TaskConfig(...)` → `run_subtask`; `background_agent_tool`; the `ag2.network` `delegate` tool | the same tool-execution hook, on the delegating tool — every handover in AG2 1.0 is a `@tool` (`ag2/tools/subagents/subagent_tool.py:45-68`, `ag2/agent.py:1673-1706`) | `BaseMiddleware.on_tool_execution` (`ag2/middleware/base.py:105`), folded around the tool at `ag2/tools/final/function_tool.py:120-124` and consumed at `:127-128`; plus per-tool `ToolMiddleware` (`:97-104`), which is the only hook that reaches a `TaskConfig` child | `ag2.testing.TestConfig` replaying scripted `ToolCallEvent`s (shipped) | nothing parent-relative: `TaskConfig.include_tools/exclude_tools` filter inheritance and `extra_tools` can give a child *more* than its parent (`ag2/agent.py:110-112`, `:1709-1730`); recursion is blocked by `tasks=False` on the spawned child (`:1468`); **agent middleware does not propagate into sub-agents** (`run_task.py:141,147`; `agent.py:1463-1469`); `ag2.network` limits are hub-enforced (`network/hub/arbiter.py:245-324`) | 5 |
| **Claude Agent SDK** 0.2 | subagents: `ClaudeAgentOptions(agents={…: AgentDefinition})`, invoked via the built-in `Agent` (né `Task`) tool | `SubagentStart` hook (+ the parent's `Agent` `PreToolUse`) | `PreToolUse` hook → `permissionDecision: "deny"`; `agent_id` on the tool event correlates the call to its subagent (the only framework here that ships that) | none exists (the SDK drives the Claude Code CLI); tests drive the hook functions with the CLI's real payload shapes; **live-verified** on a logged-in Claude Code session (see the example README) | **real, code-enforced** per-subagent tool allowlist (`AgentDefinition.tools`/`disallowedTools`) and absolute hook denies — but no argument-level ceilings, no child ⊆ parent relation, no revocation; `can_use_tool` is silently skipped for auto-approved tools; a parent in `bypassPermissions` overrides every subagent's mode | 5 |
| **smolagents** 1.26 | `managed_agents=[…]` (a managed agent is duck-typed into a tool; `MultiStepAgent.__call__`) | construction site (`DelegatedAgent` proxy in `managed_agents`) — no framework hook | `Tool.forward` via a `Tool` subclass (`GuardedTool`) — one hook covers `ToolCallingAgent` **and** `CodeAgent`'s sandbox; `step_callbacks` fire *after* the step | scripted `Model` returning `ChatMessageToolCall`s | nothing: managed agents keep their own tool list; only `additional_authorized_imports` (sandbox import allowlist, per-agent, not parent-relative) is code-enforced | 4 |
| **AWS Strands** 1.52 | agents-as-tools (`Agent.as_tool`), `Swarm` (`handoff_to_agent` injected into every node), `Graph` | `BeforeToolCallEvent` (agent-tool) / `BeforeNodeCallEvent` (swarm/graph) with `cancel_node` | `BeforeToolCallEvent` → `event.cancel_tool = reason` (checked before the executor runs the tool); also exposed as a Strands `InterventionHandler` | custom `Model` emitting scripted tool-use stream events | **real, code-enforced** per-agent tool registry, `interventions` (`Deny/Confirm/Guide/Transform`), Cedar policies — all per-agent/static; nothing relative to the caller; `Swarm` lets any node hand off to any node | 5 |
| **LlamaIndex** 0.14 | `AgentWorkflow(agents=[FunctionAgent(can_handoff_to=[…])])` with the injected `handoff` tool | wrap the `handoff` tool in `GuardedAgentWorkflow.get_tools()`; a refused delegation clears `next_agent` | `guarded_tool(fn, scope=…)` — a `FunctionTool` wrapper receiving the live `Context`; raises before the body; `_call_tool` turns it into `ToolOutput(is_error=True)` | `MockFunctionCallingLLM` with scripted `ToolCallBlock`s | `can_handoff_to` restricts *routing*, not authority; the target runs with its own tool list | 4 |
| **Semantic Kernel** 1.36 | `HandoffOrchestration` (`Handoff-transfer_to_<Target>` functions per edge), agent-as-plugin | `AUTO_FUNCTION_INVOCATION` filter on the transfer function (SK's own handoff idiom) | `FUNCTION_INVOCATION` filter — not awaiting `next(context)` provably stops the body; covers auto tool-calling **and** direct `kernel.invoke` | scripted `ChatCompletionClientBase` with `FunctionCallContent`s | nothing parent-relative; note `Kernel.clone()` deep-copies plugins *and* filters (filters must be closures; state must not live in plugins) | 4 |
| **Agno** 2.9 | `Team(members=[…])` — leader delegates via a generated `delegate_task_to_member` tool (hands over a task string) | `Team(tool_hooks=[…])` on the delegate function | `Agent(tool_hooks=[…])` — a hook that never calls `function_call(**args)` prevents the body (Agno sanitizes injected args *before* hooks "so a hook used as an authorization gate" is sound); `pre_hooks` are input guardrails, not tool gates | scripted `Model` returning tool calls | nothing: members keep their own tools, may hold **more** than the leader; leader `tool_hooks` don't propagate to members | 5 |
| **Haystack** (deepset `haystack-ai`) 3.1 | `AgentTool` — a `ComponentTool` wrapping a whole `Agent` (`haystack/tools/agent_tool.py`) | the `AgentTool` call itself: Haystack has no separate delegation callback, so the delegation moment *is* a tool invocation; the child `Guard` rides a `ContextVar` for the sub-run (a turn's parallel calls each get their own `copy_context()`, so a fan-out is siblings, not a chain) | `Tool.invoke` / `Tool.invoke_async` via a subclass of the tool's **own** class (`tools/tool.py`; the only paths out of the run loop — `components/agents/tool_calling.py`), keeping `isinstance(tool, ComponentTool)` and the `inputs_from_state`/`outputs_to_string` machinery intact; alternatively a `ConfirmationStrategy` under `ConfirmationHook` at the `before_tool` hook point (`hooks/human_in_the_loop/hooks.py`, run before `_run_tool` in `agent.py`) | a scripted `ChatGenerator` component replaying `ToolCall`s | nothing: a sub-agent behind an `AgentTool` keeps its **own** tool list and may hold tools its caller lacks (pinned as `test_haystack_itself_does_not_attenuate_a_sub_agent`); the shipped `ConfirmationHook` is a per-tool human veto, not parent-relative | 5 |
| **CAMEL-AI** 0.2.90 | `AgentToolkit.agent_run_subagent` (`toolkits/agent_toolkit.py:286`) — a persistent sub-agent per session; `Workforce` posts tasks to workers over a channel (`societies/workforce/workforce.py:4071`) | the delegation call itself, via a `GuardedAgentToolkit` subclass — no framework hook fires at handoff | `FunctionTool` subclass overriding **both** `__call__` (`toolkits/function_tool.py:613`) and `async_call` (`:700`), the two ends of every path: `ChatAgent._execute_tool` `tool(**args)` (`chat_agent.py:4048`), `_aexecute_tool`'s `tool.func.async_call` → `tool.async_call` ladder (`:4093-4099`), and the streaming twins (`:5031`, `:5165-5172`) | scripted `BaseModelBackend` returning `ChatCompletion`s with tool calls | nothing: `_create_subagent` (`agent_toolkit.py:161`) builds the child from `ChatAgent._clone_tools()` (`chat_agent.py:6183`) — a copy of the parent's **whole** toolset, `agent_run_subagent` included, so the child can delegate onward with everything too; a Workforce worker's tools are fixed at construction, not per assignment | 4 |
| **A2A** (Agent2Agent protocol) — `a2a-sdk` 1.1.2 | the HOP itself: `message:send` to a remote agent in another process (A2A has no in-process sub-agent primitive) | client side — `ClientCallInterceptor.before` (`a2a/client/interceptors.py:46`, run by `BaseClient._intercept_before` `base_client.py:460`) mints the child with `parent.delegate(...)` and puts the signed Delegation Chain on the message as an A2A **extension** (`Message.extensions` + `Message.metadata[<uri>]`, spec §4.6.2, plus the `A2A-Extensions` header §4.6.1) | server side — `GuardedAgentExecutor` wraps `AgentExecutor.execute` (`a2a/server/agent_execution/agent_executor.py:15`), verifies the chain offline (`wire.load`) and mints the served `Guard` from the leaf; `guarded_tool(fn, scope=…)` checks before each tool body via a `ContextVar` | no model needed: the remote agent's plan is scripted; both halves run over `InProcessTransport`, an implementation of the SDK's public `ClientTransport` ABC — and over real HTTP in `live_smoke.py` (Starlette + uvicorn, verified) | nothing: **§7.6.4 says so explicitly** — "the A2A protocol does not define the scope, representation, validity, or revocation semantics of the authorization decision or credential"; §7.6.3 notes in-band credentials are exposed to every agent in a chain. Per-hop authentication and the Agent Card are real and this stands on them | 5 |

*Fit = how well the framework's official hooks carry an authorization decision (1–5). Seventeen entries, seventeen offline test suites; the Claude Agent SDK integration was additionally verified live against a real session, and the A2A one over a real HTTP hop.*

Beyond the matrix: a **Langflow** custom component (`examples/integrations/langflow/`, 25 offline
tests) — Langflow is a visual builder, so the unit there is a component in the editor rather
than an adapter module. See the section below.

## Why these seventeen

Selection criteria (August 2026): (1) a Python framework with an **explicit delegation /
handoff / sub-agent primitive** — the moment attenu-guard exists to guard; (2) coverage of
every major vendor's agent stack (OpenAI, Google, Microsoft ×2, AWS, Anthropic, Hugging Face,
LangChain) plus the leading independents (CrewAI, Pydantic AI, LlamaIndex, Agno); (3) an
**offline test path** (mock/scripted model) so the integration test can run in CI with no
API key; (4) at least one real multi-agent *application*, not just a framework (deepagents).
GitHub stars at selection: CrewAI 57k · AutoGen 60k (in maintenance since 2026-04, superseded by
Microsoft Agent Framework) · LlamaIndex 52k · Agno 42k · LangGraph 40k · smolagents 29k ·
OpenAI Agents SDK 29k · Semantic Kernel 28k · deepagents 28k · Haystack 26k · ADK 21k ·
Pydantic AI 19k · Claude Agent SDK 8k · Strands 7k. Added later (August 2026): Haystack (3.x shipped
`AgentTool`, a delegation primitive), CAMEL-AI (`AgentToolkit`/`Workforce` proved hookable), and both AutoGen
successors — Microsoft Agent Framework (AutoGen + Semantic Kernel) and AG2 1.0 (the AutoGen fork; a rewrite whose
package is `ag2`, not `autogen`); AutoGen itself has been in maintenance since 2026-04, so its adapter now has two
live successors beside it. Added after those: **A2A** — a protocol rather than a framework, but its hop IS a delegation, and
spec §7.6.4 states outright that the protocol defines no scope or revocation semantics for an in-task
authorization decision, so the adapter supplies them through A2A's own extension mechanism (§4.6). MCP
remains a *recipe* rather than an adapter (below), because there the server is the resource, not a
delegate. Deliberately not (yet): MetaGPT/ChatDev/AutoGPT (research/app-shaped, weak offline story), Letta
(no delegation primitive), Dify/Flowise/n8n (not Python-embeddable), and every non-Python stack (see "Other languages").

**Also added (August 2026):** a Langflow custom component (below — Langflow is a visual builder, so the unit is a
component in the editor rather than an adapter module).

## Status of the framework findings

Nothing above has been reported upstream yet (this repository is private). Each finding is
pinned as an executable **baseline test** in `tests/integrations/` (e.g.
`test_autogen_itself_does_not_attenuate`, deepagents' `permissions`-replace test), so the weekly
unpinned `integrations-latest` job will flag the day a framework changes the behaviour — e.g. Google ADK's
`disallow_transfer_to_peers`: upstream fixed #3850 on the legacy `llm_flows` path (`fa18d26a`, in 2.7.1), but the 2.x
default workflow path (`workflow/utils/_transfer_utils.py`) still has no check — the pinned test asserts the transfer
goes through on 2.7.1 and carries the message that will fire the day it stops. When the project goes public the intent is to
file each as a constructive upstream issue with the repro and a suggested fix (child ⊆ parent
"meet" semantics; fail-closed hook dispatch), and to keep this document as the citation.

## Langflow — the visual builder

Langflow composes flows in a browser rather than in Python, so the unit of integration is a
**custom component** you drop into the editor, not an adapter module:
[`examples/integrations/langflow/attenu_guard_component.py`](../examples/integrations/langflow/).

Langflow tools are LangChain `BaseTool`s, so hook (2) is the same funnel as the LangChain
adapter's: `BaseTool.invoke` -> `run` -> `_run`, wrapped with a
`langchain_core.tools.StructuredTool` that authorizes and only then calls
`inner.invoke(...)`, mirroring `name` / `description` / `args_schema`. Hook (1) is an **edge in
the flow**: the component exposes its `Guard` as an output and accepts one on a `Parent
Authority` input, and connecting them mints the downstream agent's authority with
`parent.delegate(...)`. Two chained components is a delegation whose child can only be
narrower, drawn rather than coded.

The component also emits an `Evidence` output — the delegation graph, the audit log, and the
result of re-verifying it — so a flow's authorization history is inspectable from inside the
editor. Tested against lfx 1.11.5 / langchain-core 1.5; the parsing and wrapping half of the
test suite runs with Langflow absent.

## commerce-agents — the delegate contract

[`anthropics/commerce-agents`](https://github.com/anthropics/commerce-agents) is an application
rather than a framework, so this is a **recipe** — a paste-in adapter beside the demo, not a
shipped `attenu_guard.adapters` module:
[`examples/integrations/commerce-agents/`](../examples/integrations/commerce-agents/). Its packages
are not on any index (its own CI asserts that), so the test skips unless the repo is installed from
a clone, and the `integrations` CI matrix, which installs every framework from PyPI, does not carry
it.

Both hooks land on one method, over a seam the repo already documents.
`BaseToolExecutor.dispatch` (`commerce-common/commerce_common/execution.py:225-243`) routes
presentation, delegates and handlers by name for every path the repo ships — so hook (2) is one
override of that method, and hook (1) is the same override recognising a delegate name and calling
`parent.delegate(...)` there. The override arrives as a subclass through `executor_class`, "the seam
for a deployment's own `MerchantToolExecutor` subclass"
(`merchant-agent/runtime-messages-api/merchant_agent_runtime/orchestrator.py:86-87`), which the
Messages API orchestrator, the Agent SDK toolset and the MCP server all accept — upstream's own
`test_every_path_takes_a_deployments_own_executor_class` holds them to it. Nothing is patched.

One path does not carry that seam: `AnalysisRunner._read` names `MerchantToolExecutor` inside the
method (`analysis.py:332-339`) rather than the deployment's class, so the delegate's own reads fall
outside it. The child guard rides a `contextvars` binding, and a process-wide `install()` is what
reaches that instance today. **commerce-agents is a reference implementation that does not accept
contributions** (its `README.md:193`), so the "Status of the framework findings" intent above does
not apply here and nothing is filed upstream: the example README states the change that would close
the gap — threading `executor_class` one level further — as a diff verified to apply and pass their
own analysis tests, for a reader who vendors or forks the packages.

What the repo enforces about a delegate's authority: the contract is stated in prose
(`commerce-common/commerce_common/delegation.py:4-6` — a delegate "cannot write, present, or invoke
other delegates") and held by the shipped delegate's own tool list and a name test in its runner
(`analysis.py:361`). The executor that delegate constructs carries the full handler table and the
presentation components regardless, so a second delegate written the same way reaches both; the
example's act 3 runs one and shows all three bodies executing unguarded. Ceilings are per-deployment,
not per-caller: `MerchantAgentConfig.max_campaign_budget` is one number the delegate shares through
`DelegationContext.config`. Offline model: the repo's own `commerce_common.testing.FakeCreateClient`,
which drives the real `AnalysisRunner`.

## Other languages

The wire format (`attenu_guard.wire`: signed JWS Delegation Tokens, offline
child ⊆ parent verification) is the language-neutral contract, and `tests/vectors/` +
`scenarios/*.json` are its conformance suite. A TypeScript port of the core is the natural
next language (Vercel AI SDK, LangGraph.js, OpenAI Agents JS, Claude Agent SDK TS, the MCP TS
SDK); Go/Java/.NET follow the same recipe: port the core against the vectors, then thin
adapters at the same two hook points. Authority crosses a language boundary as a token, never
as a network call on the deny path.

## Denial semantics — one decision every adapter makes

`Guard.check()` returns a `Decision`; the adapter decides what the *framework* sees:

- **Return the denial to the model as a failed tool result** (default in most adapters:
  `ToolMessage(status="error")`, `ToolFailed`, `reject_content`, `ToolResult(is_error=True)`,
  ADK's error dict): the run continues, the model is told *why* and can recover. The tool
  body still never runs.
- **Raise** (`AuthorityDenied` or the framework's own tripwire): the run aborts. Use for
  hard-stop policies. Every adapter exposes this as a one-word switch (`on_deny="raise"`).

Either way the denial lands on the hash-chained audit log with a reason code, and
`attenu-guard view` renders it in the delegation tree — that is the only place a *sub-agent's*
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
from attenu_guard.adapters.openai_agents import GuardRegistry, DelegationGuardHooks, guarded_tool
```

Each directory's `README.md` lists the exact hooks, the version tested, and an
env-gated `live_smoke.py` (`RUN_LIVE=1` + your provider key) that replays the same
story against a real model.
