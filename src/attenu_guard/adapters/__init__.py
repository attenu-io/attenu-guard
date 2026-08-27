"""
attenu_guard.adapters — thin, optional framework integrations.

Each submodule wraps ONE framework's delegation + tool-invocation hooks around
the core `Guard` surface (docs/DEVX-REVIEW.md principle 7: "framework-agnostic
core, thin adapters"). Nothing here is imported by the core package, and this
`__init__` imports nothing — so `attenu_guard` stays zero-dependency, and a
framework is only imported when YOU import its adapter:

    from attenu_guard.adapters.openai_agents import GuardRegistry, guarded_tool
    # -> needs `pip install 'attenu-guard[openai-agents]'`

Available (see docs/INTEGRATIONS.md for hooks, versions and evidence):

    langgraph        guard_node / DelegatedToolNode — hand-written LangGraph nodes
                     (importable with NO langgraph installed; lazy imports only)
    langchain        ToolPolicy / GuardedDelegation — LangGraph ToolNode(wrap_tool_call),
                     LangChain create_agent middleware, deepagents sub-agents
    openai_agents    GuardRegistry / DelegationGuardHooks / guarded_tool — handoffs, agents-as-tools
    google_adk       DelegationGuardPlugin — sub_agents/transfer_to_agent, AgentTool, task mode
    pydantic_ai      DelegationGuard (capability) / GuardedToolset — agent delegation
    crewai           CrewAIGuardBridge — allow_delegation / hierarchical crews
    autogen          GuardedWorkbench / GuardedHandoff — Swarm handoffs, AgentTool
    agent_framework  DelegationGuard (function middleware) — Microsoft Agent Framework:
                     Agent.as_tool, handoff orchestration
    ag2              DelegationGuard / guarded_tools — AG2 1.0: Agent.as_tool,
                     TaskConfig subtasks
    claude_sdk       DelegationGuardRegistry — subagents via PreToolUse/SubagentStart hooks
    smolagents       GuardedTool / DelegatedAgent — managed_agents
    strands          hooks + InterventionHandler — agents-as-tools, Swarm, Graph
    llama_index      GuardedAgentWorkflow / guarded_tool — AgentWorkflow handoffs
    semantic_kernel  attach_guard — HandoffOrchestration via kernel filters
    agno             tool_hooks — Team member delegation

Each has a runnable offline demo under examples/integrations/<name>/ and a test
under tests/integrations/ that runs with the framework's own mock model.
"""
