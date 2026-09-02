# Baselines: what each framework does at a handoff, with no guard installed

One question, asked of each framework with its own delegation mechanism and nothing of ours in the
process: when a parent agent hands work to a sub-agent, can the child call a tool the parent never held?

Each script runs offline with a scripted model, prints the versions it ran against, declares the parent's
and the child's tool sets, and prints which tool bodies actually executed. The `output-<date>.txt` next to
each script is the run behind the corresponding row in the blog post
[Does a sub-agent inherit its parent's permissions? Five frameworks, five answers](https://attenu.io/blog/sub-agent-permissions-five-frameworks/).

| Directory | Framework | Run |
|---|---|---|
| `langgraph/` | LangGraph + Deep Agents | `python examples/baselines/langgraph/bounded_by_parent.py examples/integrations/langgraph/subagent_middleware/demo.py` (unguarded run, then the twelve-line `BoundedByParent` middleware) |
| `crewai/` | CrewAI | `python examples/baselines/crewai/baseline.py` |
| `claude_code/` | Claude Code / Claude Agent SDK | `python examples/baselines/claude_code/baseline.py` (drives the SDK's real command builder; no model call) |
| `openai_agents/` | OpenAI Agents SDK | `python examples/baselines/openai_agents/baseline.py` |
| `google_adk/` | Google ADK | `python examples/baselines/google_adk/baseline.py` |

These are the framework alone. The guarded versions live under `examples/integrations/<framework>/`.
If a framework starts bounding the child by the parent, the corresponding script's expectation fails
and the row in the post gets corrected.
