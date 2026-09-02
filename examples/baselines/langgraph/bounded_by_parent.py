"""Baseline + hand-rolled fix for the dev.to post. Uses the recipe's scripted model and tools; no attenu_guard in the fix."""
import sys, importlib.util
from pathlib import Path
import langchain, deepagents
from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from deepagents.backends import StateBackend
from deepagents.middleware import SubAgentMiddleware

demo_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("demo", demo_path); demo = importlib.util.module_from_spec(spec); spec.loader.exec_module(demo)

class BoundedByParent(AgentMiddleware):
    """A subagent may call only tools its parent holds. Nothing else."""
    def __init__(self, parent_tools: set[str]):
        self.parent_tools = parent_tools
    def wrap_tool_call(self, request, handler):
        name = request.tool_call["name"]
        if name not in self.parent_tools:
            return ToolMessage(content=f"denied: {name} is not held by the parent",
                               tool_call_id=request.tool_call["id"], status="error")
        return handler(request)

def build(sink, *, bounded: bool):
    tools = {t.name: t for t in demo.make_tools(sink)}
    parent_tool_names = {"write_brief"}
    mw = [BoundedByParent(parent_tool_names)] if bounded else []
    def spec_(name, model):
        return {"name": name, "description": name, "system_prompt": f"You are the {name}.", "model": model,
                "tools": [tools["web_search"], tools["write_brief"]], "middleware": mw}
    subagents = [spec_("writer", demo.ScriptedModel(responses=demo.writer_script()))]
    agent = create_agent(demo.ScriptedModel(responses=demo.supervisor_script(spawn_researcher=False)),
                         tools=[tools["write_brief"]],
                         middleware=[SubAgentMiddleware(backend=StateBackend(), subagents=subagents)])
    return agent

for bounded in (False, True):
    sink = []
    build(sink, bounded=bounded).invoke({"messages": [("user", "Write the Q3 brief.")]})
    print(f"bounded_by_parent={bounded}: tool bodies that ran: {sink}")
import importlib.metadata as md
print("versions:", "langchain", langchain.__version__, "deepagents", md.version("deepagents"))
