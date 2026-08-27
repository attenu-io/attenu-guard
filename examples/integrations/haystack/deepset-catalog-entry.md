---
layout: integration
name: attenu-guard
description: Give each sub-agent only the permissions its task needs, and check every tool call against them
authors:
    - name: Rafael Asor
      socials:
        github: rafaelasor
pypi: https://pypi.org/project/attenu-guard/
repo: https://github.com/attenu-io/attenu-guard
type: Tool Integration
report_issue: https://github.com/attenu-io/attenu-guard/issues
logo: /logos/attenu-guard.png
version: Haystack 2.0
toc: true
---
### **Table of Contents**
- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Overview

A Haystack `AgentTool` wraps a whole `Agent`, and that sub-agent keeps its own tool list —
nothing in the framework relates it to the agent that delegated the work, so a sub-agent can
hold permissions its caller never had. attenu-guard adds that relation. You issue an
`Authority` (a set of scopes, plus ceilings such as a row limit or an egress rank, plus a
TTL) to the top-level agent, and declare what each tool consumes; a delegated sub-agent
receives the *meet* of what it asks for and what its parent holds, so authority can only
shrink down a chain. Every tool call is then checked against the authority of the agent
actually making it, before the tool body runs, and every allow and deny is appended to a
hash-chained log that can be verified offline. The adapter uses Haystack's public
extension points only — it subclasses `Tool` for the `invoke` / `invoke_async` gate, and
implements the `ConfirmationStrategy` protocol for the `before_tool` hook — so no framework
internals are patched. A denial is raised as a `ToolInvocationError`, which means the
Agent's existing `raise_on_tool_invocation_failure` setting decides whether the model is
told and the run continues, or the run stops.

## Installation

```bash
pip install 'attenu-guard[haystack]'
```

## Usage
### Components

This integration introduces no new Haystack components. It adds one module,
`attenu_guard.adapters.haystack`, which wraps the tools you already have:

- `guard_tools(tools, policies)`: returns copies of your tools that authorize before the
  tool body runs. The copy is a subclass of each tool's own class, so `ComponentTool`,
  `AgentTool`, `PipelineTool` and their `inputs_from_state` / `outputs_to_string` behaviour
  are unchanged.
- `ToolPolicy` / `Grant`: what a tool consumes, and — for an `AgentTool` — the authority the
  sub-agent is delegated.
- `authority(guard)`: the context manager that puts a `Guard` in force for a run.
- `attenuation_hook(policies)`: the same decision as a `before_tool` `ConfirmationHook`, if
  you would rather Haystack reject the call in its own rejection shape.

### Delegate to a sub-agent with less authority than the caller

```python
from haystack.components.agents import Agent
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.dataclasses import ChatMessage
from haystack.tools import AgentTool, Tool

from attenu_guard import Authority, EgressRank, Guard, RowLimit
from attenu_guard.adapters.haystack import (
    Grant, ToolPolicy, authority, guard_tools,
)


def crm_query(rows: int) -> str:
    return f"{rows} CRM rows"


def crm_export(destination: str) -> str:
    return f"exported to {destination}"


crm_tools = [
    Tool(
        name="crm_query",
        description="Read rows from the CRM.",
        parameters={"type": "object", "properties": {"rows": {"type": "integer"}}, "required": ["rows"]},
        function=crm_query,
    ),
    Tool(
        name="crm_export",
        description="Export the CRM to an external destination.",
        parameters={
            "type": "object",
            "properties": {"destination": {"type": "string"}},
            "required": ["destination"],
        },
        function=crm_export,
    ),
]

# What each tool consumes. attenu-guard does not decide this for you.
RESEARCHER_POLICIES = {
    "crm_query": ToolPolicy("crm.read", context=lambda args: {"rows": args["rows"]}),
    "crm_export": ToolPolicy("crm.export", context=lambda args: {"egress": "any"}),
}

# The coordinator holds the CRM broadly; the researcher gets a strict subset.
COORDINATOR = Authority(scopes={"crm.*"}, ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600)
RESEARCHER = Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)

researcher = Agent(
    chat_generator=OpenAIChatGenerator(model="gpt-5.4-mini"),
    tools=guard_tools(crm_tools, RESEARCHER_POLICIES),
    system_prompt="Research the CRM pipeline and report back.",
)

coordinator = Agent(
    chat_generator=OpenAIChatGenerator(model="gpt-5.4-mini"),
    tools=guard_tools(
        [AgentTool(agent=researcher, name="research", description="Delegate CRM research.")],
        {"research": ToolPolicy(None, delegates_to="researcher",
                                grant=Grant(RESEARCHER, task="research the Q3 pipeline"))},
    ),
    system_prompt="Delegate research, then report to the user.",
)

root = Guard.issue("coordinator", COORDINATOR, task="quarterly report")
with authority(root):
    result = coordinator.run(messages=[ChatMessage.from_user("Summarise the Q3 pipeline")])

print(result["last_message"].text)

# The researcher may read the CRM but was never granted `crm.export`: if its model asks for
# it, the call is denied before `crm_export` runs, and the denial is on the ledger.
for entry in root.audit_log().entries:
    print(entry["seq"], entry["event"], entry.get("tool"), entry.get("reason", ""))
```

Running the same thing with no API key: the repository ships an offline example under
`examples/integrations/haystack/` that replays a scripted model, plus a pytest suite for
the integration.

### License

attenu-guard is licensed under the Apache License 2.0.
