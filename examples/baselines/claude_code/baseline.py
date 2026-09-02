"""Claude Agent SDK baseline: does a subagent's tool grant get intersected with its parent's?

Offline. No model call, no network, no API key. It drives the *real* installed
claude_agent_sdk serialisation code paths and prints exactly what the SDK hands to the
Claude Code CLI, so the question "is there a client-side narrowing step?" is answered by
observation rather than by reading.

Run with a python that has claude_agent_sdk installed:
    python script.py
"""

from __future__ import annotations

import datetime
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict

import claude_agent_sdk
from claude_agent_sdk import AgentDefinition, ClaudeAgentOptions
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport
from claude_agent_sdk.types import (  # noqa: PLC2701
    _get_can_use_tool_shadowed_warning,
)


def rule(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


rule("VERSIONS")
cli = shutil.which("claude")
cli_version = "not on PATH"
if cli:
    cli_version = subprocess.run(
        [cli, "--version"], capture_output=True, text=True, timeout=30
    ).stdout.strip()
print(f"date                 {datetime.date.today().isoformat()}")
print(f"python               {platform.python_version()}")
print(f"claude_agent_sdk     {claude_agent_sdk.__version__}")
print(f"claude code CLI      {cli_version}")

# ---------------------------------------------------------------------------
# The setup. The parent is deliberately narrow; the child deliberately asks for more.
# ---------------------------------------------------------------------------
PARENT_BASE_TOOLS = ["Read", "Grep", "Glob", "Agent"]
PARENT_ALLOWED = ["Read", "Grep", "Glob", "Agent"]
CHILD_TOOLS = ["Read", "Bash", "WebFetch"]  # Bash and WebFetch are NOT the parent's

options = ClaudeAgentOptions(
    tools=PARENT_BASE_TOOLS,  # the base set of tools available to the session
    allowed_tools=PARENT_ALLOWED,  # the auto-approve rules
    permission_mode="default",  # parent runs in Manual mode
    agents={
        "widener": AgentDefinition(
            description="A subagent that asks for more than its parent holds.",
            prompt="You are a subagent.",
            tools=CHILD_TOOLS,
            permissionMode="bypassPermissions",  # child asks for a LOOSER mode
        )
    },
)

rule("WHAT WAS DECLARED")
print(f"parent  options.tools        = {PARENT_BASE_TOOLS}")
print(f"parent  options.allowed_tools= {PARENT_ALLOWED}")
print(f"parent  permission_mode      = default (Manual)")
print(f"child   AgentDefinition.tools= {CHILD_TOOLS}")
print(f"child   permissionMode       = bypassPermissions")
print(f"child asks for tools the parent does not list: "
      f"{sorted(set(CHILD_TOOLS) - set(PARENT_BASE_TOOLS))}")

# ---------------------------------------------------------------------------
# 1. The argv the SDK builds. This is verbatim SDK code (_build_command).
# ---------------------------------------------------------------------------
rule("1. THE ARGV THE SDK BUILDS FOR THE CLI (real _build_command)")
transport = SubprocessCLITransport(prompt="unused", options=options)
transport._cli_path = cli or "claude"  # normally resolved in connect()
argv = transport._build_command()
# Print without the resolved binary path.
print(json.dumps(["<claude>"] + argv[1:], indent=2))

# ---------------------------------------------------------------------------
# 2. The agents payload sent in the initialize request. Verbatim from
#    _internal/client.py: {k: v for k, v in asdict(agent_def).items() if v is not None}
# ---------------------------------------------------------------------------
rule("2. THE `agents` PAYLOAD IN THE initialize REQUEST (real conversion)")
agents_dict = {
    name: {k: v for k, v in asdict(agent_def).items() if v is not None}
    for name, agent_def in options.agents.items()
}
initialize_request = {"subtype": "initialize", "agents": agents_dict}
print(json.dumps(initialize_request, indent=2))

# ---------------------------------------------------------------------------
# 3. The question. Did anything narrow the child against the parent?
# ---------------------------------------------------------------------------
rule("3. DID THE SDK NARROW THE CHILD AGAINST THE PARENT?")
sent_child_tools = agents_dict["widener"]["tools"]
sent_child_mode = agents_dict["widener"]["permissionMode"]
print(f"child tools as DECLARED  : {CHILD_TOOLS}")
print(f"child tools as SENT      : {sent_child_tools}")
print(f"identical                : {sent_child_tools == CHILD_TOOLS}")
print(f"child mode as DECLARED   : bypassPermissions")
print(f"child mode as SENT       : {sent_child_mode}")
print()
print("The parent's own limits travel on a DIFFERENT channel:")
print(f"  --tools        -> {argv[argv.index('--tools') + 1]!r}")
print(f"  --allowedTools -> {argv[argv.index('--allowedTools') + 1]!r}")
print("The child's tool list travels inside the initialize request, untouched.")
print()
print("VERDICT (SDK layer): the SDK performs NO intersection. A tool the parent")
print("does not list is forwarded verbatim in the child's grant. Whether the CLI")
print("then refuses it is decided inside the CLI, which this script cannot see.")

# ---------------------------------------------------------------------------
# 4. Corroboration: grep the installed package for any intersection at all.
# ---------------------------------------------------------------------------
rule("4. IS THERE INTERSECTION CODE ANYWHERE IN THE INSTALLED PACKAGE?")
import pathlib
import re

pkg = pathlib.Path(claude_agent_sdk.__file__).parent
pattern = re.compile(r"intersection|issubset|\bintersect\b|set\([^)]*allowed_tools")
hits = []
for path in sorted(pkg.rglob("*.py")):
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if pattern.search(line):
            hits.append(f"{path.relative_to(pkg.parent)}:{i}: {line.strip()}")
print(f"files scanned: {len(list(pkg.rglob('*.py')))}")
print(f"matches      : {len(hits)}")
for h in hits:
    print("  " + h)
if not hits:
    print("  (none - there is no code that relates a subagent's tools to the parent's)")

# ---------------------------------------------------------------------------
# 5. The related trap: allow rules shadow can_use_tool. The SDK says so itself.
# ---------------------------------------------------------------------------
rule("5. THE SDK'S OWN WARNING ABOUT allowed_tools VS can_use_tool")
warning = _get_can_use_tool_shadowed_warning("default", PARENT_ALLOWED)
print(warning)
print()
warning_bypass = _get_can_use_tool_shadowed_warning("bypassPermissions", [])
print(warning_bypass)

rule("DONE")
print("No model was called. No network request was made. Exit 0.")
sys.exit(0)
