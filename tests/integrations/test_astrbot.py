"""tests/integrations/test_astrbot.py — the AstrBot adapter against the real AstrBot.

The stdlib suite (tests/test_ledger_completeness.py) pins these with stand-ins, because AstrBot
is an application rather than a library and is not installed in the default job. This file drives
the same fixes through the real `FunctionToolManager`, the real `_PermissionGuardedTool` and the
real `MCPTool` name rewrite — which is where each was found:

  B3   a tool added after `install()` (plugin `add_func`, or an MCP refresh that rebuilds
       `func_list` wholesale) ran un-gated and un-ledgered.
  B6   AstrBot rewrites an MCP tool's name and keeps the server's own on `mcp_tool.name`; a
       policy declared under the published name bound to nothing.
  B7   `get_full_tool_set()` wrapped AstrBot's `_PermissionGuardedTool` OUTSIDE this adapter's
       gate, and it refuses before delegating — so a refused call never reached the ledger.
  B16  the receipt that says an inner layer refused the body was bound to a Decision this
       adapter keeps only in strict mode, so it appeared on the passthrough path alone.

Run: PYTHONPATH=src:<astrbot checkout> python3 -m pytest -q tests/integrations/test_astrbot.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

# The framework is not installed in the default job; this file belongs to its own pinned one.
pytest.importorskip("astrbot.core.agent.tool", reason="astrbot is not installed")

from astrbot.core.agent.tool import FunctionTool  # noqa: E402
from astrbot.core.provider.func_tool_manager import (  # noqa: E402
    FunctionToolManager, _PermissionGuardedTool,
)

from attenu_guard import Authority, Guard  # noqa: E402
from attenu_guard.adapters.astrbot import (  # noqa: E402
    GuardedDelegation, GuardedTool, ToolPolicy, _BodyWitness,
)
from attenu_guard.reasons import Policy  # noqa: E402


def _guard(**kw):
    return Guard.issue("astrbot-main", Authority(scopes={"chat.note"}, ttl=3600),
                       chain_id="ab", schema_version=2, **kw)


def _chain(tool, depth=6):
    out = []
    while tool is not None and len(out) < depth:
        out.append(type(tool).__name__)
        tool = getattr(tool, "_wrapped", None)
    return out


def _fn_tool(name, handler=None):
    return FunctionTool(name=name, description=name, parameters={"type": "object",
                                                                 "properties": {}},
                        handler=handler or (lambda event, **kw: "ran"))


@pytest.fixture
def manager():
    mgr = FunctionToolManager()
    mgr.func_list.clear()
    return mgr


# --------------------------------------------------------------------------- B3
def test_a_tool_added_after_install_is_guarded(manager):
    g = _guard()
    guarded = GuardedDelegation(g, tools={}, allow_unlisted=True)
    manager.func_list.append(_fn_tool("early"))
    guarded.install(manager)
    assert isinstance(manager.func_list[0], GuardedTool)

    # `add_func` is the plugin route; the MCP paths rebuild `func_list` wholesale.
    manager.func_list.append(_fn_tool("late_plugin"))
    manager.func_list = [_fn_tool("late_mcp")]
    manager.get_func("late_mcp")                       # an agent resolving a tool by name
    assert isinstance(manager.func_list[0], GuardedTool), \
        "a tool added after install() is not guarded"
    guarded.uninstall()


# --------------------------------------------------------------------------- B6
class _Mcpish(FunctionTool):
    """The shape that matters: AstrBot's rewritten name, and the server's own underneath."""

    def __init__(self, exposed, published):
        super().__init__(name=exposed, description=exposed,
                         parameters={"type": "object", "properties": {}},
                         handler=lambda event, **kw: "pushed")
        object.__setattr__(self, "mcp_tool", SimpleNamespace(name=published))


def test_a_policy_under_the_server_published_name_binds(manager):
    g = _guard()
    guarded = GuardedDelegation(g, tools={"push.record": ToolPolicy("chat.note")},
                                allow_unlisted=True)
    tool = _Mcpish("push_record", "push.record")
    gate = guarded._gate("push_record", {}, None, tool)

    assert gate.denial is None
    entry = g.audit_log().entries[-1]
    assert (entry["event"], entry["scope"]) == ("allow", "chat.note")
    assert entry.get("policy") is None, "it bound, so it is not an unlisted passthrough"
    assert entry["context"]["mcp_tool"] == "push.record"


def test_a_policy_that_binds_to_nothing_is_reported(manager):
    reported = []
    g = _guard()
    guarded = GuardedDelegation(g, tools={"typo_tool": ToolPolicy("chat.note")},
                                on_unbound=reported.append)
    manager.func_list.append(_fn_tool("echo_note"))
    guarded.install(manager)
    guarded.uninstall()
    assert reported == [["typo_tool"]]


# --------------------------------------------------------------------------- B7 / B16
def test_the_main_agent_toolset_puts_our_gate_outermost_over_a_real_permission_proxy(manager):
    g = _guard()
    guarded = GuardedDelegation(g, tools={"echo_note": ToolPolicy("chat.note")})
    manager.func_list.append(_fn_tool("echo_note"))
    guarded.install(manager)
    try:
        handed = manager.get_full_tool_set().tools[0]
    finally:
        pass

    assert _chain(handed) == ["AttenuGuardedTool", "_PermissionGuardedTool",
                              "_BodyWitness", "FunctionTool"], _chain(handed)
    guarded.uninstall()


def test_a_body_refused_by_astrbots_own_permission_check_carries_the_receipt(manager):
    g = _guard()
    guarded = GuardedDelegation(g, tools={"echo_note": ToolPolicy("chat.note")})
    raw = _fn_tool("echo_note")
    witness = _BodyWitness(raw)
    inner = _PermissionGuardedTool(witness, manager)

    # AstrBot refuses inside the body: a value comes back and the tool never runs.
    result = asyncio.run(guarded.call("echo_note", {}, None,
                                      lambda: "error: Permission denied.", tool=inner))
    assert result == "error: Permission denied."
    assert witness.ran is False

    allow, outcome = g.audit_log().entries[-2:]
    assert (allow["event"], allow["scope"]) == ("allow", "chat.note")
    assert allow.get("policy") is None, "this must be the DECLARED path"
    assert outcome["event"] == "outcome"
    assert outcome["call_id"] == allow["call_id"]
    assert outcome["receipt"]["type"] == "framework_refusal"
    assert outcome["receipt"]["ref"] == "astrbot:_PermissionGuardedTool"


def test_a_body_that_runs_records_no_receipt(manager):
    g = _guard()
    guarded = GuardedDelegation(g, tools={"echo_note": ToolPolicy("chat.note")})
    witness = _BodyWitness(_fn_tool("echo_note"))

    def body():
        witness.ran = True
        return "noted"

    asyncio.run(guarded.call("echo_note", {}, None, body, tool=witness))
    assert [e["event"] for e in g.audit_log().entries][-1] == "allow"
