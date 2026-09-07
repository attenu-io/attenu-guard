"""tests/integrations/test_openhands.py — the OpenHands adapter against the real SDK.

The stdlib suite (tests/test_ledger_completeness.py) pins these three fixes with stand-ins,
because openhands-sdk is not installed in the default CI job. This file drives the SAME fixes
through the real SDK surfaces, which is where the bugs were found:

  B3  a tool registered AFTER `install()` ran un-gated and left no ledger row. The adapter arms
      the registry itself, so every `register_tool()` is covered whenever it happens.
  B5  the gate keyed on the raw `subagent_type`, so the SDK's own alias `default` ->
      `general-purpose` missed a sub-agent the operator HAD declared.
  B8  `DelegateExecutor` — the SDK's second delegation mechanism — was not a spawn seam, so a
      delegated sub-agent's tool calls landed on the PARENT's node.

Run: PYTHONPATH=src python3 -m pytest -q tests/integrations/test_openhands.py
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

# The framework is not installed in the default job; this file belongs to its own pinned one.
pytest.importorskip("openhands.sdk", reason="openhands-sdk is not installed")

from openhands.sdk.subagent.registry import (  # noqa: E402
    _agent_factories, get_agent_factory, register_agent,
)
from openhands.sdk.tool import registry as tool_registry  # noqa: E402
from openhands.sdk.tool.registry import register_tool  # noqa: E402
from openhands.tools.delegate import DelegateExecutor  # noqa: E402

from attenu_guard import Authority, Guard  # noqa: E402
from attenu_guard.adapters.openhands import GuardedDelegation, ToolPolicy  # noqa: E402
from attenu_guard.reasons import ReasonCode  # noqa: E402


def _root(**kw):
    return Guard.issue("orchestrator", Authority(scopes={"repo.read"}, ttl=3600),
                       chain_id="oh", **kw)


@pytest.fixture
def clean_registries():
    """The SDK's registries are process-global; leave them exactly as they were."""
    reg_before = dict(tool_registry._REG)
    reg_obj = tool_registry._REG
    agents_before = dict(_agent_factories)
    yield
    tool_registry._REG = reg_obj
    tool_registry._REG.clear()
    tool_registry._REG.update(reg_before)
    _agent_factories.clear()
    _agent_factories.update(agents_before)


def _late_tool_class():
    """A real `ToolDefinition` subclass — what `register_tool()` accepts."""
    from openhands.sdk.tool import Action, Observation, ToolDefinition

    class LateAction(Action):
        pass

    class LateObservation(Observation):
        @property
        def to_llm_content(self):
            return list(self.content)

    class LateTool(ToolDefinition[LateAction, LateObservation]):
        @classmethod
        def create(cls, conv_state=None, **params):
            return []

    LateTool.name = "integration_push_late"
    return LateTool


# --------------------------------------------------------------------------- B3
def test_a_tool_registered_after_install_is_covered(clean_registries):
    g = _root()
    guarded = GuardedDelegation(g, tools={})
    guarded.install()                                  # arms the registry, no classes to guard

    register_tool("integration_push_late", _late_tool_class())   # the SDK's own runtime API

    resolver = tool_registry._REG["integration_push_late"]
    assert getattr(resolver, "_attenu_guarded_by", None) is guarded, \
        "a tool registered after install() is not guarded"


def test_uninstall_restores_the_registry_and_drops_every_reference(clean_registries):
    g = _root()
    guarded = GuardedDelegation(g, tools={})
    guarded.install()
    register_tool("integration_push_late", _late_tool_class())
    guarded.uninstall()

    assert "integration_push_late" in tool_registry._REG, "a registration made while armed was lost"
    for name, resolver in tool_registry._REG.items():
        assert getattr(resolver, "_attenu_guarded_by", None) is None, \
            f"uninstall() left this adapter attached to {name!r}"


# --------------------------------------------------------------------------- B5
def _register_general_purpose():
    register_agent("general-purpose", lambda llm: SimpleNamespace(llm=llm),
                   "the SDK's default general agent")


def test_the_sdk_alias_resolves_to_the_declared_subagent(clean_registries):
    _register_general_purpose()
    g = _root()
    guarded = GuardedDelegation(
        g, tools={}, subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=60)})

    # `default` is the SDK's own alias (subagent/registry.py `_DEPRECATED_NAMES`).
    assert get_agent_factory("default").definition.name == "general-purpose"
    gate = guarded._gate_delegation(g, {"subagent_type": "default", "prompt": "go"})

    assert gate.denial is None, "the SDK alias was refused for a DECLARED sub-agent"
    spawn = g.audit_log().entries[-1]
    assert (spawn["event"], spawn["agent"]) == ("spawn", "general-purpose")
    assert "requested as 'default'" in spawn["task"]


def test_an_omitted_selector_is_still_refused(clean_registries):
    _register_general_purpose()
    g = _root()
    guarded = GuardedDelegation(
        g, tools={}, subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=60)})
    gate = guarded._gate_delegation(g, {"prompt": "go"})
    assert not gate.denial
    assert g.audit_log().entries[-1]["reason"] == ReasonCode.DELEGATION_REFUSED


# --------------------------------------------------------------------------- B8
def test_delegate_executor_mints_a_child_bound_to_its_conversation(clean_registries):
    _register_general_purpose()
    g = _root()
    guarded = GuardedDelegation(
        g, tools={"terminal": ToolPolicy("repo.read")},
        subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=60)})

    # The real SDK executor, with ONLY its conversation construction overridden: `_spawn_agents`
    # needs a live LLM and a workspace, which a unit job has no business standing up. Everything
    # this adapter touches stays real — the class, its `_sub_agents` contract, and the object
    # identity the binding hangs off.
    conversation = SimpleNamespace(id="sub-conv")

    class _NoLlmDelegateExecutor(DelegateExecutor):
        def __call__(self, action, conv=None):
            for agent_id in action.ids:
                self._sub_agents[agent_id] = conversation
            return SimpleNamespace(is_error=False)

    inner = _NoLlmDelegateExecutor()
    executor = guarded.delegate_executor(inner)
    action = SimpleNamespace(command="spawn", ids=["worker"], agent_types=None)
    executor._spawn(action, conversation=None)

    spawn = g.audit_log().entries[-1]
    assert (spawn["event"], spawn["agent"]) == ("spawn", "general-purpose")
    child_node = spawn["node"]

    # `_delegate_tasks` runs each sub-agent in a plain threading.Thread, which inherits no
    # contextvars — the binding has to travel on the conversation instead.
    seen = []
    t = threading.Thread(target=lambda: seen.append(
        guarded.call("terminal", SimpleNamespace(command="ls"), lambda: "ok",
                     conversation=conversation)))
    t.start()
    t.join()

    assert seen == ["ok"]
    allow = g.audit_log().entries[-1]
    assert (allow["event"], allow["tool"]) == ("allow", "terminal")
    assert allow["node"] == child_node, "the delegated call was recorded on the parent's node"


def test_an_undeclared_agent_type_is_refused_before_the_sdk_creates_anything(clean_registries):
    _register_general_purpose()
    g = _root()
    guarded = GuardedDelegation(
        g, tools={}, subagents={"general-purpose": Authority(scopes={"repo.read"}, ttl=60)})
    inner = DelegateExecutor()
    executor = guarded.delegate_executor(inner)

    action = SimpleNamespace(command="spawn", ids=["worker"], agent_types=["code-explorer"])
    executor._spawn(action, conversation=None)

    assert inner._sub_agents == {}, "the SDK created a sub-agent for a refused type"
    entry = g.audit_log().entries[-1]
    assert (entry["event"], entry["reason"]) == ("deny", ReasonCode.DELEGATION_REFUSED)
