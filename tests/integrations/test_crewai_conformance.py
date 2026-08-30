"""attenu-guard x CrewAI -- authorization conformance contract (crewai==1.15.16).

Pinned in response to crewAIInc/crewAI#5888 (safal207), who asked for a
declared matrix of which CrewAI tool-dispatch code paths `dg_crewai`
(`attenu_guard.adapters.crewai`) is proven to hold on, plus three invariants
asserted explicitly on every path in that matrix:

  * an explicit ALLOW reaches the tool body EXACTLY ONCE,
  * a DENY reaches the tool body ZERO times,
  * an authorization-PROVIDER ERROR, or an UNRECOGNIZED authorization result,
    is converted to `crewai.hooks.HookAborted` and reaches the tool body
    ZERO times (never CrewAI's fail-open default -- see
    `crewai/hooks/dispatch.py:264` and the adapter module docstring).

CORRECTION vs `attenu_guard/adapters/crewai.py`'s module docstring and
`test_crewai.py`'s comments, found while building this matrix against the
INSTALLED crewai==1.15.16 source (not assumed from the docstrings):

  * `Agent.executor_class` defaults to
    `crewai.experimental.agent_executor.AgentExecutor` (a Flow-based
    executor) -- NOT the deprecated `crewai.agents.crew_agent_executor
    .CrewAgentExecutor`. Verified empirically: `type(agent.agent_executor)`
    after a plain `Crew.kickoff()` with no `executor_class=` override.
    `CrewAgentExecutor` now requires an explicit, deprecated opt-in
    (`Agent(executor_class=CrewAgentExecutor)`; it logs a removal warning).
  * Consequently, `test_crewai.py`'s "ReAct" test (an LLM double without
    `supports_function_calling`) does NOT exercise
    `crew_agent_executor.py`'s `_invoke_loop_react`, as the adapter
    docstring's "hook points" section implies. Traced by monkeypatching
    `crewai.hooks.tool_hooks.run_before_tool_call_hooks` and recording the
    caller's frame: it fires the hook at `crewai/utilities/tool_utils.py:286`
    (the SYNC `execute_tool_and_check_finality`, which both the default and
    the deprecated executor call into -- this one hook site is
    executor-agnostic).
  * `test_crewai.py`'s "native function calling" test
    (`supports_function_calling` -> True) does NOT exercise
    `crew_agent_executor.py:962` as both the adapter docstring and that
    test's own comment claim. Traced the same way: it fires the hook at
    `crewai/experimental/agent_executor.py:2024`
    (`AgentExecutor._execute_single_native_tool_call` -- the default
    executor's OWN implementation, a separate copy of the logic from
    `crew_agent_executor.py:868-962`). `:962` is real code, but it belongs
    to the deprecated executor, which nothing in this package exercises
    without explicitly opting in.
  * The adapter docstring's `tool_utils.py:123` (labelled "ReAct") /
    `:286` (labelled "async ReAct") pair is swapped: `:123` sits inside
    `aexecute_tool_and_check_finality` (the ASYNC function, defined first in
    the file), and `:286` sits inside the SYNC `execute_tool_and_check_finality`
    (defined second) -- the opposite of what the docstring's labels say.

None of this changes what the bridge does -- `_before_tool_call` converts
every denial and every internal error into `HookAborted` regardless of which
CrewAI internals dispatched PRE_TOOL_CALL. It changes which claims about
*which CrewAI source lines* are true for this pinned version, which is
exactly the contract this file pins. See DECLARED_PATHS below.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable

import pytest

pytest.importorskip("crewai")

# Keep the crew hermetic: no telemetry, no tracing, no network.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import Agent, Crew, Process, Task  # noqa: E402
from crewai.hooks import clear_all_global_hooks  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

from attenu_guard import Authority, Guard  # noqa: E402
import attenu_guard.adapters.crewai as dg_crewai  # noqa: E402

CrewAIGuardBridge = dg_crewai.CrewAIGuardBridge
ToolPolicy = dg_crewai.ToolPolicy


# ---------------------------------------------------------------------------
# The declared path matrix.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionPath:
    """One CrewAI tool-dispatch mechanism that can trigger a PRE_TOOL_CALL
    hook -- identified by where, in the INSTALLED crewai==1.15.16 source,
    `run_before_tool_call_hooks` is actually called from (verified by frame
    tracing, not read off a docstring)."""

    id: str
    description: str
    crewai_source: str  # file:line of the PRE_TOOL_CALL call site
    status: str  # "covered" | "not_covered"
    note: str = ""  # required (non-empty) when status == "not_covered"


DECLARED_PATHS: tuple[ExecutionPath, ...] = (
    ExecutionPath(
        id="default_text_tool_call",
        description=(
            "Default AgentExecutor (crewai.experimental.agent_executor -- the "
            "Agent.executor_class default in 1.15.16), text/'ReAct-style' "
            "tool-call parsing: the LLM double does not advertise "
            "supports_function_calling."
        ),
        crewai_source=(
            "crewai/utilities/tool_utils.py:286 "
            "(execute_tool_and_check_finality, sync)"
        ),
        status="covered",
    ),
    ExecutionPath(
        id="default_native_tool_call",
        description=(
            "Default AgentExecutor, native function-calling tool call: the "
            "LLM double's supports_function_calling() returns True."
        ),
        crewai_source=(
            "crewai/experimental/agent_executor.py:2024 "
            "(AgentExecutor._execute_single_native_tool_call)"
        ),
        status="covered",
    ),
    ExecutionPath(
        id="legacy_deprecated_native_tool_call",
        description=(
            "Deprecated CrewAgentExecutor (explicit, opt-in "
            "Agent(executor_class=CrewAgentExecutor)), native function calling."
        ),
        crewai_source=(
            "crewai/agents/crew_agent_executor.py:962 "
            "(CrewAgentExecutor._execute_single_native_tool_call)"
        ),
        status="not_covered",
        note=(
            "Reachable -- constructing Agent(executor_class=CrewAgentExecutor) "
            "and tracing the hook call site confirms it hits this exact line "
            "-- but crewai itself deprecates this executor and has announced "
            "its removal (agent/core.py: 'CrewAgentExecutor is deprecated and "
            "will be removed in a future release'). Pinning a conformance test "
            "to a code path its own maintainers are deleting buys false "
            "confidence, not conformance; drop this entry once the class is "
            "actually removed rather than let it silently stop being tested."
        ),
    ),
    ExecutionPath(
        id="async_react_tool_call",
        description="Async ReAct tool-call dispatch.",
        crewai_source=(
            "crewai/utilities/tool_utils.py:123 "
            "(aexecute_tool_and_check_finality, async)"
        ),
        status="not_covered",
        note=(
            "Empirically unreachable through CrewAI's own orchestration "
            "surface in 1.15.16: Crew.kickoff(), Crew.kickoff_async(), and "
            "Task(async_execution=True) were each traced (recording the "
            "caller frame of run_before_tool_call_hooks) on both the default "
            "and the legacy executor, and every one resolved to the SYNC hook "
            "site (tool_utils.py:286), never the async one. Driving :123 "
            "would require calling AgentExecutor.ainvoke() / "
            "Agent._aexecute_without_timeout() directly, off the Crew/Task "
            "surface every other test in this package (and this file) tests "
            "against -- marked NOT_COVERED honestly rather than faked."
        ),
    ),
    ExecutionPath(
        id="planning_step_executor_tool_call",
        description=(
            "Planning/todo-step tool call: Agent(planning=True) routes a tool "
            "call through the step-execution helper instead of the ordinary "
            "text/native branches."
        ),
        crewai_source=(
            "crewai/utilities/agent_utils.py:1693 "
            "(execute_single_native_tool_call), reached via "
            "crewai/agents/step_executor.py:609"
        ),
        status="not_covered",
        note=(
            "Only reached when planning mode is enabled, which requires "
            "scripting a distinct planner-LLM turn ahead of the tool-call "
            "turns -- a different offline-scripting shape than every other "
            "path in this file. This is the real 'seam nobody happens to "
            "test' in 1.15.16; flagged here rather than built in this pass."
        ),
    ),
)

COVERED_PATH_IDS: tuple[str, ...] = tuple(
    p.id for p in DECLARED_PATHS if p.status == "covered"
)


def test_declared_paths_matrix_has_no_unproven_covered_entry():
    """Nothing in DECLARED_PATHS is inferred as covered without a test that
    actually names it: every 'covered' id must be wired into COVERED_PATH_IDS
    (which parametrizes every invariant test below) AND have a matching LLM
    double in _LLM_BUILDERS, and every 'not_covered' id must carry a stated
    reason."""
    declared_covered = {p.id for p in DECLARED_PATHS if p.status == "covered"}
    assert declared_covered == set(COVERED_PATH_IDS)
    assert declared_covered == _LLM_BUILDERS
    for p in DECLARED_PATHS:
        if p.status == "not_covered":
            assert p.note, f"{p.id} is NOT_COVERED with no reason recorded"
        else:
            assert p.status == "covered"


# ---------------------------------------------------------------------------
# Offline LLM doubles, one per COVERED path.
# ---------------------------------------------------------------------------


class _TextScriptedLLM(BaseLLM):
    """Drives `default_text_tool_call`: no supports_function_calling, so the
    default AgentExecutor takes its text-parsing branch."""

    script: dict = {}
    counters: dict = {}

    def call(
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ) -> str:
        role = getattr(from_agent, "role", "?")
        i = self.counters.get(role, 0)
        self.counters[role] = i + 1
        steps = self.script.get(role, [])
        if i < len(steps):
            return steps[i]
        return "Thought: I am done.\nFinal Answer: done"


def _text_act(tool_name: str, payload: str) -> str:
    return f"Thought: next step.\nAction: {tool_name}\nAction Input: {payload}"


class _NativeScriptedLLM(BaseLLM):
    """Drives `default_native_tool_call`: supports_function_calling() ->
    True, so the default AgentExecutor takes its native tool-call branch."""

    script: dict = {}
    counters: dict = {}

    def supports_function_calling(self) -> bool:
        return True

    def call(
        self,
        messages,
        tools=None,
        callbacks=None,
        available_functions=None,
        from_task=None,
        from_agent=None,
        response_model=None,
    ):
        role = getattr(from_agent, "role", "?")
        i = self.counters.get(role, 0)
        self.counters[role] = i + 1
        steps = self.script.get(role, [])
        if i < len(steps):
            return steps[i]
        return "Done."


def _native_call(name: str, payload: dict) -> list:
    return [{"id": f"call_{name}", "name": name, "input": payload}]


PROBE_ROLE = "probe_agent"


def _build_probe_llm(path_id: str) -> BaseLLM:
    if path_id == "default_text_tool_call":
        return _TextScriptedLLM(
            model="scripted/text",
            script={
                PROBE_ROLE: [
                    _text_act("probe_tool", '{"x": 1}'),
                    "Thought: done.\nFinal Answer: done",
                ]
            },
            counters={},
        )
    if path_id == "default_native_tool_call":
        return _NativeScriptedLLM(
            model="scripted/native",
            script={PROBE_ROLE: [_native_call("probe_tool", {"x": 1}), "done"]},
            counters={},
        )
    raise ValueError(f"no LLM double wired for declared path {path_id!r}")


_LLM_BUILDERS = {"default_text_tool_call", "default_native_tool_call"}


# ---------------------------------------------------------------------------
# The probe harness: one agent, one tool, one call, offline.
# ---------------------------------------------------------------------------


class _Calls:
    def __init__(self) -> None:
        self.count = 0

    def hit(self) -> None:
        self.count += 1


def _probe_tool(calls: _Calls):
    @tool("probe_tool")
    def probe_tool(x: int) -> str:
        """A single probe tool. The invariant under test is whether this
        body runs, and how many times."""
        calls.hit()
        return "probed"

    return probe_tool


def _run_probe(
    path_id: str,
    *,
    tool_policies: dict[str, ToolPolicy],
    default_policy: Callable[[str], Any] | None = None,
    root_authority: Authority | None = None,
) -> tuple[int, "CrewAIGuardBridge"]:
    """Run exactly ONE probe tool call, offline, through `path_id`, and
    return (number of times the tool body ran, the installed bridge)."""
    calls = _Calls()
    probe_tool_fn = _probe_tool(calls)
    root = Guard.issue(
        PROBE_ROLE,
        root_authority or Authority(scopes={"probe.allowed"}, ceilings=[], ttl=3600),
        task="probe",
    )
    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role=PROBE_ROLE,
        tool_policies=tool_policies,
        delegation_authorities={},
        default_policy=default_policy,
    )
    llm = _build_probe_llm(path_id)
    agent = Agent(
        role=PROBE_ROLE,
        goal="run the probe tool",
        backstory="exists only to prove the conformance invariants.",
        llm=llm,
        tools=[probe_tool_fn],
        allow_delegation=False,
        verbose=False,
    )
    task = Task(description="run the probe", expected_output="a result", agent=agent)
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, telemetry=False)
    with bridge:
        crew.kickoff()
    return calls.count, bridge


@pytest.fixture(autouse=True)
def _clean_hooks():
    """CrewAI's tool hooks are process-global; never leak between tests."""
    clear_all_global_hooks()
    yield
    clear_all_global_hooks()


# ---------------------------------------------------------------------------
# Invariant 1: an explicit allow reaches the tool body EXACTLY ONCE.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path_id", COVERED_PATH_IDS)
def test_explicit_allow_reaches_tool_body_exactly_once(path_id):
    n, bridge = _run_probe(
        path_id,
        tool_policies={"probe_tool": ToolPolicy(scope="probe.allowed")},
    )
    assert n == 1, (
        f"an explicitly allowed call must reach the tool body EXACTLY ONCE "
        f"on {path_id!r}; it ran {n} times"
    )
    assert bridge.denials == []


# ---------------------------------------------------------------------------
# Invariant 2: a deny reaches the tool body ZERO times.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path_id", COVERED_PATH_IDS)
def test_deny_reaches_tool_body_zero_times(path_id):
    n, bridge = _run_probe(
        path_id,
        tool_policies={"probe_tool": ToolPolicy(scope="probe.NEVER_GRANTED")},
    )
    assert n == 0, (
        f"a denied call must NEVER reach the tool body on {path_id!r}; "
        f"it ran {n} times"
    )
    assert [d.tool_name for d in bridge.denials] == ["probe_tool"]


# ---------------------------------------------------------------------------
# Invariant 3a: an authorization-provider error -> HookAborted, zero calls.
#
# "Provider error" = the deployment's decision-shaping callable raises. Here
# that's ToolPolicy.context_fn, the callable that reads the request context
# out of the tool call for Guard.check(...).
# ---------------------------------------------------------------------------


def _raising_context_fn(_args):
    raise RuntimeError("boom: authorization-provider error")


@pytest.mark.parametrize("path_id", COVERED_PATH_IDS)
def test_provider_error_is_converted_to_hookaborted_zero_calls(path_id):
    """CrewAI's dispatcher swallows any non-HookAborted exception fail-open
    (crewai/hooks/dispatch.py:264: 'any other exception is swallowed'); the
    bridge's outer try/except (_before_tool_call) must convert this into
    HookAborted BEFORE it ever reaches CrewAI, so the tool body still never
    runs and `crew.kickoff()` itself completes without raising."""
    n, bridge = _run_probe(
        path_id,
        tool_policies={
            "probe_tool": ToolPolicy(scope="probe.allowed", context_fn=_raising_context_fn)
        },
    )
    assert n == 0, (
        f"an authorization-provider error must fail CLOSED on {path_id!r}; "
        f"the tool body ran {n} times"
    )
    assert bridge.denials and "boom" in bridge.denials[0].reason_text


# ---------------------------------------------------------------------------
# Invariant 3b: an unrecognized authorization result -> HookAborted, zero
# calls.
#
# "Unrecognized result" = the callable that resolves an undeclared tool's
# policy (default_policy) returns something that is neither a grant (a
# ToolPolicy) nor an explicit deny (None) -- a string, an int, an arbitrary
# object. The bridge must not guess at what it means; it must fail closed
# exactly like a provider error.
# ---------------------------------------------------------------------------


class _UnrecognizedPolicy:
    """Not a ToolPolicy, not None: an authorization result the bridge was
    never told how to interpret."""


UNRECOGNIZED_RESULTS = [
    pytest.param("not-a-policy", id="str"),
    pytest.param(42, id="int"),
    pytest.param(_UnrecognizedPolicy(), id="object"),
]


@pytest.mark.parametrize("garbage", UNRECOGNIZED_RESULTS)
@pytest.mark.parametrize("path_id", COVERED_PATH_IDS)
def test_unrecognized_authorization_result_is_converted_to_hookaborted_zero_calls(
    path_id, garbage
):
    n, bridge = _run_probe(
        path_id,
        tool_policies={},  # nothing declared -> default_policy is consulted
        default_policy=lambda _name: garbage,
    )
    assert n == 0, (
        f"an unrecognized authorization result ({garbage!r}) must fail CLOSED "
        f"on {path_id!r}; the tool body ran {n} times"
    )
    assert bridge.denials and bridge.denials[0].tool_name == "probe_tool"
