"""
Recipe-level test: attenu-guard x the OpenAI Agents SDK
(`examples/integrations/openai_agents/demo.py`).

`test_openai_agents.py` covers the adapter's generic behavior against synthetic
scenarios. `test_openai_agents_one_policy.py` covers the SEPARATE `one_policy/`
recipe (issue #4618's visibility/invocation gates). This file covers a NARROWER,
specific claim: that the SHIPPED delegation-attenuation recipe -- the exact
scenario `demo.py` prints and the README's "Expected output" quotes -- still runs
clean end to end, including the parts the generic suites do not touch: the
`registry=`-opt-in `Capture.WRAPPER_ASYNC` execution binding on a real handoff-then-
tool-call run, the greedy-grant clamping through `GuardRegistry.delegate(...)`, the
revocation-then-denial path, and the evidence-bundle export + packaged
`attenu-guard verify` CLI round trip. A green run here is what backs the README's
own claim; a change to `demo.py` that breaks any of `main()`'s own assertions fails
this test, not just a human re-reading the transcript.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("agents")

# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path -- the example
# directory is itself named `openai_agents`, and the installed framework package is `agents`
# (not `openai_agents`), so there is no direct name collision here the way there is for
# `crewai`/`langgraph`. We still load by file location with an explicit module name, for the
# same reason those recipes do: it keeps this test's import of `demo.py` independent of
# whatever else is on `sys.path` in a full test-suite run (e.g. the `one_policy/demo.py` module,
# loaded by `test_openai_agents_one_policy.py` under its own synthetic module name), and matches
# the one established pattern for every recipe-demo test in this directory (same as
# tests/integrations/test_crewai_recipe_demo.py / test_langgraph_recipe_demo.py / test_haystack.py).
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "openai_agents"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"attenu_example_openai_agents_{name}", _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


demo = _load("demo")


def test_the_shipped_recipe_runs_clean_end_to_end(capsys):
    """`demo.main()` is its own assertion (see its own docstring): it returns 0 only if the
    greedy grant came back clamped to the orchestrator's own authority, the over-ceiling read was
    denied inside an allowed scope, the poisoned export was denied and its body never ran, the
    revoked read was denied too, the minted child is narrower than its parent, the allowed read's
    ledger entry carries a genuine WRAPPER_ASYNC capture with matching hashes, the audit chain
    verifies, the evidence bundle verifies via the packaged CLI, and the baseline (no guard
    installed) genuinely does leak. A change that breaks any of those makes this test fail, not
    just the printed "RESULT: FAILED"."""
    rc = asyncio.run(demo.main())
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "RESULT: OK" in out
    assert "integrity=True monotonicity=True containment=True anchor=verified" in out
