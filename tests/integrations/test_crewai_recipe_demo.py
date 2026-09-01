"""
Recipe-level test: attenu-guard x CrewAI (`examples/integrations/crewai/demo.py`).

`test_crewai.py`/`test_crewai_conformance.py` cover the adapter's generic behavior against
synthetic scenarios. This file covers a NARROWER, specific claim: that the SHIPPED recipe --
the exact scenario `demo.py` prints and the README's "Expected output" quotes -- still runs
clean end to end, including the parts `test_crewai.py` does not touch: `strict_single_hook`
execution binding, the evidence-bundle export, and the packaged `attenu-guard verify` CLI round
trip. A green run here is what backs the README's own claim; a change to `demo.py` that breaks
any of `main()`'s own assertions fails this test, not just a human re-reading the transcript.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("crewai")

# NOTE: we deliberately do NOT put `examples/integrations/` on sys.path -- the example
# directory is itself named `crewai`, and adding its parent would shadow the real framework
# package. Loading by file location with an explicit module name avoids that (same pattern as
# tests/integrations/test_haystack.py).
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "crewai"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"attenu_example_{name}", _EXAMPLE_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load {name} from {_EXAMPLE_DIR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


demo = _load("demo")


def test_the_shipped_recipe_runs_clean_end_to_end(capsys):
    """`demo.main()` is its own assertion (see its own docstring): it returns 0 only if the
    export was denied, the revoked read was denied too, the export body never ran, the minted
    child is narrower than its parent, the audit chain verifies, the evidence bundle verifies
    via the packaged CLI, and the baseline (bridge uninstalled) genuinely does leak. A change
    that breaks any of those makes this test fail, not just the printed "RESULT: FAILED"."""
    rc = demo.main()
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "RESULT: OK" in out
    assert "integrity=True monotonicity=True containment=True anchor=verified" in out
