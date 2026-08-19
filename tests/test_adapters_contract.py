"""tests/test_adapters_contract.py — every adapter exposes the same disposition contract. stdlib only.

Slice 1 / Plan A, Task 5 ("fix the class"): a per-tool policy struct in ANY adapter carries `disposition`,
passes it to `Guard.check`, and an undeclared tool is recorded as `Disposition.UNRESOLVED` (via `check` or
`record_denial`) — never silently, never only in the adapter's own memory. This is a source-text contract on
purpose: the tier-2 frameworks are not installed in the default CI job; the pinned `integrations` job
exercises behaviour. Run: PYTHONPATH=src python3 tests/test_adapters_contract.py
"""
import pkgutil
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import delegation_guard.adapters as adapters_pkg  # noqa: E402

ADAPTERS_DIR = Path(adapters_pkg.__path__[0])
ADAPTER_MODULES = sorted(m.name for m in pkgutil.iter_modules([str(ADAPTERS_DIR)]) if not m.name.startswith("_"))
# adapters that hold a tool -> policy MAP and therefore have an "undeclared tool" refusal path
POLICY_MAP_ADAPTERS = {"agno", "autogen", "claude_sdk", "crewai", "google_adk", "langchain", "pydantic_ai", "semantic_kernel"}


class AdapterDispositionContract(unittest.TestCase):
    def test_every_adapter_policy_struct_has_disposition_and_uses_it(self):
        missing = []
        seen = 0
        for name in ADAPTER_MODULES:
            src = (ADAPTERS_DIR / f"{name}.py").read_text()
            if "guard.check(" not in src and ".check(" not in src:
                continue                                   # not a per-tool authorization adapter
            seen += 1
            # (1) declared: a policy-struct field OR a keyword at the per-tool declaration point
            if not re.search(r"disposition: (Optional\[str\]|str \| None) = None", src):
                missing.append(f"{name}: `disposition` is not accepted where a tool's scope is declared")
            # (2) passed through to the ledger
            if "disposition=" not in src:
                missing.append(f"{name}: never passes disposition to guard.check / record_denial")
            # (3) a policy-map adapter has an 'undeclared tool' path -> it must land on the ledger as unresolved.
            #     Wrapper-style adapters (an unwrapped tool is simply not intercepted; strands' resolver returning
            #     None means exempt BY DESIGN) have no such path and are exempt from (3).
            if name in POLICY_MAP_ADAPTERS and "Disposition.UNRESOLVED" not in src:
                missing.append(f"{name}: undeclared tools are not recorded as unresolved")
        self.assertGreaterEqual(seen, 12, f"expected 12 authorizing adapters, saw {seen}")
        self.assertEqual(missing, [], "\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main(verbosity=2)
