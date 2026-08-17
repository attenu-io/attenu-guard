"""
scenarios.py — declarative scenario runner (DevX + interop harness).

The gold-standard pattern from OpenFGA's `.fga.yaml` and SpiceDB's validation
YAML (docs/DEVX-REVIEW.md principle 5): grants + a scenario + expected
outcomes — including the expected *reason code*, not just a boolean — in one
file, runnable by a CLI, wireable into CI. A scenario file is simultaneously:

  * a DevX onboarding artifact (copy/paste and run — no Python required to
    see the library work);
  * a living authorization regression test (check it into the repo next to
    the code it protects, same as any other test fixture);
  * an IETF-interop-adjacent fixture (each `expect: deny` + `because:` is a
    MUST-be-rejected test vector in the shape the standards-alignment work
    (docs/STANDARDS-ALIGNMENT.md) needs — a scope-widening attempt, a
    ceiling overrun, etc. — expressed independently of any particular
    programming language).

Schema (see docs/V0.2-SPEC.md "scenarios.py" and docs/DEVX-REVIEW.md for the
worked example; scenarios/README.md is the user-facing version of this):

    {
      "root": {
        "agent": "planner",
        "authority": {"scopes": [...], "ceilings": [{"key": ..., ...}], "ttl": ...},
        "task": "root"                      # optional, defaults to "root"
      },
      "delegations": [
        {
          "as": "summarizer",               # required: the name this node is
                                             # addressed by in later "from" /
                                             # "node" references and in reports
          "from": "root",                   # optional, defaults to "root"
          "agent": "summarizer-agent",      # optional, defaults to the "as" name
          "task": "summarize",              # optional, defaults to the "as" name
          "attenuate": {"scopes": [...], "ceilings": [...], "ttl": ...}
        }
      ],
      "assertions": [
        {
          "node": "summarizer",             # required: "root" or a delegation's "as"
          "check": {"scope": "crm.read", "context": {"rows": 50}, "tool": "..."},
          "expect": "allow" | "deny",       # required
          "because": "scope_not_granted"    # optional: required top reason code
                                             # on a "deny" (ignored on "allow")
        }
      ]
    }

Every "ceilings" list is a list of ceiling *wire* objects — `{"key": "max_rows",
"max": 1000}`, exactly the shape `Authority.to_wire()["constraints"]` emits —
reconstructed into real `Ceiling` objects via `ceilings.ceiling_from_wire`,
the same fail-closed reconstruction path a real Delegation Token goes
through (an unrecognised ceiling type becomes an always-denying
`_UnknownCeiling`, never silently-unbounded — see ceilings.py).

Building the tree uses the real `Guard.issue`/`Guard.delegate` — a scenario
file can never express more than the library itself would allow; `meet`
still can only narrow. Two distinct failure classes, mirroring the
issue/delegate vs. check/enforce split in guard.py:

  * a malformed scenario FILE (missing "root", an assertion naming a node
    that was never defined, an unknown "expect" value, ...) is a structural
    problem with the *test*, not an authorization outcome — raises
    `ScenarioError`. A structural failure from the core itself while
    building the tree (delegating past `max_depth`/`max_fanout`, or from an
    already-revoked/expired node) is likewise structural — it propagates as
    the core's own `AuthorityError`, unwrapped.
  * an assertion's `check()` not matching its `expect`/`because` is a
    completely normal, expected, *reportable* outcome — never an exception.
    That is the entire point of the harness: a failing scenario is
    information (`ScenarioResult.ok is False`, with the specific
    `AssertionOutcome`s that diverged), not a crash.

Accept JSON natively — stdlib `json`, always available. Accept YAML too, but
only if PyYAML happens to be installed: `import yaml` is attempted lazily,
inside `load_spec()`, only when a `.yaml`/`.yml` file is actually loaded, so
importing this module (or running the JSON path) never requires it. A
`.yaml`/`.yml` file with no PyYAML installed raises `ScenarioError` with an
actionable message instead of a bare `ModuleNotFoundError`.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from .authority import Authority, AuthorityError
from .ceilings import ceiling_from_wire
from .guard import Guard
from .reasons import ReasonCode

__all__ = [
    "ScenarioError", "AssertionOutcome", "ScenarioResult",
    "load_spec", "build_tree", "run_assertions", "run_scenarios", "main",
]

ROOT_NAME = "root"


class ScenarioError(Exception):
    """A STRUCTURAL problem with a scenario file/spec itself — bad shape,
    a dangling reference, a missing PyYAML install for a .yaml file. This
    is deliberately distinct from an assertion *failing* (a normal,
    reportable `AssertionOutcome`, not an exception) — the same
    denied-is-not-errored split `guard.py` draws between `AuthorityDenied`
    and `AuthorityError`, applied one layer up at the scenario-file level.
    """


# =========================================================================
# Loading — JSON always, YAML only if PyYAML is actually importable.
# =========================================================================

def _load_yaml_module():
    """Import PyYAML lazily, only when a .yaml/.yml file is actually being
    read. Never imported at module import time, and never on the JSON
    path — the JSON path of this module is stdlib-only, full stop."""
    try:
        import yaml  # type: ignore  # optional third-party dependency
    except ImportError as e:
        raise ScenarioError(
            "PyYAML is required to load a .yaml/.yml scenario file, and "
            "isn't installed in this environment. Either `pip install "
            "pyyaml`, or write the scenario as JSON instead — the .json "
            "path of delegation_guard.scenarios is stdlib-only and needs "
            "no install."
        ) from e
    return yaml


def load_spec(path) -> dict:
    """Parse a scenario file (.json, .yaml, or .yml) into its raw spec
    dict. Routes on file suffix; anything not ending .yaml/.yml is parsed
    as JSON (the stdlib-guaranteed path)."""
    p = Path(path)
    text = p.read_text()
    if p.suffix.lower() in (".yaml", ".yml"):
        yaml = _load_yaml_module()
        spec = yaml.safe_load(text)
    else:
        spec = json.loads(text)
    if not isinstance(spec, Mapping):
        raise ScenarioError(
            f"{path}: scenario file must parse to a JSON/YAML object with "
            f"a top-level \"root\" key, got {type(spec).__name__}")
    return spec


# =========================================================================
# Building the tree — real Guard.issue/Guard.delegate, so a scenario file
# can never express anything the library itself wouldn't allow.
# =========================================================================

def _authority_from_spec(spec: Mapping | None) -> Authority:
    """Build an `Authority` from one {"scopes": [...], "ceilings": [...],
    "ttl": ...} block. Ceiling wire-dicts go through the SAME fail-closed
    `ceiling_from_wire` reconstruction a real Delegation Token uses."""
    spec = spec or {}
    scopes = spec.get("scopes", ())
    ceilings = tuple(ceiling_from_wire(c) for c in spec.get("ceilings", ()))
    ttl = spec.get("ttl")
    return Authority(scopes=frozenset(scopes), ceilings=ceilings, ttl=ttl)


def build_tree(spec: Mapping, *, clock=None) -> dict:
    """Build the delegation tree described by spec["root"] / spec[
    "delegations"] and return it as a {name: Guard} map — "root" always
    names the root node (whatever its "agent" id is), and every delegation
    is additionally addressable by its "as" name.

    `clock` is passed straight through to `Guard.issue` (every delegation
    off that root shares the same chain/clock). It exists so tests can
    inject a fake, advanceable clock and deterministically exercise TTL
    expiry between building the tree and evaluating assertions — the
    declarative schema itself has no notion of "time passing", so that
    case is exercised by calling `build_tree`/`run_assertions` directly
    rather than through `run_scenarios` (see tests/test_scenarios.py).

    Raises `ScenarioError` for a malformed spec (missing "root"/"agent"/
    "as", a duplicate "as" name, a "from" naming a node not yet defined).
    Raises the core's own `AuthorityError`, unwrapped, for a STRUCTURAL
    failure the library itself refuses (e.g. a delegation past max_depth)
    — see the module docstring for why that one is not wrapped.
    """
    if "root" not in spec:
        raise ScenarioError('scenario spec is missing the required "root" key')
    root_spec = spec["root"] or {}
    agent = root_spec.get("agent")
    if not agent:
        raise ScenarioError('scenario "root" is missing the required "agent" key')

    authority = _authority_from_spec(root_spec.get("authority"))
    task = root_spec.get("task", "root")
    issue_kwargs = {}
    if clock is not None:
        issue_kwargs["clock"] = clock
    for k in ("chain_id", "max_depth", "max_fanout"):
        if k in root_spec:
            issue_kwargs[k] = root_spec[k]

    nodes = {ROOT_NAME: Guard.issue(agent, authority, task, **issue_kwargs)}

    for i, d in enumerate(spec.get("delegations", ())):
        as_name = d.get("as")
        if not as_name:
            raise ScenarioError(f'delegations[{i}] is missing the required "as" key')
        if as_name in nodes:
            raise ScenarioError(f'delegations[{i}]: duplicate node name "{as_name}"')
        parent_name = d.get("from", ROOT_NAME)
        parent = nodes.get(parent_name)
        if parent is None:
            raise ScenarioError(
                f'delegations[{i}] ("{as_name}"): unknown parent "{parent_name}" — '
                f'a delegation may only reference "root" or an earlier '
                f'delegations[].as name (delegations are processed in file order)')
        request = _authority_from_spec(d.get("attenuate"))
        agent_id = d.get("agent", as_name)
        task = d.get("task", as_name)
        nodes[as_name] = parent.delegate(agent_id, request, task)

    return nodes


# =========================================================================
# Evaluating assertions
# =========================================================================

@dataclass(frozen=True)
class AssertionOutcome:
    """The pass/fail outcome of one `assertions[i]` entry. A scenario
    assertion PASSES iff the actual allow/deny matches `expected`, AND —
    only when `expected == "deny"` and `because` was given — the actual
    top reason code matches `because` too."""
    index: int                     # 1-based position in assertions[]
    node: str
    scope: str
    expected: str                  # "allow" | "deny", from assertions[i].expect
    actual: str                    # "allow" | "deny", what check() returned
    because: str | None = None     # the expected reason code, if asserted
    reason: str | None = None      # the actual TOP reason code, if any
    reason_codes: tuple = ()       # every reason code the Decision carried
    passed: bool = True
    detail: str = ""               # human-readable explanation (esp. on failure)

    def to_dict(self) -> dict:
        return {
            "index": self.index, "node": self.node, "scope": self.scope,
            "expected": self.expected, "actual": self.actual,
            "because": self.because, "reason": self.reason,
            "reason_codes": list(self.reason_codes),
            "passed": self.passed, "detail": self.detail,
        }

    def format(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        want = self.expected + (f"/{self.because}" if self.because else "")
        got = self.actual + (f"/{self.reason}" if self.reason else "")
        line = (f"[{mark}] #{self.index} {self.node} :: {self.scope}  "
                f"expect={want}  actual={got}")
        if not self.passed:
            line += f"\n         {self.detail}"
        return line


def run_assertions(nodes: Mapping, assertions: Sequence[Mapping]) -> list:
    """Evaluate every `assertions[i]` against an already-built {name:
    Guard} map (as returned by `build_tree`). Returns a list of
    `AssertionOutcome`, one per assertion, in order — never raises on an
    assertion *failing* (that is the normal, reportable case this whole
    harness exists to surface). Raises `ScenarioError` only for a
    malformed assertion entry: an unknown node, a missing scope, or an
    `expect` that isn't "allow"/"deny"."""
    outcomes = []
    for i, a in enumerate(assertions):
        node_name = a.get("node")
        if not node_name:
            raise ScenarioError(f'assertions[{i}] is missing the required "node" key')
        guard = nodes.get(node_name)
        if guard is None:
            raise ScenarioError(
                f'assertions[{i}]: unknown node "{node_name}" — not "root" and '
                f'not any delegations[].as name')
        chk = a.get("check") or {}
        scope = chk.get("scope")
        if not scope:
            raise ScenarioError(f'assertions[{i}].check is missing the required "scope" key')
        expect = a.get("expect")
        if expect not in ("allow", "deny"):
            raise ScenarioError(
                f'assertions[{i}].expect must be "allow" or "deny", got {expect!r}')
        because = a.get("because")

        decision = guard.check(scope, context=chk.get("context"), tool=chk.get("tool"))
        actual = "allow" if decision else "deny"
        reason_codes = tuple(r.code for r in decision.reasons)
        top_reason = reason_codes[0] if reason_codes else None

        bool_ok = actual == expect
        reason_ok = True
        if expect == "deny" and because is not None:
            reason_ok = top_reason == because
        passed = bool_ok and reason_ok

        if passed:
            detail = decision.explain()
        elif not bool_ok:
            detail = f"expected {expect} but got {actual} ({decision.explain()})"
        else:
            detail = f"expected reason {because!r} but got {top_reason!r}"

        outcomes.append(AssertionOutcome(
            index=i + 1, node=node_name, scope=scope, expected=expect, actual=actual,
            because=because, reason=top_reason, reason_codes=reason_codes,
            passed=passed, detail=detail,
        ))
    return outcomes


# =========================================================================
# ScenarioResult — the report
# =========================================================================

@dataclass
class ScenarioResult:
    total: int
    passed: int
    failed: int
    outcomes: list = field(default_factory=list)
    path: str | None = None

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def coverage(self) -> set:
        """The set of ReasonCode values actually exercised by this run —
        i.e. every reason code that appeared in ANY assertion's Decision,
        whether that assertion passed or failed. Used by `--coverage` to
        show which slice of the reason-code taxonomy a scenario file
        actually tests."""
        codes = set()
        for o in self.outcomes:
            codes.update(o.reason_codes)
        return codes

    def format_report(self) -> str:
        lines = [f"scenario: {self.path or '<in-memory>'}"]
        for o in self.outcomes:
            lines.append("  " + o.format())
        summary = f"{self.passed}/{self.total} assertions passed"
        if not self.ok:
            summary += f"  ({self.failed} FAILED)"
        lines.append(summary)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "path": self.path, "total": self.total, "passed": self.passed,
            "failed": self.failed, "ok": self.ok,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


def run_scenarios(path, *, clock=None) -> ScenarioResult:
    """Load (if `path` is a file path) or use directly (if `path` is
    already a parsed spec `Mapping` — handy for in-memory scenario dicts
    in tests), build the delegation tree, evaluate every assertion, and
    return the aggregate `ScenarioResult`. Never raises on an assertion
    failing; raises `ScenarioError`/`AuthorityError` for a structurally
    broken scenario (see the module docstring)."""
    if isinstance(path, Mapping):
        spec = path
        display_path = None
    else:
        spec = load_spec(path)
        display_path = str(path)

    nodes = build_tree(spec, clock=clock)
    outcomes = run_assertions(nodes, spec.get("assertions", ()))
    passed = sum(1 for o in outcomes if o.passed)
    return ScenarioResult(total=len(outcomes), passed=passed,
                          failed=len(outcomes) - passed, outcomes=outcomes,
                          path=display_path)


# =========================================================================
# --coverage: which of the ReasonCode taxonomy did this run exercise?
# =========================================================================

def _all_reason_codes() -> list:
    return sorted(
        v for k, v in vars(ReasonCode).items()
        if not k.startswith("_") and isinstance(v, str)
    )


# =========================================================================
# CLI:  python3 -m delegation_guard.scenarios <path> [<path> ...] [--coverage]
# =========================================================================

def main(argv=None) -> int:
    """Run one or more scenario files and print a report for each.
    Exit code 0 iff every assertion in every file passed; 2 on a
    structurally broken invocation/file (bad usage, malformed spec).
    `--coverage` additionally prints which ReasonCode values were (and
    were not) exercised, aggregated across all files given."""
    args = sys.argv[1:] if argv is None else list(argv)
    show_coverage = "--coverage" in args
    paths = [a for a in args if a != "--coverage"]
    if not paths:
        print("usage: python3 -m delegation_guard.scenarios <path> [<path> ...] [--coverage]",
              file=sys.stderr)
        return 2

    overall_ok = True
    exercised: set = set()
    for p in paths:
        try:
            result = run_scenarios(p)
        except (ScenarioError, AuthorityError) as e:
            print(f"{p}: ERROR: {e}", file=sys.stderr)
            overall_ok = False
            continue
        print(result.format_report())
        print()
        exercised |= result.coverage()
        if not result.ok:
            overall_ok = False

    if show_coverage:
        all_codes = _all_reason_codes()
        missing = [c for c in all_codes if c not in exercised]
        print(f"coverage: {len(exercised)}/{len(all_codes)} reason code(s) exercised: "
              f"{sorted(exercised)}")
        if missing:
            print(f"  not exercised: {missing}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
