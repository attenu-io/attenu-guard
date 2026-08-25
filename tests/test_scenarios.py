"""
tests/test_scenarios.py — unit tests for attenu_guard.scenarios.

stdlib-only (unittest), no pytest, runs with bare `python3`:

    python3 tests/test_scenarios.py

Covers: an allow assertion passing; a deny assertion with the correct
`because` reason passing; a deny assertion with the WRONG `because` reason
being reported as a failure (not an exception); an `expect: allow` assertion
on something actually denied being reported as a failure; loading both the
JSON and YAML forms of the shipped crm_summarizer example (and that they are
byte-for-byte equivalent specs); ceiling-exceeded and scope-not-granted
outcomes (from the shipped example); revoked and expired outcomes (built
directly via `build_tree`/`run_assertions`, since revocation and the passage
of time aren't expressible as static scenario-file content); the
`.yaml`-without-PyYAML error path; structural spec errors (`ScenarioError`)
vs. the core's own structural errors (`AuthorityError`) propagating
unwrapped; and the `main()` CLI entry point's exit codes.
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import AuthorityError, ReasonCode
from attenu_guard.scenarios import (
    ScenarioError, AssertionOutcome, ScenarioResult,
    load_spec, build_tree, run_assertions, run_scenarios, main,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
JSON_EXAMPLE = REPO_ROOT / "scenarios" / "crm_summarizer.json"
YAML_EXAMPLE = REPO_ROOT / "scenarios" / "crm_summarizer.yaml"


def _yaml_available() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


_HAS_YAML = _yaml_available()


class _ManualClock:
    """Deterministic, advanceable clock for TTL/expiry tests — mirrors the
    _ManualClock pattern in tests/red_team.py."""
    def __init__(self):
        self.t = 0.0

    def now(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def crm_summarizer_spec() -> dict:
    """The DEVX-REVIEW.md worked example, as a fresh in-memory dict each
    call (matches scenarios/crm_summarizer.json exactly)."""
    return {
        "root": {
            "agent": "planner",
            "authority": {
                "scopes": ["crm.read", "crm.write"],
                "ceilings": [{"key": "max_rows", "max": 1000}],
                "ttl": 3600,
            },
        },
        "delegations": [
            {
                "as": "summarizer",
                "attenuate": {
                    "scopes": ["crm.read"],
                    "ceilings": [{"key": "max_rows", "max": 100}],
                },
            },
        ],
        "assertions": [
            {"node": "summarizer", "check": {"scope": "crm.read", "context": {"rows": 50}},
             "expect": "allow"},
            {"node": "summarizer", "check": {"scope": "crm.write"},
             "expect": "deny", "because": "scope_not_granted"},
            {"node": "summarizer", "check": {"scope": "crm.read", "context": {"rows": 5000}},
             "expect": "deny", "because": "ceiling_exceeded"},
        ],
    }


# =========================================================================
# The four required behaviors, in-memory (run_scenarios accepts a dict
# directly, no temp file needed).
# =========================================================================
class TestAssertionPassFailSemantics(unittest.TestCase):
    def test_allow_assertion_passes(self):
        result = run_scenarios(crm_summarizer_spec())
        self.assertTrue(result.outcomes[0].passed)
        self.assertEqual(result.outcomes[0].expected, "allow")
        self.assertEqual(result.outcomes[0].actual, "allow")

    def test_deny_with_correct_reason_passes(self):
        result = run_scenarios(crm_summarizer_spec())
        scope_outcome = result.outcomes[1]
        self.assertTrue(scope_outcome.passed)
        self.assertEqual(scope_outcome.actual, "deny")
        self.assertEqual(scope_outcome.reason, ReasonCode.SCOPE_NOT_GRANTED)

        ceiling_outcome = result.outcomes[2]
        self.assertTrue(ceiling_outcome.passed)
        self.assertEqual(ceiling_outcome.actual, "deny")
        self.assertEqual(ceiling_outcome.reason, ReasonCode.CEILING_EXCEEDED)

        self.assertTrue(result.ok)
        self.assertEqual((result.total, result.passed, result.failed), (3, 3, 0))

    def test_deny_with_wrong_expected_reason_is_reported_as_failure(self):
        spec = crm_summarizer_spec()
        # crm.write actually denies with scope_not_granted -- assert the
        # WRONG reason on purpose.
        spec["assertions"] = [
            {"node": "summarizer", "check": {"scope": "crm.write"},
             "expect": "deny", "because": "ceiling_exceeded"},
        ]
        result = run_scenarios(spec)
        self.assertFalse(result.ok)
        outcome = result.outcomes[0]
        self.assertFalse(outcome.passed)
        # the boolean was right (it IS a deny) -- only the reason was wrong.
        self.assertEqual(outcome.actual, "deny")
        self.assertEqual(outcome.expected, "deny")
        self.assertEqual(outcome.reason, ReasonCode.SCOPE_NOT_GRANTED)
        self.assertEqual(outcome.because, "ceiling_exceeded")
        self.assertIn("expected reason", outcome.detail)

    def test_allow_expected_but_actually_denied_fails(self):
        spec = crm_summarizer_spec()
        spec["assertions"] = [
            {"node": "summarizer", "check": {"scope": "crm.write"}, "expect": "allow"},
        ]
        result = run_scenarios(spec)
        self.assertFalse(result.ok)
        outcome = result.outcomes[0]
        self.assertFalse(outcome.passed)
        self.assertEqual(outcome.expected, "allow")
        self.assertEqual(outcome.actual, "deny")
        self.assertIn("expected allow but got deny", outcome.detail)

    def test_because_is_ignored_on_an_allow_assertion(self):
        # "because" only matters when expect == "deny"; a (nonsensical but
        # harmless) "because" alongside "expect: allow" must not affect an
        # otherwise-passing allow.
        spec = crm_summarizer_spec()
        spec["assertions"] = [
            {"node": "summarizer", "check": {"scope": "crm.read", "context": {"rows": 1}},
             "expect": "allow", "because": "scope_not_granted"},
        ]
        result = run_scenarios(spec)
        self.assertTrue(result.outcomes[0].passed)


# =========================================================================
# Reason-code coverage: ceiling_exceeded, scope_not_granted (declarative,
# from the shipped example), revoked and expired (built directly, since
# revocation/time aren't expressible as static scenario-file content).
# =========================================================================
class TestReasonCodeCoverage(unittest.TestCase):
    def test_crm_summarizer_exercises_scope_and_ceiling_denials(self):
        result = run_scenarios(crm_summarizer_spec())
        self.assertEqual(result.coverage(),
                         {ReasonCode.SCOPE_NOT_GRANTED, ReasonCode.CEILING_EXCEEDED})

    def test_revoked_case_via_build_tree_and_revoke(self):
        spec = crm_summarizer_spec()
        nodes = build_tree(spec)
        revoked_ids = nodes["summarizer"].revoke()
        self.assertIn(nodes["summarizer"].node_id, revoked_ids)

        outcomes = run_assertions(nodes, [
            {"node": "summarizer", "check": {"scope": "crm.read", "context": {"rows": 1}},
             "expect": "deny", "because": "revoked"},
        ])
        self.assertTrue(outcomes[0].passed, outcomes[0].detail)
        self.assertEqual(outcomes[0].reason, ReasonCode.REVOKED)

    def test_revoking_root_also_denies_the_delegated_child(self):
        spec = crm_summarizer_spec()
        nodes = build_tree(spec)
        nodes["root"].revoke()
        outcomes = run_assertions(nodes, [
            {"node": "summarizer", "check": {"scope": "crm.read", "context": {"rows": 1}},
             "expect": "deny", "because": "revoked"},
        ])
        self.assertTrue(outcomes[0].passed, outcomes[0].detail)

    def test_expired_case_via_manual_clock(self):
        spec = {
            "root": {"agent": "planner",
                     "authority": {"scopes": ["crm.read"], "ttl": 5}},
            "delegations": [
                {"as": "summarizer", "attenuate": {"scopes": ["crm.read"], "ttl": 5}},
            ],
        }
        clock = _ManualClock()
        nodes = build_tree(spec, clock=clock)

        fresh = run_assertions(nodes, [
            {"node": "summarizer", "check": {"scope": "crm.read"}, "expect": "allow"},
        ])
        self.assertTrue(fresh[0].passed, fresh[0].detail)

        clock.advance(3600)  # ttl was 5s; well past expiry now
        stale = run_assertions(nodes, [
            {"node": "summarizer", "check": {"scope": "crm.read"},
             "expect": "deny", "because": "expired"},
        ])
        self.assertTrue(stale[0].passed, stale[0].detail)
        self.assertEqual(stale[0].reason, ReasonCode.EXPIRED)


# =========================================================================
# build_tree: node naming, "from" default, and structural DSL errors.
# =========================================================================
class TestBuildTree(unittest.TestCase):
    def test_root_is_addressable_as_root_regardless_of_agent_id(self):
        nodes = build_tree(crm_summarizer_spec())
        self.assertIn("root", nodes)
        self.assertEqual(nodes["root"].authority.scopes, {"crm.read", "crm.write"})

    def test_delegation_default_parent_is_root(self):
        spec = crm_summarizer_spec()
        self.assertNotIn("from", spec["delegations"][0])  # relies on the default
        nodes = build_tree(spec)
        self.assertTrue(nodes["summarizer"].authority.is_narrower_than(nodes["root"].authority))

    def test_delegation_can_chain_off_a_named_parent(self):
        spec = crm_summarizer_spec()
        spec["delegations"].append({
            "as": "sub_summarizer", "from": "summarizer",
            "attenuate": {"scopes": ["crm.read"], "ceilings": [{"key": "max_rows", "max": 10}]},
        })
        nodes = build_tree(spec)
        self.assertTrue(nodes["sub_summarizer"].authority.is_narrower_than(nodes["summarizer"].authority))
        self.assertEqual(nodes["sub_summarizer"].authority.ceiling("max_rows").max_rows, 10)

    def test_missing_root_key_raises_scenario_error(self):
        with self.assertRaises(ScenarioError):
            build_tree({"delegations": [], "assertions": []})

    def test_missing_agent_raises_scenario_error(self):
        with self.assertRaises(ScenarioError):
            build_tree({"root": {"authority": {"scopes": ["crm.read"]}}})

    def test_delegation_missing_as_raises_scenario_error(self):
        spec = crm_summarizer_spec()
        spec["delegations"] = [{"attenuate": {"scopes": ["crm.read"]}}]
        with self.assertRaises(ScenarioError):
            build_tree(spec)

    def test_duplicate_as_name_raises_scenario_error(self):
        spec = crm_summarizer_spec()
        spec["delegations"].append({"as": "summarizer", "attenuate": {"scopes": ["crm.read"]}})
        with self.assertRaises(ScenarioError):
            build_tree(spec)

    def test_unknown_parent_reference_raises_scenario_error(self):
        spec = crm_summarizer_spec()
        spec["delegations"][0]["from"] = "does-not-exist"
        with self.assertRaises(ScenarioError):
            build_tree(spec)

    def test_forward_reference_is_rejected_like_an_unknown_parent(self):
        # delegations are processed in file order; a "from" naming a node
        # defined LATER in the file must be rejected, not silently allowed.
        spec = {
            "root": {"agent": "planner", "authority": {"scopes": ["crm.*"], "ttl": 100}},
            "delegations": [
                {"as": "a", "from": "b", "attenuate": {"scopes": ["crm.read"]}},
                {"as": "b", "attenuate": {"scopes": ["crm.read"]}},
            ],
        }
        with self.assertRaises(ScenarioError):
            build_tree(spec)

    def test_core_structural_failure_propagates_as_authority_error_not_scenario_error(self):
        # max_depth=1: root(depth0) -> a(depth1) is fine, a -> b(depth2)
        # overflows. This is a STRUCTURAL failure the core itself refuses
        # (guard.delegate/chain.add_child) -- it must surface as the core's
        # own AuthorityError, unwrapped, not a ScenarioError.
        spec = {
            "root": {"agent": "p", "authority": {"scopes": ["crm.*"], "ttl": 100},
                     "max_depth": 1},
            "delegations": [
                {"as": "a", "attenuate": {"scopes": ["crm.read"], "ttl": 100}},
                {"as": "b", "from": "a", "attenuate": {"scopes": ["crm.read"], "ttl": 100}},
            ],
        }
        with self.assertRaises(AuthorityError):
            build_tree(spec)


# =========================================================================
# run_assertions: structural DSL errors on the assertion side.
# =========================================================================
class TestRunAssertionsErrors(unittest.TestCase):
    def setUp(self):
        self.nodes = build_tree(crm_summarizer_spec())

    def test_unknown_node_raises_scenario_error(self):
        with self.assertRaises(ScenarioError):
            run_assertions(self.nodes, [
                {"node": "nonexistent", "check": {"scope": "crm.read"}, "expect": "allow"},
            ])

    def test_missing_scope_raises_scenario_error(self):
        with self.assertRaises(ScenarioError):
            run_assertions(self.nodes, [{"node": "summarizer", "check": {}, "expect": "allow"}])

    def test_bad_expect_value_raises_scenario_error(self):
        with self.assertRaises(ScenarioError):
            run_assertions(self.nodes, [
                {"node": "summarizer", "check": {"scope": "crm.read"}, "expect": "maybe"},
            ])


# =========================================================================
# Loading the shipped example files: JSON always, YAML when PyYAML exists.
# =========================================================================
class TestExampleFiles(unittest.TestCase):
    def test_json_example_loads_and_all_assertions_pass(self):
        result = run_scenarios(JSON_EXAMPLE)
        self.assertEqual(result.path, str(JSON_EXAMPLE))
        self.assertTrue(result.ok, result.format_report())
        self.assertEqual(result.total, 3)

    @unittest.skipUnless(_HAS_YAML, "PyYAML not installed")
    def test_yaml_example_loads_and_all_assertions_pass(self):
        result = run_scenarios(YAML_EXAMPLE)
        self.assertTrue(result.ok, result.format_report())
        self.assertEqual(result.total, 3)

    @unittest.skipUnless(_HAS_YAML, "PyYAML not installed")
    def test_json_and_yaml_examples_are_equivalent_specs(self):
        self.assertEqual(load_spec(JSON_EXAMPLE), load_spec(YAML_EXAMPLE))

    @unittest.skipUnless(_HAS_YAML, "PyYAML not installed")
    def test_json_and_yaml_examples_exercise_the_same_coverage(self):
        json_result = run_scenarios(JSON_EXAMPLE)
        yaml_result = run_scenarios(YAML_EXAMPLE)
        self.assertEqual(json_result.coverage(), yaml_result.coverage())

    def test_yaml_path_without_pyyaml_raises_clear_scenario_error(self):
        # Simulate "PyYAML is not installed" deterministically, regardless
        # of whether it's actually installed in THIS environment: setting
        # sys.modules['yaml'] = None makes the next `import yaml` raise
        # ModuleNotFoundError, exactly like a real absent install would.
        old = sys.modules.get("yaml", "__unset__")
        sys.modules["yaml"] = None
        try:
            with self.assertRaises(ScenarioError) as ctx:
                load_spec(YAML_EXAMPLE)
            msg = str(ctx.exception)
            self.assertIn("pyyaml", msg.lower())
            self.assertIn("json", msg.lower())
        finally:
            if old == "__unset__":
                sys.modules.pop("yaml", None)
            else:
                sys.modules["yaml"] = old

    def test_non_mapping_json_raises_scenario_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "not_a_mapping.json"
            p.write_text(json.dumps([1, 2, 3]))
            with self.assertRaises(ScenarioError):
                load_spec(p)


# =========================================================================
# ScenarioResult: report formatting, coverage(), to_dict().
# =========================================================================
class TestScenarioResultReport(unittest.TestCase):
    def test_format_report_marks_pass_and_fail(self):
        spec = crm_summarizer_spec()
        spec["assertions"].append(
            {"node": "summarizer", "check": {"scope": "crm.write"}, "expect": "allow"})
        result = run_scenarios(spec)
        report = result.format_report()
        self.assertIn("[PASS]", report)
        self.assertIn("[FAIL]", report)
        self.assertIn("assertions passed", report)
        self.assertFalse(result.ok)

    def test_to_dict_is_json_serializable_and_matches_totals(self):
        result = run_scenarios(crm_summarizer_spec())
        as_dict = result.to_dict()
        json.dumps(as_dict)  # must not raise
        self.assertEqual(as_dict["total"], 3)
        self.assertEqual(as_dict["passed"], 3)
        self.assertEqual(as_dict["failed"], 0)
        self.assertTrue(as_dict["ok"])
        self.assertEqual(len(as_dict["outcomes"]), 3)

    def test_in_memory_spec_has_no_path(self):
        result = run_scenarios(crm_summarizer_spec())
        self.assertIsNone(result.path)
        self.assertIn("<in-memory>", result.format_report())


# =========================================================================
# main() — the CLI entry point.
# =========================================================================
class TestMain(unittest.TestCase):
    @staticmethod
    def _run(argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_main_on_passing_example_exits_zero(self):
        code, out = self._run([str(JSON_EXAMPLE)])
        self.assertEqual(code, 0)
        self.assertIn("3/3 assertions passed", out)

    def test_main_coverage_flag_prints_exercised_reason_codes(self):
        code, out = self._run([str(JSON_EXAMPLE), "--coverage"])
        self.assertEqual(code, 0)
        self.assertIn("coverage:", out)
        self.assertIn(ReasonCode.SCOPE_NOT_GRANTED, out)
        self.assertIn(ReasonCode.CEILING_EXCEEDED, out)
        # a code this scenario does NOT exercise should show up as missing.
        self.assertIn(ReasonCode.REVOKED, out)

    def test_main_no_args_returns_usage_error(self):
        code, _ = self._run([])
        self.assertEqual(code, 2)

    def test_main_on_failing_scenario_returns_nonzero(self):
        spec = crm_summarizer_spec()
        spec["assertions"] = [
            {"node": "summarizer", "check": {"scope": "crm.write"}, "expect": "allow"},
        ]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text(json.dumps(spec))
            code, out = self._run([str(p)])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL]", out)

    def test_main_on_malformed_spec_reports_error_and_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "malformed.json"
            p.write_text(json.dumps({"delegations": [], "assertions": []}))  # no "root"
            code, out = self._run([str(p)])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
