"""`_check_client` / `_check_server` must report an unreadable authority, not raise.

Ops #111, a regression introduced by the #109 work and found by a code review
reading the call sites rather than running them.

`Authority.from_wire` became PARTIAL in 0.17.0: it refuses a constraint carrying
members this build does not read. That is the point of #109 and it is correct on
the token path, where `wire._authority_from_payload` wraps it into a
`WireError`. But `Authority.from_wire` is a public API, and these two functions
are documented to return `(bool, failures)`. Three call sites here were
unguarded, so a bundle carrying such a constraint raised straight out of that
contract and handed a caller who correctly handles a failure list an exception
instead.

A bundle is untrusted input. "Untrusted input makes a documented-total function
raise" is the same defect shape as the one #109 fixed, one layer out.

These tests exist because nothing else exercises them: the `a2a` extra is not
installed in the default dev environment, so the whole adapter is skipped and
the suite went from 578 to 582 passing while saying nothing about this file.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from attenu_guard import Authority  # noqa: E402

try:
    from attenu_guard.adapters import a2a
except Exception as exc:  # pragma: no cover - the extra is optional
    a2a = None
    _IMPORT_ERROR = exc


# A constraint the current build refuses: `min` alongside `max` is two typed
# values in one object, which the draft's constraint vocabulary does not allow.
UNREADABLE = {"key": "max_rows", "max": 100, "min": 9999}
READABLE = {"key": "max_rows", "max": 100}


def _bundle(constraint, node="leaf", agent="worker"):
    return {
        "chain_id": "chain-1",
        "entries": [
            {
                "event": "root",
                "seq": 0,
                "node": node,
                "agent": agent,
                "authority": {"scopes": ["crm.read"], "constraints": [constraint], "ttl": 300},
            }
        ],
    }


@unittest.skipIf(a2a is None, f"a2a extra not installed: {globals().get('_IMPORT_ERROR')}")
class UnreadableAuthorityIsReported(unittest.TestCase):

    def test_authority_of_returns_none_and_names_the_reason(self):
        failures = []
        held = a2a._authority_of(_bundle(UNREADABLE), "leaf", failures)
        self.assertIsNone(held)
        self.assertEqual(len(failures), 1)
        self.assertIn("unreadable authority", failures[0])

    def test_authority_of_still_reads_a_good_bundle(self):
        failures = []
        held = a2a._authority_of(_bundle(READABLE), "leaf", failures)
        self.assertIsNotNone(held)
        self.assertEqual(failures, [])

    def test_authority_of_absent_node_is_not_reported_as_unreadable(self):
        """Absent and unreadable both return None; only one is a parse failure."""
        failures = []
        self.assertIsNone(a2a._authority_of(_bundle(READABLE), "no-such-node", failures))
        self.assertEqual(failures, [])

    def test_check_server_reports_rather_than_raises(self):
        """The contract is `(bool, failures)`. It must hold on untrusted input."""
        leaf_authority = Authority.from_wire(
            {"scopes": ["crm.read"], "constraints": [READABLE], "ttl": 300})
        bundle = _bundle(UNREADABLE, node="root-node", agent="worker")
        try:
            ok, failures = a2a._check_server(
                bundle, "chain-1", "worker", leaf_authority)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"_check_server raised out of its (bool, failures) contract: {exc!r}")
        self.assertFalse(ok)
        self.assertTrue(failures, "a refusal must be reported, not swallowed")

    def test_check_client_reports_rather_than_raises(self):
        leaf_authority = Authority.from_wire(
            {"scopes": ["crm.read"], "constraints": [READABLE], "ttl": 300})
        bundle = _bundle(UNREADABLE, node="leaf", agent="worker")
        try:
            ok, failures = a2a._check_client(bundle, "leaf", "worker", leaf_authority)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"_check_client raised out of its (bool, failures) contract: {exc!r}")
        self.assertFalse(ok)
        self.assertTrue(failures, "a refusal must be reported, not swallowed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
