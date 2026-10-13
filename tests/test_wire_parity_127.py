"""Two cross-language differences in the token and ledger paths (attenu-ops #127), each as a test
that failed before its fix. Both were found by the 0.19.2 re-review, identical on 0.19.1, and held
for this release.

1. A Delegation Token whose `scopes` is a JSON object verified under the default -01 profile:
   `_authority_from_payload` handed the object to `Authority`, which read its member names as the
   scopes. The projection class again. The TypeScript implementation refused it. Both now refuse a
   non-array `scopes` as `malformed`, with the same message, on the -01 path; the -02 path refused
   it already, in both.

2. A number whose value is an integer past 2**53 - 1 was refused here only when its JSON text was
   an integer literal: `1e+21` and `1e+308` verified (`9007199254740992.0` was already
   `non_canonical`, and is `malformed` now). JSON has one number type, and the
   JCS form of an integer that large is the exponent form (`10**21` serialises as `1e+21`), so the
   lexical test let the very value it exists to refuse through. The rule is now the value: any
   number whose value is an integer of magnitude above 2**53 - 1 is refused, by
   `canonical.dumps` and at token parse (`malformed`, as the -02's Table 2 names it), whatever its
   lexical form. That is the rule the TypeScript implementation applied all along, and the one the
   published -01 vector `valid_jcs_exponent_form` already states. A ledger entry carrying one has
   no hash to reproduce, so `verify` reports `hash mismatch` at that entry, as TypeScript does.

stdlib-only: python3 tests/test_wire_parity_127.py
"""
import base64
import copy
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attenu_guard import Authority, AuthorityDenied, CallLimit, Guard, SpendCap, canonical, wire  # noqa: E402
from attenu_guard import draft02  # noqa: E402
from attenu_guard.reasons import Disposition, ReasonCode  # noqa: E402
from attenu_guard.audit import GENESIS, AuditLog, _hash  # noqa: E402
from attenu_guard.wire import WireError, WireReasonCode  # noqa: E402

V01 = json.loads((ROOT / "tests/vectors/valid_chain.json").read_text())
V02 = json.loads((ROOT / "tests/vectors-02/valid_chain.json").read_text())


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _resigned(vector, index, edit, *, raw=None, truncate=False):
    """The vector's tokens with token `index` edited by `edit(payload)` and re-signed. With `raw`,
    the member `raw[0]` is written as the JSON text `raw[1]` verbatim (a form Python cannot hold)."""
    tokens = list(vector["tokens"][: index + 1] if truncate else vector["tokens"])
    header_b64, payload_b64, _ = tokens[index].split(".")
    payload = json.loads(_unb64u(payload_b64))
    edit(payload)
    if raw is None:
        text = canonical.dumps(payload)
    else:
        payload[raw[0]] = "__RAW__"
        text = canonical.dumps(payload).replace(b'"__RAW__"', raw[1].encode())
    body = _b64u(text)
    secret = bytes.fromhex(vector["signer"]["secret_hex"])
    sig = hmac.new(secret, f"{header_b64}.{body}".encode(), hashlib.sha256).digest()
    tokens[index] = f"{header_b64}.{body}.{_b64u(sig)}"
    return tokens


def _load(vector, tokens):
    signer = wire.HS256TestSigner(bytes.fromhex(vector["signer"]["secret_hex"]), kid=vector["signer"]["kid"])
    if vector.get("draft") == "02":
        return wire.load(tokens, signer, now=vector["now"], draft="02",
                         accepted_algs=vector["verifier"]["accepted_algs"],
                         audience=vector["verifier"]["audience"])
    return wire.load(tokens, signer, now=vector["now"])


def _set_scopes(value):
    def edit(payload):
        payload["authorization_details"][0]["scopes"] = copy.deepcopy(value)
    return edit


def _noop(payload):
    return None


class ScopesMustBeAnArray(unittest.TestCase):
    """#127 (1): `scopes` read by projection on the -01 token path."""

    def _reason(self, vector, tokens):
        with self.assertRaises(WireError) as cm:
            _load(vector, tokens)
        return cm.exception

    def test_control_resigned_unchanged_still_verifies(self):
        for vector in (V01, V02):
            _load(vector, _resigned(vector, len(vector["tokens"]) - 1, _noop))
            _load(vector, _resigned(vector, 0, _noop, truncate=True))

    def test_object_scopes_on_the_leaf_is_malformed_under_01(self):
        leaf = len(V01["tokens"]) - 1
        e = self._reason(V01, _resigned(V01, leaf, _set_scopes({"crm.read": 1})))
        self.assertEqual(e.reason, WireReasonCode.MALFORMED)
        self.assertIn("scopes is an object, not an array", str(e))

    def test_object_scopes_on_the_root_is_malformed_under_01(self):
        e = self._reason(V01, _resigned(V01, 0, _set_scopes({"crm.read": 1, "mail.send": 1}), truncate=True))
        self.assertEqual(e.reason, WireReasonCode.MALFORMED)
        self.assertIn("scopes is an object, not an array", str(e))

    def test_null_and_string_scopes_are_malformed_under_01(self):
        for value, kind in ((None, "null"), ("crm", "a string")):
            e = self._reason(V01, _resigned(V01, 0, _set_scopes(value), truncate=True))
            self.assertEqual(e.reason, WireReasonCode.MALFORMED, value)
            self.assertIn(f"scopes is {kind}, not an array", str(e))

    def test_object_scopes_is_malformed_under_02(self):
        leaf = len(V02["tokens"]) - 1
        for tokens in (_resigned(V02, leaf, _set_scopes({"crm.read": 1})),
                       _resigned(V02, 0, _set_scopes({"crm.read": 1}), truncate=True)):
            self.assertEqual(self._reason(V02, tokens).reason, WireReasonCode.MALFORMED)

    def test_non_string_members_are_malformed_with_one_message(self):
        """Review m4: a non-string member raised `unhashable type: 'list'` here (a TypeError) and
        `invalid scope ['crm.read']` in TypeScript. Both now say the same thing."""
        for value in ([["crm.read"]], [1], [None], [{"x": 1}], ["crm.read", 1]):
            with self.assertRaises(ValueError, msg=repr(value)) as cm:
                Authority.from_wire({"scopes": value, "constraints": [], "ttl": 60})
            self.assertEqual(str(cm.exception), "scopes must be an array of strings")
            e = self._reason(V01, _resigned(V01, 0, _set_scopes(value), truncate=True))
            self.assertEqual(e.reason, WireReasonCode.MALFORMED)
            self.assertIn("invalid authorization_details: scopes must be an array of strings", str(e))

    def test_from_wire_refuses_a_non_array(self):
        for value in ({"crm.read": 1}, "crm", None, 5, True):
            with self.assertRaises(ValueError, msg=repr(value)):
                Authority.from_wire({"scopes": value, "constraints": [], "ttl": 60})
        self.assertEqual(Authority.from_wire({"scopes": ["crm.read"], "constraints": [], "ttl": 60}).scopes,
                         frozenset({"crm.read"}))
        self.assertEqual(Authority.from_wire({"constraints": [], "ttl": 60}).scopes, frozenset())


class IntegersPastTheSafeRangeByValue(unittest.TestCase):
    """#127 (2): the safe-integer rule applied by lexical form, not by value."""

    def test_canonical_refuses_an_integral_float_past_the_range(self):
        for value in (1e308, -1e308, 1e21, 1.5e300, 9007199254740992.0, -9007199254740992.0, 2.0 ** 60):
            with self.assertRaises(canonical.UnsafeIntegerError, msg=repr(value)):
                canonical.dumps({"t": value})

    def test_the_message_renders_the_number_as_jcs_would(self):
        with self.assertRaises(canonical.UnsafeIntegerError) as cm:
            canonical.dumps(9007199254740992.0)
        self.assertIn("integer 9007199254740992 exceeds", str(cm.exception))
        with self.assertRaises(canonical.UnsafeIntegerError) as cm:
            canonical.dumps(1e308)
        self.assertIn("integer 1e+308 exceeds", str(cm.exception))

    def test_canonical_keeps_every_safe_number(self):
        cases = {9007199254740991.0: b"9007199254740991", -9007199254740991.0: b"-9007199254740991",
                 1e15: b"1000000000000000", 1.5: b"1.5", 1e-7: b"1e-7", 0.5: b"0.5",
                 4503599627370495.5: b"4503599627370495.5", 9007199254740991: b"9007199254740991"}
        for value, out in cases.items():
            self.assertEqual(canonical.dumps(value), out, repr(value))

    def test_a_token_carrying_one_is_malformed_whatever_its_lexical_form(self):
        for vector in (V01, V02):
            for text in ("1e+308", "1e+21", "9007199254740992.0", "9007199254740992"):
                tokens = _resigned(vector, 0, _noop, raw=("exp", text), truncate=True)
                with self.assertRaises(WireError, msg=text) as cm:
                    _load(vector, tokens)
                self.assertEqual(cm.exception.reason, WireReasonCode.MALFORMED, text)
                self.assertIn("exceeds the safe range", str(cm.exception), text)

    def test_the_boundary_value_still_verifies(self):
        for vector in (V01, V02):
            _load(vector, _resigned(vector, 0, _noop, raw=("exp", "9007199254740991"), truncate=True))

    def test_non_finite_keeps_its_own_name(self):
        tokens = _resigned(V01, 0, _noop, raw=("exp", "1e400"), truncate=True)
        with self.assertRaises(WireError) as cm:
            _load(V01, tokens)
        self.assertEqual(cm.exception.reason, WireReasonCode.NON_FINITE)

    def test_a_ledger_entry_carrying_one_does_not_reproduce(self):
        """The bundle case of #127: a root entry whose authority ttl is 1e308 verified here and
        failed integrity in TypeScript. It has no JCS hash now, so the chain fails at that entry."""
        payload = {"v": 2, "c14n": "JCS", "seq": 0, "ts": 0, "event": "root", "node": "n0",
                   "authority": {"scopes": ["crm.read"], "constraints": [], "ttl": 1e308},
                   "prev_hash": GENESIS}
        with self.assertRaises(canonical.UnsafeIntegerError):
            _hash(GENESIS, payload)
        entry = dict(payload, hash="0" * 64)
        self.assertEqual(AuditLog.verify([entry]), (False, "hash mismatch at seq 0"))

    def test_the_02_integer_check_is_by_value(self):
        """Review m3: `draft02.check_integer_safe` tested the Python type."""
        for value in (1e21, 9007199254740992.0, -1e308, 10**21, 2**53):
            with self.assertRaises(ValueError, msg=repr(value)):
                draft02.check_integer_safe(value)
        for value in (2**53 - 1, 9007199254740991.0, 1.5, 0, float("inf"), "1e+21", True):
            draft02.check_integer_safe(value)

    def test_append_refuses_to_write_one(self):
        log = AuditLog()
        with self.assertRaises(canonical.UnsafeIntegerError):
            log.append("note", 0, value=1e300)
        self.assertEqual(log.entries, [])


class UnrepresentableContextIsARecordedDeny(unittest.TestCase):
    """Review M1. With the value rule, a context float of 2**53 or more cannot be written to the
    ledger, and `Guard.check` raised `UnsafeIntegerError` with nothing recorded. Adapters fill the
    context from tool arguments, so a model-sent `amount: 1e21` became an unrecorded refusal. It is
    now a recorded deny: `no_authority` on the constraint `context`, disposition `unresolved`, the
    context left out of the row, the meters as they were, and `AuthorityDenied` raised."""

    def _guard(self, *ceilings):
        return Guard.issue("payer", Authority({"pay.send"}, tuple(ceilings), 60), chain_id="t")

    def _assert_recorded_deny(self, g, before, exc, scope="pay.send"):
        r = exc.decision.reasons[0]
        self.assertFalse(exc.decision)
        self.assertEqual((r.code, r.constraint, r.requested), (ReasonCode.NO_AUTHORITY, "context", scope))
        self.assertTrue(r.message.startswith("context not representable: integer "), r.message)
        entries = g._audit.entries
        self.assertEqual(len(entries), before + 1)
        row = entries[-1]
        self.assertEqual((row["event"], row["reason"], row["disposition"], row["scope"]),
                         ("deny", ReasonCode.NO_AUTHORITY, Disposition.UNRESOLVED, scope))
        self.assertEqual(row["context"], {})
        self.assertEqual(AuditLog.verify(entries), (True, None))
        return r

    def test_spend_past_the_range_is_a_recorded_deny(self):
        g = self._guard(SpendCap(100.0))
        before = len(g._audit.entries)
        with self.assertRaises(AuthorityDenied) as cm:
            g.check("pay.send", spend=1e21)
        r = self._assert_recorded_deny(g, before, cm.exception)
        self.assertEqual(r.message, "context not representable: integer 1e+21 exceeds the safe range "
                                    "±9007199254740991 for a binary64 signing surface "
                                    "(RFC 8785 numbers are IEEE 754 doubles)")

    def test_an_allowed_call_with_a_nanosecond_timestamp_leaves_the_meter_as_it_was(self):
        g = self._guard(CallLimit(2))
        before = len(g._audit.entries)
        with self.assertRaises(AuthorityDenied) as cm:
            g.check("pay.send", context={"ts_ns": 1.76e18})
        self._assert_recorded_deny(g, before, cm.exception)
        self.assertTrue(g.check("pay.send"))
        self.assertTrue(g.check("pay.send"))
        self.assertFalse(g.check("pay.send"))

    def test_enforce_raises_the_same_deny(self):
        g = self._guard(SpendCap(100.0))
        before = len(g._audit.entries)
        with self.assertRaises(AuthorityDenied) as cm:
            g.enforce("pay.send", spend=1e21)
        self._assert_recorded_deny(g, before, cm.exception)

    def test_would_allow_reports_the_deny_and_writes_nothing(self):
        g = self._guard(CallLimit(2))
        before = len(g._audit.entries)
        d = g.would_allow("pay.send", context={"ts_ns": 1.76e18})
        self.assertFalse(d)
        r = d.reasons[0]
        self.assertEqual((r.code, r.constraint, r.requested), (ReasonCode.NO_AUTHORITY, "context", "pay.send"))
        self.assertTrue(r.message.startswith("context not representable: integer 1760000000000000000 exceeds"), r.message)
        self.assertEqual(len(g._audit.entries), before)
        self.assertTrue(g.would_allow("pay.send", context={"ts_ns": 1.76e15}))

    def test_a_representable_context_is_untouched(self):
        g = self._guard(SpendCap(100.0))
        self.assertFalse(g.check("pay.send", spend=1e15))      # an ordinary ceiling deny, returned
        self.assertEqual(g._audit.entries[-1]["context"], {"spend": 1e15})
        self.assertTrue(g.check("pay.send", spend=5.0))

    def test_a_failure_outside_the_context_still_raises(self):
        g = self._guard()
        with self.assertRaises(canonical.LoneSurrogateError):
            g.check("pay.send", tool="\ud800")


if __name__ == "__main__":
    unittest.main(verbosity=2)
