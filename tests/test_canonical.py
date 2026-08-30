"""RFC 8785 JSON Canonicalization Scheme tests (stdlib-only)."""
from __future__ import annotations

import math
import sys
import unittest
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import canonical  # noqa: E402


class IntSubclass(int):
    pass


class TestCanonicalBytes(unittest.TestCase):
    def test_five_reachable_divergence_classes_use_jcs_bytes(self):
        # A sixth class existed here through v0.7: a Python arbitrary-precision int
        # rendered through binary64 (2**60 + 1 -> b"1152921504606847000", silently
        # losing precision). That class is no longer reachable: canonical.dumps now
        # rejects any int outside \u00b1MAX_SAFE_INTEGER instead of lossily rendering it
        # (see TestClosedInputModel.test_unsafe_integers_are_rejected below), so
        # there is no longer a divergent byte form to pin for it.
        cases = (
            (100.0, b"100"),
            (1e-6, b"0.000001"),
            (1e16, b"10000000000000000"),
            ("r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}",
             "\"r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}\"".encode()),
            ({"\ue000": 2, "\U00010000": 1},
             "{\"\U00010000\":1,\"\ue000\":2}".encode()),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(canonical.dumps(value), expected)

    def test_negative_zero_and_required_string_escapes(self):
        self.assertEqual(canonical.dumps(-0.0), b"0")
        self.assertEqual(
            canonical.dumps('"\\\b\f\n\r\t\x00\x1f'),
            b'"\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f"',
        )

    def test_tuple_is_serialized_as_a_json_array(self):
        self.assertEqual(canonical.dumps((None, True, 1, "x")), b'[null,true,1,"x"]')


class TestClosedInputModel(unittest.TestCase):
    def test_non_finite_numbers_are_rejected(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(canonical.NonFiniteNumberError):
                canonical.dumps(value)

    def test_lone_surrogates_are_rejected_in_keys_and_values(self):
        for value in ("\ud800", {"\udfff": "value"}):
            with self.subTest(value=repr(value)), self.assertRaises(canonical.LoneSurrogateError):
                canonical.dumps(value)

    def test_unsafe_integers_are_rejected(self):
        self.assertEqual(canonical.dumps(canonical.MAX_SAFE_INTEGER), b"9007199254740991")
        self.assertEqual(canonical.dumps(-canonical.MAX_SAFE_INTEGER), b"-9007199254740991")
        for value in (canonical.MAX_SAFE_INTEGER + 1, -(canonical.MAX_SAFE_INTEGER + 1)):
            with self.subTest(value=value), self.assertRaises(canonical.UnsafeIntegerError):
                canonical.dumps(value)

    def test_the_collision_pair_no_longer_produces_equal_bytes(self):
        # The bug this closes: two DIFFERENT integers converted through binary64
        # used to render as IDENTICAL JCS bytes (a collision at the signing
        # surface). Now the larger one raises instead of silently colliding.
        two53 = 2**53
        with self.assertRaises(canonical.UnsafeIntegerError):
            canonical.dumps({"max": two53})
        with self.assertRaises(canonical.UnsafeIntegerError):
            canonical.dumps({"max": two53 + 1})

    def test_non_json_and_subclass_values_are_rejected(self):
        values = (
            Decimal("0.1"),
            Fraction(1, 2),
            IntSubclass(7),
            {"x"},
            {1: "non-string key"},
        )
        for value in values:
            with self.subTest(value=repr(value)), self.assertRaises(canonical.UnsupportedTypeError):
                canonical.dumps(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
