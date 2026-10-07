"""The -02 profile of `Authority` (draft-asor-wimse-agent-delegation-chain-02, Sections 4.1 to
4.3): the three-form scope grammar, the generic constraint vocabulary, one constraint per
(key, type), rank with its ordering on the wire, the cumulative types, and the guarantee the
whole library rests on, restated for the new profile: the meet never widens.

The default profile is "01" and is asserted unchanged here, so that no existing caller, adapter,
or published vector changes behaviour.

stdlib-only: python3 tests/test_draft02_authority.py
"""
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import (Allow, Authority, AuthorityError, CallLimit, Deny, EgressRank, Guard,  # noqa: E402
                          Prefix, RowLimit, SpendCap)
from attenu_guard import draft02 as d  # noqa: E402
from attenu_guard.ceilings import _UnknownCeiling  # noqa: E402

ORDER = ["none", "internal", "any"]


def A02(scopes, ceilings=(), ttl=100):
    return Authority(scopes, ceilings, ttl, profile="02")


class ScopeGrammar(unittest.TestCase):
    def test_classification_by_bytes_in_the_drafts_order(self):
        self.assertEqual(d.classify_scope("crm.read"), "literal")
        self.assertEqual(d.classify_scope("crm.*"), "wildcard")
        self.assertEqual(d.classify_scope("crm.x.*"), "wildcard")
        for opaque in ("User.Read", "openid", "repo:status", "https://graph.example/.default", "a"):
            self.assertEqual(d.classify_scope(opaque), "opaque", opaque)
        for invalid in ("*", "crm.re*", "crm.*.read", "User.*", "", "a b", "crm.readé", 5, None):
            self.assertIsNone(d.classify_scope(invalid), repr(invalid))

    def test_covering_relation(self):
        self.assertTrue(d.scope_covers("crm.*", "crm.read"))
        self.assertTrue(d.scope_covers("crm.*", "crm.x.y.z"))
        self.assertTrue(d.scope_covers("crm.*", "crm.x.*"))          # a narrower wildcard under its prefix
        self.assertFalse(d.scope_covers("crm.*", "crm"))
        self.assertFalse(d.scope_covers("crm.*", "crmx.read"))
        self.assertTrue(d.scope_covers("crm.read", "crm.read"))
        self.assertFalse(d.scope_covers("crm.read", "crm.*"))
        # Kieran Sweeney's three cases, from the list thread of 2026-10-06/07.
        self.assertFalse(d.scope_covers("drive.*", "drive.Read"), "a wildcard never covers an opaque scope")
        self.assertFalse(d.scope_covers("drive.Read", "drive.*"), "an opaque scope never covers a wildcard")
        self.assertTrue(d.scope_covers("repo:status", "repo:status"), "opaque covers byte-identical only")
        self.assertFalse(d.scope_covers("User.Read", "user.read"), "no case folding")

    def test_a_provider_string_shaped_like_a_literal_is_a_literal(self):
        """The residual ambiguity the -02 states beside the grammar (Iman Schrock's request):
        `payment.release` is a literal, so `payment.*` covers it."""
        self.assertEqual(d.classify_scope("payment.release"), "literal")
        self.assertTrue(d.scope_covers("payment.*", "payment.release"))

    def test_the_default_profile_is_unchanged(self):
        with self.assertRaises(ValueError):
            Authority({"User.Read"})
        self.assertTrue(Authority({"drive.*"}).covers_scope("drive.read"))
        a02 = A02({"User.Read", "repo:status"})
        self.assertTrue(a02.covers_scope("User.Read"))
        self.assertFalse(a02.covers_scope("user.read"))
        with self.assertRaises(ValueError):
            A02({"User.*"})


class OneConstraintPerKeyAndType(unittest.TestCase):
    def test_a_min_and_a_max_on_one_key_form_a_range(self):
        a = A02({"hr.read"}, [d.Min("tenure_years", 2), d.Max("tenure_years", 10)])
        self.assertEqual(len(a.ceilings_for("tenure_years")), 2)
        self.assertTrue(a.permits("hr.read", {"tenure_years": 5}))
        self.assertFalse(a.permits("hr.read", {"tenure_years": 1}))
        self.assertFalse(a.permits("hr.read", {"tenure_years": 11}))

    def test_two_of_one_type_on_one_key_are_malformed(self):
        with self.assertRaises(ValueError) as cm:
            A02({"a.b"}, [d.Max("rows", 1), d.Max("rows", 2)])
        self.assertIn("one per (key, type)", str(cm.exception))
        with self.assertRaises(ValueError):
            A02({"a.b"}, [RowLimit(1), d.Max("max_rows", 2)])        # legacy and generic are both `max`

    def test_an_allow_list_and_a_deny_list_on_one_key_are_both_evaluated(self):
        a = A02({"a.b"}, [Allow("region", ["us", "eu"]), Deny("region", ["eu"])])
        self.assertTrue(a.permits("a.b", {"region": "us"}))
        self.assertFalse(a.permits("a.b", {"region": "eu"}))
        self.assertFalse(a.permits("a.b", {"region": "jp"}))

    def test_the_default_profile_still_refuses_two_per_key(self):
        with self.assertRaises(ValueError) as cm:
            Authority({"a.b"}, [Allow("region", ["us"]), Deny("region", ["rm"])])
        self.assertIn("one per key", str(cm.exception))

    def test_narrowing_pairs_by_key_and_type(self):
        parent = A02({"a.b"}, [d.Min("t", 2), d.Max("t", 10)])
        self.assertTrue(A02({"a.b"}, [d.Min("t", 3), d.Max("t", 9)]).is_narrower_than(parent))
        self.assertFalse(A02({"a.b"}, [d.Min("t", 1), d.Max("t", 9)]).is_narrower_than(parent))
        self.assertFalse(A02({"a.b"}, [d.Max("t", 9)]).is_narrower_than(parent), "the floor is dropped")
        child = parent.meet(A02({"a.b"}, [d.Min("t", 5), d.Max("t", 20)]))
        self.assertEqual(child.to_wire()["constraints"], [{"key": "t", "max": 10}, {"key": "t", "min": 5}])


class NoInferenceAcrossTypes(unittest.TestCase):
    def test_a_lifetime_bound_does_not_satisfy_a_per_action_bound(self):
        parent = A02({"a.b"}, [d.Max("spend", 100)])
        self.assertFalse(A02({"a.b"}, [d.MaxLifetime("spend", 50)]).is_narrower_than(parent))
        self.assertFalse(A02({"a.b"}, [d.Max("spend", 50)]).is_narrower_than(
            A02({"a.b"}, [d.MaxLifetime("spend", 100)])))
        self.assertTrue(A02({"a.b"}, [d.Max("spend", 50), d.MaxLifetime("spend", 40)]).is_narrower_than(
            A02({"a.b"}, [d.Max("spend", 100), d.MaxLifetime("spend", 400)])))


class CumulativeConstraintsDenyWithoutATotal(unittest.TestCase):
    def test_a_lifetime_bound_with_no_running_total_denies(self):
        a = A02({"a.b"}, [d.MaxLifetime("spend", 100)])
        decision = a.permits("a.b", {"spend": 10})
        self.assertFalse(decision)
        self.assertIn("no running total", decision.reasons[0].message)
        self.assertTrue(a.permits("a.b", {"spend": 10}, totals={"spend_total": 90}))
        self.assertFalse(a.permits("a.b", {"spend": 10}, totals={"spend_total": 101}))
        self.assertFalse(a.permits("a.b", {"spend_total": 90}), "a total in the caller context is ignored")

    def test_a_subtree_bound_reads_its_own_total(self):
        a = A02({"a.b"}, [d.MaxSubtree("spend", 100)])
        self.assertFalse(a.permits("a.b", {}, totals={"spend_total": 1}))
        self.assertTrue(a.permits("a.b", {}, totals={"spend_subtree_total": 100}))

    def test_a_per_action_max_still_asserts_nothing_when_absent(self):
        self.assertTrue(A02({"a.b"}, [d.Max("spend", 100)]).permits("a.b", {}))

    def test_the_guards_call_meter_feeds_a_lifetime_call_bound(self):
        """`max_calls` is the one key whose per-action field IS the running total: the guard
        fills `calls` itself, so a -02 chain holding a lifetime call bound is held by the guard."""
        root = Guard.issue("root", A02({"crm.read"}, [CallLimit(2)], ttl=60), max_depth=2)
        self.assertTrue(root.check("crm.read"))
        self.assertTrue(root.check("crm.read"))
        self.assertFalse(root.check("crm.read"))
        # The same bound after a -02 wire round trip is the generic type, reading the same field.
        generic = Authority.from_wire(root.authority.to_wire(), profile="02")
        self.assertIsInstance(generic.ceilings[0], d.MaxLifetime)
        self.assertEqual(generic.ceilings[0].ctx_field, "calls")
        self.assertTrue(generic.permits("crm.read", {"calls": 2}))
        self.assertFalse(generic.permits("crm.read", {"calls": 3}))
        self.assertFalse(generic.permits("crm.read", {}), "no total held: deny")


class RankWithOrdering(unittest.TestCase):
    def test_the_ordering_travels_on_the_wire(self):
        self.assertEqual(EgressRank("internal").to_wire_02(),
                         {"key": "egress", "rank": "internal", "order": ORDER})
        a = Authority.from_wire({"scopes": ["a.b"], "constraints": [EgressRank("internal").to_wire_02()],
                                 "ttl": 10}, profile="02")
        self.assertIsInstance(a.ceilings[0], d.Rank)
        self.assertTrue(a.permits("a.b", {"egress": "none"}))
        self.assertFalse(a.permits("a.b", {"egress": "any"}))
        self.assertFalse(a.permits("a.b", {"egress": "everywhere"}), "a value outside order is refused")

    def test_a_child_must_carry_the_parents_ordering(self):
        parent = A02({"a.b"}, [d.Rank("egress", "internal", ORDER)])
        self.assertTrue(A02({"a.b"}, [d.Rank("egress", "none", ORDER)]).is_narrower_than(parent))
        self.assertFalse(A02({"a.b"}, [d.Rank("egress", "any", ORDER)]).is_narrower_than(parent))
        self.assertFalse(A02({"a.b"}, [d.Rank("egress", "none", ["none", "any"])]).is_narrower_than(parent))
        with self.assertRaises(AuthorityError) as cm:
            parent.meet(A02({"a.b"}, [d.Rank("egress", "none", ["none", "any"])]))
        self.assertEqual(cm.exception.reason, "not_narrower")

    def test_malformed_ranks(self):
        with self.assertRaises(ValueError):
            d.Rank("egress", "none", ["none"])                # fewer than two members
        with self.assertRaises(ValueError):
            d.Rank("egress", "none", ["none", "none"])        # not distinct
        with self.assertRaises(ValueError):
            d.Rank("egress", "high", ORDER)                   # rank not a member
        with self.assertRaises(ValueError):
            d.ceiling_from_wire_02({"key": "egress", "rank": "none"})   # the -01 shape lacks order


class ClosedConstraintObjects(unittest.TestCase):
    def test_closed_members(self):
        for bad in ({"key": "x", "max": 1, "note": "n"},
                    {"key": "x", "max": 1, "min": 0},
                    {"key": "x", "one_of": ["a"], "type": "allow"},
                    {"key": "x", "one_of": ["a"], "field": "y"},
                    {"key": "x", "max_lifetime": 5, "applies_to": "a.b"},
                    {"key": "x"},
                    {"key": "x", "foo": 1, "bar": 2}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                d.ceiling_from_wire_02(bad)

    def test_one_unknown_type_fails_closed_rather_than_malformed(self):
        c = d.ceiling_from_wire_02({"key": "x", "quota": 5})
        self.assertIsInstance(c, _UnknownCeiling)
        self.assertFalse(c.permits({"x": 1}))

    def test_the_library_ceilings_emit_closed_objects(self):
        a = A02({"a.b"}, [Allow("region", ["us"]), Deny("tool", ["rm"]), Prefix("path", "/tmp/"),
                          RowLimit(5), SpendCap(2.5), CallLimit(3, "a.*"), EgressRank("none")])
        for c in a.to_wire()["constraints"]:
            self.assertNotIn("type", c)
            self.assertNotIn("field", c)
            self.assertNotIn("applies_to", c)
            d.ceiling_from_wire_02(c)             # round-trips through the -02 parser
        self.assertIn({"key": "max_calls[a.*]", "max_lifetime": 3}, a.to_wire()["constraints"])
        with self.assertRaises(ValueError):
            A02({"a.b"}, [Allow("region", ["us"], field="geo")]).to_wire()

    def test_the_default_profile_wire_form_is_unchanged(self):
        self.assertEqual(Authority({"a.b"}, [CallLimit(3)]).to_wire()["constraints"],
                         [{"key": "max_calls", "max": 3}])
        self.assertEqual(Authority({"a.b"}, [EgressRank("none")]).to_wire()["constraints"],
                         [{"key": "egress", "rank": "none"}])


class ProfilesDoNotMix(unittest.TestCase):
    def test_meet_refuses_and_narrower_is_false_across_profiles(self):
        a01 = Authority({"a.b"}, [RowLimit(1)], 10)
        a02 = A02({"a.b"}, [RowLimit(1)], 10)
        self.assertFalse(a01.is_narrower_than(a02))
        self.assertFalse(a02.is_narrower_than(a01))
        with self.assertRaises(AuthorityError) as cm:
            a01.meet(a02)
        self.assertEqual(cm.exception.reason, "not_narrower")
        with self.assertRaises(ValueError):
            Authority({"a.b"}, profile="03")


# =========================================================================
# Property trials: under the -02 profile the meet never widens
# =========================================================================

LITERALS = ["crm.read", "crm.write", "crm.export", "mail.send", "files.read", "pay.transfer"]
WILDS = ["crm.*", "mail.*", "files.*"]
OPAQUES = ["User.Read", "repo:status", "openid", "user.read"]


def rnd_authority(rng):
    scopes = set(rng.sample(LITERALS + WILDS + OPAQUES, rng.randint(0, 6)))
    pool = [
        lambda: RowLimit(rng.randint(0, 1000)),
        lambda: d.Max("max_rows", rng.randint(0, 1000)),
        lambda: d.Min("max_rows", rng.randint(0, 1000)),
        lambda: d.MaxLifetime("max_spend", rng.randint(0, 1000)),
        lambda: d.MaxSubtree("max_spend", rng.randint(0, 1000)),
        lambda: SpendCap(rng.randint(0, 1000)),
        lambda: d.Rank("egress", rng.choice(ORDER), ORDER),
        lambda: d.Rank("tier", rng.choice(["t1", "t2", "t3"]), ["t1", "t2", "t3"]),
        lambda: Allow("region", rng.sample(["us", "eu", "jp", "br"], rng.randint(0, 4))),
        lambda: Deny("region", rng.sample(["us", "eu", "jp", "br"], rng.randint(0, 4))),
        # Prefixes drawn from one chain so every pair is comparable: the meet of two
        # incomparable prefixes is the library's "admits nothing" NUL encoding, which
        # `Prefix.subsumes` does not recognise as narrower (a -01 property, unchanged here).
        lambda: Prefix("path", rng.choice(["/", "/tmp", "/tmp/a"])),
    ]
    ceilings = []
    seen = set()
    for make in rng.sample(pool, rng.randint(0, len(pool))):
        c = make()
        k = (c.key, d.draft_type_of(c))
        if k in seen:
            continue
        seen.add(k)
        ceilings.append(c)
    return Authority(scopes, ceilings, rng.randint(1, 7200), profile="02")


class MeetNeverWidensUnderTheNewProfile(unittest.TestCase):
    TRIALS = 2000

    def test_meet_is_narrower_than_both_inputs(self):
        rng = random.Random(20261007)
        for _ in range(self.TRIALS):
            p, r = rnd_authority(rng), rnd_authority(rng)
            try:
                c = p.meet(r)
            except AuthorityError as e:
                # Only a rank whose ordering differs, or two types under a key the library
                # cannot narrow, refuse a meet; both are recorded as not_narrower.
                self.assertEqual(e.reason, "not_narrower", (p, r))
                continue
            self.assertTrue(c.is_narrower_than(p), (p, r, c))
            self.assertTrue(c.is_narrower_than(r), (p, r, c))
            self.assertTrue(c.is_narrower_than(c))

    def test_a_meet_survives_a_wire_round_trip_as_narrower(self):
        rng = random.Random(7)
        for _ in range(500):
            p, r = rnd_authority(rng), rnd_authority(rng)
            try:
                c = p.meet(r)
            except AuthorityError:
                continue
            p2 = Authority.from_wire(p.to_wire(), profile="02")
            c2 = Authority.from_wire(c.to_wire(), profile="02")
            self.assertTrue(c2.is_narrower_than(p2), (p, c))
            self.assertEqual(c2.to_wire(), c.to_wire())

    def test_a_random_widening_is_caught(self):
        rng = random.Random(99)
        caught = 0
        for _ in range(500):
            p = rnd_authority(rng)
            wider = Authority(p.scopes | {rng.choice(LITERALS + OPAQUES)}, p.ceilings, p.ttl, profile="02")
            if wider.scopes != p.scopes and not any(p.covers_scope(s) for s in wider.scopes - p.scopes):
                self.assertFalse(wider.is_narrower_than(p))
                caught += 1
        self.assertGreater(caught, 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
