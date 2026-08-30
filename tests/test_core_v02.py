"""
tests/test_core_v02.py — unit tests for the v0.2 core surface.

stdlib-only (unittest), no pytest, runs with bare `python3`:

    python3 tests/test_core_v02.py

Covers what run_properties.py (randomised invariants) and red_team.py
(adversarial scenarios) don't specifically pin down: the exact shape of
Decision/Reason, every built-in Ceiling's permits/narrow/subsumes/wire
round-trip, fail-closed handling of an unknown wire constraint, that `meet`
never widens, `is_narrower_than` correctness (including custom ceilings),
that the v0.1 aliases still work and warn, that `would_allow` never touches
the audit log, and that `enforce`/`check` really are two different gates on
top of the same evaluation.
"""
import sys
import unittest
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attenu_guard import (
    Authority, Guard, AuthorityError, AuthorityDenied,
    Decision, Reason, ReasonCode, AuditLog,
    Ceiling, RowLimit, SpendCap, CallLimit, EgressRank, Allow, Deny, Prefix,
    register_ceiling,
)
from attenu_guard.ceilings import ceiling_from_wire, _UnknownCeiling
from dataclasses import dataclass, field


@dataclass(frozen=True)
class _WidgetLimit:
    """A minimal custom Ceiling (outside the built-in registry), used to
    test that meet/is_narrower_than/permits are sound for ANY ceiling key,
    not just the ones ceilings.py ships. Mirrors RowLimit's shape."""
    max_widgets: int
    key: str = field(default="max_widgets", init=False, repr=False)

    def permits(self, ctx):
        n = ctx.get("widgets")
        if n is None or n <= self.max_widgets:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_widgets, n))

    def narrow(self, other):
        return _WidgetLimit(min(self.max_widgets, other.max_widgets))

    def subsumes(self, other):
        return self.max_widgets >= other.max_widgets

    def to_wire(self):
        return {"key": self.key, "type": "widget_limit", "max": self.max_widgets}

    @classmethod
    def from_wire(cls, d):
        return cls(d["max"])


# =========================================================================
# Decision / Reason
# =========================================================================
class TestDecision(unittest.TestCase):
    def test_allow_is_truthy_and_has_no_reasons(self):
        d = Decision.allow()
        self.assertTrue(d)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reasons, ())
        self.assertIsNone(d.determining_node)

    def test_deny_is_falsy_and_carries_reasons(self):
        r = Reason(ReasonCode.SCOPE_NOT_GRANTED, requested="crm.export")
        d = Decision.deny(r, node="n1")
        self.assertFalse(d)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reasons, (r,))
        self.assertEqual(d.determining_node, "n1")

    def test_explain_allow(self):
        self.assertEqual(Decision.allow().explain(), "allowed")

    def test_explain_deny_mentions_code_and_message(self):
        r = Reason(ReasonCode.CEILING_EXCEEDED, "max_rows", 100, 500, "too many rows")
        d = Decision.deny(r)
        text = d.explain()
        self.assertIn("ceiling_exceeded", text)
        self.assertIn("max_rows", text)
        self.assertIn("too many rows", text)

    def test_decision_to_dict_shape(self):
        r = Reason(ReasonCode.EXPIRED, limit=10, requested=20)
        d = Decision.deny(r, node="n1")
        as_dict = d.to_dict()
        self.assertEqual(as_dict["allowed"], False)
        self.assertEqual(as_dict["determining_node"], "n1")
        self.assertEqual(len(as_dict["reasons"]), 1)
        self.assertEqual(as_dict["reasons"][0]["code"], ReasonCode.EXPIRED)

    def test_reason_to_dict_roundtrips_fields(self):
        r = Reason("custom_code", "k", 1, 2, "msg")
        d = r.to_dict()
        self.assertEqual(d, {"code": "custom_code", "constraint": "k",
                             "limit": 1, "requested": 2, "message": "msg"})


# =========================================================================
# Built-in ceilings — permits / narrow / subsumes / wire round-trip
# =========================================================================
class TestRowLimit(unittest.TestCase):
    def test_permits_within_and_over_bound(self):
        c = RowLimit(100)
        self.assertTrue(c.permits({"rows": 100}))
        self.assertTrue(c.permits({"rows": 0}))
        self.assertFalse(c.permits({"rows": 101}))

    def test_missing_ctx_field_is_permitted(self):
        # nothing asserted this call -> not a violation (mirrors v0.1: an
        # omitted quantity simply isn't checked).
        self.assertTrue(RowLimit(1).permits({}))

    def test_deny_reason_shape(self):
        d = RowLimit(10).permits({"rows": 50})
        self.assertFalse(d)
        self.assertEqual(d.reasons[0].code, ReasonCode.CEILING_EXCEEDED)
        self.assertEqual(d.reasons[0].constraint, "max_rows")
        self.assertEqual(d.reasons[0].limit, 10)
        self.assertEqual(d.reasons[0].requested, 50)

    def test_narrow_takes_min(self):
        self.assertEqual(RowLimit(100).narrow(RowLimit(10)).max_rows, 10)
        self.assertEqual(RowLimit(10).narrow(RowLimit(100)).max_rows, 10)

    def test_subsumes(self):
        self.assertTrue(RowLimit(100).subsumes(RowLimit(10)))   # 100 admits more than 10
        self.assertFalse(RowLimit(10).subsumes(RowLimit(100)))

    def test_wire_roundtrip(self):
        c = RowLimit(500)
        wire = c.to_wire()
        self.assertEqual(wire, {"key": "max_rows", "max": 500})
        self.assertEqual(RowLimit.from_wire(wire), c)
        self.assertEqual(ceiling_from_wire(wire), c)


class TestSpendCap(unittest.TestCase):
    def test_permits(self):
        c = SpendCap(50.0)
        self.assertTrue(c.permits({"spend": 50.0}))
        self.assertFalse(c.permits({"spend": 50.01}))

    def test_narrow_and_subsumes(self):
        a, b = SpendCap(20), SpendCap(5)
        self.assertEqual(a.narrow(b).max_spend, 5)
        self.assertTrue(a.subsumes(b))
        self.assertFalse(b.subsumes(a))

    def test_wire_roundtrip(self):
        wire = SpendCap(12.5).to_wire()
        self.assertEqual(wire, {"key": "max_spend", "max": 12.5})
        self.assertEqual(ceiling_from_wire(wire), SpendCap(12.5))


class TestCallLimit(unittest.TestCase):
    def test_permits(self):
        c = CallLimit(3)
        self.assertTrue(c.permits({"calls": 3}))
        self.assertFalse(c.permits({"calls": 4}))

    def test_narrow_and_subsumes(self):
        a, b = CallLimit(9), CallLimit(2)
        self.assertEqual(a.narrow(b).max_calls, 2)
        self.assertTrue(a.subsumes(b))

    def test_wire_roundtrip(self):
        wire = CallLimit(7).to_wire()
        self.assertEqual(wire, {"key": "max_calls", "max": 7})
        self.assertEqual(ceiling_from_wire(wire), CallLimit(7))


class TestEgressRank(unittest.TestCase):
    def test_order_none_lt_internal_lt_any(self):
        c = EgressRank("internal")
        self.assertTrue(c.permits({"egress": "none"}))
        self.assertTrue(c.permits({"egress": "internal"}))
        self.assertFalse(c.permits({"egress": "any"}))

    def test_unknown_value_fails_closed(self):
        # a garbage egress value is treated as maximally permissive-requested
        # (worst case), so it must NOT sneak past a real bound.
        self.assertFalse(EgressRank("none").permits({"egress": "not-a-real-level"}))

    def test_narrow_picks_stricter(self):
        self.assertEqual(EgressRank("any").narrow(EgressRank("none")).level, "none")
        self.assertEqual(EgressRank("none").narrow(EgressRank("any")).level, "none")

    def test_subsumes(self):
        self.assertTrue(EgressRank("any").subsumes(EgressRank("none")))
        self.assertFalse(EgressRank("none").subsumes(EgressRank("any")))

    def test_wire_roundtrip(self):
        wire = EgressRank("internal").to_wire()
        self.assertEqual(wire, {"key": "egress", "rank": "internal"})
        self.assertEqual(ceiling_from_wire(wire), EgressRank("internal"))


class TestAllow(unittest.TestCase):
    def test_permits_membership(self):
        c = Allow("region", frozenset({"eu", "us"}))
        self.assertTrue(c.permits({"region": "eu"}))
        self.assertFalse(c.permits({"region": "apac"}))
        self.assertTrue(c.permits({}))  # nothing asserted -> permitted

    def test_narrow_is_intersection(self):
        a = Allow("region", frozenset({"eu", "us", "apac"}))
        b = Allow("region", frozenset({"us", "apac"}))
        self.assertEqual(a.narrow(b).one_of, frozenset({"us", "apac"}))

    def test_subsumes_is_superset(self):
        a = Allow("region", frozenset({"eu", "us", "apac"}))
        b = Allow("region", frozenset({"us"}))
        self.assertTrue(a.subsumes(b))
        self.assertFalse(b.subsumes(a))

    def test_custom_ctx_field(self):
        # `field` lets the ceiling's dimension name (key, used for pairing
        # across meet/is_narrower_than) differ from the ctx lookup name.
        c = Allow("region", frozenset({"eu"}), field="deploy_region")
        self.assertTrue(c.permits({"deploy_region": "eu"}))
        self.assertFalse(c.permits({"deploy_region": "us"}))

    def test_wire_roundtrip(self):
        c = Allow("region", frozenset({"eu", "us"}))
        wire = c.to_wire()
        self.assertEqual(wire["key"], "region")
        self.assertEqual(wire["type"], "allow")
        self.assertEqual(set(wire["one_of"]), {"eu", "us"})
        self.assertEqual(ceiling_from_wire(wire), c)


class TestDeny(unittest.TestCase):
    def test_permits_anti_membership(self):
        c = Deny("tool", frozenset({"rm", "curl"}))
        self.assertTrue(c.permits({"tool": "grep"}))
        self.assertFalse(c.permits({"tool": "rm"}))

    def test_narrow_is_union(self):
        a = Deny("tool", frozenset({"rm"}))
        b = Deny("tool", frozenset({"curl"}))
        self.assertEqual(a.narrow(b).not_one_of, frozenset({"rm", "curl"}))

    def test_subsumes_is_subset_of_forbidden(self):
        a = Deny("tool", frozenset({"rm"}))
        b = Deny("tool", frozenset({"rm", "curl"}))
        # a forbids fewer things -> a is more permissive -> a subsumes b
        self.assertTrue(a.subsumes(b))
        self.assertFalse(b.subsumes(a))

    def test_wire_roundtrip(self):
        c = Deny("tool", frozenset({"rm", "curl"}))
        wire = c.to_wire()
        self.assertEqual(wire["type"], "deny")
        self.assertEqual(ceiling_from_wire(wire), c)


class TestPrefix(unittest.TestCase):
    def test_permits_prefix_match(self):
        c = Prefix("path", "/tmp/")
        self.assertTrue(c.permits({"path": "/tmp/foo.txt"}))
        self.assertFalse(c.permits({"path": "/etc/passwd"}))

    def test_narrow_comparable_prefixes_picks_more_specific(self):
        broad, narrow = Prefix("path", "/tmp/"), Prefix("path", "/tmp/scratch/")
        self.assertEqual(broad.narrow(narrow).prefix, "/tmp/scratch/")
        self.assertEqual(narrow.narrow(broad).prefix, "/tmp/scratch/")

    def test_narrow_incomparable_prefixes_is_sound(self):
        # "eu-" and "us-" share no real values; the meet must admit NEITHER
        # side's values (soundness), not arbitrarily pick one.
        eu, us = Prefix("region", "eu-"), Prefix("region", "us-")
        met = eu.narrow(us)
        self.assertFalse(met.permits({"region": "eu-west-1"}))
        self.assertFalse(met.permits({"region": "us-east-1"}))

    def test_subsumes(self):
        broad, narrow = Prefix("path", "/tmp/"), Prefix("path", "/tmp/scratch/")
        self.assertTrue(broad.subsumes(narrow))
        self.assertFalse(narrow.subsumes(broad))

    def test_wire_roundtrip(self):
        c = Prefix("path", "/tmp/")
        wire = c.to_wire()
        self.assertEqual(wire, {"key": "path", "type": "prefix", "prefix": "/tmp/"})
        self.assertEqual(ceiling_from_wire(wire), c)


# =========================================================================
# Unknown ceiling — fail-closed
# =========================================================================
class TestUnknownCeilingFailsClosed(unittest.TestCase):
    def test_ceiling_from_wire_unknown_type_denies(self):
        c = ceiling_from_wire({"key": "quantum_flux", "type": "quantum_flux", "max": 1})
        self.assertIsInstance(c, _UnknownCeiling)
        d = c.permits({"quantum_flux": 0})   # even a trivially-safe-looking value
        self.assertFalse(d)
        self.assertEqual(d.reasons[0].code, ReasonCode.UNKNOWN_CONSTRAINT)

    def test_unknown_ceiling_denies_regardless_of_ctx_content(self):
        c = ceiling_from_wire({"key": "mystery"})
        for ctx in ({}, {"mystery": "anything"}, {"unrelated": 1}):
            self.assertFalse(c.permits(ctx))

    def test_narrow_of_unknown_stays_denying(self):
        c = ceiling_from_wire({"key": "mystery"})
        met = c.narrow(RowLimit(5))
        self.assertFalse(met.permits({}))

    def test_authority_from_wire_with_unknown_constraint_fails_closed_end_to_end(self):
        wire = {"scopes": ["crm.read"],
                "constraints": [{"key": "mystery_bound", "max": 5}],
                "ttl": 100}
        auth = Authority.from_wire(wire)
        # scope is fine, but the unrecognised constraint must still deny.
        decision = auth.permits("crm.read", {"mystery_bound": 1})
        self.assertFalse(decision)
        self.assertEqual(decision.reasons[0].code, ReasonCode.UNKNOWN_CONSTRAINT)

    def test_register_ceiling_extension_seam(self):
        # a freshly-registered discriminator becomes deserializable, routed
        # to whatever class the caller associates with it (the same seam a
        # custom Ceiling type would register itself under).
        register_ceiling("double_row_limit", RowLimit)  # route a new tag to RowLimit
        c = ceiling_from_wire({"key": "max_rows", "type": "double_row_limit", "max": 42})
        self.assertIsInstance(c, RowLimit)
        self.assertEqual(c.max_rows, 42)


# =========================================================================
# A custom Ceiling end-to-end: attenuated by meet AND enforced by check(),
# exactly the v0.1 red-team finding ("custom ceiling declared but inert")
# that ceilings.py's typed Ceiling protocol closes.
# =========================================================================
class TestCustomCeilingEndToEnd(unittest.TestCase):
    def test_attenuated_by_delegate_and_enforced_by_check(self):
        root = Guard.issue("p", Authority({"crm.read"}, [_WidgetLimit(5)], ttl=3600))
        # child tries to escalate the custom ceiling; meet must clamp to 5
        child = root.delegate("c", Authority({"crm.read"}, [_WidgetLimit(1000)], ttl=3600),
                              task="t")
        self.assertEqual(child.authority.ceiling("max_widgets").max_widgets, 5)
        self.assertTrue(child.check("crm.read", context={"widgets": 5}))
        denied = child.check("crm.read", context={"widgets": 6})
        self.assertFalse(denied)
        self.assertEqual(denied.reasons[0].code, ReasonCode.CEILING_EXCEEDED)
        self.assertEqual(denied.reasons[0].constraint, "max_widgets")

    def test_wire_roundtrip(self):
        c = _WidgetLimit(5)
        self.assertEqual(_WidgetLimit.from_wire(c.to_wire()), c)


# =========================================================================
# Authority scope syntax — one interoperable grammar, no glob traps
# =========================================================================
class TestScopeSyntax(unittest.TestCase):
    def test_accepts_lowercase_dot_segments_and_terminal_wildcards(self):
        valid = {
            "crm.read", "crm.x.y.z", "crm.*", "crm.x.*",
            "agent.delegate.research_agent", "s3.write",
        }
        self.assertEqual(Authority(valid, [], ttl=100).scopes, valid)

    def test_rejects_bare_empty_uppercase_and_glob_like_scopes(self):
        invalid = (
            "", "crm", "*", "crm.re*", "*.read", "crm.*.read",
            "crm..read", "CRM.Read", "crm.read ",
        )
        for scope in invalid:
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "invalid scope"):
                Authority({scope}, [], ttl=100)

    def test_from_wire_applies_the_same_scope_validation(self):
        with self.assertRaisesRegex(ValueError, "invalid scope"):
            Authority.from_wire({"scopes": ["*"], "constraints": [], "ttl": 100})

    def test_terminal_wildcard_is_segment_bounded_and_covers_any_depth(self):
        authority = Authority({"crm.*"}, [], ttl=100)
        self.assertTrue(authority.covers_scope("crm.read"))
        self.assertTrue(authority.covers_scope("crm.x.y.z"))
        self.assertFalse(authority.covers_scope("crm"))
        self.assertFalse(authority.covers_scope("crmx.read"))
        self.assertTrue(Authority({"crm.x.*"}, [], ttl=100).is_narrower_than(authority))


# =========================================================================
# Authority.meet — never widens
# =========================================================================
class TestMeetNeverWidens(unittest.TestCase):
    def test_scopes_are_intersected(self):
        a = Authority({"crm.read", "crm.write"}, [], ttl=100)
        b = Authority({"crm.read", "mail.send"}, [], ttl=100)
        m = a.meet(b)
        self.assertEqual(m.scopes, {"crm.read"})

    def test_ceilings_take_the_stricter_side(self):
        a = Authority({"crm.read"}, [RowLimit(1000), EgressRank("any")], ttl=100)
        b = Authority({"crm.read"}, [RowLimit(10), EgressRank("none")], ttl=100)
        m = a.meet(b)
        self.assertEqual(m.ceiling("max_rows").max_rows, 10)
        self.assertEqual(m.ceiling("egress").level, "none")

    def test_ceiling_present_on_only_one_side_carries_through(self):
        a = Authority({"crm.read"}, [RowLimit(100)], ttl=100)
        b = Authority({"crm.read"}, [], ttl=100)   # no row bound at all
        m = a.meet(b)
        # the bound from the ONE side that had it must still apply.
        self.assertEqual(m.ceiling("max_rows").max_rows, 100)
        self.assertTrue(m.is_narrower_than(a))
        self.assertTrue(m.is_narrower_than(b))

    def test_ttl_takes_the_min(self):
        a = Authority(set(), [], ttl=100)
        b = Authority(set(), [], ttl=10)
        self.assertEqual(a.meet(b).ttl, 10)

    def test_ttl_none_is_unbounded_min_takes_the_other(self):
        a = Authority(set(), [], ttl=None)
        b = Authority(set(), [], ttl=10)
        self.assertEqual(a.meet(b).ttl, 10)

    def test_meet_result_is_narrower_than_both_inputs(self):
        a = Authority({"crm.*"}, [RowLimit(500), EgressRank("any")], ttl=500)
        b = Authority({"crm.read", "crm.write"}, [RowLimit(50)], ttl=50)
        m = a.meet(b)
        self.assertTrue(m.is_narrower_than(a))
        self.assertTrue(m.is_narrower_than(b))

    def test_wildcard_granted_by_both_sides_survives_pruning(self):
        a = Authority({"crm.*"}, [], ttl=100)
        b = Authority({"crm.*", "crm.read"}, [], ttl=100)
        m = a.meet(b)
        self.assertTrue(m.covers_scope("crm.write"))  # only reachable via crm.*


# =========================================================================
# Authority.is_narrower_than — correctness, including custom ceilings
# =========================================================================
class TestIsNarrowerThan(unittest.TestCase):
    def test_reflexive(self):
        a = Authority({"crm.read"}, [RowLimit(10)], ttl=10)
        self.assertTrue(a.is_narrower_than(a))

    def test_false_when_scope_not_covered(self):
        child = Authority({"crm.read", "pay.transfer"}, [], ttl=10)
        parent = Authority({"crm.read"}, [], ttl=10)
        self.assertFalse(child.is_narrower_than(parent))

    def test_true_when_child_ceiling_is_tighter(self):
        parent = Authority({"crm.read"}, [RowLimit(1000)], ttl=100)
        child = Authority({"crm.read"}, [RowLimit(10)], ttl=100)
        self.assertTrue(child.is_narrower_than(parent))

    def test_false_when_child_ceiling_is_looser(self):
        parent = Authority({"crm.read"}, [RowLimit(10)], ttl=100)
        child = Authority({"crm.read"}, [RowLimit(1000)], ttl=100)
        self.assertFalse(child.is_narrower_than(parent))

    def test_false_when_parent_ceiling_absent_on_child_custom_key(self):
        # the exact soundness gap the red-team suite targets: a ceiling key
        # outside the built-in registry must not be silently treated as
        # "unbounded is fine".
        parent = Authority({"crm.read"}, [RowLimit(100), _WidgetLimit(5)], ttl=100)
        child = Authority({"crm.read"}, [RowLimit(100)], ttl=100)  # no _WidgetLimit
        self.assertFalse(child.is_narrower_than(parent))

    def test_extra_ceiling_on_child_not_present_on_parent_is_fine(self):
        # self may be bounded on a dimension the parent never mentioned —
        # that is EXTRA restriction, still a subset.
        parent = Authority({"crm.read"}, [], ttl=100)
        child = Authority({"crm.read"}, [RowLimit(1)], ttl=100)
        self.assertTrue(child.is_narrower_than(parent))

    def test_ttl_must_not_exceed_parent(self):
        parent = Authority({"crm.read"}, [], ttl=100)
        shorter = Authority({"crm.read"}, [], ttl=50)
        longer = Authority({"crm.read"}, [], ttl=200)
        self.assertTrue(shorter.is_narrower_than(parent))
        self.assertFalse(longer.is_narrower_than(parent))

    def test_child_ttl_none_but_parent_bounded_is_false(self):
        parent = Authority({"crm.read"}, [], ttl=100)
        unbounded_child = Authority({"crm.read"}, [], ttl=None)
        self.assertFalse(unbounded_child.is_narrower_than(parent))

    def test_le_operator_matches_is_narrower_than(self):
        parent = Authority({"crm.*"}, [RowLimit(100)], ttl=100)
        child = Authority({"crm.read"}, [RowLimit(10)], ttl=50)
        self.assertEqual(child <= parent, child.is_narrower_than(parent))
        self.assertTrue(child <= parent)


# =========================================================================
# Deprecated aliases — still work, still warn
# =========================================================================
class TestDeprecatedAliases(unittest.TestCase):
    def test_guard_root_warns_and_behaves_like_issue(self):
        with self.assertWarns(DeprecationWarning):
            g = Guard.root("orchestrator", Authority({"crm.read"}, [], ttl=100))
        self.assertEqual(g.authority.scopes, {"crm.read"})

    def test_guard_spawn_warns_and_behaves_like_delegate(self):
        root = Guard.issue("orchestrator", Authority({"crm.*"}, [], ttl=100))
        with self.assertWarns(DeprecationWarning):
            child = root.spawn("child", Authority({"crm.read"}, [], ttl=50), task="t")
        self.assertEqual(child.authority.scopes, {"crm.read"})

    def test_guard_kill_warns_and_behaves_like_revoke(self):
        root = Guard.issue("orchestrator", Authority({"crm.*"}, [], ttl=100))
        with self.assertWarns(DeprecationWarning):
            revoked = root.kill()
        self.assertIn(root.node_id, revoked)

    def test_check_legacy_kwargs_warn_and_fold_into_context(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10), EgressRank("none")], ttl=100))
        with self.assertWarns(DeprecationWarning):
            decision = g.check("crm.read", rows=5, egress="none", tool="t")
        self.assertTrue(decision)
        with self.assertWarns(DeprecationWarning):
            decision2 = g.check("crm.read", rows=50, tool="t")   # exceeds max_rows=10
        self.assertFalse(decision2)
        self.assertEqual(decision2.reasons[0].constraint, "max_rows")

    def test_check_without_legacy_kwargs_does_not_warn(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=100))
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # any warning here fails the test
            g.check("crm.read", context={"rows": 5}, tool="t")


# =========================================================================
# would_allow vs check — audit side effects
# =========================================================================
class TestAuditSideEffects(unittest.TestCase):
    def test_would_allow_writes_nothing_to_audit(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=100))
        before = len(g.audit_log().entries)
        g.would_allow("crm.read", context={"rows": 1})     # allow case
        g.would_allow("pay.transfer", context={})           # deny case
        g.would_allow("crm.read", context={"rows": 999})    # deny case
        after = len(g.audit_log().entries)
        self.assertEqual(before, after)

    def test_check_writes_to_audit_on_both_allow_and_deny(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=100))
        before = len(g.audit_log().entries)
        g.check("crm.read", context={"rows": 1})     # allow
        g.check("pay.transfer")                      # deny
        after = len(g.audit_log().entries)
        self.assertEqual(after - before, 2)

    def test_would_allow_and_check_agree_on_the_decision(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=100))
        probe = g.would_allow("crm.read", context={"rows": 999})
        real = g.check("crm.read", context={"rows": 999})
        self.assertEqual(bool(probe), bool(real))
        self.assertEqual(probe.reasons[0].code, real.reasons[0].code)


# =========================================================================
# enforce() vs check() — raising gate vs. Decision
# =========================================================================
class TestEnforceVsCheck(unittest.TestCase):
    def test_check_does_not_raise_on_denial(self):
        g = Guard.issue("p", Authority({"crm.read"}, [], ttl=100))
        decision = g.check("pay.transfer")   # must not raise
        self.assertFalse(decision)

    def test_enforce_raises_authority_denied_on_denial(self):
        g = Guard.issue("p", Authority({"crm.read"}, [], ttl=100))
        with self.assertRaises(AuthorityDenied) as ctx:
            g.enforce("pay.transfer")
        self.assertFalse(ctx.exception.decision.allowed)
        self.assertEqual(ctx.exception.decision.reasons[0].code, ReasonCode.SCOPE_NOT_GRANTED)

    def test_enforce_does_not_raise_on_allow(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=100))
        g.enforce("crm.read", context={"rows": 1})  # must not raise

    def test_authority_denied_is_not_an_authority_error(self):
        # policy denial (AuthorityDenied) and structural failure
        # (AuthorityError) are deliberately different exception types.
        self.assertFalse(issubclass(AuthorityDenied, AuthorityError))

    def test_delegate_structural_failure_still_raises_authority_error(self):
        root = Guard.issue("p", Authority({"crm.*"}, [], ttl=100), max_depth=1)
        child = root.delegate("c", Authority({"crm.read"}, [], ttl=50), task="t")
        with self.assertRaises(AuthorityError):
            child.delegate("grandchild", Authority({"crm.read"}, [], ttl=50), task="t")


# =========================================================================
# Public export surface — Ceiling (protocol) and AuditLog, imported above
# alongside the rest of __init__.py's exports but not otherwise exercised
# by the tests above.
# =========================================================================
class TestStrictMeteringPartialContext(unittest.TestCase):
    """Regression for the fail-open found by the Pydantic AI integration PoC:
    `strict_metering=True` only refused a call whose context was ENTIRELY
    empty. A context that mentioned SOME dimensions but omitted a held,
    metered ceiling's dimension slipped through and that ceiling was simply
    never evaluated — the exact mistake an adapter's per-tool context lambda
    makes when it forgets one field. The invariant users actually rely on:
    with strict metering, a metered call must declare EVERY metered
    dimension the node holds, or it is refused (fail closed)."""

    def _strict_child(self, ceilings):
        root = Guard.issue("o", Authority({"crm.read"}, ceilings, ttl=10**6),
                           strict_metering=True)
        return root.delegate("c", Authority({"crm.read"}, ceilings, ttl=10**6), task="t")

    def test_partial_context_omitting_a_metered_ceiling_is_refused(self):
        g = self._strict_child([RowLimit(5_000), EgressRank("none")])
        # egress is declared, rows is not — RowLimit(5000) would never be evaluated.
        d = g.check("crm.read", context={"egress": "none"}, metered=True)
        self.assertFalse(d, "partial context must fail closed under strict metering")
        self.assertEqual(d.reasons[0].code, ReasonCode.UNMETERED)
        self.assertIn("max_rows", str(d.reasons[0]))

    def test_every_builtin_metered_ceiling_is_covered(self):
        # The CLASS of the bug: each metered (max_*) ceiling reads its own ctx
        # field. Omitting any one of them must be caught, not just rows.
        # CallLimit is deliberately absent: the Guard AUTO-METERS call counts per (node, scope),
        # so an omitted `calls` is not an undeclared quantity (see TestScopedCallLimit).
        cases = [
            (RowLimit(10), {"spend": 1, "calls": 1}, "max_rows"),
            (SpendCap(10.0), {"rows": 1, "calls": 1}, "max_spend"),
        ]
        for ceiling, ctx, key in cases:
            with self.subTest(ceiling=ceiling):
                g = self._strict_child([RowLimit(10), SpendCap(10.0), CallLimit(10)])
                d = g.check("crm.read", context=ctx, metered=True)
                self.assertFalse(d)
                self.assertEqual(d.reasons[0].code, ReasonCode.UNMETERED)
                self.assertIn(key, str(d.reasons[0]))

    def test_full_context_still_evaluates_normally(self):
        g = self._strict_child([RowLimit(5_000), EgressRank("none")])
        self.assertTrue(g.check("crm.read", context={"rows": 10, "egress": "none"}, metered=True))
        over = g.check("crm.read", context={"rows": 10**6, "egress": "none"}, metered=True)
        self.assertFalse(over)
        self.assertEqual(over.reasons[0].code, ReasonCode.CEILING_EXCEEDED)

    def test_empty_context_is_still_refused(self):
        # The original v0.2 behaviour, kept: no context at all -> UNMETERED.
        g = self._strict_child([RowLimit(5_000)])
        d = g.check("crm.read", metered=True)
        self.assertFalse(d)
        self.assertEqual(d.reasons[0].code, ReasonCode.UNMETERED)

    def test_non_metered_ceilings_do_not_trigger_strictness(self):
        # EgressRank is a rank, not a metered quantity: omitting it under
        # strict metering is fine (the call isn't consuming egress).
        g = self._strict_child([RowLimit(5_000), EgressRank("none")])
        self.assertTrue(g.check("crm.read", context={"rows": 10}, metered=True))

    def test_unmetered_calls_and_non_strict_guards_are_unchanged(self):
        g = self._strict_child([RowLimit(5_000), EgressRank("none")])
        self.assertTrue(g.check("crm.read", context={"egress": "none"}))          # metered=False
        loose = Guard.issue("o", Authority({"crm.read"}, [RowLimit(5)], ttl=10**6))
        self.assertTrue(loose.check("crm.read", context={"egress": "none"}, metered=True))


class TestAdapterFacingSurface(unittest.TestCase):
    """The small read-only/introspection surface the framework-integration
    PoCs (examples/integrations/) independently asked for. Each was hit by
    more than one adapter, so it lives in the core rather than being
    re-invented per framework."""

    def _pair(self):
        root = Guard.issue("orchestrator", Authority({"crm.*"}, [RowLimit(100)], ttl=3600))
        child = root.delegate("summarizer", Authority({"crm.read"}, [RowLimit(10)], ttl=900),
                              task="summarize")
        return root, child

    def test_agent_id_is_readable(self):
        root, child = self._pair()
        self.assertEqual(root.agent_id, "orchestrator")
        self.assertEqual(child.agent_id, "summarizer")

    def test_is_revoked_and_is_expired_reflect_chain_state(self):
        root, child = self._pair()
        self.assertFalse(child.is_revoked)
        self.assertFalse(child.is_expired)
        root.revoke(child.node_id)
        self.assertTrue(child.is_revoked)
        self.assertFalse(root.is_revoked)
        # expiry: a zero-ttl-ish child under a manual clock
        class _Clock:
            t = 0
            def now(self): return self.t
        clk = _Clock()
        r2 = Guard.issue("o", Authority({"test.x"}, [], ttl=100), clock=clk)
        c2 = r2.delegate("c", Authority({"test.x"}, [], ttl=5), task="t")
        self.assertFalse(c2.is_expired)
        clk.t = 6
        self.assertTrue(c2.is_expired)
        self.assertFalse(c2.check("test.x"))
        self.assertEqual(c2.check("test.x").reasons[0].code, ReasonCode.EXPIRED)

    def test_reason_code_no_authority_exists(self):
        self.assertEqual(ReasonCode.NO_AUTHORITY, "no_authority")

    def test_record_denial_lands_in_the_audit_log_as_a_deny_event(self):
        # An adapter refusing something UPSTREAM of policy (unknown principal,
        # undeclared sub-agent, unparseable tool args) must be able to put
        # that refusal on the same tamper-evident trail as policy denials --
        # otherwise `attenu-guard view` never sees it.
        root, child = self._pair()
        before = len(root.audit_log().entries)
        d = child.record_denial(ReasonCode.NO_AUTHORITY, "sub-agent 'exfiltrator' was never delegated to",
                                scope="crm.export", tool="crm_export")
        self.assertFalse(d)
        self.assertEqual(d.reasons[0].code, ReasonCode.NO_AUTHORITY)
        self.assertEqual(d.determining_node, child.node_id)
        entries = root.audit_log().entries
        self.assertEqual(len(entries), before + 1)
        last = entries[-1]
        self.assertEqual(last["event"], "deny")
        self.assertEqual(last["reason"], ReasonCode.NO_AUTHORITY)
        self.assertEqual(last["scope"], "crm.export")
        self.assertEqual(last["tool"], "crm_export")
        self.assertEqual(last["node"], child.node_id)
        ok, err = AuditLog.verify(entries)
        self.assertTrue(ok, err)

    def test_record_denial_accepts_a_prebuilt_reason_and_defaults_scope(self):
        root, child = self._pair()
        d = child.record_denial(Reason(ReasonCode.UNKNOWN_CONSTRAINT, message="bad args"), tool="t")
        last = root.audit_log().entries[-1]
        self.assertEqual(last["reason"], ReasonCode.UNKNOWN_CONSTRAINT)
        self.assertIsInstance(last["scope"], str)     # schema: scope is a string
        self.assertFalse(d)

    def test_audit_log_is_iterable_and_sized(self):
        root, child = self._pair()
        log = root.audit_log()
        self.assertEqual(len(log), len(log.entries))
        self.assertEqual([e["event"] for e in log], [e["event"] for e in log.entries])
        self.assertEqual(len(log), 2)   # root + spawn


class TestPrincipalRevocationAndDelegationDryRun(unittest.TestCase):
    """Found by the Strands + OpenAI-SDK integration PoCs: `revoke()` is
    node-scoped, so a framework that re-hands-off to the SAME agent after a
    revoke (swarm ping-pong, a second `as_tool()` call) minted a fresh, clean
    child from the still-valid parent — a re-delegation bypass every adapter
    had to close with its own invisible "revoked names" set. The invariant
    users rely on: once an agent is revoked BY NAME, no node in the chain
    can delegate to it again, and that ban is on the audit trail."""

    def _chain(self):
        root = Guard.issue("orchestrator", Authority({"crm.*"}, [RowLimit(100)], ttl=3600))
        c1 = root.delegate("summarizer", Authority({"crm.read"}, [], ttl=900), task="t1")
        return root, c1

    def test_re_delegating_to_a_revoked_agent_is_refused_chain_wide(self):
        root, c1 = self._chain()
        revoked = root.revoke_agent("summarizer")
        self.assertIn(c1.node_id, revoked)
        self.assertTrue(c1.is_revoked)
        with self.assertRaises(AuthorityError) as cm:
            root.delegate("summarizer", Authority({"crm.read"}, [], ttl=900), task="t2")
        self.assertEqual(cm.exception.reason, "agent_banned")
        # ...from ANY node in the chain, not just the one that revoked
        other = root.delegate("planner", Authority({"crm.read"}, [], ttl=900), task="p")
        with self.assertRaises(AuthorityError):
            other.delegate("summarizer", Authority({"crm.read"}, [], ttl=900), task="t3")
        # other agents are unaffected
        self.assertTrue(other.check("crm.read"))

    def test_revoke_agent_revokes_every_node_of_that_principal(self):
        root, c1 = self._chain()
        c2 = root.delegate("summarizer", Authority({"crm.read"}, [], ttl=900), task="t2")
        gc = c2.delegate("helper", Authority({"crm.read"}, [], ttl=900), task="h")
        revoked = root.revoke_agent("summarizer")
        self.assertEqual(set(revoked), {c1.node_id, c2.node_id, gc.node_id})   # cascade too
        for g in (c1, c2, gc):
            self.assertFalse(g.check("crm.read"))
            self.assertEqual(g.check("crm.read").reasons[0].code, ReasonCode.REVOKED)

    def test_revoke_agent_is_on_the_audit_trail(self):
        root, c1 = self._chain()
        root.revoke_agent("summarizer")
        kill = [e for e in root.audit_log() if e["event"] == "kill"][-1]
        self.assertEqual(kill["agent"], "summarizer")
        self.assertIn(c1.node_id, kill["revoked"])
        try:
            root.delegate("summarizer", Authority({"crm.read"}, [], ttl=900), task="t2")
        except AuthorityError:
            pass
        denied = [e for e in root.audit_log() if e["event"] == "spawn_denied"][-1]
        self.assertEqual(denied["reason"], "agent_banned")
        ok, err = AuditLog.verify(root.audit_log().entries)
        self.assertTrue(ok, err)

    def test_would_delegate_is_a_pure_dry_run(self):
        root, c1 = self._chain()
        n = len(root.audit_log())
        d = root.would_delegate("helper", Authority({"crm.read"}, [], ttl=10))
        self.assertTrue(d)
        self.assertEqual(len(root.audit_log()), n)                    # nothing written
        self.assertEqual(len(root.graph()["nodes"]), 2)               # no node created
        root.revoke_agent("summarizer")
        d2 = root.would_delegate("summarizer", Authority({"crm.read"}, [], ttl=10))
        self.assertFalse(d2)
        self.assertEqual(d2.reasons[0].code, "agent_banned")
        root.revoke()                                                # whole chain
        d3 = root.would_delegate("helper", Authority({"crm.read"}, [], ttl=10))
        self.assertFalse(d3)
        self.assertEqual(d3.reasons[0].code, "chain_revoked")
        self.assertEqual(len(root.graph()["nodes"]), 2)

    def test_would_delegate_reports_depth_and_fanout_ceilings(self):
        root = Guard.issue("o", Authority({"test.x"}, [], ttl=100), max_depth=1, max_fanout=1)
        self.assertTrue(root.would_delegate("a", Authority({"test.x"}, [], ttl=10)))
        a = root.delegate("a", Authority({"test.x"}, [], ttl=10), task="t")
        self.assertEqual(root.would_delegate("b", Authority({"test.x"}, [], ttl=10)).reasons[0].code, "max_fanout")
        self.assertEqual(a.would_delegate("c", Authority({"test.x"}, [], ttl=10)).reasons[0].code, "max_depth")


class TestThreadSafetyUnderParallelToolCalls(unittest.TestCase):
    """Several frameworks execute an agent's parallel tool calls on a thread
    pool (smolagents `process_tool_calls`, ADK's `asyncio.gather` under a
    threaded executor). Every `check()` appends to ONE hash-chained audit log
    and bumps ONE sequence counter, so unsynchronised appends can interleave
    `prev_hash` reads and writes — producing a log that `verify()` rejects,
    i.e. a tamper alarm caused by the library itself, or a lost/duplicated
    seq. The invariant: N concurrent checks yield exactly N verifiable,
    strictly-sequenced entries."""

    def _hammer(self, fn, threads=16, per_thread=200):
        import threading
        errors = []
        # Force very frequent thread switches so the (tiny) critical sections
        # in AuditLog.append / _SeqClock.now actually interleave; with the
        # default 5 ms interval the race exists but almost never fires here.
        prev_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        self.addCleanup(sys.setswitchinterval, prev_interval)
        def worker():
            try:
                for _ in range(per_thread):
                    fn()
            except Exception as e:                       # pragma: no cover
                errors.append(e)
        ts = [threading.Thread(target=worker) for _ in range(threads)]
        for t in ts: t.start()
        for t in ts: t.join()
        self.assertEqual(errors, [])
        return threads * per_thread

    def test_concurrent_checks_keep_the_audit_chain_verifiable_and_complete(self):
        root = Guard.issue("o", Authority({"crm.read"}, [RowLimit(10)], ttl=10**6))
        child = root.delegate("c", Authority({"crm.read"}, [RowLimit(10)], ttl=10**6), task="t")
        base = len(root.audit_log())
        n = self._hammer(lambda: child.check("crm.read", context={"rows": 1}, tool="t"))
        entries = root.audit_log().entries
        self.assertEqual(len(entries), base + n, "lost or duplicated audit entries")
        ok, err = AuditLog.verify(entries)
        self.assertTrue(ok, f"audit chain broken by concurrent appends: {err}")
        seqs = [e["seq"] for e in entries]
        self.assertEqual(seqs, list(range(len(entries))), "seq must be dense and ordered")
        tss = [e["ts"] for e in entries]
        self.assertEqual(len(set(tss)), len(tss), "audit ts (seq clock) must be unique")
        self.assertEqual(tss, sorted(tss), "ts must advance with seq (no out-of-order logging)")

    def test_concurrent_delegate_and_revoke_do_not_corrupt_the_chain(self):
        root = Guard.issue("o", Authority({"test.x"}, [], ttl=10**6), max_fanout=10**6)
        counter = {"i": 0}
        import threading
        lock = threading.Lock()
        def op():
            with lock:
                counter["i"] += 1; i = counter["i"]
            g = root.delegate(f"a{i}", Authority({"test.x"}, [], ttl=10**6), task="t")
            g.check("test.x")
            if i % 3 == 0:
                root.revoke(g.node_id)
        n = self._hammer(op, threads=8, per_thread=50)
        nodes = root.graph()["nodes"]
        self.assertEqual(len(nodes), 1 + n)
        ok, err = AuditLog.verify(root.audit_log().entries)
        self.assertTrue(ok, err)


class TestDescribeAndStructuralReasonCodes(unittest.TestCase):
    """Two ergonomics asks from the integration PoCs: a uniform, human-readable
    rendering of ceilings/authorities (every adapter demo re-invented one), and
    constants for the STRUCTURAL failure reasons `AuthorityError` carries so
    adapters can map them without a hand-written lookup table."""

    def test_builtin_ceilings_describe_themselves(self):
        from attenu_guard.ceilings import describe
        self.assertEqual(RowLimit(5000).describe(), "max_rows<=5000")
        self.assertEqual(SpendCap(2.5).describe(), "max_spend<=2.5")
        self.assertEqual(CallLimit(3).describe(), "max_calls<=3")
        self.assertEqual(EgressRank("none").describe(), "egress<=none")
        self.assertEqual(Allow("region", {"eu", "us"}).describe(), "region in [eu, us]")
        self.assertEqual(Deny("region", {"cn"}).describe(), "region not in [cn]")
        self.assertEqual(Prefix("path", "/data/").describe(), "path startswith /data/")
        # module-level helper works for custom ceilings without describe()
        d = describe(_WidgetLimit(5))
        self.assertTrue(d.startswith("max_widgets=") and "'max': 5" in d, d)   # falls back to key=<wire form>

    def test_authority_describe_is_stable_and_readable(self):
        a = Authority({"crm.read", "crm.*"}, [RowLimit(5000), EgressRank("none")], ttl=900)
        self.assertEqual(a.describe(), "scopes=[crm.*, crm.read] ceilings=[egress<=none, max_rows<=5000] ttl=900")
        # repr/str are unchanged (docs, GIF and wire rely on them)
        self.assertTrue(repr(a).startswith("Authority("))

    def test_structural_reason_constants_match_authorityerror_reasons(self):
        root = Guard.issue("o", Authority({"test.x"}, [], ttl=100), max_depth=1)
        a = root.delegate("a", Authority({"test.x"}, [], ttl=10), task="t")
        with self.assertRaises(AuthorityError) as cm:
            a.delegate("b", Authority({"test.x"}, [], ttl=10), task="t")
        self.assertEqual(cm.exception.reason, ReasonCode.MAX_DEPTH)
        root.revoke()
        with self.assertRaises(AuthorityError) as cm:
            root.delegate("c", Authority({"test.x"}, [], ttl=10), task="t")
        self.assertEqual(cm.exception.reason, ReasonCode.CHAIN_REVOKED)
        for name in ("CHAIN_REVOKED", "AGENT_BANNED", "TTL_EXPIRED", "MAX_DEPTH", "MAX_FANOUT", "CHAIN_CEILING"):
            self.assertIsInstance(getattr(ReasonCode, name), str)


class TestScopedCallLimit(unittest.TestCase):
    """attenu-derive T4: gold-v1 labels an orchestrator as `fs.write` with `CallLimit(5, applies_to="fs.write")`
    — a per-SCOPE call ceiling. Two things must hold: the ceiling only bites the scope it applies to
    (reads are unaffected), and it is enforceable WITHOUT every adapter learning to count — the Guard
    meters calls per (node, scope) itself when the caller supplies no `calls`."""

    def _writer(self):
        root = Guard.issue("o", Authority({"fs.*", "agent.delegate.*"}, [RowLimit(10**6)], ttl=None))
        return root.delegate("w", Authority({"fs.write", "fs.read"}, [CallLimit(5, applies_to="fs.write"), RowLimit(1000)], ttl=None), task="write report")

    def test_sixth_write_is_denied_reads_unaffected_auto_metered(self):
        w = self._writer()
        for i in range(5):
            self.assertTrue(w.check("fs.write", tool="write_file"), f"write {i+1} should be allowed")
        d = w.check("fs.write", tool="write_file")
        self.assertFalse(d, "the 6th write must be denied")
        self.assertEqual(d.reasons[0].code, ReasonCode.CEILING_EXCEEDED)
        self.assertIn("max_calls", d.reasons[0].constraint)
        for _ in range(20):
            self.assertTrue(w.check("fs.read", context={"rows": 5}, tool="read_file"))   # reads never counted against the write limit

    def test_explicit_calls_context_still_wins(self):
        # A scoped limit reads its OWN field, `calls[<applies_to>]`, so scoped and unscoped
        # counts coexist; an explicit value there overrides the auto-meter.
        w = self._writer()
        self.assertFalse(w.check("fs.write", context={"calls[fs.write]": 6}))
        self.assertTrue(w.check("fs.write", context={"calls[fs.write]": 1}))

    def test_would_allow_does_not_consume_the_meter(self):
        w = self._writer()
        for _ in range(50):
            self.assertTrue(w.would_allow("fs.write"))
        for _ in range(5):
            self.assertTrue(w.check("fs.write"))
        self.assertFalse(w.check("fs.write"))

    def test_scoped_and_unscoped_are_distinct_dimensions_and_meet_is_sound(self):
        parent = Authority({"fs.*"}, [CallLimit(100)], ttl=None)                       # unscoped: any call
        req = Authority({"fs.write"}, [CallLimit(5, applies_to="fs.write")], ttl=None)
        child = parent.meet(req)
        self.assertTrue(child.is_narrower_than(parent))
        keys = sorted(c.key for c in child.ceilings)
        self.assertEqual(keys, ["max_calls", "max_calls[fs.write]"])                  # both kept: distinct keys
        wider = Authority({"fs.write"}, [CallLimit(500, applies_to="fs.write")], ttl=None)
        self.assertFalse(wider.is_narrower_than(req))
        self.assertTrue(req.is_narrower_than(wider))

    def test_wire_round_trip_and_describe(self):
        c = CallLimit(5, applies_to="fs.write")
        w = c.to_wire()
        self.assertEqual(w, {"key": "max_calls[fs.write]", "type": "max_calls", "max": 5, "applies_to": "fs.write"})
        from attenu_guard.ceilings import ceiling_from_wire
        back = ceiling_from_wire(w)
        self.assertEqual(back, c)
        self.assertEqual(c.describe(), "max_calls[fs.write]<=5")
        a = Authority({"fs.write"}, [c], ttl=60)
        self.assertEqual(Authority.from_wire(a.to_wire()), a)

    def test_applies_to_supports_wildcards(self):
        g = Guard.issue("o", Authority({"fs.*", "web.*"}, [CallLimit(2, applies_to="web.*")], ttl=None))
        self.assertTrue(g.check("web.fetch")); self.assertTrue(g.check("web.search")); self.assertFalse(g.check("web.fetch"))
        for _ in range(10):
            self.assertTrue(g.check("fs.read"))


class TestPublicExports(unittest.TestCase):
    def test_ceiling_protocol_isinstance_check(self):
        # runtime_checkable: any object with the right method names — built
        # -in or a caller's own class like _WidgetLimit above — satisfies
        # the Ceiling protocol without inheriting from it.
        self.assertIsInstance(RowLimit(10), Ceiling)
        self.assertIsInstance(_WidgetLimit(5), Ceiling)
        self.assertNotIsInstance(object(), Ceiling)

    def test_audit_log_is_the_type_guard_uses_and_verifies(self):
        g = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=100))
        g.check("crm.read", context={"rows": 1})
        log = g.audit_log()
        self.assertIsInstance(log, AuditLog)
        ok, reason = AuditLog.verify(log.entries)
        self.assertTrue(ok, reason)



# ---- Slice 1 / Plan A, Task 1: deny entries say WHY (held != over-reach) -----------------------------------
def test_deny_entries_carry_a_disposition_and_allow_entries_do_not():
    from attenu_guard import Authority, Guard, Disposition
    g = Guard.issue("agent", Authority({"crm.read"}, [], ttl=None), task="t")
    g.check("crm.read", tool="lookup")                                   # allowed
    g.check("payments.transfer", tool="charge_card")                     # not held -> denied, caller said nothing
    g.check("mail.send", tool="send_care", disposition=Disposition.HELD_PENDING_GRANT)
    g.record_denial("no_authority", "undeclared tool", tool="mystery", disposition=Disposition.UNRESOLVED)
    ents = g.audit_log().entries
    allow = [e for e in ents if e["event"] == "allow"]
    deny = [e for e in ents if e["event"] == "deny"]
    assert allow and all("disposition" not in e for e in allow)
    by_tool = {e["tool"]: e for e in deny}
    assert by_tool["charge_card"]["disposition"] == Disposition.OUT_OF_AUTHORITY   # the shim's own truth: not in this node's authority
    assert by_tool["send_care"]["disposition"] == Disposition.HELD_PENDING_GRANT      # the caller's stated reason survives
    assert by_tool["mystery"]["disposition"] == Disposition.UNRESOLVED
    assert Disposition.ALL == {"held_pending_grant", "withheld_tier2", "unresolved", "out_of_authority"}


def test_unknown_disposition_is_rejected_fail_closed():
    from attenu_guard import Authority, Guard
    g = Guard.issue("agent", Authority({"crm.read"}, [], ttl=None), task="t")
    try:
        g.check("x.y", tool="t", disposition="made_up")
    except ValueError as exc:
        assert "disposition" in str(exc)
    else:
        raise AssertionError("an unknown disposition must be refused, never written to the ledger")
    assert not [e for e in g.audit_log().entries if e["event"] == "deny"]          # nothing reached the ledger


def test_disposition_survives_strict_export_and_the_bundle_verifies():
    from attenu_guard import Authority, Guard, Disposition, evidence
    from attenu_guard.wire import HS256TestSigner
    g = Guard.issue("agent", Authority({"crm.read"}, [], ttl=None), task="t")
    g.check("mail.send", tool="send_care", disposition=Disposition.HELD_PENDING_GRANT)
    bundle = evidence.export_bundle(g.audit_log(), HS256TestSigner(secret=b"k", kid="k"), strict=True)   # must not raise EvidenceLeakError
    assert evidence.verify_bundle(bundle, HS256TestSigner(secret=b"k", kid="k"))["ok"] is True
    assert [e for e in bundle["entries"] if e["event"] == "deny"][0]["disposition"] == "held_pending_grant"


# ---- Slice 1 / Plan A, Task 2: the Decisions-screen fold ------------------------------------------------------
def test_denials_fold_groups_deny_events_for_the_decisions_screen():
    from attenu_guard import Authority, Guard, Disposition, evidence
    from attenu_guard.wire import HS256TestSigner
    root = Guard.issue("planner", Authority({"agent.delegate.booker", "crm.read"}, [], ttl=None), task="plan")
    child = root.delegate("booker", Authority({"crm.read"}, [], ttl=None), task="book")
    child.check("payments.transfer", tool="book_flight", disposition=Disposition.HELD_PENDING_GRANT)
    child.check("payments.transfer", tool="book_flight", disposition=Disposition.HELD_PENDING_GRANT)
    child.check("fs.write", tool="write_file")                               # out_of_authority by default
    bundle = evidence.export_bundle(root.audit_log(), HS256TestSigner(secret=b"k", kid="k"))
    rows = evidence.denials(bundle)
    assert [(r["tool"], r["disposition"], r["count"]) for r in rows] == [("book_flight", "held_pending_grant", 2), ("write_file", "out_of_authority", 1)]
    assert rows[0]["agent"] == "booker" and rows[0]["scope"] == "payments.transfer" and rows[0]["first_seq"] < rows[0]["last_seq"]
    graph = evidence.delegation_graph(bundle)
    assert graph["nodes"][child.node_id]["denials_by_disposition"] == {"held_pending_grant": 2, "out_of_authority": 1}
    assert graph["nodes"][root.node_id]["denials_by_disposition"] == {}
    # a deny with no disposition is named by its reason (e.g. revoked) rather than lumped as "unstated"
    child.revoke(); child.check("crm.read", tool="q")
    bundle2 = evidence.export_bundle(root.audit_log(), HS256TestSigner(secret=b"k", kid="k"))
    assert evidence.delegation_graph(bundle2)["nodes"][child.node_id]["denials_by_disposition"].get("revoked") == 1


def test_is_descendant_of_walks_the_chain_and_rejects_foreign_chains():
    from attenu_guard import Authority, Guard
    root = Guard.issue("a", Authority({"agent.delegate.b", "agent.delegate.c", "x.y"}, [], ttl=None), task="t")
    b = root.delegate("b", Authority({"agent.delegate.c", "x.y"}, [], ttl=None), task="t")
    c = b.delegate("c", Authority({"x.y"}, [], ttl=None), task="t")
    assert c.is_descendant_of(b) and c.is_descendant_of(root) and b.is_descendant_of(root)
    assert not root.is_descendant_of(c) and not b.is_descendant_of(c) and not root.is_descendant_of(root)
    other = Guard.issue("a", Authority({"x.y"}, [], ttl=None), task="t")
    assert not c.is_descendant_of(other)

if __name__ == "__main__":
    unittest.main(verbosity=2)


# ---- node lifecycle end: Guard.complete() -> "done" audit event (attenu-derive T21: per-node truncation) ----------
def test_complete_records_a_done_event_once_and_leaves_authority_intact():
    from attenu_guard import Authority, Guard, AuditLog
    root = Guard.issue("orchestrator", Authority({"fs.*", "agent.delegate.*"}, [], ttl=None), task="t")
    child = root.delegate("researcher", Authority({"fs.read"}, [], ttl=None), task="explore")
    assert child.check("fs.read").allowed
    assert child.complete() is True and child.is_complete
    assert child.complete() is False                                    # idempotent: one lifecycle end per node
    dones = [e for e in root.audit_log().entries if e["event"] == "done"]
    assert len(dones) == 1 and dones[0]["node"] == child.node_id and dones[0]["agent"] == "researcher"
    assert child.check("fs.read").allowed                                # informational marker: authority itself is unchanged (revocation is the hard stop)
    ok, err = AuditLog.verify(root.audit_log().entries); assert ok, err
    assert not root.is_complete


# ---- Strike policy (attenu-derive T26): revoke a node after N same-scope denials (default 3, configurable, on/off) ------
def test_strike_policy_revokes_after_n_same_scope_denials():
    from attenu_guard import Authority, Guard, StrikePolicy, ReasonCode
    root = Guard.issue("orchestrator", Authority({"fs.*", "agent.delegate.*"}, [], ttl=None), task="t",
                       strikes=StrikePolicy(enabled=True, n=3, mode="same_scope"))
    child = root.delegate("researcher", Authority({"fs.read"}, [], ttl=None), task="explore")
    # three denials of the SAME scope trips the strike -> node revoked (cascade)
    for i in range(3):
        d = child.check("fs.write", tool="write_file")
        assert not d
    assert child.is_revoked
    # a previously-allowed scope is now denied too (the node is revoked)
    dr = child.check("fs.read"); assert not dr and any(r.code == ReasonCode.REVOKED for r in dr.reasons)
    strikes = [e for e in root.audit_log().entries if e.get("event") == "kill" and e.get("reason") == "strike_policy"]
    assert strikes and strikes[-1]["scope"] == "fs.write" and strikes[-1]["strikes"] == 3


def test_strike_policy_same_scope_does_not_trip_on_different_scopes():
    from attenu_guard import Authority, Guard, StrikePolicy
    root = Guard.issue("o", Authority({"fs.read"}, [], ttl=None), task="t", strikes=StrikePolicy(n=3, mode="same_scope"))
    child = root.delegate("r", Authority({"fs.read"}, [], ttl=None), task="x")
    for scope in ("fs.write", "mail.send", "payments.transfer"):     # 3 denials, all DIFFERENT scopes
        child.check(scope)
    assert not child.is_revoked                                       # same_scope mode: no single scope hit 3
    child.check("fs.write"); child.check("fs.write")                  # now fs.write reaches 3 total
    assert child.is_revoked


def test_strike_policy_total_mode_and_off():
    from attenu_guard import Authority, Guard, StrikePolicy
    root = Guard.issue("o", Authority({"fs.read"}, [], ttl=None), task="t", strikes=StrikePolicy(n=3, mode="total"))
    child = root.delegate("r", Authority({"fs.read"}, [], ttl=None), task="x")
    for scope in ("fs.write", "mail.send", "payments.transfer"):      # 3 denials across ANY scope -> total mode trips
        child.check(scope)
    assert child.is_revoked
    # off by default when no policy is passed: denials never revoke
    root2 = Guard.issue("o", Authority({"fs.read"}, [], ttl=None), task="t")
    c2 = root2.delegate("r", Authority({"fs.read"}, [], ttl=None), task="x")
    for _ in range(10): c2.check("fs.write")
    assert not c2.is_revoked


# ---- Ledger anchoring (attenu-derive T27 / ADR-14): an external signed commitment to the chain head, so a fully -------
# rewritten-and-re-hashed log is still detectable ------------------------------------------------------------------------
def test_anchor_detects_a_consistently_rewritten_ledger():
    import copy
    from attenu_guard import Authority, Guard, AuditLog
    from attenu_guard.audit import _hash, GENESIS
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"anchor-key", kid="anchor-1")
    root = Guard.issue("orchestrator", Authority({"crm.*"}, [], ttl=None), task="quarterly review")
    child = root.delegate("summarizer", Authority({"crm.read"}, [], ttl=None), task="summarize")
    child.check("crm.read", context={"rows": 10}, tool="crm_query")
    log = root.audit_log(); entries = log.entries
    # the operator publishes an anchor to an external store
    anchor = log.anchor(signer)
    assert anchor["seq"] == len(entries) - 1 and anchor["head"] == entries[-1]["hash"] and anchor["chain_id"] == "chain"
    ok, err = AuditLog.verify_anchor(entries, anchor, signer); assert ok, err
    # attacker rewrites history: change a granted scope, then RE-HASH the whole chain so plain verify() passes
    forged = copy.deepcopy(entries)
    forged[1]["granted"] = {"scopes": ["crm.read", "crm.export", "mail.send"], "ceilings": [], "ttl": None}
    prev = GENESIS
    for e in forged:
        e["prev_hash"] = prev; payload = {k: v for k, v in e.items() if k != "hash"}
        e["hash"] = _hash(prev, payload); prev = e["hash"]
    assert AuditLog.verify(forged)[0]                       # internal chain is self-consistent again...
    ok2, err2 = AuditLog.verify_anchor(forged, anchor, signer)
    assert not ok2 and "anchor" in err2.lower()             # ...but the signed anchor's head no longer matches -> caught


def test_anchor_rejects_a_forged_signature():
    from attenu_guard import Authority, Guard, AuditLog
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"real-key", kid="k1"); attacker = HS256TestSigner(secret=b"attacker-key", kid="k1")
    root = Guard.issue("o", Authority({"crm.read"}, [], ttl=None), task="t")
    entries = root.audit_log().entries
    anchor = root.audit_log().anchor(signer)
    bad = dict(anchor, sig=attacker.sign(b"whatever").hex())
    ok, err = AuditLog.verify_anchor(entries, bad, signer); assert not ok and "signature" in err.lower()


def test_anchor_rejects_a_chain_id_that_does_not_match_the_entries():
    from attenu_guard import Authority, Guard, AuditLog, canonical
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"real-key", kid="k1")
    root = Guard.issue("o", Authority({"crm.read"}, [], ttl=None), task="t")
    entries = root.audit_log().entries
    anchor = root.audit_log().anchor(signer)
    # an honestly-signed anchor for a DIFFERENT chain than the one the entries actually belong to
    wrong_chain = dict(anchor, chain_id="some-other-chain")
    body = {k: v for k, v in wrong_chain.items() if k not in ("kid", "sig", "verified")}
    wrong_chain["sig"] = signer.sign(canonical.dumps(body)).hex()
    ok, err = AuditLog.verify_anchor(entries, wrong_chain, signer)
    assert not ok and "chain_id" in err.lower()


# ---- Offline evidence bundle + verifier (attenu-derive T33a): an auditor verifies, from the bundle ALONE with no --------
# access to the engine, that (1) every action was within the acting node's authority, (2) the chain was monotonic at
# every hop, (3) the ledger is untampered against its anchor. -----------------------------------------------------------
def _evidence_chain():
    from attenu_guard import Authority, Guard, RowLimit, EgressRank
    root = Guard.issue("orchestrator", Authority({"crm.read", "crm.write", "agent.delegate.summarizer"}, [RowLimit(100_000), EgressRank("any")], ttl=None), task="review")
    child = root.delegate("summarizer", Authority({"crm.read"}, [RowLimit(5_000), EgressRank("none")], ttl=None), task="summarize")
    child.check("crm.read", context={"rows": 10}, tool="crm_query")           # allowed
    child.check("crm.export", tool="crm_export")                              # denied (not granted)
    child.complete()
    return root


def test_evidence_bundle_verifies_offline():
    from attenu_guard import evidence
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"anchor", kid="k1")
    root = _evidence_chain()
    bundle = evidence.export_bundle(root.audit_log(), signer)
    assert bundle["chain_id"] == "chain" and bundle["entries"] and bundle["anchor"]["verified"] is not None
    rep = evidence.verify_bundle(bundle, signer)
    assert rep["ok"] is True
    assert rep["checks"] == {
        "integrity": True,
        "monotonicity": True,
        "containment": True,
        "anchor": "verified",
        "version": True,
        "chain_id": True,
    }
    assert rep["nodes"] == 2 and rep["actions_checked"] >= 1


def test_altered_bundle_fails_each_check_independently():
    import copy, json
    from attenu_guard import evidence
    from attenu_guard.audit import _hash, GENESIS
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"anchor", kid="k1")
    root = _evidence_chain()
    good = evidence.export_bundle(root.audit_log(), signer)

    # (1) INTEGRITY: flip one field without re-hashing -> hash chain breaks
    b1 = copy.deepcopy(good); b1["entries"][2]["scope"] = "crm.export"
    r1 = evidence.verify_bundle(b1, signer); assert r1["ok"] is False and r1["checks"]["integrity"] is False

    # (1b) INTEGRITY vs ANCHOR: consistent full rewrite (re-hash the chain) passes hash-chain but not the anchor
    b1b = copy.deepcopy(good); b1b["entries"][1]["granted"]["scopes"] = ["crm.read", "crm.export"]
    prev = GENESIS
    for e in b1b["entries"]:
        e["prev_hash"] = prev; payload = {k: v for k, v in e.items() if k != "hash"}; e["hash"] = _hash(prev, payload); prev = e["hash"]
    r1b = evidence.verify_bundle(b1b, signer); assert r1b["ok"] is False and r1b["checks"]["integrity"] is False

    # (2) MONOTONICITY: widen a child's granted authority beyond its parent, and re-anchor honestly (attacker holds the log
    #     but NOT the parent's true authority) -> monotonicity fails even though integrity passes against the new anchor
    b2 = copy.deepcopy(good)
    for e in b2["entries"]:
        if e.get("event") == "spawn":
            e["granted"]["scopes"] = sorted(set(e["granted"]["scopes"]) | {"mail.send"})   # child now claims a scope the parent never had
    prev = GENESIS
    for e in b2["entries"]:
        e["prev_hash"] = prev; payload = {k: v for k, v in e.items() if k != "hash"}; e["hash"] = _hash(prev, payload); prev = e["hash"]
    b2["anchor"] = evidence._anchor_for(b2["entries"], signer)
    r2 = evidence.verify_bundle(b2, signer)
    assert r2["checks"]["integrity"] is True and r2["checks"]["monotonicity"] is False and r2["ok"] is False

    # (3) CONTAINMENT: turn a recorded allow into a scope the node was never granted, re-anchor honestly
    b3 = copy.deepcopy(good)
    for e in b3["entries"]:
        if e.get("event") == "allow":
            e["scope"] = "mail.send"                          # an action outside the summarizer's {crm.read}
    prev = GENESIS
    for e in b3["entries"]:
        e["prev_hash"] = prev; payload = {k: v for k, v in e.items() if k != "hash"}; e["hash"] = _hash(prev, payload); prev = e["hash"]
    b3["anchor"] = evidence._anchor_for(b3["entries"], signer)
    r3 = evidence.verify_bundle(b3, signer)
    assert r3["checks"]["integrity"] is True and r3["checks"]["containment"] is False and r3["ok"] is False

    # (4) UNSUPPORTED VERSION: a bundle declaring a schema version this build doesn't know
    b4 = copy.deepcopy(good); b4["v"] = 999
    r4 = evidence.verify_bundle(b4, signer)
    assert r4["checks"]["version"] is False and r4["ok"] is False
    assert any(f.startswith("unsupported_version:") for f in r4["failures"])

    # (5) ANCHOR VERSION MISMATCH: an honestly-signed anchor for a DIFFERENT version than the bundle
    from attenu_guard import canonical
    tampered_anchor = dict(good["anchor"]); tampered_anchor["v"] = 2
    body = {k: v for k, v in tampered_anchor.items() if k not in ("kid", "sig", "verified")}
    tampered_anchor["sig"] = signer.sign(canonical.dumps(body)).hex()
    b5 = copy.deepcopy(good); b5["anchor"] = tampered_anchor
    r5 = evidence.verify_bundle(b5, signer)
    assert r5["checks"]["version"] is False and r5["ok"] is False
    assert any(f.startswith("anchor_version_mismatch:") for f in r5["failures"])

    # (6) CHAIN_ID MISMATCH (entries): an entry claims a different chain than the bundle declares,
    #     re-hashed and re-anchored honestly so only the chain_id check is isolated
    b6 = copy.deepcopy(good); b6["entries"][1]["chain_id"] = "other-chain"
    prev = GENESIS
    for e in b6["entries"]:
        e["prev_hash"] = prev; payload = {k: v for k, v in e.items() if k != "hash"}; e["hash"] = _hash(prev, payload); prev = e["hash"]
    b6["anchor"] = evidence._anchor_for(b6["entries"], signer)
    r6 = evidence.verify_bundle(b6, signer)
    assert r6["checks"]["integrity"] is True and r6["checks"]["chain_id"] is False and r6["ok"] is False

    # (7) CHAIN_ID MISMATCH (anchor): an honestly-signed anchor for a DIFFERENT chain than the entries
    tampered_anchor2 = dict(good["anchor"]); tampered_anchor2["chain_id"] = "other-chain"
    body2 = {k: v for k, v in tampered_anchor2.items() if k not in ("kid", "sig", "verified")}
    tampered_anchor2["sig"] = signer.sign(canonical.dumps(body2)).hex()
    b7 = copy.deepcopy(good); b7["anchor"] = tampered_anchor2
    r7 = evidence.verify_bundle(b7, signer)
    assert r7["checks"]["chain_id"] is False and r7["ok"] is False


def test_delegation_graph_view_from_the_bundle():
    from attenu_guard import evidence
    from attenu_guard.wire import HS256TestSigner
    root = _evidence_chain()
    g = evidence.delegation_graph(evidence.export_bundle(root.audit_log(), HS256TestSigner(secret=b"k", kid="k")))
    assert g["edges"] == [{"parent": root.node_id, "child": next(n for n in g["nodes"] if g["nodes"][n]["agent"] == "summarizer")}]
    summ = next(v for v in g["nodes"].values() if v["agent"] == "summarizer")
    assert summ["scopes"] == ["crm.read"] and summ["allows"] == 1 and summ["denies"] == 1 and summ["complete"] is True


# ---- Bundle redaction guarantee (attenu-derive A2b): the flywheel transports customer data, so "nothing leaks" is a -----
# TEST, not a habit. Field allow-list + a caller context allow-list + free-text redaction; a raw argument in a bundle fails.
def test_export_rejects_an_unknown_ledger_field():
    from attenu_guard import Authority, Guard, evidence
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"k", kid="k")
    root = Guard.issue("o", Authority({"crm.read"}, [], ttl=None), task="t")
    # simulate an adapter smuggling a raw value as a NEW field (exactly where a leak would hide)
    root.audit_log().append("allow", 9, chain_id="chain", node="chain:n0", scope="crm.read", customer_email="alice@bank.example")
    rep = evidence.redaction_report(root.audit_log().entries)
    assert not rep["ok"] and any(v["field"] == "customer_email" for v in rep["violations"])
    import pytest
    with pytest.raises(evidence.EvidenceLeakError):
        evidence.export_bundle(root.audit_log(), signer, strict=True)


def test_raw_argument_in_context_is_caught_by_the_context_allowlist():
    from attenu_guard import Authority, Guard, evidence
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"k", kid="k")
    root = Guard.issue("o", Authority({"crm.read"}, [], ttl=None), task="t")
    root.check("crm.read", context={"rows": 5}, tool="q")                          # redacted feature: fine
    root.check("crm.read", context={"to": "victim@evil.example"}, tool="send")     # a RAW arg value in context
    FEATURES = {"rows", "spend", "egress", "calls", "arg_shape", "quantities", "str_len_buckets", "arg_hashes", "arg_keys"}
    rep = evidence.redaction_report(root.audit_log().entries, context_allowlist=FEATURES)
    assert not rep["ok"] and any(v.get("context_key") == "to" for v in rep["violations"])
    import pytest
    with pytest.raises(evidence.EvidenceLeakError):
        evidence.export_bundle(root.audit_log(), signer, context_allowlist=FEATURES, strict=True)
    # the clean-feature bundle passes
    root2 = Guard.issue("o", Authority({"crm.read"}, [], ttl=None), task="t"); root2.check("crm.read", context={"rows": 5}, tool="q")
    assert evidence.redaction_report(root2.audit_log().entries, context_allowlist=FEATURES)["ok"]


def test_free_text_task_is_redacted_for_transport():
    import json
    from attenu_guard import Authority, Guard, evidence
    from attenu_guard.wire import HS256TestSigner
    signer = HS256TestSigner(secret=b"k", kid="k")
    root = Guard.issue("orchestrator", Authority({"agent.delegate.s"}, [], ttl=None), task="Wire $10k to account 4821 for customer Alice Smith")
    root.delegate("s", Authority(set(), [], ttl=None), task="pay the invoice for alice@bank.example")
    bundle = evidence.export_bundle(root.audit_log(), signer, redact_task=True)
    blob = json.dumps(bundle)
    assert "Alice Smith" not in blob and "alice@bank.example" not in blob and "4821" not in blob   # no raw task text leaves
    # the bundle still verifies (redaction happens before the anchor, so the hashes cover the redacted form)
    assert evidence.verify_bundle(bundle, signer)["ok"] is True
    # and a task field is present as a length/hash marker, not raw
    tasks = [e["task"] for e in bundle["entries"] if e.get("task")]                 # root events carry no task in the ledger; spawns do
    assert tasks and all(t.startswith("redacted:") for t in tasks)
