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

from delegation_guard import (
    Authority, Guard, AuthorityError, AuthorityDenied,
    Decision, Reason, ReasonCode, AuditLog,
    Ceiling, RowLimit, SpendCap, CallLimit, EgressRank, Allow, Deny, Prefix,
    register_ceiling,
)
from delegation_guard.ceilings import ceiling_from_wire, _UnknownCeiling
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
        cases = [
            (RowLimit(10), {"spend": 1, "calls": 1}, "max_rows"),
            (SpendCap(10.0), {"rows": 1, "calls": 1}, "max_spend"),
            (CallLimit(10), {"rows": 1, "spend": 1}, "max_calls"),
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
        r2 = Guard.issue("o", Authority({"x"}, [], ttl=100), clock=clk)
        c2 = r2.delegate("c", Authority({"x"}, [], ttl=5), task="t")
        self.assertFalse(c2.is_expired)
        clk.t = 6
        self.assertTrue(c2.is_expired)
        self.assertFalse(c2.check("x"))
        self.assertEqual(c2.check("x").reasons[0].code, ReasonCode.EXPIRED)

    def test_reason_code_no_authority_exists(self):
        self.assertEqual(ReasonCode.NO_AUTHORITY, "no_authority")

    def test_record_denial_lands_in_the_audit_log_as_a_deny_event(self):
        # An adapter refusing something UPSTREAM of policy (unknown principal,
        # undeclared sub-agent, unparseable tool args) must be able to put
        # that refusal on the same tamper-evident trail as policy denials --
        # otherwise `dg view` never sees it.
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
        root = Guard.issue("o", Authority({"x"}, [], ttl=100), max_depth=1, max_fanout=1)
        self.assertTrue(root.would_delegate("a", Authority({"x"}, [], ttl=10)))
        a = root.delegate("a", Authority({"x"}, [], ttl=10), task="t")
        self.assertEqual(root.would_delegate("b", Authority({"x"}, [], ttl=10)).reasons[0].code, "max_fanout")
        self.assertEqual(a.would_delegate("c", Authority({"x"}, [], ttl=10)).reasons[0].code, "max_depth")


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
        root = Guard.issue("o", Authority({"x"}, [], ttl=10**6), max_fanout=10**6)
        counter = {"i": 0}
        import threading
        lock = threading.Lock()
        def op():
            with lock:
                counter["i"] += 1; i = counter["i"]
            g = root.delegate(f"a{i}", Authority({"x"}, [], ttl=10**6), task="t")
            g.check("x")
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
        from delegation_guard.ceilings import describe
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
        root = Guard.issue("o", Authority({"x"}, [], ttl=100), max_depth=1)
        a = root.delegate("a", Authority({"x"}, [], ttl=10), task="t")
        with self.assertRaises(AuthorityError) as cm:
            a.delegate("b", Authority({"x"}, [], ttl=10), task="t")
        self.assertEqual(cm.exception.reason, ReasonCode.MAX_DEPTH)
        root.revoke()
        with self.assertRaises(AuthorityError) as cm:
            root.delegate("c", Authority({"x"}, [], ttl=10), task="t")
        self.assertEqual(cm.exception.reason, ReasonCode.CHAIN_REVOKED)
        for name in ("CHAIN_REVOKED", "AGENT_BANNED", "TTL_EXPIRED", "MAX_DEPTH", "MAX_FANOUT", "CHAIN_CEILING"):
            self.assertIsInstance(getattr(ReasonCode, name), str)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
