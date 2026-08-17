"""
Property-based tests of the core safety invariants (hypothesis).

These are the credibility artifact: they assert, over thousands of randomly
generated delegation trees, the properties that no framework or platform in the
market enforces. If any of these can be made to fail, the product's central
claim is false — so they run in CI on every commit.

Requires `hypothesis` (an optional test dependency: `pip install -e '.[test]'`).
The zero-dependency mirror in tests/run_properties.py covers the same invariants
with only the standard library, for environments without hypothesis.

v0.2: ported to the new API — Guard.issue/delegate/revoke, typed Ceiling objects,
Decision-returning check(), and is_narrower_than() as the subsumption relation.
"""
from hypothesis import given, settings, strategies as st

from delegation_guard import Authority, Guard, AuthorityError, ReasonCode
from delegation_guard.ceilings import RowLimit, SpendCap, EgressRank
from delegation_guard.audit import AuditLog as AL

# ---- strategies --------------------------------------------------------
scopes_pool = ["crm.read", "crm.write", "crm.export", "mail.send", "mail.read",
               "files.read", "files.write", "pay.transfer"]
wild_pool = ["crm.*", "mail.*", "files.*"]


def authorities(draw_wild=True):
    pool = scopes_pool + (wild_pool if draw_wild else [])
    return st.builds(
        lambda scopes, rows, spend, egress, ttl: Authority(
            scopes=scopes,
            ceilings=[RowLimit(rows), SpendCap(spend), EgressRank(egress)],
            ttl=ttl,
        ),
        scopes=st.sets(st.sampled_from(pool), max_size=5),
        rows=st.integers(min_value=0, max_value=1_000_000),
        spend=st.integers(min_value=0, max_value=100_000),
        egress=st.sampled_from(["none", "internal", "any"]),
        ttl=st.integers(min_value=1, max_value=7200),
    )


# ---- INVARIANT 1: attenuation never widens -----------------------------
@given(parent=authorities(), requested=authorities())
@settings(max_examples=500)
def test_meet_never_exceeds_parent(parent, requested):
    child = parent.meet(requested)
    assert child.is_narrower_than(parent), f"{child} !<= {parent}"


@given(parent=authorities(), requested=authorities())
@settings(max_examples=500)
def test_meet_never_exceeds_request(parent, requested):
    child = parent.meet(requested)
    assert child.is_narrower_than(requested)


@given(a=authorities())
@settings(max_examples=200)
def test_meet_with_self_never_widens(a):
    # meeting an authority with itself can only ever stay within it.
    assert a.meet(a).is_narrower_than(a)


# ---- INVARIANT 2: transitive attenuation down a real chain -------------
@given(auths=st.lists(authorities(), min_size=1, max_size=6))
@settings(max_examples=300)
def test_chain_is_monotonic(auths):
    """Every node in a delegated chain is <= all its ancestors."""
    root = Guard.issue("a0", auths[0], max_depth=len(auths) + 1, max_fanout=4)
    guards = [root]
    cur = root
    for i, req in enumerate(auths[1:], start=1):
        try:
            cur = cur.delegate(f"a{i}", req, task=f"t{i}")
        except AuthorityError:
            break  # depth/fanout hit — fine, the ones we made still hold
        guards.append(cur)
    for g in guards:
        assert g.authority.is_narrower_than(root.authority)


# ---- INVARIANT 3: a child can never regain a scope the parent dropped ---
@given(child_req=authorities())
@settings(max_examples=300)
def test_no_scope_resurrection(child_req):
    parent = Authority(scopes={"crm.read"}, ceilings=[EgressRank("none")], ttl=100)
    g = Guard.issue("p", parent, max_depth=3)
    child = g.delegate("c", child_req, task="t")
    assert not child.authority.covers_scope("pay.transfer")
    assert not child.authority.covers_scope("crm.export")
    # egress can only be 'none' (the strictest) after meeting a none-egress parent
    egress = child.authority.ceiling("egress")
    assert egress is None or egress.level == "none"


# ---- INVARIANT 4: cascade revocation reaches every descendant ----------
@given(width=st.integers(min_value=1, max_value=3),
       depth=st.integers(min_value=1, max_value=4))
@settings(max_examples=200)
def test_cascade_revokes_whole_subtree(width, depth):
    broad = Authority(scopes={"crm.*"}, ceilings=[RowLimit(10**9)], ttl=10**9)
    root = Guard.issue("root", broad, max_depth=depth + 1, max_fanout=width + 1)

    made = []
    def build(g, d):
        if d == 0:
            return
        for i in range(width):
            child = g.delegate(f"a{d}_{i}", Authority(scopes={"crm.read"},
                               ceilings=[RowLimit(100)], ttl=10**9), task="t")
            made.append(child)
            build(child, d - 1)
    build(root, depth)

    root.revoke()  # revoke from the top
    for g in made:
        decision = g.check("crm.read", context={"rows": 1})
        assert not decision, "revoked node authorized an action"
        assert decision.reasons[0].code == ReasonCode.REVOKED


# ---- INVARIANT 5: the audit log is tamper-evident ----------------------
@given(n=st.integers(min_value=1, max_value=20))
@settings(max_examples=100)
def test_audit_chain_verifies(n):
    broad = Authority(scopes={"crm.*"}, ceilings=[RowLimit(10**9)], ttl=10**9)
    g = Guard.issue("root", broad, max_depth=n + 1, max_fanout=n + 1)
    cur = g
    for i in range(n):
        cur = cur.delegate(f"a{i}", Authority(scopes={"crm.read"},
                           ceilings=[RowLimit(10)], ttl=100), task="t")
    entries = g.audit_log().entries
    ok, reason = AL.verify(entries)
    assert ok, reason


@given(n=st.integers(min_value=2, max_value=15),
       tamper=st.integers(min_value=1, max_value=14))
@settings(max_examples=100)
def test_audit_tamper_is_detected(n, tamper):
    broad = Authority(scopes={"crm.*"}, ceilings=[RowLimit(10**9)], ttl=10**9)
    g = Guard.issue("root", broad, max_depth=n + 1, max_fanout=n + 1)
    cur = g
    for i in range(n):
        cur = cur.delegate(f"a{i}", Authority(scopes={"crm.read"},
                           ceilings=[RowLimit(10)], ttl=100), task="t")
    entries = g.audit_log().entries
    idx = min(tamper, len(entries) - 1)
    entries[idx] = {**entries[idx], "agent": "attacker"}
    ok, reason = AL.verify(entries)
    assert not ok
