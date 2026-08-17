"""
Zero-dependency property runner — proves the core invariants with only the
standard library, so anyone can verify the safety claims with `python
tests/run_properties.py` and no install. CI additionally runs the richer
hypothesis suite in tests/test_invariants.py.

v0.2: adapted to the new API (Guard.issue/delegate, typed Ceiling objects,
Decision-returning check()) — the invariants themselves are unchanged from
v0.1: attenuation never widens, transitive monotonicity down a chain, no
scope resurrection, cascade revocation reaches every descendant, and the
audit log is tamper-evident.

Exit code 0 = all invariants held across all random trials; non-zero = a
counterexample was found (and is printed).
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from delegation_guard import Authority, Guard, AuthorityError, ReasonCode
from delegation_guard.ceilings import RowLimit, SpendCap, EgressRank
from delegation_guard.audit import AuditLog

SCOPES = ["crm.read", "crm.write", "crm.export", "mail.send", "mail.read",
          "files.read", "files.write", "pay.transfer"]
WILD = ["crm.*", "mail.*", "files.*"]
EGRESS = ["none", "internal", "any"]


def rnd_authority(rng, allow_wild=True):
    pool = SCOPES + (WILD if allow_wild else [])
    scopes = set(rng.sample(pool, rng.randint(0, min(5, len(pool)))))
    ceilings = [
        RowLimit(rng.randint(0, 1_000_000)),
        SpendCap(rng.randint(0, 100_000)),
        EgressRank(rng.choice(EGRESS)),
    ]
    return Authority(scopes, ceilings, ttl=rng.randint(1, 7200))


def check(name, cond, ctx):
    if not cond:
        print(f"FAIL: {name}\n  counterexample: {ctx}")
        raise SystemExit(1)


def main(trials=4000, seed=None):
    rng = random.Random(seed if seed is not None else 1234567)
    print(f"running {trials} trials per invariant ...")

    # INV1: meet never exceeds either input
    for _ in range(trials):
        p, r = rnd_authority(rng), rnd_authority(rng)
        c = p.meet(r)
        check("meet <= parent", c.is_narrower_than(p), (p, r, c))
        check("meet <= requested", c.is_narrower_than(r), (p, r, c))

    # INV2: transitive monotonicity down a delegated chain
    for _ in range(trials):
        auths = [rnd_authority(rng) for _ in range(rng.randint(1, 6))]
        root = Guard.issue("a0", auths[0], max_depth=len(auths) + 1, max_fanout=4)
        cur, made = root, [root]
        for i, req in enumerate(auths[1:], 1):
            try:
                cur = cur.delegate(f"a{i}", req, task=f"t{i}")
                made.append(cur)
            except AuthorityError:
                break
        for g in made:
            check("chain node <= root", g.authority.is_narrower_than(root.authority),
                  (root.authority, g.authority))

    # INV3: no scope resurrection past a dropping parent
    for _ in range(trials):
        parent = Authority({"crm.read"}, [EgressRank("none")], ttl=100)
        g = Guard.issue("p", parent, max_depth=3)
        child = g.delegate("c", rnd_authority(rng), task="t")
        check("no pay.transfer", not child.authority.covers_scope("pay.transfer"),
              child.authority)
        check("no crm.export", not child.authority.covers_scope("crm.export"),
              child.authority)

    # INV4: cascade revoke reaches every descendant
    for _ in range(trials // 4):
        width = rng.randint(1, 3)
        depth = rng.randint(1, 4)
        broad = Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9)
        root = Guard.issue("root", broad, max_depth=depth + 1, max_fanout=width + 1)
        made = []

        def build(g, d):
            if d == 0:
                return
            for i in range(width):
                ch = g.delegate(f"a{d}_{i}", Authority({"crm.read"},
                                [RowLimit(100)], ttl=10**9), task="t")
                made.append(ch)
                build(ch, d - 1)
        build(root, depth)
        root.revoke()
        for g in made:
            decision = g.check("crm.read", context={"rows": 1})
            denied = (not decision) and bool(decision.reasons) \
                and decision.reasons[0].code == ReasonCode.REVOKED
            check("revoked node denies", denied, (g.node_id, decision))

    # INV5: audit tamper-evidence
    for _ in range(trials // 4):
        n = rng.randint(2, 15)
        broad = Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9)
        g = Guard.issue("root", broad, max_depth=n + 1, max_fanout=n + 1)
        cur = g
        for i in range(n):
            cur = cur.delegate(f"a{i}", Authority({"crm.read"}, [RowLimit(10)],
                               ttl=100), task="t")
        entries = g.audit_log().entries
        ok, _ = AuditLog.verify(entries)
        check("clean log verifies", ok, "clean")
        idx = rng.randint(0, len(entries) - 1)
        entries[idx] = {**entries[idx], "agent": "attacker"}
        ok2, _ = AuditLog.verify(entries)
        check("tampered log detected", not ok2, idx)

    print("ALL INVARIANTS HELD ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
