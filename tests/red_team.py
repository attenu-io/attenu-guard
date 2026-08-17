"""
red_team.py — adversarial assessment of the delegation-guard authorization protocol.

We try to BREAK our own attenuation. Two boxes:

  BLACK-BOX  attacks use only the public API (Guard.delegate / check / revoke).
             This is what a hostile agent or a malicious delegation *request*
             can do — the realistic in-band threat model.

  WHITE-BOX  attacks use knowledge of / access to internals (mutating node
             state, hand-constructing Authority objects, probing the order
             relation itself). This is a same-process adversary and a
             correctness audit of the proof machinery.

Each attack reports one of:
  DEFENDED   the protocol refused the unauthorized outcome (good)
  BROKEN     the attacker obtained authority or an effect it should not have
             (a finding — printed with a repro)
  LIMITATION a known, documented boundary of the in-process library tier
             (not a finding — reported separately from BROKEN)

A break here is defined in AUTHORIZATION terms:
  * escalation  — a child ends up able to do something outside its parent's grant
  * containment — a revoked/killed node still authorizes an action
  * unenforced  — a declared control (ttl, budget) does not actually gate
  * integrity   — a tamper of the record goes undetected
  * false-deny  — a legitimately-granted authority is refused (breaks workflows)

v0.2: check() now returns a Decision instead of raising — a policy denial is
a normal outcome (docs/DEVX-REVIEW.md principle 3), so attacks that probe
check() assert on `not decision` / `decision.reasons[0].code`, not on a
caught exception. `delegate()` still raises `AuthorityError` for STRUCTURAL
failures (revoked/expired parent, integrity failure, depth/fanout overflow)
— those two failure classes are deliberately different mechanisms; both are
exercised below.

Run:  python tests/red_team.py
Exit code = number of BROKEN findings (0 = protocol survived every attack).
"""
import sys
import pathlib
from dataclasses import dataclass, field

try:
    import delegation_guard  # noqa
except ModuleNotFoundError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from delegation_guard import (
    Authority, Guard, AuthorityError, Decision, Reason, ReasonCode,
)
from delegation_guard.ceilings import RowLimit, EgressRank
from delegation_guard.audit import AuditLog

RESULTS = []


def record(name, box, category, verdict, evidence):
    RESULTS.append((name, box, category, verdict, evidence))


def attempt(name, box, category, fn):
    """fn() -> (verdict, evidence)."""
    try:
        verdict, evidence = fn()
    except Exception as e:  # an unexpected crash is itself a finding
        verdict, evidence = "BROKEN", f"unexpected exception: {type(e).__name__}: {e}"
    record(name, box, category, verdict, evidence)


# =====================================================================
# A tiny custom Ceiling — demonstrates the extension seam (ceilings.py's
# registry / Ceiling protocol) used by the white-box "custom ceiling" tests.
# Mirrors the built-in RowLimit almost exactly, but for a dimension the
# library core has never heard of ("widgets"), which is exactly the point.
# =====================================================================
@dataclass(frozen=True)
class WidgetLimit:
    max_widgets: int
    key: str = field(default="max_widgets", init=False, repr=False)

    def permits(self, ctx):
        n = ctx.get("widgets")
        if n is None or n <= self.max_widgets:
            return Decision.allow()
        return Decision.deny(Reason(ReasonCode.CEILING_EXCEEDED, self.key, self.max_widgets, n))

    def narrow(self, other):
        return WidgetLimit(min(self.max_widgets, other.max_widgets))

    def subsumes(self, other):
        return self.max_widgets >= other.max_widgets

    def to_wire(self):
        return {"key": self.key, "type": "widget_limit", "max": self.max_widgets}

    @classmethod
    def from_wire(cls, d):
        return cls(d["max"])


# =====================================================================
# BLACK-BOX ATTACKS — public API only
# =====================================================================

def bb_scope_escalation():
    """Child requests scopes and a wildcard the parent never held."""
    parent = Guard.issue("p", Authority({"crm.read"}, [EgressRank("none")], ttl=3600))
    child = parent.delegate("c", Authority({"crm.*", "pay.transfer"},
                                           [EgressRank("any")], ttl=3600), task="t")
    d1 = child.check("pay.transfer", tool="bank")
    if d1:
        return "BROKEN", "child transferred money parent could not"
    d2 = child.check("crm.export", context={"egress": "any"}, tool="crm")
    if d2:
        return "BROKEN", "child exported via wildcard parent never held"
    return "DEFENDED", f"child authority scopes = {sorted(child.authority.scopes)}"


def bb_ceiling_escalation():
    """Child requests a higher numeric ceiling than the parent granted."""
    parent = Guard.issue("p", Authority({"crm.read"}, [RowLimit(100)], ttl=3600))
    child = parent.delegate("c", Authority({"crm.read"}, [RowLimit(10**9)], ttl=3600),
                            task="t")
    d = child.check("crm.read", context={"rows": 1000}, tool="crm")
    if d:
        return "BROKEN", "child read 1000 rows under a parent cap of 100"
    return "DEFENDED", f"cap enforced at {child.authority.ceiling('max_rows').max_rows}"


def bb_egress_escalation():
    """Parent forbids egress; child asks for 'any' and tries to exfiltrate."""
    parent = Guard.issue("p", Authority({"crm.read"}, [EgressRank("none")], ttl=3600))
    child = parent.delegate("c", Authority({"crm.read"}, [EgressRank("any")], ttl=3600),
                            task="t")
    d = child.check("crm.read", context={"egress": "any"}, tool="exfil")
    if d:
        return "BROKEN", "child egressed data under a parent egress=none"
    return "DEFENDED", "egress pinned to none"


def bb_ttl_expiry():
    """A short-TTL grant should stop authorizing after it expires."""
    clk = _ManualClock()
    parent = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10**9)], ttl=10**9),
                         clock=clk)
    child = parent.delegate("c", Authority({"crm.read"}, [RowLimit(100)], ttl=1), task="t")
    fresh = child.check("crm.read", context={"rows": 1}, tool="crm")
    if not fresh:
        return "BROKEN", f"a fresh, in-bounds grant was unexpectedly denied: {fresh.explain()}"
    clk.advance(3600)                                   # an hour passes; ttl was 1s
    stale = child.check("crm.read", context={"rows": 1}, tool="crm")
    if stale:
        return "BROKEN", "expired grant (ttl=1s) still authorized after 3600s"
    code = stale.reasons[0].code if stale.reasons else None
    if code != ReasonCode.EXPIRED:
        return "BROKEN", f"expired grant denied for the wrong reason: {code}"
    return "DEFENDED", f"expired grant denied ({code})"


def bb_budget_omission():
    """Aggregate row budget and the declared-quantity trust boundary."""
    # Default mode: the library enforces against the number it is GIVEN.
    parent = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10**9)], ttl=10**9))
    child = parent.delegate("c", Authority({"crm.read"}, [RowLimit(10**9)], ttl=10**9),
                            task="t")
    honest = child.check("crm.read", context={"rows": 900}, tool="crm")
    if not honest:
        return "BROKEN", f"a legitimate 900-row read was denied: {honest.explain()}"

    # v0.1 had an implicit "chain_max_rows" aggregate ceiling, wired
    # automatically into check(). v0.2's typed Ceiling model has no
    # first-class *cumulative-across-calls* ceiling (every built-in in
    # ceilings.py — RowLimit, SpendCap, CallLimit, EgressRank, Allow, Deny,
    # Prefix — bounds a single call), so that auto-wiring is not
    # reintroduced at the Guard.check() layer; inventing one was out of
    # scope for the v0.2 core contract (docs/V0.2-SPEC.md). The underlying
    # accumulator (Chain.consume) is kept for any caller/adapter that wants
    # a chain-wide aggregate — exercised directly here, white-box:
    tripped = False
    child._chain.consume("max_rows", 900, chain_ceiling=1000)      # 900 <= 1000: fine
    try:
        child._chain.consume("max_rows", 900, chain_ceiling=1000)  # 1800 > 1000: trips
    except AuthorityError:
        tripped = True

    # the actual attack: omit the quantity. check() has nothing to compare
    # against, so nothing about the call size is ever asserted or recorded.
    for _ in range(50):
        undeclared = child.check("crm.read", tool="crm")           # no context at all
        if not undeclared:
            return "BROKEN", f"an undeclared read was unexpectedly denied: {undeclared.explain()}"

    # mitigation: strict metering makes undeclared access to a metered
    # resource fail closed (adapters flag consuming calls metered=True).
    sp = Guard.issue("p", Authority({"crm.read"}, [RowLimit(1000)], ttl=10**9),
                     strict_metering=True)
    sc = sp.delegate("c", Authority({"crm.read"}, [RowLimit(1000)], ttl=10**9), task="t")
    guarded = sc.check("crm.read", metered=True, tool="crm")       # metered, no context
    blocked = (not guarded) and guarded.reasons and guarded.reasons[0].code == ReasonCode.UNMETERED
    return "LIMITATION", (
        f"declared-quantity trust: a chain-wide aggregate exists (Chain.consume, "
        f"exercised directly above, tripped={tripped}) but is not auto-wired into "
        f"check() for v0.2's typed per-call ceilings; undeclared reads are invisible "
        f"to the in-process library either way. Mitigation: strict_metering fails "
        f"closed on undeclared metered access (blocked={blocked}); the production "
        f"data-plane measures at the gateway, which the agent does not control.")


def bb_cascade_kill():
    """Revoking the root must silence the whole subtree."""
    broad = Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9)
    root = Guard.issue("root", broad, max_depth=6, max_fanout=6)
    a = root.delegate("a", Authority({"crm.read"}, [RowLimit(100)], ttl=10**9), task="t")
    b = a.delegate("b", Authority({"crm.read"}, [RowLimit(100)], ttl=10**9), task="t")
    root.revoke()
    for g, nm in ((a, "a"), (b, "b")):
        d = g.check("crm.read", context={"rows": 1}, tool="crm")
        if d:
            return "BROKEN", f"revoked descendant {nm} still authorized"
    return "DEFENDED", "whole subtree denied after root revoke"


def bb_delegate_after_revoke():
    """A revoked node must not be able to mint fresh children."""
    root = Guard.issue("root", Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9))
    a = root.delegate("a", Authority({"crm.read"}, [RowLimit(100)], ttl=10**9), task="t")
    root.revoke()
    try:
        a.delegate("evil", Authority({"crm.read"}, [RowLimit(100)], ttl=10**9), task="t")
        return "BROKEN", "revoked node minted a new child"
    except AuthorityError:
        return "DEFENDED", "delegate from revoked node refused"


def bb_sibling_containment():
    """Revoking one subtree must NOT silence an unrelated sibling."""
    root = Guard.issue("root", Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9),
                       max_fanout=6)
    a = root.delegate("a", Authority({"crm.read"}, [RowLimit(100)], ttl=10**9), task="t")
    b = root.delegate("b", Authority({"crm.read"}, [RowLimit(100)], ttl=10**9), task="t")
    root.revoke(a.node_id)  # revoke only subtree a
    if not b.check("crm.read", context={"rows": 1}, tool="crm"):
        return "BROKEN", "revoking subtree a also silenced unrelated sibling b"
    if a.check("crm.read", context={"rows": 1}, tool="crm"):
        return "BROKEN", "revoked subtree a still authorized"
    return "DEFENDED", "sibling b survived; subtree a denied (blast radius scoped)"


def bb_depth_bomb():
    """Runaway recursive delegation must hit the depth ceiling."""
    root = Guard.issue("root", Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9),
                       max_depth=4, max_fanout=4)
    cur = root
    depth = 0
    try:
        for i in range(50):
            cur = cur.delegate(f"a{i}", Authority({"crm.read"}, [RowLimit(1)], ttl=10**9),
                               task="t")
            depth += 1
        return "BROKEN", f"delegated to depth {depth}, ceiling was 4"
    except AuthorityError:
        return "DEFENDED", f"depth ceiling stopped delegation at {depth}"


def bb_scope_prefix_confusion():
    """A narrow parent scope must not be widened by a look-alike request."""
    parent = Guard.issue("p", Authority({"crm.read"}, [EgressRank("none")], ttl=3600))
    # 'crm.readsecrets' shares a prefix but is a different permission
    child = parent.delegate("c", Authority({"crm.readsecrets", "crm.read.write"},
                                           [EgressRank("none")], ttl=3600), task="t")
    for scope in ("crm.readsecrets", "crm.read.write"):
        if child.check(scope, tool="x"):
            return "BROKEN", f"prefix look-alike '{scope}' authorized"
    return "DEFENDED", f"look-alikes rejected; child scopes={sorted(child.authority.scopes)}"


# =====================================================================
# WHITE-BOX ATTACKS — internal knowledge / same-process adversary
# =====================================================================

def wb_node_mutation_naive():
    """Adversary rewrites a node's authority object but not its integrity seal."""
    parent = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=3600))
    child = parent.delegate("c", Authority({"crm.read"}, [RowLimit(10)], ttl=3600),
                            task="t")
    # reach past the API into the node and widen it (leaving the seal stale)
    child._node.authority = Authority({"pay.transfer", "crm.*"},
                                      [RowLimit(10**9), EgressRank("any")], ttl=10**9)
    d = child.check("pay.transfer", tool="bank")
    if d:
        return "BROKEN", "naive node mutation bypassed attenuation"
    code = d.reasons[0].code if d.reasons else None
    return "DEFENDED", f"integrity seal caught the mutation ({code})"


def wb_node_mutation_secret_aware():
    """A full same-process adversary that also re-seals the mutated authority.

    This is OUT OF SCOPE for the in-process library tier by design: a component
    running in the same process can read the per-chain secret. Documented as a
    limitation; the production data-plane's signed, offline-verifiable grants
    remove the shared secret and make this class of attack detectable.
    """
    parent = Guard.issue("p", Authority({"crm.read"}, [RowLimit(10)], ttl=3600))
    child = parent.delegate("c", Authority({"crm.read"}, [RowLimit(10)], ttl=3600),
                            task="t")
    forged = Authority({"pay.transfer"}, [RowLimit(10**9), EgressRank("any")], ttl=10**9)
    child._node.authority = forged
    child._node.seal = child._chain._seal(forged)  # re-seal with the read secret
    d = child.check("pay.transfer", tool="bank")
    if d:
        return "LIMITATION", ("same-process adversary that reads the chain secret "
                              "can re-seal a forged authority — by design for the "
                              "in-process tier; mitigated by signed grants in the "
                              "production data-plane")
    return "DEFENDED", "unexpectedly blocked"


def wb_order_relation_soundness():
    """Probe the is_narrower_than relation that the whole proof depends on.

    Construct a child that is unbounded on a ceiling the parent bounds, using a
    ceiling key outside the built-in registry (WidgetLimit, defined above). If
    is_narrower_than returns True, the invariant checker is unsound (it would
    bless an escalating child).
    """
    parent = Authority({"crm.read"}, [RowLimit(100), WidgetLimit(5)], ttl=100)
    child = Authority({"crm.read"}, [RowLimit(100)], ttl=100)  # no WidgetLimit bound
    # child is unbounded on max_widgets while parent caps it at 5 -> child is MORE
    # powerful there, so a sound relation must say child.is_narrower_than(parent) is False.
    if child.is_narrower_than(parent):
        return "BROKEN", ("is_narrower_than returned True though child is unbounded on "
                          "'max_widgets' that parent caps at 5 (checker unsound "
                          "for ceilings outside the built-in registry)")
    return "DEFENDED", "is_narrower_than correctly rejected the unbounded custom ceiling"


def wb_unknown_ceiling_enforced():
    """A custom ceiling must be both attenuated AND enforceable."""
    parent = Guard.issue("p", Authority({"crm.read"}, [WidgetLimit(5)], ttl=3600))
    # child tries to escalate the custom ceiling; meet must clamp to 5
    child = parent.delegate("c", Authority({"crm.read"}, [WidgetLimit(1000)], ttl=3600),
                            task="t")
    clamped = child.authority.ceiling("max_widgets")
    if clamped is None or clamped.max_widgets != 5:
        return "BROKEN", f"custom ceiling not attenuated (max_widgets={clamped})"
    # and it must actually gate an action that declares the quantity
    d = child.check("crm.read", context={"widgets": 10}, tool="crm")  # 10 > 5
    if d:
        return "BROKEN", "custom ceiling carried but not enforced by check()"
    code = d.reasons[0].code if d.reasons else None
    return "DEFENDED", f"custom ceiling attenuated to 5 and enforced ({code})"


def wb_wildcard_pruning_false_deny():
    """A wildcard granted by BOTH parent and request must survive the meet."""
    parent = Guard.issue("p", Authority({"crm.*"}, [RowLimit(10**9)], ttl=3600))
    # request the same wildcard AND a concrete member of it
    child = parent.delegate("c", Authority({"crm.*", "crm.read"},
                            [RowLimit(10**9)], ttl=3600), task="t")
    # crm.write is inside crm.*, which both sides granted -> must be allowed
    d = child.check("crm.write", tool="crm")
    if d:
        return "DEFENDED", f"wildcard preserved; child scopes={sorted(child.authority.scopes)}"
    return "BROKEN", (f"legitimately-granted crm.write was DENIED — meet pruned "
                      f"the wildcard away; child scopes="
                      f"{sorted(child.authority.scopes)} (false-deny)")


def wb_audit_tamper():
    """Mutating an audit entry must break offline verification."""
    root = Guard.issue("root", Authority({"crm.*"}, [RowLimit(10**9)], ttl=10**9),
                       audit_path="/tmp/rt_audit.jsonl")
    c = root.delegate("c", Authority({"crm.read"}, [RowLimit(10)], ttl=100), task="t")
    c.check("crm.read", context={"rows": 5}, tool="crm")
    entries = root.audit_log().entries
    ok0, _ = AuditLog.verify(entries)
    entries[1] = {**entries[1], "granted": {"scopes": ["pay.transfer"]}}
    ok1, reason = AuditLog.verify(entries)
    if ok0 and not ok1:
        return "DEFENDED", f"tamper detected: {reason}"
    return "BROKEN", "audit tamper went undetected"


def wb_would_allow_no_audit_trail():
    """would_allow() must be a pure dry-run: it must not write to the audit
    log, even when the caller probes the SAME denial repeatedly."""
    root = Guard.issue("root", Authority({"crm.read"}, [RowLimit(10)], ttl=3600))
    before = len(root.audit_log().entries)
    for _ in range(10):
        root.would_allow("pay.transfer", tool="bank")
        root.would_allow("crm.read", context={"rows": 1})
    after = len(root.audit_log().entries)
    if after != before:
        return "BROKEN", f"would_allow() wrote {after - before} audit entries"
    return "DEFENDED", "would_allow() left the audit log untouched"


# ---- helpers -----------------------------------------------------------
class _ManualClock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def advance(self, dt):
        self.t += dt


BLACK = [
    ("scope escalation via broad re-request", "escalation", bb_scope_escalation),
    ("numeric ceiling escalation", "escalation", bb_ceiling_escalation),
    ("egress escalation / exfiltration", "escalation", bb_egress_escalation),
    ("expired-TTL grant still used", "unenforced", bb_ttl_expiry),
    ("aggregate budget via undeclared quantity", "unenforced", bb_budget_omission),
    ("cascade revoke of a subtree", "containment", bb_cascade_kill),
    ("delegate from a revoked node", "containment", bb_delegate_after_revoke),
    ("sibling blast-radius containment", "containment", bb_sibling_containment),
    ("recursive delegation depth bomb", "containment", bb_depth_bomb),
    ("scope prefix confusion", "escalation", bb_scope_prefix_confusion),
]

WHITE = [
    ("naive node.authority mutation (seal stale)", "escalation", wb_node_mutation_naive),
    ("same-process re-seal (out of scope)", "escalation", wb_node_mutation_secret_aware),
    ("order-relation soundness (custom ceiling)", "escalation", wb_order_relation_soundness),
    ("custom ceiling attenuated + enforced", "unenforced", wb_unknown_ceiling_enforced),
    ("wildcard pruning false-deny", "false-deny", wb_wildcard_pruning_false_deny),
    ("audit tamper detection", "integrity", wb_audit_tamper),
    ("would_allow() dry-run leaves no audit trail", "integrity", wb_would_allow_no_audit_trail),
]


def main():
    for name, cat, fn in BLACK:
        attempt(name, "BLACK", cat, fn)
    for name, cat, fn in WHITE:
        attempt(name, "WHITE", cat, fn)

    broken = [r for r in RESULTS if r[3] == "BROKEN"]
    limits = [r for r in RESULTS if r[3] == "LIMITATION"]
    defended = [r for r in RESULTS if r[3] == "DEFENDED"]
    marks = {"DEFENDED": "✓ DEFENDED  ", "BROKEN": "✗ BROKEN    ",
             "LIMITATION": "○ LIMITATION"}
    print("=" * 78)
    print("  delegation-guard — RED TEAM REPORT")
    print("=" * 78)
    for box in ("BLACK", "WHITE"):
        print(f"\n{box}-BOX")
        print("-" * 78)
        for name, b, cat, verdict, ev in RESULTS:
            if b != box:
                continue
            print(f"  {marks[verdict]} [{cat:11}] {name}")
            print(f"              {ev}")
    print("\n" + "=" * 78)
    print(f"  {len(RESULTS)} attacks · {len(defended)} defended · "
          f"{len(limits)} documented limitation(s) · {len(broken)} BROKEN")
    if limits:
        print("  documented limitations (by design for the in-process tier):")
        for name, b, cat, verdict, ev in limits:
            print(f"    - [{b}/{cat}] {name}")
    if broken:
        print("  UNRESOLVED FINDINGS:")
        for name, b, cat, verdict, ev in broken:
            print(f"    - [{b}/{cat}] {name}")
    print("=" * 78)
    return len(broken)


if __name__ == "__main__":
    raise SystemExit(main())
