"""
Guard — the runtime object a developer actually holds.

  issue(...)      -> a fresh root Guard, starting a new delegation chain.
  delegate(...)   -> a child Guard whose authority is the attenuated meet of
                      this guard's authority and what was requested. Never
                      widens — there is no method that can. Raises
                      AuthorityError on a STRUCTURAL failure (revoked/expired
                      parent, integrity failure, depth/fanout overflow).
  check(...)      -> authorize an action. Returns a `Decision` — it never
                      raises on a policy denial, because a denial is a
                      normal outcome to reason about, not a bug (see
                      docs/DEVX-REVIEW.md principle 3). Every allow/deny is
                      appended to the audit log.
  enforce(...)    -> check() and raise `AuthorityDenied(decision)` if not
                      allowed — the hard-stop gate for callers that want to
                      fail fast instead of branching on a Decision.
  would_allow(...) -> the same policy evaluation as check(), as a pure
                      dry-run: it writes NOTHING to the audit log, so a
                      planner can ask "could I do this?" without creating a
                      record as though the action were attempted.
  revoke(...)     -> cascade-revoke a node (default: this one) and its whole
                      subtree.

`AuthorityError` (raised by issue/delegate — bad input / invalid chain state)
and `AuthorityDenied` (raised only by enforce() — wraps a policy Decision)
are deliberately distinct: a policy denial is not an error.

v0.1's `root`/`spawn`/`kill` remain as thin deprecated aliases (process
metaphor -> authority vocabulary; docs/DEVX-REVIEW.md principle 4) and emit
`DeprecationWarning`.
"""
from __future__ import annotations

import threading
import warnings
from contextlib import contextmanager
from typing import Mapping

from .authority import Authority, AuthorityError
from .chain import Chain, Node, MonotonicClock
from .audit import AuditLog
from .reasons import Decision, Reason, ReasonCode
from .ceilings import ctx_field_of, is_metered

__all__ = ["Guard", "AuthorityDenied"]


class AuthorityDenied(Exception):
    """Raised only by `enforce()`. Carries the full `Decision` so a caller
    can branch on `.decision.reasons[i].code` instead of parsing a message
    string; `str(exc)` still gives a human-readable one-liner via
    `Decision.explain()`.
    """

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.explain())


class _SeqClock:
    """Monotonic integer for audit sequencing (distinct from the wall clock
    used for TTL expiry) — keeps the audit log's ordering deterministic in
    tests regardless of wall-clock resolution."""
    def __init__(self):
        self._t = 0
        self._lock = threading.Lock()

    def now(self) -> int:
        with self._lock:
            self._t += 1
            return self._t


class Guard:
    def __init__(self, node: Node, chain: Chain, audit: AuditLog, seq: _SeqClock,
                 strict_metering: bool, strikes=None):
        self._node = node
        self._chain = chain
        self._audit = audit
        self._seq = seq
        self._strict = strict_metering
        self._strikes = strikes            # StrikePolicy | None (shared across the chain's Guards)

    # ---- factory ---------------------------------------------------------
    @classmethod
    def issue(cls, agent_id: str, authority: Authority, task: str = "root",
              *, chain_id: str = "chain", max_depth: int = 6, max_fanout: int = 16,
              audit_path=None, clock=None, strict_metering: bool = False, strikes=None) -> "Guard":
        chain = Chain(chain_id, max_depth=max_depth, max_fanout=max_fanout,
                      clock=clock or MonotonicClock())
        audit = AuditLog(audit_path)
        seq = _SeqClock()
        node = chain.add_root(agent_id, authority, task)
        audit.append("root", seq.now(), chain_id=chain_id, node=node.node_id,
                     agent=agent_id, authority=authority.to_wire())
        return cls(node, chain, audit, seq, strict_metering, strikes)

    @classmethod
    def root(cls, *args, **kwargs) -> "Guard":
        """Deprecated alias for `issue` (v0.1 name). Will be removed after
        one minor version — see docs/DEVX-REVIEW.md principle 4."""
        warnings.warn("Guard.root is deprecated; use Guard.issue",
                      DeprecationWarning, stacklevel=2)
        return cls.issue(*args, **kwargs)

    # ---- identity ----------------------------------------------------
    @property
    def node_id(self) -> str:
        return self._node.node_id

    @property
    def chain_id(self) -> str:
        return self._chain.chain_id

    @property
    def authority(self) -> Authority:
        return self._node.authority

    @property
    def agent_id(self) -> str:
        """The `agent_id` this Guard was issued/delegated to. Adapters key
        their per-agent registries on it."""
        return self._node.agent_id

    @property
    def is_revoked(self) -> bool:
        """Read-only chain state: has this node (or an ancestor) been
        revoked? A cheap way for adapters/UIs to render "authority pulled"
        without fabricating a scope to `would_allow()`."""
        return self._chain.is_revoked(self._node.node_id)

    @property
    def is_expired(self) -> bool:
        """Read-only chain state: has this node's TTL elapsed?"""
        return self._chain.is_expired(self._node)

    @property
    def is_complete(self) -> bool:
        """Read-only lifecycle state: did the holder mark this node's work finished (`complete()`)?"""
        return bool(getattr(self._node, "complete", False))

    def complete(self) -> bool:
        """Mark this node's work FINISHED — one `done` audit event (idempotent: returns False if already
        marked). Purely a lifecycle marker for the ledger and for downstream analytics (a delegation that
        never reached `done` was cut short); it does NOT change authority — revocation is the hard stop.
        Adapters call it when the delegation returns to its parent."""
        if getattr(self._node, "complete", False):
            return False
        self._node.complete = True
        self._append("done", chain_id=self.chain_id, node=self._node.node_id, agent=self._node.agent_id)
        return True

    # ---- delegation ----------------------------------------------------
    def delegate(self, agent_id: str, request: Authority, task: str) -> "Guard":
        """Create a child Guard. The child's authority is
        `self.authority.meet(request)` — provably `is_narrower_than`
        `self.authority` by construction (see authority.py). Raises
        `AuthorityError` for structural failures (revoked/expired parent,
        integrity failure, depth/fanout overflow) — these are invalid calls,
        not policy outcomes, so they are not expressed as a Decision.

        NOTE on audit event names: the *Python* API is renamed per v0.2
        (issue/delegate/revoke replace root/spawn/kill — authority
        vocabulary, not process metaphor), but the audit log's `event`
        field keeps the v0.1 strings ("spawn"/"spawn_denied"/"kill"). That
        field is a separately-versioned, published wire contract
        (schema/agent-audit.schema.json, schema_version=1) consumed by
        `dg view`/`dg verify` in cli.py — neither is part of this rewrite's
        scope, so the log vocabulary they depend on is left untouched.
        """
        try:
            child = self._chain.add_child(self._node.node_id, agent_id, request, task)
        except AuthorityError as e:
            self._append("spawn_denied", chain_id=self.chain_id,
                               parent=self._node.node_id, agent=agent_id, task=task,
                               reason=e.reason, detail=e.detail)
            raise
        self._append("spawn", chain_id=self.chain_id,
                           parent=self._node.node_id, node=child.node_id,
                           agent=agent_id, task=task, requested=request.to_wire(),
                           granted=child.authority.to_wire())
        return Guard(child, self._chain, self._audit, self._seq, self._strict, self._strikes)

    def spawn(self, *args, **kwargs) -> "Guard":
        """Deprecated alias for `delegate` (v0.1 name)."""
        warnings.warn("Guard.spawn is deprecated; use Guard.delegate",
                      DeprecationWarning, stacklevel=2)
        return self.delegate(*args, **kwargs)

    def _append(self, event: str, **fields) -> dict:
        """Take the next audit sequence timestamp AND append under one lock,
        so parallel tool calls (thread pools) can never log out of order:
        `seq` and `ts` advance together."""
        with self._chain._lock:
            return self._audit.append(event, self._seq.now(), **fields)

    # ---- policy evaluation (shared by check/enforce/would_allow) --------
    def _merge_legacy(self, context: Mapping | None, *, rows=None, spend=None,
                       egress=None) -> dict:
        """Fold the deprecated rows=/spend=/egress= kwargs into the context
        bag, warning once per call site that uses them. An explicit legacy
        kwarg wins over the same key already present in `context` (the
        kwarg was the more specific thing the caller wrote)."""
        legacy = {}
        if rows is not None:
            legacy["rows"] = rows
        if spend is not None:
            legacy["spend"] = spend
        if egress is not None:
            legacy["egress"] = egress
        if legacy:
            warnings.warn(
                "check()/enforce()/would_allow()(rows=/spend=/egress=) is deprecated; "
                "pass context={...} instead",
                DeprecationWarning, stacklevel=3)
        merged = dict(context) if context else {}
        merged.update(legacy)
        return merged

    def _evaluate(self, scope: str, context: Mapping, metered: bool) -> Decision:
        """The actual policy evaluation, shared verbatim by check() and
        would_allow() (would_allow just skips the audit write the caller
        does afterwards). Order mirrors v0.1: node state (integrity,
        revocation, ttl) is checked before scope/ceilings, because a
        compromised or revoked node's scope grants are moot."""
        node, chain, auth = self._node, self._chain, self._node.authority
        nid = node.node_id

        if not chain.verify_integrity(node):
            return Decision.deny(
                Reason(ReasonCode.INTEGRITY, message="authority state failed its integrity seal"),
                node=nid)
        if chain.is_revoked(nid):
            return Decision.deny(
                Reason(ReasonCode.REVOKED, message="node has been revoked"), node=nid)
        if chain.is_expired(node):
            age = chain.clock.now() - node.issued_at
            return Decision.deny(
                Reason(ReasonCode.EXPIRED, limit=auth.ttl, requested=age,
                       message="authority ttl has elapsed"), node=nid)

        # Strict metering (opt-in, for adapters): a call flagged as consuming
        # a metered resource must DECLARE every metered dimension this node
        # holds a ceiling on; any it omits is refused rather than silently
        # treated as free — closes the "undeclared quantity" trust gap
        # documented in red_team.bb_budget_omission. Checked PER CEILING (not
        # "is the context empty?"): a partial context that mentions egress
        # but forgets rows would otherwise let RowLimit go unevaluated —
        # the exact slip an adapter's per-tool context lambda makes.
        if self._strict and metered:
            missing = [c.key for c in auth.ceilings
                       if is_metered(c) and ctx_field_of(c) not in context]
            if missing:
                held = [c.key for c in auth.ceilings if is_metered(c)]
                return Decision.deny(
                    Reason(ReasonCode.UNMETERED, constraint=",".join(missing),
                           message=f"metered=True but context omits {missing}; "
                                   f"metered ceilings held: {held}"),
                    node=nid)

        decision = auth.permits(scope, context)
        if decision.determining_node is None:
            decision = Decision(decision.allowed, decision.reasons, nid)
        return decision

    def _log_decision(self, decision: Decision, scope: str,
                       tool: str | None, context: Mapping) -> None:
        event = "allow" if decision else "deny"
        fields = dict(chain_id=self.chain_id, node=self._node.node_id, scope=scope,
                     tool=tool, context=dict(context))
        if not decision:
            # "reason": a single code string — matches the v0.1 shape that
            # schema/agent-audit.schema.json publishes and that cli.py's
            # `dg view` reads (`e.get("reason")`); kept for that untouched
            # consumer. "reasons": the full v0.2 structured list, for
            # anyone reading the log who wants every violated Reason, not
            # just the first.
            fields["reason"] = decision.reasons[0].code if decision.reasons else None
            fields["reasons"] = [r.to_dict() for r in decision.reasons]
        self._append(event, **fields)

    # ---- enforcement ---------------------------------------------------
    def _call_limits(self):
        return [c for c in self._node.authority.ceilings if str(c.key).startswith("max_calls")]

    def _auto_meter(self, scope: str, ctx: dict) -> list:
        """Fill in `calls` / `calls[<pattern>]` for every held CallLimit the caller left
        undeclared, reading the per-(node, pattern) meter. Returns the limits that were
        auto-filled AND apply to this scope (to be counted on allow)."""
        filled = []
        for c in self._call_limits():
            fld = getattr(c, "ctx_field", "calls")
            if fld in ctx:
                continue                                              # explicit count wins
            applies = getattr(c, "applies_to_scope", lambda s: True)(scope)
            ctx[fld] = self._chain.calls_so_far(self._node.node_id, getattr(c, "meter_key", "*")) + (1 if applies else 0)
            if applies:
                filled.append(c)
        return filled

    def check(self, scope: str, *, context: Mapping | None = None,
              metered: bool = False, tool: str | None = None,
              rows=None, spend=None, egress=None) -> Decision:
        """Authorize an action. Returns a `Decision` (does NOT raise on
        denial). Every call — allow or deny — is appended to the audit log.

        Auto-metering: when this node holds a `CallLimit` and the caller did
        not supply `calls`, the guard supplies the running count for
        (node, scope) itself — including this call — and increments it on
        allow. An explicit `calls` in the context always wins.
        """
        ctx = self._merge_legacy(context, rows=rows, spend=spend, egress=egress)
        filled = self._auto_meter(scope, ctx)
        decision = self._evaluate(scope, ctx, metered)
        if decision:
            for c in filled:
                self._chain.count_call(self._node.node_id, getattr(c, "meter_key", "*"))
        self._log_decision(decision, scope, tool, ctx)
        if not decision and self._strikes is not None and self._strikes.enabled and not self._chain.is_revoked(self._node.node_id):
            count = self._chain.record_strike(self._strikes.key(self._node.node_id, scope))
            if count >= self._strikes.n:
                revoked = self._chain.revoke(self._node.node_id)
                self._append("kill", chain_id=self.chain_id, target=self._node.node_id,
                             reason="strike_policy", scope=scope, strikes=count, mode=self._strikes.mode, revoked=revoked)
        return decision

    def enforce(self, scope: str, **kwargs) -> None:
        """`check()` and raise `AuthorityDenied(decision)` if not allowed.
        The hard-stop gate: use this where a denial should abort the caller
        rather than be branched on."""
        decision = self.check(scope, **kwargs)
        if not decision:
            raise AuthorityDenied(decision)

    def would_allow(self, scope: str, *, context: Mapping | None = None,
                    metered: bool = False, tool: str | None = None,
                    rows=None, spend=None, egress=None) -> Decision:
        """Pure dry-run: identical policy evaluation to `check()`, but never
        raises and — critically — writes NOTHING to the audit log. For
        planners/UIs that want to ask "could I do this?" without leaving a
        record as though the action were actually attempted."""
        ctx = self._merge_legacy(context, rows=rows, spend=spend, egress=egress)
        self._auto_meter(scope, ctx)                                  # read the meters, never consume them
        return self._evaluate(scope, ctx, metered)

    def record_denial(self, reason, message: str = "", *, scope: str | None = None,
                      tool: str | None = None, context: Mapping | None = None) -> Decision:
        """Put an ADAPTER-LEVEL refusal on the audit trail as a `deny` event
        and return it as a Decision — for denials that happen UPSTREAM of
        policy evaluation (an agent the chain never delegated to, a tool
        with no declared policy, unparseable tool arguments). Nothing is
        evaluated: the caller has already decided; this only records it,
        with this Guard's node/chain, in the same tamper-evident log as
        `check()` denials, so `dg view` and offline verifiers see it.

        `reason` is a `Reason` or a `ReasonCode` string (typically
        `ReasonCode.NO_AUTHORITY`); `message` is used only when a code is
        given. `scope` defaults to `tool` (or "-") because the published
        audit schema requires a string scope on allow/deny events.
        """
        r = reason if isinstance(reason, Reason) else Reason(str(reason), message=message)
        decision = Decision.deny(r, node=self._node.node_id)
        self._log_decision(decision, scope if scope is not None else (tool or "-"),
                           tool, dict(context) if context else {})
        return decision

    @contextmanager
    def authorize(self, scope: str, **kwargs):
        """Convenience sugar (not part of the core issue/delegate/revoke/
        check/enforce/would_allow surface): raises before entering the
        `with` block if denied, via `enforce()`, so the block only ever runs
        when authorized."""
        self.enforce(scope, **kwargs)
        yield

    # ---- chain controls ------------------------------------------------
    def revoke(self, node_id: str | None = None) -> list:
        # Audit event stays "kill" (v0.1 wire vocabulary) — see the note in
        # delegate() about schema/agent-audit.schema.json and cli.py.
        target = node_id or self._node.node_id
        revoked = self._chain.revoke(target)
        self._append("kill", chain_id=self.chain_id,
                           target=target, revoked=revoked)
        return revoked

    def revoke_agent(self, agent_id: str) -> list:
        """Revoke an agent BY NAME, chain-wide: every node it holds is
        cascade-revoked and no node may `delegate()` to it again
        (`AuthorityError`, reason "agent_banned"). Use this — not
        `revoke(node_id)` — when the intent is "this principal is done",
        because frameworks re-hand-off to the same agent freely and a fresh
        `delegate()` would otherwise mint it clean authority. One audit event."""
        revoked = self._chain.revoke_agent(agent_id)
        self._append("kill", chain_id=self.chain_id,
                           target=self._node.node_id, agent=agent_id, revoked=revoked)
        return revoked

    def would_delegate(self, agent_id: str, request: Authority) -> Decision:
        """Pure dry-run of `delegate()`'s structural preconditions (revoked
        or expired parent, banned agent, depth/fanout ceilings): returns a
        Decision, creates no node, consumes no fanout, writes nothing to the
        audit log. `request` is accepted for symmetry with `delegate()`; the
        granted authority would be `self.authority.meet(request)`."""
        err = self._chain.delegation_error(self._node.node_id, agent_id)
        if err is None:
            return Decision.allow(node=self._node.node_id)
        return Decision.deny(Reason(err.reason, message=str(err)), node=self._node.node_id)

    def kill(self, *args, **kwargs) -> list:
        """Deprecated alias for `revoke` (v0.1 name)."""
        warnings.warn("Guard.kill is deprecated; use Guard.revoke",
                      DeprecationWarning, stacklevel=2)
        return self.revoke(*args, **kwargs)

    # ---- provable narrowing ---------------------------------------------
    def is_narrower_than(self, parent: "Guard") -> bool:
        """Convenience over authorities: is this guard's authority provably
        `is_narrower_than` `parent`'s? Exactly the relation an offline
        verifier applies to two wire tokens (see authority.py)."""
        return self.authority.is_narrower_than(parent.authority)

    # ---- introspection ---------------------------------------------------
    def audit_log(self) -> AuditLog:
        return self._audit

    def graph(self) -> dict:
        return self._chain.graph()
