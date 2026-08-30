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
  record_outcome(...) -> (schema_version=2 chains only) bind what happened
                      after an `allow`ed call to that call's `call_id` — see
                      "Execution binding" below.

`AuthorityError` (raised by issue/delegate — bad input / invalid chain state)
and `AuthorityDenied` (raised only by enforce() — wraps a policy Decision)
are deliberately distinct: a policy denial is not an error.

v0.1's `root`/`spawn`/`kill` remain as thin deprecated aliases (process
metaphor -> authority vocabulary; docs/DEVX-REVIEW.md principle 4) and emit
`DeprecationWarning`.

Execution binding (0.9.0, `Guard.issue(..., schema_version=2)` only)
---------------------------------------------------------------------
`schema_version=1` chains (the default — nothing below applies to them) behave
EXACTLY as they did before 0.9.0: no `call_id`, no pending tracking, no
`node_finalized` refusal, `check()`'s new `authorized_params`/`capture`/
`adapter` kwargs are refused with `ValueError` if supplied. A caller opts in
per chain, once, at `Guard.issue()` — schema versions never mix within a
chain (docs/execution-binding spec section 9).

On a `schema_version=2` chain, `check()`'s locked transition (spec section 1)
is, in order, under one lock (`self._chain._lock`, re-entrant):

  1. refuse if the node is already `complete()`d (`ReasonCode.NODE_FINALIZED`);
  2. otherwise evaluate authority/ceilings and update meters (`_evaluate` +
     auto-metering, unchanged from v1);
  3. allocate `call_id` — 16 bytes from `os.urandom`, lowercase hex; if the
     CSPRNG raises, the call is denied and NOTHING is appended
     (`ReasonCode.CALL_ID_UNAVAILABLE`);
  4. commit the entry (append to the audit log — may raise
     `CommittedAuditError` if persistence fails AFTER the in-memory commit;
     this method attaches `.decision` to that exception before it propagates,
     per spec section 1: "carries the committed `entry` and the `decision`");
  5. register an allowed call as pending (even across a `CommittedAuditError`
     — spec: "the guard registers an allowed call as pending before raising");
  6. return the `Decision`, which now carries `.call_id`.

`record_outcome()` is the producer API a body-owning wrapper calls once it
knows how the call ended; `complete()` refuses (returns a falsy
`CompletionResult`) while calls are still pending; `revoke()`/`revoke_agent()`
snapshot the still-pending call_ids onto the `kill` entry as `pending_at_kill`
without clearing them — a late `record_outcome()` after a kill is accepted.
"""
from __future__ import annotations

import dataclasses
import os
import threading
import warnings
from contextlib import contextmanager
from typing import Mapping

from .authority import Authority, AuthorityError
from .chain import Chain, Node, MonotonicClock
from .audit import AuditLog, CommittedAuditError
from .reasons import (
    Decision, Reason, ReasonCode, Disposition, Capture, BodyState, CompletionResult,
)
from .ceilings import ctx_field_of, is_metered
from . import params as params_mod

__all__ = ["Guard", "AuthorityDenied", "DuplicateOutcomeError"]

# Sentinel distinguishing "the caller never attempted a params commitment at all" (nothing
# written — a deployment opted out of the whole feature) from "attempted, but the value was
# outside the params_c14n_v1 domain" (params_hash_reason: unsupported). See params.py and
# docs/execution-binding spec section 4/5 ("A deployment that must not disclose argument
# equality omits the hashes").
_UNSET = object()

_REQUIRED_ADAPTER_KEYS = ("module", "version", "hook_path")


class AuthorityDenied(Exception):
    """Raised only by `enforce()`. Carries the full `Decision` so a caller
    can branch on `.decision.reasons[i].code` instead of parsing a message
    string; `str(exc)` still gives a human-readable one-liner via
    `Decision.explain()`.
    """

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.explain())


class DuplicateOutcomeError(ValueError):
    """Raised by `Guard.record_outcome()` when `call_id` already has a recorded outcome in this
    chain's lifetime. A programming error in the caller (a wrapper observing the same call
    twice), not a policy outcome — "exactly one outcome per call_id, enforced at append under
    the lock" (docs/execution-binding spec section 3); the restart rule (audit.py) is what makes
    that enforceable within one continuous chain lifetime."""


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
              audit_path=None, clock=None, strict_metering: bool = False, strikes=None,
              audit_sinks=None, audit_overwrite: bool = False,
              schema_version: int = 1) -> "Guard":
        """`schema_version` (default 1, unchanged from every prior release): pass 2 to opt this
        WHOLE chain into execution binding (call_id, capture/adapter, params commitments,
        `record_outcome()` — see the module docstring). A chain never mixes schema versions
        (docs/execution-binding spec section 9); the version is stated once, here, on the `root`
        entry, and every Guard delegated from this one inherits it."""
        if schema_version not in (1, 2):
            raise ValueError(f"unsupported schema_version {schema_version!r}; expected 1 or 2")
        chain = Chain(chain_id, max_depth=max_depth, max_fanout=max_fanout,
                      clock=clock or MonotonicClock())
        audit = AuditLog(audit_path, sinks=tuple(audit_sinks or ()), overwrite=audit_overwrite,
                        schema_version=schema_version)
        seq = _SeqClock()
        node = chain.add_root(agent_id, authority, task)
        root_fields = dict(chain_id=chain_id, node=node.node_id, agent=agent_id,
                           authority=authority.to_wire())
        if schema_version == 2:
            chain.params_salt = os.urandom(16)
            root_fields["params_salt"] = chain.params_salt.hex()
        audit.append("root", seq.now(), **root_fields)
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

    def is_descendant_of(self, other: "Guard") -> bool:
        """True if `other` is an ancestor of this guard in the same chain (parent, grandparent, …)."""
        if other._chain is not self._chain:
            return False
        node = self._node
        while node.parent_id is not None:
            if node.parent_id == other._node.node_id:
                return True
            node = self._chain.nodes[node.parent_id]
        return False

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

    @property
    def _is_v2(self) -> bool:
        return self._audit.schema_version == 2

    def complete(self) -> "CompletionResult":
        """Mark this node's work FINISHED — one `done` audit event. Returns a `CompletionResult`
        (bool-coercible, so `if guard.complete():` still reads naturally). On a `schema_version=2`
        chain, refuses (returns a falsy `CompletionResult` carrying `.pending_call_ids`) while
        this node has `allow`ed calls that have not yet reported an outcome — completing while a
        call is still open would be a false claim that the node's work is finished. On a v1
        chain, or once no calls are pending, marks complete and returns
        `CompletionResult(True, ())`. Idempotent: `CompletionResult(False, ())` if already marked.
        Purely a lifecycle marker — it does NOT change authority; revocation is the hard stop."""
        if getattr(self._node, "complete", False):
            return CompletionResult(False, ())
        pending = self._chain.pending_for(self._node.node_id) if self._is_v2 else ()
        if pending:
            return CompletionResult(False, pending)
        self._node.complete = True
        self._append("done", chain_id=self.chain_id, node=self._node.node_id, agent=self._node.agent_id)
        return CompletionResult(True, ())

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
        `attenu-guard view`/`attenu-guard verify` in cli.py — neither is part of this rewrite's
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

    @staticmethod
    def _check_disposition(disposition: str | None) -> None:
        if disposition is not None and disposition not in Disposition.ALL:
            raise ValueError(f"unknown disposition {disposition!r}; expected one of {sorted(Disposition.ALL)}")

    def _log_decision(self, decision: Decision, scope: str,
                       tool: str | None, context: Mapping,
                       disposition: str | None = None, extra_fields: dict | None = None) -> dict:
        event = "allow" if decision else "deny"
        fields = dict(chain_id=self.chain_id, node=self._node.node_id, scope=scope,
                     tool=tool, context=dict(context))
        if not decision:
            # "reason": a single code string — matches the v0.1 shape that
            # schema/agent-audit.schema.json publishes and that cli.py's
            # `attenu-guard view` reads (`e.get("reason")`); kept for that untouched
            # consumer. "reasons": the full v0.2 structured list, for
            # anyone reading the log who wants every violated Reason, not
            # just the first.
            fields["reason"] = decision.reasons[0].code if decision.reasons else None
            fields["reasons"] = [r.to_dict() for r in decision.reasons]
            # "disposition": WHY the scope was absent — the caller's statement
            # (held pending grant / withheld tier-2 / unresolved) or, for a plain
            # scope_not_granted the caller did not explain, the shim's own truth:
            # out_of_authority. Allow entries never carry it.
            self._check_disposition(disposition)
            d = disposition or (Disposition.OUT_OF_AUTHORITY
                                if fields["reason"] == ReasonCode.SCOPE_NOT_GRANTED else None)
            if d is not None:
                fields["disposition"] = d
        if extra_fields:
            fields.update(extra_fields)
        return self._append(event, **fields)

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

    @staticmethod
    def _attach_call_id(decision: Decision, call_id: str | None) -> Decision:
        return decision if call_id is None else dataclasses.replace(decision, call_id=call_id)

    def _params_commitment(self, value) -> tuple[str | None, str | None]:
        """(hash_hex, reason) against this chain's params_salt — see params.py. `(None, None)`
        if the caller passed the `_UNSET` sentinel (opted out of this specific commitment)."""
        if value is _UNSET:
            return None, None
        salt = self._chain.params_salt
        if salt is None:      # cannot happen for a properly-issued v2 chain; defensive fallback only
            return None, params_mod.ParamsHashReason.UNSUPPORTED
        return params_mod.commit(value, salt)

    @staticmethod
    def _validate_capture_adapter(capture, adapter) -> None:
        if capture is not None and capture not in Capture.ALL:
            raise ValueError(f"unknown capture {capture!r}; expected one of {sorted(Capture.ALL)}")
        if capture is not None and adapter is None:
            raise ValueError("adapter={module,version,hook_path} is required alongside capture "
                             "(docs/execution-binding spec section 2)")
        if adapter is not None:
            missing = [k for k in _REQUIRED_ADAPTER_KEYS if k not in adapter]
            if missing:
                raise ValueError(f"adapter is missing {missing}; expected {list(_REQUIRED_ADAPTER_KEYS)}")

    def check(self, scope: str, *, context: Mapping | None = None,
              metered: bool = False, tool: str | None = None,
              rows=None, spend=None, egress=None,
              disposition: str | None = None,
              authorized_params=_UNSET, capture: str | None = None,
              adapter: Mapping | None = None) -> Decision:
        """Authorize an action. Returns a `Decision` (does NOT raise on
        denial). Every call — allow or deny — is appended to the audit log.

        Auto-metering: when this node holds a `CallLimit` and the caller did
        not supply `calls`, the guard supplies the running count for
        (node, scope) itself — including this call — and increments it on
        allow. An explicit `calls` in the context always wins.

        `disposition` (optional, a `Disposition` value): what the caller knows
        about WHY this scope would be absent from the node's authority —
        held pending an operator grant, withheld tier-2, unresolved tool. It
        is recorded on a `deny` entry only; on a plain `scope_not_granted`
        deny with no statement the ledger records `out_of_authority`.

        `authorized_params`/`capture`/`adapter` (schema_version=2 chains
        only — `ValueError` otherwise): the execution-binding inputs, see
        the module docstring and docs/execution-binding spec sections 1-4.
        `authorized_params` is the exact tool-call JSON object presented at
        authorization time (hashed, never logged); `capture` is one of the
        `Capture` constants describing what the caller's wrapper will be
        able to observe; `adapter` is `{module, version, hook_path}`,
        required together with `capture`. On a v2 chain, the returned
        `Decision.call_id` is what a later `record_outcome()` call binds to.
        """
        self._check_disposition(disposition)                      # refuse before anything reaches the ledger
        is_v2 = self._is_v2
        if not is_v2 and (authorized_params is not _UNSET or capture is not None or adapter is not None):
            raise ValueError("authorized_params/capture/adapter require a schema_version=2 chain "
                             "(Guard.issue(..., schema_version=2))")
        self._validate_capture_adapter(capture, adapter)

        ctx = self._merge_legacy(context, rows=rows, spend=spend, egress=egress)
        nid = self._node.node_id

        with self._chain._lock:
            # 1. refuse if the node is finalized (v2 only — a v1 chain's complete() has always
            #    been a pure informational marker that leaves authority, and check(), untouched;
            #    see complete()'s docstring and Guard.issue()'s module-docstring note on v1/v2).
            if is_v2 and getattr(self._node, "complete", False):
                decision = Decision.deny(
                    Reason(ReasonCode.NODE_FINALIZED, message="node already finalized (complete())"),
                    node=nid)
                filled = []
            else:
                # 2. evaluate authority/ceilings; update meters on allow.
                filled = self._auto_meter(scope, ctx)
                decision = self._evaluate(scope, ctx, metered)
                if decision:
                    for c in filled:
                        self._chain.count_call(nid, getattr(c, "meter_key", "*"))

            # 3. allocate call_id (v2 only) — fail-closed, nothing written, on a CSPRNG failure.
            call_id = None
            if is_v2:
                try:
                    call_id = os.urandom(16).hex()
                except Exception as exc:  # pragma: no cover - CSPRNG failure is not reproducible
                    # Pre-commit failure (spec section 1): meters are restored, nothing is
                    # pending, the call is denied, nothing is appended.
                    if decision:
                        for c in filled:
                            self._chain.uncount_call(nid, getattr(c, "meter_key", "*"))
                    return Decision.deny(
                        Reason(ReasonCode.CALL_ID_UNAVAILABLE, message=str(exc)), node=nid)

            extra = {}
            if is_v2:
                extra["call_id"] = call_id
                if decision:
                    if capture is not None:
                        extra["capture"] = capture
                        extra["adapter"] = {k: adapter[k] for k in _REQUIRED_ADAPTER_KEYS}
                    ph, preason = self._params_commitment(authorized_params)
                    if ph is not None:
                        extra["authorized_params_hash"] = ph
                    elif preason is not None:
                        extra["params_hash_reason"] = preason

            # 4. commit (append) — a post-commit persistence failure raises CommittedAuditError;
            #    attach `.decision` (spec: "carries the committed entry and the decision") before
            #    it propagates, and still register the pending call first (step 5).
            try:
                self._log_decision(decision, scope, tool, ctx, disposition, extra_fields=extra)
            except CommittedAuditError as exc:
                decision_with_id = self._attach_call_id(decision, call_id)
                if is_v2 and decision:
                    self._chain.register_pending(nid, call_id)
                exc.decision = decision_with_id
                raise

            decision = self._attach_call_id(decision, call_id)
            # 5. register pending (allows only).
            if is_v2 and decision:
                self._chain.register_pending(nid, call_id)
            # 6. return the Decision — falls through to strike-policy handling below, then returns.

        if not decision and self._strikes is not None and self._strikes.enabled and not self._chain.is_revoked(nid):
            count = self._chain.record_strike(self._strikes.key(nid, scope))
            if count >= self._strikes.n:
                revoked = self._chain.revoke(nid)
                kill_extra = self._pending_at_kill(revoked) if is_v2 else {}
                self._append("kill", chain_id=self.chain_id, target=nid,
                             reason="strike_policy", scope=scope, strikes=count,
                             mode=self._strikes.mode, revoked=revoked, **kill_extra)
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
        record as though the action were actually attempted. Never allocates
        a `call_id` (there is nothing to bind an outcome to)."""
        ctx = self._merge_legacy(context, rows=rows, spend=spend, egress=egress)
        self._auto_meter(scope, ctx)                                  # read the meters, never consume them
        return self._evaluate(scope, ctx, metered)

    def record_denial(self, reason, message: str = "", *, scope: str | None = None,
                      tool: str | None = None, context: Mapping | None = None,
                      disposition: str | None = None) -> Decision:
        """Put an ADAPTER-LEVEL refusal on the audit trail as a `deny` event
        and return it as a Decision — for denials that happen UPSTREAM of
        policy evaluation (an agent the chain never delegated to, a tool
        with no declared policy, unparseable tool arguments). Nothing is
        evaluated: the caller has already decided; this only records it,
        with this Guard's node/chain, in the same tamper-evident log as
        `check()` denials, so `attenu-guard view` and offline verifiers see it.

        `reason` is a `Reason` or a `ReasonCode` string (typically
        `ReasonCode.NO_AUTHORITY`); `message` is used only when a code is
        given. `scope` defaults to `tool` (or "-") because the published
        audit schema requires a string scope on allow/deny events.

        On a `schema_version=2` chain this also allocates and attaches a
        `call_id` (same fail-closed CSPRNG handling as `check()`) — every
        `allow`/`deny` entry carries one; a deny never expects an outcome."""
        self._check_disposition(disposition)
        r = reason if isinstance(reason, Reason) else Reason(str(reason), message=message)
        decision = Decision.deny(r, node=self._node.node_id)
        is_v2 = self._is_v2
        resolved_scope = scope if scope is not None else (tool or "-")
        resolved_ctx = dict(context) if context else {}

        with self._chain._lock:
            call_id = None
            if is_v2:
                try:
                    call_id = os.urandom(16).hex()
                except Exception as exc:  # pragma: no cover - CSPRNG failure is not reproducible
                    return Decision.deny(r, node=self._node.node_id)  # fail-closed: nothing written
            try:
                self._log_decision(decision, resolved_scope, tool, resolved_ctx, disposition,
                                   extra_fields={"call_id": call_id} if is_v2 else None)
            except CommittedAuditError as exc:
                exc.decision = self._attach_call_id(decision, call_id)
                raise
            return self._attach_call_id(decision, call_id)

    def record_outcome(self, call_id: str, body_state: str, *, error_code: str | None = None,
                       invoked_params=_UNSET, duration_ms: int, receipt: Mapping | None = None) -> dict:
        """The body-owning wrapper's report of how an `allow`ed call (identified by `call_id`,
        from that `check()` call's `Decision.call_id`) ended. `schema_version=2` chains only.

        `body_state`: one of the `BodyState` constants. `error_code` is required exactly when
        `body_state == BodyState.RAISED` (a normalized exception class name, never a message) and
        forbidden otherwise. `duration_ms` (observation start to observation end) is required.
        `invoked_params` is the corresponding JSON object the wrapper observed immediately before
        the actual invocation — hashed the same way as `check()`'s `authorized_params` (see
        params.py); pass the `_UNSET`-equivalent default (omit the kwarg) to opt out. `receipt`
        is unverified carriage, `{type, ref, digest}` (docs/execution-binding spec section 7).

        Exactly one outcome per `call_id` is enforced here (raises `DuplicateOutcomeError`); a
        second outcome for the same call_id is a caller bug, not a policy outcome. A call_id that
        was never pending anywhere in this chain (bound to a deny, or foreign) is still recorded
        — this is a best-effort runtime cleanup, not a gate; the offline verifier is what flags
        `outcome_without_allow`/`cross_ref` from the ledger alone.
        """
        if not self._is_v2:
            raise ValueError("record_outcome requires a schema_version=2 chain "
                             "(Guard.issue(..., schema_version=2))")
        if body_state not in BodyState.ALL:
            raise ValueError(f"unknown body_state {body_state!r}; expected one of {sorted(BodyState.ALL)}")
        if (error_code is not None) != (body_state == BodyState.RAISED):
            raise ValueError("error_code is required exactly when body_state == BodyState.RAISED")
        if not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or duration_ms < 0:
            raise ValueError(f"duration_ms must be a non-negative integer; got {duration_ms!r}")
        if receipt is not None:
            missing = [k for k in ("type", "ref", "digest") if k not in receipt]
            if missing:
                raise ValueError(f"receipt is missing {missing}; expected type/ref/digest")

        with self._chain._lock:
            if not self._chain.mark_outcomed(call_id):
                raise DuplicateOutcomeError(f"call_id {call_id!r} already has a recorded outcome")
            self._chain.resolve_pending(call_id)
            fields = dict(chain_id=self.chain_id, node=self._node.node_id, call_id=call_id,
                         body_state=body_state, duration_ms=duration_ms)
            if error_code is not None:
                fields["error_code"] = error_code
            ph, preason = self._params_commitment(invoked_params)
            if ph is not None:
                fields["invoked_params_hash"] = ph
            elif preason is not None:
                fields["params_hash_reason"] = preason
            if receipt is not None:
                fields["receipt"] = dict(receipt)
            return self._append("outcome", **fields)

    @contextmanager
    def authorize(self, scope: str, **kwargs):
        """Convenience sugar (not part of the core issue/delegate/revoke/
        check/enforce/would_allow surface): raises before entering the
        `with` block if denied, via `enforce()`, so the block only ever runs
        when authorized."""
        self.enforce(scope, **kwargs)
        yield

    # ---- chain controls ------------------------------------------------
    def _pending_at_kill(self, revoked_nodes: list) -> dict:
        """`{"pending_at_kill": [...]}` — the still-open call_ids across every node a kill
        revoked, snapshotted (NOT cleared: a late `record_outcome()` after this kill is still
        accepted — spec section 1). Only meaningful on v2 chains; called only when `_is_v2`."""
        pending: set = set()
        for nid in revoked_nodes:
            pending.update(self._chain.pending_for(nid))
        return {"pending_at_kill": sorted(pending)}

    def revoke(self, node_id: str | None = None) -> list:
        # Audit event stays "kill" (v0.1 wire vocabulary) — see the note in
        # delegate() about schema/agent-audit.schema.json and cli.py.
        target = node_id or self._node.node_id
        revoked = self._chain.revoke(target)
        extra = self._pending_at_kill(revoked) if self._is_v2 else {}
        self._append("kill", chain_id=self.chain_id,
                           target=target, revoked=revoked, **extra)
        return revoked

    def revoke_agent(self, agent_id: str) -> list:
        """Revoke an agent BY NAME, chain-wide: every node it holds is
        cascade-revoked and no node may `delegate()` to it again
        (`AuthorityError`, reason "agent_banned"). Use this — not
        `revoke(node_id)` — when the intent is "this principal is done",
        because frameworks re-hand-off to the same agent freely and a fresh
        `delegate()` would otherwise mint it clean authority. One audit event."""
        revoked = self._chain.revoke_agent(agent_id)
        extra = self._pending_at_kill(revoked) if self._is_v2 else {}
        self._append("kill", chain_id=self.chain_id,
                           target=self._node.node_id, agent=agent_id, revoked=revoked, **extra)
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
