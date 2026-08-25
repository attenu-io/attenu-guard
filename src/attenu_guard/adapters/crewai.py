"""dg_crewai — enforce attenu-guard authority attenuation inside CrewAI.

Hook points used (CrewAI 1.15.16, paths relative to site-packages/)
------------------------------------------------------------------
1. CHILD CREATION — `crewai/tools/agent_tools/delegate_work_tool.py` +
   `ask_question_tool.py`. CrewAI's delegation is *a tool call*: an agent with
   `allow_delegation=True` gets the `Delegate work to coworker` /
   `Ask question to coworker` tools injected (`crewai/crew.py:1746`,
   `crewai/agent/core.py:1221`). We intercept that call in the global
   `before_tool_call` hook, and mint the coworker's Guard there with
   `parent_guard.delegate(...)` — before `BaseAgentTool._execute` runs the
   coworker's task (`crewai/tools/agent_tools/base_agent_tools.py:110-120`).

2. TOOL INVOCATION — `crewai.hooks.register_before_tool_call_hook`
   (`crewai/hooks/tool_hooks.py:208`). CrewAI dispatches this at
   `InterceptionPoint.PRE_TOOL_CALL` on every tool path:
   `crewai/utilities/tool_utils.py:123` (ReAct), `:286` (async ReAct),
   `crewai/agents/crew_agent_executor.py:962` (native function calling) and
   `crewai/utilities/agent_utils.py:1693` — always *before* the tool body.
   We run `guard.check(scope, context=..., tool=...)` there.

Blocking semantics — why we do NOT raise `AuthorityDenied`
----------------------------------------------------------
`crewai/hooks/dispatch.py:264` is explicit: "Raises HookAborted ... to abort;
**any other exception is swallowed (fail-open)**". Letting `AuthorityDenied`
escape a hook would therefore be *silently ignored and the tool would run*.
So this bridge converts every denial — and every internal error of its own —
into `crewai.hooks.HookAborted`, which CrewAI honours. CrewAI then substitutes
its own generic "Tool execution blocked by hook." string; a paired
`after_tool_call` hook replaces that with the machine-readable attenu-guard
reason (CrewAI runs POST_TOOL_CALL even on a blocked call — `tool_utils.py:126`),
so the model is told *why* it was denied and can adapt instead of retrying.

Usage
-----
Give the bridge the orchestrator's root Guard, a `ToolPolicy` per tool (which
scope it needs and how to read the request context out of the tool arguments),
and the `Authority` you are willing to hand each coworker. Then install it —
globally, for the process — and run your crew as usual::

    root = Guard.issue("orchestrator", Authority(
        scopes={"crm.*", "mail.send"},
        ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600))

    bridge = CrewAIGuardBridge(
        root_guard=root,
        root_role="orchestrator",
        tool_policies={
            "crm_query":  ToolPolicy("crm.read",   lambda a: {"rows": a["rows"]}),
            "crm_export": ToolPolicy("crm.export", lambda a: {"egress": "any"}),
        },
        delegation_authorities={
            "summarizer": Authority(scopes={"crm.read"},
                                    ceilings=[RowLimit(5_000), EgressRank("none")],
                                    ttl=900),
        },
    )
    with bridge:                       # or bridge.install() / bridge.uninstall()
        crew.kickoff()

Everything is fail-closed: an agent with no Guard, a tool with no policy, a
coworker with no configured `Authority`, and any internal error in the bridge
all deny. attenu-guard never invents authority for you — you write the
`Authority` for each delegation, exactly as the library intends.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from crewai.hooks import (
    HookAborted,
    register_after_tool_call_hook,
    register_before_tool_call_hook,
    unregister_after_tool_call_hook,
    unregister_before_tool_call_hook,
)

from attenu_guard import (
    Authority,
    AuthorityError,
    Decision,
    Guard,
    ReasonCode,
)
from attenu_guard.reasons import Disposition

__all__ = ["ToolPolicy", "Denial", "CrewAIGuardBridge", "DELEGATION_TOOLS"]


# CrewAI sanitizes every tool name before it reaches a hook
# (`crewai/utilities/string_utils.py:26`), so "Delegate work to coworker"
# arrives as "delegate_work_to_coworker".
try:  # pragma: no cover - trivial import shim
    from crewai.utilities.string_utils import sanitize_tool_name as _sanitize_tool_name
except ImportError:  # pragma: no cover
    def _sanitize_tool_name(name: str) -> str:
        return "_".join(str(name).lower().split())


DELEGATION_TOOLS = frozenset(
    {
        _sanitize_tool_name("Delegate work to coworker"),
        _sanitize_tool_name("Ask question to coworker"),
    }
)


def _normalize_role(name: Any) -> str:
    """Mirror CrewAI's own coworker matching.

    `BaseAgentTool.sanitize_agent_name` (base_agent_tools.py:20-35) collapses
    whitespace, strips quotes and casefolds; `_get_coworker` (:37-44) also
    unwraps a `[...]` list the LLM may emit. We match on the same normal form
    so `coworker: "Summarizer"` finds the Guard registered for role
    `"summarizer"`.
    """
    if name is None:
        return ""
    text = " ".join(str(name).split())
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].split(",")[0]
    return text.replace('"', "").replace("'", "").strip().casefold()


@dataclass(frozen=True)
class ToolPolicy:
    """Maps one CrewAI tool onto the authority it consumes.

    scope:      the attenu-guard scope the tool needs, e.g. "crm.read".
    context_fn: reads the request context out of the tool's arguments, e.g.
                ``lambda args: {"rows": args["rows"]}``. Whatever it returns is
                handed to `Guard.check(context=...)` and evaluated against the
                ceilings. Omit it for a scope-only check.
    disposition: optional `Disposition` the authority source knows about this
                tool (`held_pending_grant` · `withheld_tier2` · `unresolved`);
                recorded on a `deny` so "held" never reads as "denied". Omit
                for a grantable tool (a deny is then `out_of_authority`).
    """

    scope: str
    context_fn: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None
    disposition: Optional[str] = None


@dataclass(frozen=True)
class Denial:
    """A recorded refusal — for tests, dashboards and incident review."""

    role: str
    tool_name: str
    tool_input: Mapping[str, Any]
    reason_text: str
    decision: Optional[Decision] = None


@dataclass
class _Pending:
    denial: Optional[Denial] = None


class CrewAIGuardBridge:
    """Installs attenu-guard as CrewAI's tool-authorization layer.

    Args:
        root_guard: the orchestrator's Guard (from `Guard.issue(...)`).
        root_role: the `Agent.role` that holds `root_guard`.
        tool_policies: `{tool name: ToolPolicy}`. Names are matched after
            CrewAI's own sanitization, so "CRM Query" and "crm_query" both work.
        delegation_authorities: `{coworker role: Authority}` — the authority
            this bridge is willing to *request* on that coworker's behalf. The
            Guard grants `meet(parent, request)`, so it can only ever shrink.
        revoke_on_deny: if True, the first denial revokes the offending agent's
            whole subtree (`guard.revoke()`), so a compromised sub-agent is cut
            off for the rest of the run rather than left to keep probing.
        deny_message_fn: renders the message handed back to the model on a
            denial. Defaults to a machine-readable one-liner.
        default_policy / default_delegation_authority: OBSERVE-MODE hooks for
            sampling (attenu-derive) — called with the (sanitized) tool name /
            (normalized) coworker role when no ToolPolicy / Authority was
            declared, and their result is used as if it had been declared, so
            every call is authorized-and-RECORDED on the audit log with the
            generated scope/context instead of denied. Deny stays the default
            without the hooks.
    """

    def __init__(
        self,
        *,
        root_guard: Guard,
        root_role: str,
        tool_policies: Mapping[str, ToolPolicy],
        delegation_authorities: Mapping[str, Authority],
        revoke_on_deny: bool = False,
        deny_message_fn: Optional[Callable[[Denial], str]] = None,
        delegation_tools: frozenset = DELEGATION_TOOLS,
        default_policy: Optional[Callable[[str], ToolPolicy]] = None,
        default_delegation_authority: Optional[Callable[[str], Authority]] = None,
    ) -> None:
        self._root_role = _normalize_role(root_role)
        self._guards: dict[str, Guard] = {self._root_role: root_guard}
        self._policies = {
            _sanitize_tool_name(name): policy for name, policy in tool_policies.items()
        }
        self._delegation_authorities = {
            _normalize_role(role): authority
            for role, authority in delegation_authorities.items()
        }
        self._delegation_tools = frozenset(
            _sanitize_tool_name(name) for name in delegation_tools
        )
        self._revoke_on_deny = revoke_on_deny
        self._deny_message_fn = deny_message_fn or _default_deny_message
        self._default_policy = default_policy
        self._default_delegation_authority = default_delegation_authority
        self._denials: list[Denial] = []
        self._lock = threading.Lock()
        self._local = threading.local()
        self._installed = False

    # ---- lifecycle -------------------------------------------------------

    def install(self) -> "CrewAIGuardBridge":
        """Register the global before/after tool-call hooks. Idempotent."""
        if not self._installed:
            register_before_tool_call_hook(self._before_tool_call)
            register_after_tool_call_hook(self._after_tool_call)
            self._installed = True
        return self

    def uninstall(self) -> None:
        """Remove the hooks. Idempotent."""
        if self._installed:
            unregister_before_tool_call_hook(self._before_tool_call)
            unregister_after_tool_call_hook(self._after_tool_call)
            self._installed = False

    def __enter__(self) -> "CrewAIGuardBridge":
        return self.install()

    def __exit__(self, *exc_info: Any) -> None:
        self.uninstall()

    # ---- introspection ---------------------------------------------------

    def guard_for(self, role: str) -> Optional[Guard]:
        """The Guard currently held by `role`, or None if it holds none."""
        with self._lock:
            return self._guards.get(_normalize_role(role))

    @property
    def denials(self) -> list[Denial]:
        with self._lock:
            return list(self._denials)

    # ---- hook point 2: every tool invocation -----------------------------

    def _before_tool_call(self, ctx: Any) -> None:
        """PRE_TOOL_CALL. Returns None to allow; raises HookAborted to block.

        The outer try/except is load-bearing, not defensive noise: CrewAI's
        dispatcher swallows any non-HookAborted exception and lets the tool run
        (`crewai/hooks/dispatch.py:264`), so a bug in this bridge — or in a
        user-supplied `context_fn` — would otherwise fail OPEN.
        """
        self._pending().denial = None
        try:
            self._authorize(ctx)
        except HookAborted:
            raise
        except BaseException as exc:  # noqa: BLE001 - deliberate catch-all
            self._deny(
                role=_normalize_role(getattr(getattr(ctx, "agent", None), "role", "")),
                tool_name=_sanitize_tool_name(getattr(ctx, "tool_name", "") or ""),
                tool_input=getattr(ctx, "tool_input", None) or {},
                reason_text=f"bridge internal error, failing closed: {exc!r}",
            )

    def _authorize(self, ctx: Any) -> None:
        tool_name = _sanitize_tool_name(getattr(ctx, "tool_name", "") or "")
        role = _normalize_role(getattr(getattr(ctx, "agent", None), "role", ""))
        args: Mapping[str, Any] = getattr(ctx, "tool_input", None) or {}

        if tool_name in self._delegation_tools:
            self._authorize_delegation(role, tool_name, args)
            return

        guard = self.guard_for(role)
        if guard is None:
            self._deny(
                role,
                tool_name,
                args,
                f"no authority: agent {role!r} holds no delegated Guard",
            )

        policy = self._policies.get(tool_name)
        if policy is None and self._default_policy is not None:
            policy = self._default_policy(tool_name)
        if policy is None:
            # No authority is known for this tool: put the refusal on the
            # ledger (record_denial) as `unresolved`, not only in `denials` —
            # an operator's Decisions queue is a fold over the ledger.
            decision = guard.record_denial(
                ReasonCode.NO_AUTHORITY,
                f"no tool policy declared for {tool_name!r}",
                tool=tool_name,
                disposition=Disposition.UNRESOLVED,
            )
            self._deny(
                role,
                tool_name,
                args,
                f"no tool policy declared for {tool_name!r}",
                decision=decision,
            )

        context = dict(policy.context_fn(args)) if policy.context_fn else {}
        decision = guard.check(policy.scope, context=context, tool=tool_name,
                               disposition=policy.disposition)
        if not decision:
            self._deny(role, tool_name, args, decision.explain(), decision=decision)

    # ---- hook point 1: child creation ------------------------------------

    def _authorize_delegation(
        self, role: str, tool_name: str, args: Mapping[str, Any]
    ) -> None:
        """Mint the coworker's attenuated Guard at the delegation tool call."""
        parent = self.guard_for(role)
        if parent is None:
            self._deny(
                role,
                tool_name,
                args,
                f"no authority: agent {role!r} holds no Guard and cannot delegate",
            )

        coworker = _normalize_role(
            args.get("coworker") or args.get("co_worker") or args.get("agent") or ""
        )
        if not coworker:
            self._deny(role, tool_name, args, "delegation names no coworker")

        requested = self._delegation_authorities.get(coworker)
        if requested is None and self._default_delegation_authority is not None:
            requested = self._default_delegation_authority(coworker)
        if requested is None:
            self._deny(
                role,
                tool_name,
                args,
                f"no Authority configured for coworker {coworker!r}; "
                "refusing to delegate authority that was never written down",
            )

        task_text = str(args.get("task") or args.get("question") or "")
        try:
            child = parent.delegate(coworker, requested, task=task_text)
        except AuthorityError as exc:
            self._deny(
                role,
                tool_name,
                args,
                f"delegation refused by chain: {exc.reason}",
            )
        else:
            with self._lock:
                self._guards[coworker] = child

    # ---- denial plumbing -------------------------------------------------

    def _pending(self) -> _Pending:
        pending = getattr(self._local, "pending", None)
        if pending is None:
            pending = _Pending()
            self._local.pending = pending
        return pending

    def _deny(
        self,
        role: str,
        tool_name: str,
        tool_input: Mapping[str, Any],
        reason_text: str,
        decision: Optional[Decision] = None,
    ) -> None:
        """Record the refusal and abort the tool call. Never returns."""
        denial = Denial(
            role=role,
            tool_name=tool_name,
            tool_input=dict(tool_input),
            reason_text=reason_text,
            decision=decision,
        )
        with self._lock:
            self._denials.append(denial)
        self._pending().denial = denial

        # Don't re-revoke an already-revoked subtree: that would append a
        # second `kill` to the audit log on every subsequent probe.
        already_revoked = decision is not None and any(
            r.code == ReasonCode.REVOKED for r in decision.reasons
        )
        if self._revoke_on_deny and not already_revoked:
            guard = self.guard_for(role)
            if guard is not None:
                try:
                    guard.revoke()
                except Exception:  # noqa: BLE001 - revocation must never unblock
                    pass

        raise HookAborted(reason=self._deny_message_fn(denial), source=self)

    def _after_tool_call(self, ctx: Any) -> Optional[str]:
        """POST_TOOL_CALL. CrewAI runs this even for a blocked call, so it is
        where the generic "Tool execution blocked by hook." message gets
        replaced with the real attenu-guard reason."""
        pending = self._pending()
        denial = pending.denial
        pending.denial = None
        tool_name = _sanitize_tool_name(getattr(ctx, "tool_name", "") or "")
        if denial is None and tool_name in self._delegation_tools:
            args = getattr(ctx, "tool_input", None) or {}
            coworker = _normalize_role(args.get("coworker") or args.get("co_worker") or args.get("agent") or "")
            child = self.guard_for(coworker) if coworker else None
            if child is not None:
                child.complete()                  # the coworker returned: lifecycle end on the ledger (informational)
        if denial is None:
            return None
        if _sanitize_tool_name(getattr(ctx, "tool_name", "") or "") != denial.tool_name:
            return None
        return self._deny_message_fn(denial)


def _default_deny_message(denial: Denial) -> str:
    return (
        f"AuthorityDenied [{denial.tool_name}]: {denial.reason_text}. "
        "This action exceeds the authority delegated to you; do not retry it. "
        "Continue with what you are authorized to do, or report that you cannot."
    )
