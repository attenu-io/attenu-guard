"""adapters/_context.py — one rule for every adapter: a failing gate is a RECORDED refusal.

Every adapter lets the operator supply a callable that turns a tool call's arguments into the
context ceilings are evaluated against (`context_fn`, `ToolPolicy.context`, `context_for`, …).
It is operator code, so it can raise: a lookup against a store that is down, a key that is not in
the arguments this time, a type it did not expect.

When it did, the call was refused — correctly, the body never ran — and NOTHING was written. The
refusal existed in the caller's stack trace and nowhere else, so the audit trail showed the calls
that were allowed and was silent about the one that was stopped. That is the same defect as an
unrecorded passthrough (`Guard.record_passthrough`) and an unrecorded delegation refusal, found
the same way: by running the adapters against real agents (open-swe, OpenHands, AstrBot, cuga,
minion) and reading the ledgers instead of the transcripts.

`evaluate()` is the one place that decides what happens, so no adapter has to remember:

  * the context callable runs inside a try;
  * on success its result is returned and nothing is recorded — `guard.check()` does that next,
    exactly as before;
  * on failure a `deny` is written to the ledger with `ReasonCode.NO_AUTHORITY` and
    `Disposition.UNRESOLVED`, and `AuthorityDenied` is raised carrying that decision.

`NO_AUTHORITY` is the existing vocabulary, not a new token: its definition in `reasons.py` is an
adapter-level refusal upstream of scope and ceiling evaluation, and it already names unparseable
arguments. No context means no ceiling can be evaluated, so no authority can be determined for
this call. The closed reason vocabulary and every published vector are untouched.

Raising is deliberate. Before this, a raising context callable propagated its own exception out
of the adapter, so the call already aborted; `AuthorityDenied` keeps that shape, adds the ledger
row, and gives callers a typed error carrying the `Decision`. Adapters that return a denial to
the model instead of raising (`openhands`, `astrbot`) do that at their own gate and do not use
this helper — same ledger entry, each in its framework's idiom.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from attenu_guard import AuthorityDenied, Reason
from attenu_guard.reasons import Disposition, ReasonCode

__all__ = ["evaluate"]


def evaluate(guard: Any, compute: Optional[Callable[..., Mapping[str, Any]]], *args: Any,
             tool: Optional[str] = None, scope: Optional[str] = None,
             **kwargs: Any) -> Mapping[str, Any]:
    """Run the operator's context callable, or record the refusal and raise.

    `compute` is the callable (None means "no context declared", which is not a failure — an
    empty mapping is returned). `*args`/`**kwargs` are passed to it unchanged, because adapters
    call it with quite different shapes: a single arguments dict, a LangGraph state, `(args,
    caller)`, or the node function's own signature.

    Raises `AuthorityDenied` with the recorded `Decision` when the callable raises.
    """
    if compute is None:
        return {}
    if not callable(compute):
        # Several adapters accept EITHER a callable or a literal context mapping
        # (`agno.ContextSpec`, `semantic_kernel`, `llama_index`). A literal cannot fail, so it is
        # returned unchanged — this helper only guards the callable case.
        return compute
    try:
        return compute(*args, **kwargs) or {}
    except Exception as exc:
        name = tool or scope or "-"
        decision = guard.record_denial(
            Reason(ReasonCode.NO_AUTHORITY, constraint="context", requested=name,
                   message=f"context function for tool {name!r} raised "
                           f"{type(exc).__name__}: {exc}"),
            scope=scope, tool=tool, disposition=Disposition.UNRESOLVED)
        raise AuthorityDenied(decision) from exc
