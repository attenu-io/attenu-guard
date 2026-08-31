"""
attenu-guard x A2A (Agent2Agent protocol) — carrying the attenuated chain across a hop.

Ships as `attenu_guard.adapters.a2a` (`pip install 'attenu-guard[a2a]'`). Validated against
`a2a-sdk` 1.1.2 and the A2A specification of 2026-08 (`a2aproject/A2A`, `docs/specification.md`).

A2A is a protocol, not a framework: the calling agent and the remote agent are separate
processes, each with its own framework, its own tools and its own ledger. So the delegation
moment is the HOP itself — `message:send` — and this adapter is two halves that meet on the
wire:

  * the CLIENT mints the child `Guard` for the remote agent (`parent.delegate(...)`) and puts
    the resulting Delegation Chain (`attenu_guard.wire`) on the outgoing message;
  * the SERVER verifies that chain offline — signatures, parent-hash linkage, depth, and
    child-subset-of-parent at every hop — and mints its OWN `Guard` from the verified LEAF,
    attenuated again by what the remote agent's task needs. The remote agent therefore runs
    with permissions that are a subset of the caller's, and the caller never had to be trusted
    to say so: the tokens carry the proof.

WHY THIS IS THE PROTOCOL'S OWN INVITATION
-----------------------------------------
A2A §7.6.4 ("In-Task Authorization Scope") is explicit that this layer is not the protocol's
job:

    "The A2A protocol does not define the scope, representation, validity, or revocation
    semantics of the authorization decision or credential obtained in response to this state.
    ... If an implementation requires authorization for specific operations, it is responsible
    for defining how the authorized operation is identified and how that authorization is
    checked before the operation is performed."

That is what this adapter supplies, and it supplies it through A2A's own extension mechanism
(§4.6) rather than beside it — see EXTENSION below.

HOOK POINTS USED
----------------
1. Client — attach the chain to the outgoing message
   `a2a.client.interceptors.ClientCallInterceptor.before(BeforeArgs)`
   (`a2a/client/interceptors.py:46`), invoked for every call by
   `BaseClient._intercept_before` (`a2a/client/base_client.py:460`, reached from
   `_execute_with_interceptors` `:390` and `_execute_stream_with_interceptors` `:433`).
   `BeforeArgs.input` is the live `SendMessageRequest`, so `DelegationInterceptor` writes the
   chain onto `request.message` before the transport sees it. This is the same seam the SDK's
   own `AuthInterceptor` uses for bearer tokens (`a2a/client/auth/interceptor.py:23`).

2. Server — read the chain, gate the remote agent
   `a2a.server.agent_execution.AgentExecutor.execute(context, event_queue)`
   (`a2a/server/agent_execution/agent_executor.py:15`) — the one boundary every A2A binding
   funnels an inbound task through before the agent's own logic runs
   (`DefaultRequestHandlerV2.on_message_send`, `a2a/server/request_handlers/
   default_request_handler_v2.py:240`). `GuardedAgentExecutor` wraps the deployment's executor;
   the chain is read from `RequestContext.message.metadata` (the Message extension point,
   §4.6.2), with `RequestContext.metadata` (`a2a/server/agent_execution/context.py:150`, the
   request-level map) accepted as a fallback.

EXTENSION
---------
The chain travels as an A2A **extension** (§4.6), not as an ad-hoc field:

    message.extensions = ["https://attenu.io/a2a/delegation-chain/v1"]
    message.metadata["https://attenu.io/a2a/delegation-chain/v1"] = {"v": 1, "chain": [DT_0, …]}

and the client sets the `A2A-Extensions` request header (§4.6.1) through
`ClientCallContext.service_parameters`, exactly as `AuthInterceptor` sets `Authorization`. A
server that does not know the extension ignores it (§4.6.3) and is simply unguarded — which is
why an Attenu-guarded deployment declares the extension on its Agent Card with
`required=True` (`agent_extension()` below builds that entry) and why the guard, not the
declaration, is what enforces.

USAGE
-----
Client (the calling agent's process)::

    from attenu_guard.adapters.a2a import DelegationInterceptor, delegating_guard_for

    orchestrator = Guard.issue("orchestrator", ORCHESTRATOR_AUTHORITY, chain_id="orch")
    interceptor = DelegationInterceptor(
        guard_for=delegating_guard_for(
            orchestrator,
            authority_for=lambda card, task: REMOTE_AUTHORITY[card.name],
        ),
        signer=signer,
    )
    client = factory.create(card, interceptors=[interceptor])

Server (the remote agent's process)::

    from attenu_guard.adapters.a2a import GuardedAgentExecutor, guarded_tool, require_guard

    executor = GuardedAgentExecutor(
        SummarizerExecutor(),
        agent_id="summarizer",
        authority_for=lambda agent_id, task: Authority(scopes={"crm.read"}, ...),
        signer=verifier_key,
        root_key_ids={"issuer-1"},
    )
    handler = DefaultRequestHandler(agent_executor=executor, task_store=..., agent_card=card)

and inside the remote agent, before any tool body::

    crm_query = guarded_tool(crm_query, scope="crm.read",
                             context_for=lambda rows: {"rows": rows})

attenu-guard deliberately does NOT decide what permissions a task needs — you write
`authority_for`. Whatever it returns is only ever an *input* to `Authority.meet`, so the
remote agent can never come out wider than the token it was handed.

WHAT VERIFIES FROM WHERE (be precise about this)
------------------------------------------------
Two processes, two ledgers, one token chain between them:

  * the CLIENT's bundle proves the caller's own chain root -> the child it minted for the
    remote agent, and that the child is a subset of the caller;
  * the SERVER's bundle proves the remote agent's node is a subset of the authority the server
    was handed, and carries every allow/deny the remote agent's tools produced;
  * the TOKENS bind the two: the server's continuation root holds byte-identical
    `Authority.to_wire()` to the leaf token, and the server's `chain_id` is the leaf token's
    `jti` (the client's leaf node id) plus a fingerprint of that token's exact bytes — see
    `continuation_chain_id`.

`verify_hop(tokens, signer, client_bundle=…, server_bundle=…)` checks all three from those
inputs alone, with no service in the path. Neither bundle alone proves the hop; that is stated
here rather than papered over.

LIMITS
------
Cross-process revocation propagation is NOT solved here. `wire.load` does not check a Token
Status List (draft {{verify}} step 7 is out of scope for the wire format), so a token revoked
in the caller's process after it was minted still verifies until it expires. What IS enforced
server-side: an EXPIRED token is refused, and `revocation_check=` is the seam where a
deployment plugs its own status list or revocation feed. Keep TTLs short.

EXECUTION BINDING (0.9.0, on a `schema_version=2` chain -- see `Guard.issue`)
------------------------------------------------------------------------------
`guarded_tool()` calls the wrapped tool itself (`fn(*args, **kwargs)`/`await fn(*args,
**kwargs)`), exactly like `adapters.langgraph`'s reference wiring, so `Capture.WRAPPER_SYNC`/
`WRAPPER_ASYNC` is a genuine observation -- unlike the delegation/hop machinery above, which is
a cross-PROCESS protocol boundary this file has no visibility into a "body" for at all.
`authorized_params`/`invoked_params` are one immutable snapshot (`_freeze()`, never a copy
protocol -- see its own docstring) of `{"args": [...], "kwargs": {...}}`, taken BEFORE `fn` runs
and reused unchanged for both. `BodyState.RAISED` (with `error_code`) is genuinely observed on
both paths -- this wrapper calls `fn` directly, so an exception it raises propagates straight
through. `asyncio.CancelledError` on the async path is `BodyState.ABANDONED`, still re-raised.

Neither half of the protocol boundary itself is affected: the CLIENT's `DelegationInterceptor`
mints the remote agent's Guard via `parent.delegate(...)`, and the SERVER's
`GuardedAgentExecutor` mints its own served Guard via `leaf.meet(requested)` -- neither calls
`guard.check()` at all, so there is no `Decision`/`call_id` on either side of the hop to bind an
outcome to. On `schema_version=1` (the default), nothing in `guarded_tool()` changes at all --
`capture`/`adapter`/`authorized_params` are never passed to `check()`, and `record_outcome()` is
never called; it keeps calling `guard.enforce()`, byte-and-type identical to before this release.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import functools
import hashlib
import inspect
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from a2a.client.interceptors import ClientCallInterceptor
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.types.a2a_pb2 import AgentExtension, Message, Role, SendMessageRequest

from attenu_guard import Authority, AuthorityDenied, AuthorityError, Guard, evidence, wire, __version__
from attenu_guard.reasons import BodyState, Capture, Disposition

__all__ = [
    "EXTENSION_URI",
    "EXTENSION_HEADER",
    "A2ADelegationError",
    "agent_extension",
    "attach_delegation",
    "read_delegation",
    "DelegationInterceptor",
    "delegating_guard_for",
    "GuardedAgentExecutor",
    "current_guard",
    "require_guard",
    "guarded_tool",
    "verify_hop",
    "continuation_chain_id",
]

#: The A2A extension URI this adapter registers (spec §4.6.3: the version lives in the URI).
EXTENSION_URI = "https://attenu.io/a2a/delegation-chain/v1"

#: The request header clients use to opt in to an extension (spec §4.6.1). Mirrors
#: `a2a.extensions.common.HTTP_EXTENSION_HEADER`, restated here so importing this adapter does
#: not depend on that module's location.
EXTENSION_HEADER = "A2A-Extensions"

_PAYLOAD_VERSION = 1


class A2ADelegationError(Exception):
    """A hop that must not go out, or must not be served.

    Raised client-side when no `Guard` can be resolved for an outgoing call (fail closed: an
    unguarded hop is not sent), and available to server-side callers of `require_guard()`.
    """


# ---------------------------------------------------------------------------
# The extension, declared and carried
# ---------------------------------------------------------------------------

def agent_extension(*, required: bool = True, description: str | None = None) -> AgentExtension:
    """The `AgentExtension` entry for an Agent Card's `capabilities.extensions` (spec §4.6.1).

    `required=True` is the honest default for a guarded deployment: a client that does not
    send the chain gets `ExtensionSupportRequiredError` from the binding instead of silently
    reaching an agent whose permissions nobody bounded. It is a declaration, not enforcement —
    `GuardedAgentExecutor` denies a missing chain regardless of what the card says.
    """
    return AgentExtension(
        uri=EXTENSION_URI,
        description=description or (
            "Carries an attenu-guard Delegation Chain so the remote agent runs with "
            "permissions bounded by the caller's, verifiable offline."
        ),
        required=required,
    )


def _message_of(target: Any) -> Message:
    """The `Message` to write the extension onto: a `SendMessageRequest`'s message, or a bare
    `Message`. Anything else is a programming error and is refused rather than guessed at."""
    if isinstance(target, Message):
        return target
    message = getattr(target, "message", None)
    if isinstance(message, Message):
        return message
    raise TypeError(
        f"attach_delegation() expects a SendMessageRequest or a Message, got "
        f"{type(target).__name__}"
    )


def attach_delegation(target: Any, guard: Guard, signer, *, iat: int | None = None,
                      aud: Any = None, iss: str = "attenu-guard") -> list[str]:
    """Serialize `guard`'s chain (root -> `guard`) and put it on the outgoing message as the
    A2A extension. Returns the tokens.

    `iat` defaults to the wall clock, because a hop is a real event with a real expiry — unlike
    `wire.serialize_chain`, whose default of 0 keeps test vectors reproducible. Pass `iat=`
    explicitly to get that determinism back.
    """
    tokens = wire.serialize_chain(
        guard, signer, iss=iss, aud=aud,
        iat=int(time.time()) if iat is None else int(iat),
    )
    message = _message_of(target)
    if EXTENSION_URI not in list(message.extensions):
        message.extensions.append(EXTENSION_URI)
    message.metadata[EXTENSION_URI] = {"v": _PAYLOAD_VERSION, "chain": list(tokens)}
    return list(tokens)


def read_delegation(source: Any) -> list[str]:
    """The Delegation Chain carried by an inbound request, or `[]`.

    Accepts a `RequestContext`, a `Message`, or an already-decoded metadata mapping. Reads the
    Message extension point first (spec §4.6.2), then the request-level metadata map, so a
    deployment that puts the chain at either place is served. Anything malformed reads as `[]`
    — the caller then denies, which is the same fail-closed outcome as "absent".
    """
    for meta in _candidate_metadata(source):
        payload = meta.get(EXTENSION_URI)
        if not isinstance(payload, Mapping):
            continue
        chain = payload.get("chain")
        if isinstance(chain, (list, tuple)) and all(isinstance(t, str) for t in chain) and chain:
            return list(chain)
    return []


def _candidate_metadata(source: Any) -> list[dict]:
    """Every metadata map an inbound request might carry the extension on, most specific
    first. Protobuf `Struct` values are converted to plain Python."""
    out: list[dict] = []
    if isinstance(source, Mapping):
        return [dict(source)]

    message = getattr(source, "message", None)
    if message is not None:
        out.append(_struct_to_dict(getattr(message, "metadata", None)))
    if isinstance(source, Message):
        out.append(_struct_to_dict(source.metadata))

    # `RequestContext.metadata` is already a plain dict (context.py:150); a raw
    # SendMessageRequest's is a Struct.
    request_meta = getattr(source, "metadata", None)
    if isinstance(request_meta, Mapping):
        out.append(dict(request_meta))
    elif request_meta is not None:
        out.append(_struct_to_dict(request_meta))
    return [m for m in out if m]


def _struct_to_dict(struct: Any) -> dict:
    if struct is None:
        return {}
    try:
        from google.protobuf import json_format

        return json_format.MessageToDict(struct)
    except Exception:      # noqa: BLE001 - a metadata map we cannot read is an absent chain
        return {}


# ---------------------------------------------------------------------------
# Client side
# ---------------------------------------------------------------------------

# (agent_card, request) -> the Guard whose chain this hop should carry, or None to refuse.
GuardResolver = Callable[[Any, Any], "Guard | None"]


def delegating_guard_for(parent: Guard,
                         authority_for: "Callable[[Any, str], Authority | None]",
                         *, task_for: "Callable[[Any, Any], str] | None" = None,
                         agent_id_for: "Callable[[Any], str] | None" = None) -> GuardResolver:
    """A `guard_for` resolver that mints the child at the hop.

    The first call to a given remote agent runs `parent.delegate(agent_id, requested, task)`;
    later calls to the same agent reuse that child, so a conversation with one remote agent is
    one node in the chain rather than a new node per message. `authority_for` returning None
    refuses the hop.
    """
    minted: dict[str, Guard] = {}

    def resolve(card: Any, request: Any) -> "Guard | None":
        agent_id = agent_id_for(card) if agent_id_for else str(getattr(card, "name", "") or "remote-agent")
        existing = minted.get(agent_id)
        if existing is not None and not existing.is_revoked and not existing.is_expired:
            return existing
        task = task_for(card, request) if task_for else _task_text(request)
        requested = authority_for(card, task)
        if requested is None:
            return None
        try:
            child = parent.delegate(agent_id, requested, task=task)
        except AuthorityError:
            return None                    # structural refusal: no chain goes out
        minted[agent_id] = child
        return child

    return resolve


def _task_text(request: Any) -> str:
    """The outgoing message's text, as the task string recorded on the delegation."""
    message = getattr(request, "message", None)
    if message is None:
        return ""
    try:
        from a2a.helpers.proto_helpers import get_message_text

        return get_message_text(message)
    except Exception:      # noqa: BLE001
        return ""


class DelegationInterceptor(ClientCallInterceptor):
    """Attaches the Delegation Chain to every outgoing `message:send`.

    Registered like any other A2A interceptor — `Client(interceptors=[...])` or
    `ClientFactory.create(card, interceptors=[...])` — so nothing about the calling agent's
    own framework changes.

    Fail-closed: if `guard_for` returns None for a call this interceptor covers, the call is
    NOT sent (`A2ADelegationError` propagates out of `before`, and `BaseClient` has already
    stopped at `_intercept_before`). `required=False` opts a deployment out, for a migration
    where some remote agents are not guarded yet.
    """

    #: The client methods that carry a delegation. `get_task`/`cancel_task` and the push-config
    #: calls act on a task the server already bound to a chain, so they carry nothing.
    DELEGATING_METHODS = ("send_message", "send_message_streaming")

    def __init__(self, guard_for: GuardResolver, signer, *,
                 iat: "int | None" = None, aud: Any = None, iss: str = "attenu-guard",
                 methods: Sequence[str] = DELEGATING_METHODS,
                 required: bool = True,
                 set_header: bool = True) -> None:
        self._guard_for = guard_for
        self._signer = signer
        self._iat = iat
        self._aud = aud
        self._iss = iss
        self._methods = tuple(methods)
        self._required = required
        self._set_header = set_header
        #: Every chain this interceptor put on the wire, newest last — the client-side record.
        self.sent: list[tuple[str, list[str]]] = []

    async def before(self, args) -> None:                       # BeforeArgs
        if args.method not in self._methods:
            return
        if not isinstance(args.input, SendMessageRequest):
            return

        guard = self._guard_for(args.agent_card, args.input)
        if guard is None:
            if self._required:
                raise A2ADelegationError(
                    f"attenu-guard: refusing to send {args.method!r} to "
                    f"{getattr(args.agent_card, 'name', '?')!r} — no delegated permissions "
                    f"resolved for this hop (guard_for returned None)"
                )
            return

        tokens = attach_delegation(args.input, guard, self._signer,
                                   iat=self._iat, aud=self._aud, iss=self._iss)
        self.sent.append((guard.agent_id, tokens))
        if self._set_header:
            self._opt_in(args)

    async def after(self, args) -> None:                        # AfterArgs
        """Nothing to do on the way back: the response carries no permissions."""

    def _opt_in(self, args) -> None:
        """Add the extension URI to the `A2A-Extensions` request header (spec §4.6.1), the way
        `AuthInterceptor` adds `Authorization` (`a2a/client/auth/interceptor.py:56`)."""
        from a2a.client.client import ClientCallContext

        if args.context is None:
            args.context = ClientCallContext()
        if args.context.service_parameters is None:
            args.context.service_parameters = {}
        current = args.context.service_parameters.get(EXTENSION_HEADER)
        uris = [u.strip() for u in str(current).split(",") if u.strip()] if current else []
        if EXTENSION_URI not in uris:
            uris.append(EXTENSION_URI)
        args.context.service_parameters[EXTENSION_HEADER] = ",".join(uris)


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

_CURRENT_GUARD: contextvars.ContextVar["Guard | None"] = contextvars.ContextVar(
    "attenu_guard_a2a_current", default=None,
)


def current_guard() -> "Guard | None":
    """The `Guard` for the A2A request being served on this task, or None outside one."""
    return _CURRENT_GUARD.get()


def require_guard() -> Guard:
    """`current_guard()`, or raise. Use this in a tool body that must never run unguarded — a
    tool reached by some path that did not pass through `GuardedAgentExecutor` raises here
    instead of running."""
    guard = _CURRENT_GUARD.get()
    if guard is None:
        raise A2ADelegationError(
            "attenu-guard: no delegated permissions bound to this request — the tool was "
            "reached outside GuardedAgentExecutor.execute()"
        )
    return guard


_ADAPTER_INFO = {
    "module": __name__,
    "version": __version__,
    "hook_path": f"{__name__}.guarded_tool",
}


def _is_deferred_result(result: Any) -> bool:
    if inspect.isgenerator(result) or inspect.isasyncgen(result):
        return True
    if isinstance(result, (asyncio.Future, concurrent.futures.Future)):
        return True
    return False


def _body_state_for(result: Any) -> str:
    return BodyState.DEFERRED if _is_deferred_result(result) else BodyState.RETURNED


def _elapsed_ms(started_at: float) -> int:
    return int((time.monotonic() - started_at) * 1000)


from ._snapshot import freeze as _freeze


def _snapshot_params(args, kwargs) -> Any:
    """An immutable snapshot of the call's arguments, taken BEFORE the wrapped tool runs and
    reused for both `authorized_params` and `invoked_params`."""
    return _freeze({"args": list(args), "kwargs": dict(kwargs)})


def guarded_tool(fn: Callable, *, scope: str,
                 context_for: "Callable[..., Mapping[str, Any]] | None" = None,
                 metered: bool = False, disposition: str | None = None,
                 tool: str | None = None) -> Callable:
    """Wrap a remote agent's tool so the request's permissions are checked BEFORE the body.

    Works on sync and async callables. On a denial it raises `AuthorityDenied` — the remote
    agent's own framework decides whether that becomes a tool error the model can react to or
    an aborted run; both keep the body unrun.
    """
    name = tool or getattr(fn, "__name__", "tool")

    def _check(args, kwargs, *, capture: str) -> "tuple[Guard, Any, Any]":
        """Raise `AuthorityDenied` on denial; else return `(guard, call_id_or_None,
        snapshot_or_None)` -- the last two set only for an ALLOWED, v2 check()."""
        guard = require_guard()
        ctx = dict(context_for(*args, **kwargs)) if context_for else {}
        v2 = guard.schema_version == 2
        snapshot = _snapshot_params(args, kwargs) if v2 else None
        extra = (
            dict(capture=capture, adapter=_ADAPTER_INFO, authorized_params=snapshot)
            if v2 else {}
        )
        decision = guard.check(scope, context=ctx, metered=metered, tool=name,
                               disposition=disposition, **extra)
        if not decision:
            raise AuthorityDenied(decision)
        return guard, (decision.call_id if v2 else None), snapshot

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            guard, call_id, snapshot = _check(args, kwargs, capture=Capture.WRAPPER_ASYNC)
            if call_id is None:
                return await fn(*args, **kwargs)
            start = time.monotonic()
            try:
                result = await fn(*args, **kwargs)
            except asyncio.CancelledError:
                # The wrapper stopped observing while the body may still run -- `abandoned`,
                # not `raised`; still re-raised so cancellation propagates normally.
                guard.record_outcome(call_id, BodyState.ABANDONED,
                                     invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                raise
            except Exception as exc:
                guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                     invoked_params=snapshot, duration_ms=_elapsed_ms(start))
                raise
            guard.record_outcome(call_id, _body_state_for(result),
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            return result

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        guard, call_id, snapshot = _check(args, kwargs, capture=Capture.WRAPPER_SYNC)
        if call_id is None:
            return fn(*args, **kwargs)
        start = time.monotonic()
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            guard.record_outcome(call_id, BodyState.RAISED, error_code=type(exc).__name__,
                                 invoked_params=snapshot, duration_ms=_elapsed_ms(start))
            raise
        guard.record_outcome(call_id, _body_state_for(result),
                             invoked_params=snapshot, duration_ms=_elapsed_ms(start))
        return result

    return wrapper


@dataclass(frozen=True)
class _Denial:
    error: str
    detail: str
    disposition: str | None = None

    def to_dict(self, agent_id: str) -> dict:
        out = {"error": self.error, "agent": agent_id, "detail": self.detail,
               "extension": EXTENSION_URI}
        if self.disposition:
            out["disposition"] = self.disposition
        return out


class GuardedAgentExecutor(AgentExecutor):
    """Wraps a deployment's `AgentExecutor` so an inbound A2A task is served only with
    permissions bounded by the verified Delegation Chain it carried.

    Per request, in order:

      1. read the chain from the message extension — absent is a deny;
      2. `wire.load(...)` verifies it offline: every signature, the parent-hash byte
         commitment at every hop, depth against `del_max_depth`, child-subset-of-parent at
         every hop, and expiry. A forged, spliced, widened or expired chain is a deny;
      3. `revocation_check(leaf_payload)` — the seam for a status list (see LIMITS);
      4. `authority_for(agent_id, task)` says what THIS agent's task needs; the served `Guard`
         is `leaf.meet(requested)`, so it is bounded by the token no matter what
         `authority_for` returns;
      5. only then `inner.execute(...)`, with the `Guard` bound to the request.

    A denial never reaches `inner`: the executor enqueues a single `Message` carrying the
    denial contract (`docs/DENIAL-CONTRACT.md`) and returns. Any exception raised while
    deciding is also a denial — there is no path on which `inner.execute` runs without a
    verified chain.
    """

    def __init__(self, inner: AgentExecutor, *, agent_id: str,
                 authority_for: "Callable[[str, str], Authority | None]",
                 signer,
                 root_key_ids: "Sequence[str] | None" = None,
                 now: "Callable[[], int] | None" = None,
                 revocation_check: "Callable[[Mapping[str, Any]], str | None] | None" = None,
                 audit_dir: Any = None,
                 max_depth: int = 6,
                 strict_metering: bool = False,
                 on_decision: "Callable[[str, _Denial | None], None] | None" = None) -> None:
        self._inner = inner
        self._agent_id = agent_id
        self._authority_for = authority_for
        self._signer = signer
        self._root_key_ids = set(root_key_ids) if root_key_ids is not None else None
        self._now = now or (lambda: int(time.time()))
        self._revocation_check = revocation_check
        self._audit_dir = audit_dir
        self._max_depth = max_depth
        self._strict = strict_metering
        self._on_decision = on_decision
        #: task_id -> the Guard served for it, for evidence export after the run.
        self.guards: dict[str, Guard] = {}
        #: (task_id, _Denial) for every refused request, newest last.
        self.denials: list[tuple[str, _Denial]] = []

    # -- AgentExecutor ------------------------------------------------------

    async def execute(self, context: RequestContext, event_queue) -> None:
        task_id = str(context.task_id or "")
        try:
            guard, denial = self._authorize(context)
        except Exception as exc:                       # noqa: BLE001 - fail closed on any bug
            guard, denial = None, _Denial(
                "chain_invalid", f"{type(exc).__name__}: {exc}", Disposition.UNRESOLVED,
            )

        if denial is not None or guard is None:
            denial = denial or _Denial("no_authority", "no permissions minted",
                                       Disposition.UNRESOLVED)
            self.denials.append((task_id, denial))
            if self._on_decision:
                self._on_decision(task_id, denial)
            await event_queue.enqueue_event(self._denial_message(context, denial))
            return

        self.guards[task_id] = guard
        if self._on_decision:
            self._on_decision(task_id, None)
        token = _CURRENT_GUARD.set(guard)
        try:
            await self._inner.execute(context, event_queue)
        finally:
            _CURRENT_GUARD.reset(token)
            guard.complete()

    async def cancel(self, context: RequestContext, event_queue) -> None:
        """Cancellation carries no permissions of its own — it acts on a task this executor
        already bound to a chain, so it is passed straight through."""
        await self._inner.cancel(context, event_queue)

    # -- the decision -------------------------------------------------------

    def _authorize(self, context: RequestContext) -> "tuple[Guard | None, _Denial | None]":
        tokens = read_delegation(context)
        if not tokens:
            return None, _Denial(
                "no_delegation_chain",
                f"no {EXTENSION_URI} extension on the message; default deny",
                Disposition.UNRESOLVED,
            )

        try:
            verified = wire.load(tokens, self._signer,
                                 root_key_ids=self._root_key_ids, now=self._now())
        except wire.WireError as exc:
            return None, _Denial("chain_invalid", f"{exc.reason}: {exc}",
                                 Disposition.OUT_OF_AUTHORITY)

        leaf = verified.payloads[-1]
        if self._revocation_check is not None:
            reason = self._revocation_check(leaf)
            if reason:
                return None, _Denial("revoked", reason, Disposition.OUT_OF_AUTHORITY)

        task = context.get_user_input()
        requested = self._authority_for(self._agent_id, task)
        if requested is None:
            return None, _Denial(
                "no_authority",
                f"no permissions defined for {self._agent_id!r} (authority_for returned None)",
                Disposition.UNRESOLVED,
            )

        caller = str(leaf.get("sub") or "caller")
        chain_id = continuation_chain_id(verified)
        try:
            # The continuation root IS the verified leaf: same agent, byte-identical authority.
            # Nothing local widens it — `delegate` can only meet downwards from here.
            inbound = Guard.issue(
                caller, verified.leaf_authority, task=task, chain_id=chain_id,
                max_depth=self._max_depth, strict_metering=self._strict,
                audit_path=self._ledger_path(chain_id),
            )
            served = inbound.delegate(self._agent_id, requested, task=task)
        except AuthorityError as exc:
            return None, _Denial("no_authority", f"{exc.reason}: {exc}",
                                 Disposition.OUT_OF_AUTHORITY)
        return served, None

    def _ledger_path(self, chain_id: str):
        if self._audit_dir is None:
            return None
        from pathlib import Path

        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in chain_id)
        return Path(self._audit_dir) / f"{safe}.jsonl"

    def _denial_message(self, context: RequestContext, denial: _Denial) -> Message:
        body = denial.to_dict(self._agent_id)
        message = Message(
            role=Role.ROLE_AGENT,
            message_id=f"attenu-denial-{context.task_id or 'unknown'}",
            task_id=context.task_id or "",
            context_id=context.context_id or "",
        )
        message.parts.add().text = (
            f"denied: {denial.error} — {denial.detail}. "
            f"This agent runs only with permissions carried by {EXTENSION_URI}."
        )
        message.extensions.append(EXTENSION_URI)
        message.metadata[EXTENSION_URI] = {"v": _PAYLOAD_VERSION, "denial": body}
        return message

    # -- evidence -----------------------------------------------------------

    def guard_for_task(self, task_id: str) -> "Guard | None":
        return self.guards.get(str(task_id))

    def bundle_for_task(self, task_id: str, signer, **kwargs) -> "dict | None":
        """The offline-verifiable evidence bundle for one served task, or None if that task was
        denied (a denied request mints no chain, so there is no ledger to export — the denial
        is in `self.denials`)."""
        guard = self.guards.get(str(task_id))
        if guard is None:
            return None
        return evidence.export_bundle(guard.audit_log(), signer, **kwargs)


# ---------------------------------------------------------------------------
# Cross-process verification
# ---------------------------------------------------------------------------

def verify_hop(tokens: Sequence[str], signer, *, client_bundle: "dict | None" = None,
               server_bundle: "dict | None" = None, now: int = 0) -> dict:
    """Verify one A2A hop end to end, from the tokens and the two ledgers ALONE.

    Checks, in order:

      chain       `wire.load` — signatures, parent-hash linkage, depth, child-subset-of-parent
                  at every hop, expiry (draft {{verify}} steps 1-5);
      client      the client bundle verifies (`evidence.verify_bundle`) AND contains a node
                  whose id is the leaf token's `jti`, whose agent is the leaf `sub`, and whose
                  authority is exactly the leaf token's;
      server      the server bundle verifies AND its root node holds exactly the leaf token's
                  authority under the leaf's agent id — i.e. the server continued the chain it
                  was handed and did not widen it — with `chain_id` equal to
                  `continuation_chain_id(...)`, recomputed here from the leaf token's bytes.

    Returns `{"ok", "checks", "failures", …}`, the same shape as
    `attenu_guard.evidence.verify_bundle`. A bundle that is not supplied is reported as
    `"not checked"`, never as passing.
    """
    checks: dict[str, Any] = {"chain": False, "client": "not checked", "server": "not checked"}
    failures: list[str] = []

    try:
        verified = wire.load(list(tokens), signer, now=now)
        checks["chain"] = True
    except wire.WireError as exc:
        failures.append(f"chain: {exc.reason}: {exc}")
        return {"ok": False, "checks": checks, "failures": failures}

    leaf = verified.payloads[-1]
    leaf_jti = str(leaf.get("jti") or "")
    leaf_sub = str(leaf.get("sub") or "")
    leaf_authority = verified.leaf_authority

    if client_bundle is not None:
        ok, why = _check_client(client_bundle, leaf_jti, leaf_sub, leaf_authority)
        checks["client"] = "verified" if ok else "FAILED"
        failures += why

    if server_bundle is not None:
        ok, why = _check_server(server_bundle, continuation_chain_id(verified), leaf_sub,
                                leaf_authority)
        checks["server"] = "verified" if ok else "FAILED"
        failures += why

    return {
        "ok": checks["chain"] and not failures,
        "checks": checks,
        "failures": failures,
        "hops": len(verified.tokens),
        "leaf": {"agent": leaf_sub, "node": leaf_jti,
                 "scopes": sorted(leaf_authority.scopes)},
    }


def continuation_chain_id(verified: "wire.VerifiedChain") -> str:
    """The `chain_id` a server gives the chain it continues: the leaf token's `jti` (readable —
    it is the caller's leaf node id) plus a fingerprint of that exact token's JWS signing input.

    The `jti` alone is not unique: node ids are unique only within a chain, and chain ids are
    chosen by whoever issued the root, so two callers can legitimately produce the same one.
    The fingerprint covers the whole leaf token — issuer, subject, `iat`, `exp`, permissions —
    so a server ledger can be tied to the one hop that produced it, and `verify_hop` recomputes
    it from the tokens alone.

    What it does NOT give you is a nonce: two hops whose leaf tokens are byte-identical — same
    issuer, same node id, same permissions, same `iat` second — are the same token and land in
    the same ledger. Give chains distinct `chain_id`s if you need per-hop ledgers under
    otherwise identical conditions.
    """
    header_b64, payload_b64, _sig = verified.tokens[-1].split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    fingerprint = wire.b64url_encode(hashlib.sha256(signing_input).digest())[:12]
    return f"{verified.payloads[-1].get('jti') or 'leaf'}#{fingerprint}"


def _same_authority(a: Authority, b: Authority) -> bool:
    """Equal as authorities: each is narrower than the other. Uses the library's own
    subsumption relation rather than dataclass equality, so ceiling ordering and wire
    round-tripping cannot make two identical grants look different."""
    return a.is_narrower_than(b) and b.is_narrower_than(a)


def _authority_of(bundle: dict, node_id: str) -> "Authority | None":
    for entry in bundle.get("entries") or []:
        if entry.get("node") != node_id:
            continue
        if entry.get("event") == "root" and entry.get("authority") is not None:
            return Authority.from_wire(entry["authority"])
        if entry.get("event") == "spawn" and entry.get("granted") is not None:
            return Authority.from_wire(entry["granted"])
    return None


def _check_client(bundle: dict, leaf_jti: str, leaf_sub: str,
                  leaf_authority: Authority) -> "tuple[bool, list[str]]":
    failures: list[str] = []
    report = evidence.verify_bundle(bundle)
    if not report["ok"]:
        failures.append(f"client: bundle does not verify: {report['failures']}")
    nodes = evidence.delegation_graph(bundle)["nodes"]
    node = nodes.get(leaf_jti)
    if node is None:
        failures.append(
            f"client: no node {leaf_jti!r} in the client ledger — the token was not minted by "
            f"this chain"
        )
        return False, failures
    if node.get("agent") != leaf_sub:
        failures.append(
            f"client: node {leaf_jti!r} is agent {node.get('agent')!r}, token says {leaf_sub!r}"
        )
    held = _authority_of(bundle, leaf_jti)
    if held is None or not _same_authority(held, leaf_authority):
        failures.append(
            f"client: node {leaf_jti!r} holds {sorted(held.scopes) if held else None}, the "
            f"token carries {sorted(leaf_authority.scopes)}"
        )
    return not failures, failures


def _check_server(bundle: dict, chain_id: str, leaf_sub: str,
                  leaf_authority: Authority) -> "tuple[bool, list[str]]":
    failures: list[str] = []
    report = evidence.verify_bundle(bundle)
    if not report["ok"]:
        failures.append(f"server: bundle does not verify: {report['failures']}")
    if bundle.get("chain_id") != chain_id:
        failures.append(
            f"server: ledger chain_id {bundle.get('chain_id')!r} is not {chain_id!r}, the id "
            f"derived from the leaf token — this ledger did not continue this hop"
        )
    roots = [e for e in (bundle.get("entries") or []) if e.get("event") == "root"]
    if len(roots) != 1:
        failures.append(f"server: expected exactly one root event, found {len(roots)}")
        return False, failures
    root = roots[0]
    if root.get("agent") != leaf_sub:
        failures.append(
            f"server: continuation root is agent {root.get('agent')!r}, token says {leaf_sub!r}"
        )
    held = Authority.from_wire(root["authority"])
    if not _same_authority(held, leaf_authority):
        failures.append(
            f"server: continuation root holds {sorted(held.scopes)}, the token carries "
            f"{sorted(leaf_authority.scopes)} — the server did not continue the chain it was "
            f"handed"
        )
    return not failures, failures
