"""
Integration test: attenu-guard x A2A (Agent2Agent protocol), `a2a-sdk` 1.1.2.

Runs entirely offline. The two agents live in one process but talk through the SDK's real
stack — client interceptors, `BaseClient`, a `ClientTransport`, `DefaultRequestHandler`, the
request-context builder, `AgentExecutor.execute`. No network, no API key.

What is asserted is the *user-felt* outcome, not the internals: a remote agent reached over
A2A runs with permissions bounded by the caller's, and the tool body is proven never to have
run on a denial (via the side-effect ledger the body would have written to). Every way of
getting the chain wrong — forged, spliced, widened, expired, absent — is a refusal at the
boundary, before the remote agent's own logic starts.

The test drives the SHIPPED example (`examples/integrations/a2a/demo.py` +
`attenu_guard.adapters.a2a`), so a green run also proves the example works.
"""
from __future__ import annotations

import asyncio
import importlib.metadata
import importlib.util
import inspect
import sys
from pathlib import Path

import pytest

pytest.importorskip("a2a")

from attenu_guard import (  # noqa: E402
    AuditLog,
    Authority,
    AuthorityDenied,
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
    evidence,
)
from attenu_guard.reasons import BodyState, Capture  # noqa: E402

# The upstream surface this adapter stands on, pinned so the weekly unpinned CI job flags the
# day A2A moves it.
PINNED = {
    "package": "a2a-sdk",
    "version": "1.1.2",
    "client_hook": "a2a.client.interceptors.ClientCallInterceptor.before(BeforeArgs)",
    "server_hook": "a2a.server.agent_execution.AgentExecutor.execute(context, event_queue)",
    "extension_point": "Message.extensions + Message.metadata[<uri>] (A2A spec §4.6.2)",
    "spec_disclaimer": (
        "A2A spec §7.6.4: the protocol does not define the scope, representation, validity or "
        "revocation semantics of an in-task authorization decision"
    ),
}

# --------------------------------------------------------------------------
# Load the example by path. The example directory is itself named `a2a`, so its PARENT is
# never put on sys.path — that would shadow the real SDK package.
# --------------------------------------------------------------------------
_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "integrations" / "a2a"


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, _EXAMPLE_DIR / filename)
    assert spec and spec.loader, f"cannot load {filename} from the a2a example directory"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


import attenu_guard.adapters.a2a as dg_a2a  # noqa: E402

demo = _load("attenu_a2a_demo", "demo.py")


@pytest.fixture(autouse=True)
def _clean_world():
    demo.reset_world()
    yield


def _signer():
    return demo.signer()


# ==========================================================================
# Compat: the upstream API surface this adapter relies on
# ==========================================================================

def test_compat_a2a_hook_points_are_public_and_unchanged():
    """Both seams are public ABCs with the signatures the adapter binds to."""
    from a2a.client.interceptors import BeforeArgs, ClientCallInterceptor
    from a2a.server.agent_execution import AgentExecutor, RequestContext

    before = inspect.signature(ClientCallInterceptor.before)
    assert list(before.parameters) == ["self", "args"], PINNED["client_hook"]
    assert {"input", "method", "agent_card", "context", "early_return"} <= set(
        BeforeArgs.__dataclass_fields__
    ), PINNED["client_hook"]

    execute = inspect.signature(AgentExecutor.execute)
    assert list(execute.parameters) == ["self", "context", "event_queue"], PINNED["server_hook"]
    assert isinstance(RequestContext.metadata, property)

    from a2a.types.a2a_pb2 import Message

    fields = {f.name for f in Message.DESCRIPTOR.fields}
    assert {"extensions", "metadata"} <= fields, PINNED["extension_point"]
    print("a2a-sdk", importlib.metadata.version("a2a-sdk"), "(pinned:", PINNED["version"] + ")")


def test_compat_interceptors_are_run_before_the_transport():
    """`BaseClient` calls every interceptor's `before` and passes `args.input` on to the
    transport — the property that lets the adapter write the chain onto the outgoing message."""
    from a2a.client.base_client import BaseClient

    source = inspect.getsource(BaseClient._execute_with_interceptors)
    assert "_intercept_before" in source and "transport_call(before_args.input" in source


# ==========================================================================
# The hop, guarded
# ==========================================================================

def test_the_chain_travels_as_an_a2a_extension_not_an_ad_hoc_field():
    hop, _ = demo.run_hop()
    request = hop.interceptor
    assert request.sent, "the interceptor attached nothing"
    agent_id, tokens = request.sent[-1]
    assert agent_id == "summariser" and len(tokens) == 2

    # And it is declared the way the spec declares an extension.
    card_uris = [e.uri for e in hop.card.capabilities.extensions]
    assert dg_a2a.EXTENSION_URI in card_uris
    assert all(e.required for e in hop.card.capabilities.extensions)


def test_remote_agent_is_served_a_strict_subset_of_the_callers_permissions():
    hop, _ = demo.run_hop()
    served = next(iter(hop.executor.guards.values()))
    assert sorted(served.authority.scopes) == ["crm.read"]
    assert served.authority.is_narrower_than(hop.orchestrator.authority)
    assert not hop.orchestrator.authority.is_narrower_than(served.authority)


def test_the_allowed_read_runs_and_the_export_body_never_does():
    """The adapter-test trap: assert on the side-effect ledger the tool body writes to, not on
    the guard's own bookkeeping."""
    hop, _ = demo.run_hop()
    assert hop.inner.attempted == ["crm_query", "crm_export"], "the agent did try to export"
    assert demo.WORLD["bodies_run"] == [("crm_query", 1_800)]
    assert demo.WORLD["exported_to"] is None


def test_the_unguarded_control_does_export():
    """The oracle sees the effect when nobody is checking — otherwise the test above proves
    nothing."""
    demo.run_unguarded_control()
    assert demo.WORLD["exported_to"] == "s3://attacker-bucket/crm-dump.csv"


def test_the_remote_end_may_narrow_further_than_the_caller_did():
    hop, _ = demo.run_oversize_read()
    assert hop.inner.attempted == ["crm_query"]
    assert demo.WORLD["bodies_run"] == [], "4 200 rows exceeded this deployment's own ceiling"
    denials = [e for e in hop.executor.guards.popitem()[1].audit_log().entries
               if e["event"] == "deny"]
    assert denials and denials[-1]["reason"] == ReasonCode.CEILING_EXCEEDED


def test_the_denial_is_reported_back_to_the_caller_machine_readably():
    hop, reply = demo.run_hop()
    # The refused TOOL is reported inside the agent's own answer …
    assert "refused" in demo.text_of(reply)
    # … and a refused HOP is reported in the extension's metadata slot.
    _, denied = demo.run_no_chain()
    body = demo.denial_of(denied)
    assert body["error"] == "no_delegation_chain"
    assert body["extension"] == dg_a2a.EXTENSION_URI


def test_the_request_level_metadata_map_is_accepted_as_a_fallback():
    """The Message extension point is where the spec puts extension data, but a deployment that
    puts the chain on the request-level metadata map is served too — the documented fallback."""
    from a2a.helpers.proto_helpers import new_text_message
    from a2a.types.a2a_pb2 import Role, SendMessageRequest

    demo.reset_world()
    source = demo.Hop()
    asyncio.run(source.send())
    tokens = source.tokens

    demo.reset_world()
    hop = demo.Hop(interceptors=[])
    request = SendMessageRequest(message=new_text_message("summarise", role=Role.ROLE_USER))
    request.metadata[dg_a2a.EXTENSION_URI] = {"v": 1, "chain": list(tokens)}
    reply = asyncio.run(hop._send(request))

    assert demo.denial_of(reply) is None, "the request-level map should have been read"
    assert demo.WORLD["bodies_run"] == [("crm_query", 1_800)]


def test_a_metadata_map_with_no_chain_reads_as_absent_not_as_a_crash():
    assert dg_a2a.read_delegation({}) == []
    assert dg_a2a.read_delegation({dg_a2a.EXTENSION_URI: {"v": 1}}) == []
    assert dg_a2a.read_delegation({dg_a2a.EXTENSION_URI: {"chain": [1, 2]}}) == []
    assert dg_a2a.read_delegation({dg_a2a.EXTENSION_URI: "not-an-object"}) == []


def test_attach_delegation_refuses_a_target_it_cannot_write_to():
    hop = demo.Hop()
    child = hop.orchestrator.delegate("summariser", demo.SUMMARISER_REQUEST, task="t")
    with pytest.raises(TypeError):
        dg_a2a.attach_delegation("not a request", child, _signer())


# ==========================================================================
# Getting the chain wrong: every route is a refusal at the boundary
# ==========================================================================

@pytest.mark.parametrize("scenario,error", [
    ("run_forged_chain", "chain_invalid"),
    ("run_widened_chain", "chain_invalid"),
    ("run_expired_chain", "chain_invalid"),
    ("run_no_chain", "no_delegation_chain"),
])
def test_a_bad_chain_is_refused_before_the_remote_agents_logic_starts(scenario, error):
    hop, reply = getattr(demo, scenario)()
    assert demo.denial_of(reply)["error"] == error
    assert hop.inner.attempted == [], "the remote agent's own logic must not start"
    assert demo.WORLD["bodies_run"] == []
    assert hop.executor.guards == {}, "a refused hop mints no permissions"


def test_the_widened_token_is_refused_for_being_wider_not_for_being_malformed():
    _, reply = demo.run_widened_chain()
    assert "not_narrower" in demo.denial_of(reply)["detail"]


def test_a_spliced_chain_is_refused():
    """Two chains, each valid on its own; the child of one presented under the root of the
    other. The parent-hash byte commitment catches it."""
    from attenu_guard import wire

    a = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, chain_id="a")
    b = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, chain_id="b")
    child_b = b.delegate("summariser", demo.SUMMARISER_REQUEST, task="summarise")
    spliced = [wire.serialize_chain(a, _signer())[0], wire.serialize_chain(child_b, _signer())[1]]

    hop, reply = _send_raw_chain(spliced)
    assert demo.denial_of(reply)["error"] == "chain_invalid"
    assert "par_hash" in demo.denial_of(reply)["detail"]
    assert hop.inner.attempted == []


def test_a_chain_signed_by_an_untrusted_root_kid_is_refused():
    from attenu_guard.wire import HS256TestSigner

    other = HS256TestSigner(demo.SIGNING_KEY, kid="somebody-elses-key")
    parent = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, chain_id="untrusted")
    child = parent.delegate("summariser", demo.SUMMARISER_REQUEST, task="summarise")
    from attenu_guard import wire

    hop, reply = _send_raw_chain(wire.serialize_chain(child, other))
    assert demo.denial_of(reply)["error"] == "chain_invalid"
    assert hop.inner.attempted == []


def test_a_deciding_bug_denies_rather_than_serving():
    """Fail closed on any exception raised while deciding — including one from the
    deployment's own `authority_for`."""
    def explode(agent_id, task):
        raise RuntimeError("policy lookup is down")

    hop = demo.Hop(authority_for=explode)
    reply = asyncio.run(hop.send())
    body = demo.denial_of(reply)
    assert body["error"] == "chain_invalid" and "policy lookup is down" in body["detail"]
    assert hop.inner.attempted == []


def test_authority_for_returning_none_refuses_the_request():
    hop = demo.Hop(authority_for=lambda agent_id, task: None)
    reply = asyncio.run(hop.send())
    assert demo.denial_of(reply)["error"] == "no_authority"
    assert hop.inner.attempted == []


def test_a_tool_reached_outside_the_executor_refuses_to_run():
    """`require_guard()` is the backstop: a tool called by some path that never passed through
    `GuardedAgentExecutor` raises instead of running."""
    with pytest.raises(dg_a2a.A2ADelegationError):
        demo.crm_query(rows=10)
    assert demo.WORLD["bodies_run"] == []


def test_the_client_half_refuses_to_send_an_unguarded_hop():
    refusal = demo.client_refuses_unguarded_hop()
    assert "no delegated permissions" in refusal


def test_revocation_check_is_the_seam_for_a_status_list():
    """Cross-process revocation propagation is not solved by the wire format; this hook is
    where a deployment plugs its own feed, and it denies before anything is minted."""
    hop = demo.Hop()
    hop.executor._revocation_check = lambda leaf: f"jti {leaf['jti']} is on the status list"
    reply = asyncio.run(hop.send())
    body = demo.denial_of(reply)
    assert body["error"] == "revoked" and "status list" in body["detail"]
    assert hop.inner.attempted == []


# ==========================================================================
# The cross-process record
# ==========================================================================

def _bundles(hop):
    client_bundle = evidence.export_bundle(hop.orchestrator.audit_log(), _signer())
    task_id = next(iter(hop.executor.guards))
    return client_bundle, hop.executor.bundle_for_task(task_id, _signer())


def test_both_ledgers_and_the_tokens_verify_offline_together():
    hop, _ = demo.run_hop()
    client_bundle, server_bundle = _bundles(hop)
    report = dg_a2a.verify_hop(hop.tokens, _signer(),
                               client_bundle=client_bundle, server_bundle=server_bundle)
    assert report["ok"], report["failures"]
    assert report["checks"] == {"chain": True, "client": "verified", "server": "verified",
                                "envelopes": dg_a2a.ENVELOPES_NOT_EVALUATED}
    assert report["hops"] == 2


def test_each_bundle_verifies_on_its_own_too():
    hop, _ = demo.run_hop()
    for bundle in _bundles(hop):
        assert evidence.verify_bundle(bundle, _signer())["ok"]


def test_a_bundle_not_supplied_is_reported_as_not_checked_never_as_passing():
    hop, _ = demo.run_hop()
    report = dg_a2a.verify_hop(hop.tokens, _signer())
    assert report["checks"]["client"] == "not checked"
    assert report["checks"]["server"] == "not checked"


def test_verify_hop_catches_a_server_ledger_from_a_different_hop():
    """The linkage claim, tested: a server bundle that did not continue THIS chain fails."""
    other = demo.Hop(orchestrator_authority=Authority(
        scopes={"crm.read", "crm.export"},
        ceilings=[RowLimit(50_000), EgressRank("any")], ttl=1800,
    ))
    asyncio.run(other.send())
    _, other_server = _bundles(other)

    hop, _ = demo.run_hop()
    report = dg_a2a.verify_hop(hop.tokens, _signer(), server_bundle=other_server)
    assert not report["ok"]
    assert any("did not continue this hop" in f for f in report["failures"])


def test_two_hops_that_differ_in_any_signed_field_get_different_ledger_ids():
    """The continuation id is derived from the leaf token's bytes, so a hop with a different
    grant, issuer, expiry or node id lands in a different ledger."""
    from attenu_guard import wire

    a = demo.Hop()
    b = demo.Hop(requested=Authority(scopes={"crm.read"},
                                     ceilings=[RowLimit(1_000), EgressRank("none")], ttl=300))
    asyncio.run(a.send())
    asyncio.run(b.send())
    ids = {dg_a2a.continuation_chain_id(wire.load(h.tokens, _signer(), now=0))
           for h in (a, b)}
    assert len(ids) == 2
    assert all("#" in i for i in ids)


def test_verify_hop_catches_a_server_that_widened_what_it_was_handed():
    hop, _ = demo.run_hop()
    _, server_bundle = _bundles(hop)
    root = next(e for e in server_bundle["entries"] if e["event"] == "root")
    root["authority"] = Authority(
        scopes={"crm.read", "crm.export"},
        ceilings=[RowLimit(5_000), EgressRank("any")], ttl=900,
    ).to_wire()
    report = dg_a2a.verify_hop(hop.tokens, _signer(), server_bundle=server_bundle)
    assert not report["ok"]
    assert any("did not continue the chain it was handed" in f for f in report["failures"])


def test_verify_hop_catches_a_client_ledger_that_never_minted_the_token():
    hop, _ = demo.run_hop()
    other = Guard.issue("impostor", demo.ORCHESTRATOR_AUTHORITY, chain_id="impostor")
    other.delegate("summariser", demo.SUMMARISER_REQUEST, task="summarise")
    report = dg_a2a.verify_hop(
        hop.tokens, _signer(),
        client_bundle=evidence.export_bundle(other.audit_log(), _signer()),
    )
    assert not report["ok"]
    assert any("was not minted by this chain" in f for f in report["failures"])


# ---- observer envelopes on a hop -----------------------------------------
_WITNESS_SEED = bytes(range(32))
_WITNESS_KID = "a2a-hop-witness"


def _witness_keys():
    public = evidence._ed25519_backend()[2]
    return [{"kid": _WITNESS_KID, "alg": evidence.ENVELOPE_ALG,
             "public_key_hex": public(_WITNESS_SEED).hex()}]


def _with_envelope(bundle):
    """The same bundle, carrying one honest envelope over its first envelope-eligible entry."""
    seq = next(e["seq"] for e in bundle["entries"]
               if e.get("event") in evidence.ENVELOPE_SUBJECT_MEMBERS)
    bundle = dict(bundle)
    bundle["envelopes"] = [evidence.sign_envelope(bundle["entries"], seq, _WITNESS_SEED,
                                                  kid=_WITNESS_KID, at="2026-09-01T11:00:00Z",
                                                  method="sidecar:ledger-tail")]
    return bundle


def test_a_hop_carrying_envelopes_is_not_refused_when_no_trust_set_is_configured():
    """The defect: `verify_hop` scored envelopes against an empty trust set, so a peer refused
    every honest hop whose ledger carried one. Envelope trust belongs to the deployment; with
    none configured the hop is checked without the envelopes, and says so."""
    hop, _ = demo.run_hop()
    client_bundle, server_bundle = _bundles(hop)
    report = dg_a2a.verify_hop(hop.tokens, _signer(),
                               client_bundle=_with_envelope(client_bundle),
                               server_bundle=_with_envelope(server_bundle))
    assert report["ok"], report["failures"]
    assert report["checks"]["envelopes"] == "not evaluated (no witness_keys configured)"


def test_a_configured_trust_set_scores_the_envelopes_on_the_hop():
    hop, _ = demo.run_hop()
    client_bundle, server_bundle = _bundles(hop)
    report = dg_a2a.verify_hop(hop.tokens, _signer(),
                               client_bundle=_with_envelope(client_bundle),
                               server_bundle=_with_envelope(server_bundle),
                               witness_keys=_witness_keys())
    assert report["ok"], report["failures"]
    assert report["checks"]["envelopes"] == "evaluated"


def test_a_broken_envelope_fails_the_hop_once_a_trust_set_is_configured():
    """The other half: not evaluating them by default is not the same as ignoring them. With
    keys configured, an envelope that does not verify fails the hop like any other check."""
    hop, _ = demo.run_hop()
    client_bundle, _server = _bundles(hop)
    carried = _with_envelope(client_bundle)
    carried["envelopes"][0]["sig"] = "00" * 64
    report = dg_a2a.verify_hop(hop.tokens, _signer(), client_bundle=carried,
                               witness_keys=_witness_keys())
    assert not report["ok"]
    assert any("envelope_bad_signature" in f for f in report["failures"])
    # And the same bundle passes with no trust set: the envelope is not evaluated, not ignored.
    assert dg_a2a.verify_hop(hop.tokens, _signer(), client_bundle=carried)["ok"]


def test_the_hop_check_does_not_mutate_the_bundle_it_was_given():
    hop, _ = demo.run_hop()
    client_bundle, _server = _bundles(hop)
    carried = _with_envelope(client_bundle)
    dg_a2a.verify_hop(hop.tokens, _signer(), client_bundle=carried)
    assert "envelopes" in carried and len(carried["envelopes"]) == 1


def test_a_tampered_server_ledger_fails():
    hop, _ = demo.run_hop()
    _, server_bundle = _bundles(hop)
    for entry in server_bundle["entries"]:
        if entry["event"] == "deny":
            entry["event"] = "allow"
    assert not evidence.verify_bundle(server_bundle, _signer())["ok"]
    assert not dg_a2a.verify_hop(hop.tokens, _signer(), server_bundle=server_bundle)["ok"]


def test_the_server_ledger_records_the_refusal_with_its_disposition():
    hop, _ = demo.run_hop()
    _, server_bundle = _bundles(hop)
    rows = evidence.denials(server_bundle)
    assert [(r["tool"], r["scope"]) for r in rows] == [("crm_export", "crm.export")]
    assert rows[0]["reason"] == ReasonCode.SCOPE_NOT_GRANTED
    assert rows[0]["disposition"] == "out_of_authority"


def test_a_refused_hop_leaves_a_denial_and_no_ledger_to_export():
    hop, _ = demo.run_no_chain()
    assert hop.executor.denials and hop.executor.denials[0][1].error == "no_delegation_chain"
    assert hop.executor.bundle_for_task("anything", _signer()) is None


def test_the_server_ledger_is_written_to_disk_and_verifies_from_the_file(tmp_path):
    hop = demo.Hop(audit_dir=tmp_path)
    asyncio.run(hop.send())
    files = sorted(tmp_path.glob("*.jsonl"))
    assert len(files) == 1, "one ledger per inbound chain"
    ok, why = AuditLog.verify(AuditLog.load(files[0]))
    assert ok, why


# ==========================================================================
# The example itself
# ==========================================================================

def test_demo_main_runs_clean(capsys):
    assert demo.main() == 0
    out = capsys.readouterr().out
    assert out.rstrip().endswith("RESULT: OK")
    assert "s3://attacker-bucket/crm-dump.csv" in out       # the control did export
    assert "data exported anywhere:           nothing" in out


# ==========================================================================
# Helpers
# ==========================================================================

def _send_raw_chain(tokens):
    """Send a hand-built chain, bypassing the interceptor that would mint a valid one."""
    from a2a.helpers.proto_helpers import new_text_message
    from a2a.types.a2a_pb2 import Role, SendMessageRequest

    demo.reset_world()
    hop = demo.Hop(interceptors=[])
    request = SendMessageRequest(message=new_text_message("summarise", role=Role.ROLE_USER))
    request.message.extensions.append(dg_a2a.EXTENSION_URI)
    request.message.metadata[dg_a2a.EXTENSION_URI] = {"v": 1, "chain": list(tokens)}
    return hop, asyncio.run(hop._send(request))


# ==========================================================================
# Execution binding (0.9.0): record_outcome() on a schema_version=2 chain.
# guarded_tool() calls the wrapped tool itself (fn(*args, **kwargs) /
# await fn(*args, **kwargs)), exactly like adapters/langgraph.py's
# reference wiring, so WRAPPER_SYNC/WRAPPER_ASYNC is a genuine observation
# with no cross-hook correlation of any kind.
# ==========================================================================
def _bind_v2_guard(authority=None):
    guard = Guard.issue(
        "summarizer",
        authority or Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900),
        task="summarize", schema_version=2,
    )
    token = dg_a2a._CURRENT_GUARD.set(guard)
    return guard, token


def test_v2_allowed_sync_call_records_a_returned_outcome():
    guard, token = _bind_v2_guard()
    try:
        def crm_query(rows: int) -> str:
            return f"{rows} rows"

        tool = dg_a2a.guarded_tool(crm_query, scope="crm.read",
                                   context_for=lambda rows: {"rows": rows})
        assert tool(rows=10) == "10 rows"
    finally:
        dg_a2a._CURRENT_GUARD.reset(token)

    entries = guard.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_SYNC
    assert allow["adapter"]["module"] == "attenu_guard.adapters.a2a"
    assert outcome["body_state"] == BodyState.RETURNED
    assert allow["authorized_params_hash"] == outcome["invoked_params_hash"]
    assert isinstance(outcome["duration_ms"], int) and outcome["duration_ms"] >= 0
    assert guard.complete()


def test_v2_allowed_async_call_records_a_returned_outcome_wrapper_async():
    guard, token = _bind_v2_guard()
    try:
        async def crm_query(rows: int) -> str:
            return f"{rows} rows"

        tool = dg_a2a.guarded_tool(crm_query, scope="crm.read",
                                   context_for=lambda rows: {"rows": rows})
        assert asyncio.run(tool(rows=10)) == "10 rows"
    finally:
        dg_a2a._CURRENT_GUARD.reset(token)

    entries = guard.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    outcome = next(e for e in entries if e["event"] == "outcome" and e.get("call_id") == allow["call_id"])
    assert allow["capture"] == Capture.WRAPPER_ASYNC
    assert outcome["body_state"] == BodyState.RETURNED


def test_v2_a_tool_that_raises_records_a_raised_outcome():
    guard, token = _bind_v2_guard()
    try:
        def crm_query(rows: int) -> str:
            raise ValueError("boom")

        tool = dg_a2a.guarded_tool(crm_query, scope="crm.read",
                                   context_for=lambda rows: {"rows": rows})
        with pytest.raises(ValueError):
            tool(rows=10)
    finally:
        dg_a2a._CURRENT_GUARD.reset(token)

    entries = guard.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.RAISED
    assert outcome["error_code"] == "ValueError"


def test_v2_denied_call_never_records_an_outcome():
    guard, token = _bind_v2_guard()  # crm.read only
    reached = []
    try:
        def crm_export(destination: str) -> str:
            reached.append(destination)
            return "exported"

        tool = dg_a2a.guarded_tool(crm_export, scope="crm.export",
                                   context_for=lambda destination: {"egress": "any"})
        with pytest.raises(AuthorityDenied):
            tool(destination="attacker.example")
    finally:
        dg_a2a._CURRENT_GUARD.reset(token)

    assert reached == []
    entries = guard.audit_log().entries
    assert [e for e in entries if e["event"] == "allow"] == []
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v1_chain_gets_no_capture_adapter_or_outcome():
    guard = Guard.issue("summarizer", Authority(scopes={"crm.read"}, ttl=900), task="t")  # v1
    token = dg_a2a._CURRENT_GUARD.set(guard)
    try:
        def crm_query(rows: int) -> str:
            return f"{rows} rows"

        tool = dg_a2a.guarded_tool(crm_query, scope="crm.read",
                                   context_for=lambda rows: {"rows": rows})
        tool(rows=10)
    finally:
        dg_a2a._CURRENT_GUARD.reset(token)

    entries = guard.audit_log().entries
    allow = next(e for e in entries if e["event"] == "allow" and e.get("tool") == "crm_query")
    assert "capture" not in allow and "adapter" not in allow and "call_id" not in allow
    assert [e for e in entries if e["event"] == "outcome"] == []


def test_v2_async_cancelled_call_records_abandoned_and_still_propagates():
    guard, token = _bind_v2_guard()
    try:
        async def hangs(rows: int) -> str:
            await asyncio.sleep(3600)
            return "never"

        tool = dg_a2a.guarded_tool(hangs, scope="crm.read",
                                   context_for=lambda rows: {"rows": rows})

        async def scenario():
            task = asyncio.ensure_future(tool(rows=10))
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(scenario())
    finally:
        dg_a2a._CURRENT_GUARD.reset(token)

    entries = guard.audit_log().entries
    outcome = next(e for e in entries if e["event"] == "outcome")
    assert outcome["body_state"] == BodyState.ABANDONED
    assert "error_code" not in outcome


def test_v2_delegation_hop_never_gets_capture_or_an_outcome():
    """Neither half of the protocol hop calls guard.check() -- the CLIENT side
    (delegating_guard_for -> parent.delegate(...)) and the SERVER side
    (GuardedAgentExecutor._authorize -> leaf.meet(requested), exercised end to end by every
    other test in this file via demo.run_hop()) both mint through Guard.delegate()/.meet(),
    never through check() -- so on a v2 chain, minting the hop leaves no allow/outcome at all,
    only the tool calls guarded_tool() actually wraps get either."""
    parent = Guard.issue("orchestrator", demo.ORCHESTRATOR_AUTHORITY, task="root", schema_version=2)
    card = type("Card", (), {"name": "summariser"})()

    resolve = dg_a2a.delegating_guard_for(
        parent, authority_for=lambda c, t: demo.SUMMARISER_REQUEST,
        task_for=lambda c, r: "summarise Q3 pipeline",
    )
    child = resolve(card, None)
    assert child is not None

    entries = parent.audit_log().entries
    assert [e for e in entries if e["event"] in ("allow", "outcome")] == []
    assert any(e["event"] == "spawn" for e in entries)  # the mint itself IS recorded, just not as a check()


def test_snapshot_freeze_never_aliases_a_custom_deepcopy_that_returns_itself():
    """Codex review (all six earlier adapters, round 2, finding 4): _freeze() must never call
    ANY copy protocol (copy.deepcopy included) on a container -- a class free to implement
    __deepcopy__ to return `self` would otherwise make a "snapshot" alias the live object."""
    class AliasingList(list):
        def __deepcopy__(self, memo):
            return self

    live_kwargs = {"x": AliasingList([1])}
    snapshot = dg_a2a._snapshot_params((), live_kwargs)

    assert snapshot["kwargs"]["x"] is not live_kwargs["x"], "the snapshot aliased the live container"
    live_kwargs["x"].append(2)
    assert snapshot["kwargs"]["x"] == [1], "mutating the live container changed the snapshot"
