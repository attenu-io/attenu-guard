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
    EgressRank,
    Guard,
    ReasonCode,
    RowLimit,
    evidence,
)

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
    assert report["checks"] == {"chain": True, "client": "verified", "server": "verified"}
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
