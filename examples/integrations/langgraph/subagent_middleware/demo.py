"""The subagent middleware, with authority attached — an attenu-guard recipe for LangChain 1.x.

What this shows, offline, with a scripted model (no API key):

  [1] `create_agent` + `SubAgentMiddleware`, no guard: a supervisor that holds only
      `write_brief` spawns a `writer` subagent whose spec lists `web_search` too — and
      the writer's `web_search` BODY RUNS. A subagent's tool list is its own; nothing
      relates it to what the supervisor holds. (LangChain issue #33879, "Add subagent
      middleware", is open; `langchain.agents.middleware` ships no subagent middleware
      on 1.3.17, so the pattern lives in `deepagents`. Pinned by the test next to this file.)
  [2] The same tree with one more middleware — `GuardedDelegation.middleware()`. The
      supervisor still spawns both subagents (that is LangChain's decision to make), but
      each child is minted as `meet(supervisor, requested)`: the researcher may search,
      the writer may not. The writer's `web.search` is DENIED before the tool body runs.
      The sink proves it.
  [3] The audit log verifies offline; a signed evidence bundle verifies too.

Exit codes: 0 = every expectation held · 1 = an expectation failed ·
3 = the upstream premise changed (LangChain now ships a subagent middleware, or a
    subagent's tools are now constrained to the parent's — see README "freshness").

Run:  python examples/integrations/langgraph/subagent_middleware/demo.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

from deepagents.backends import StateBackend
from deepagents.middleware import SubAgentMiddleware
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import BaseTool, tool

from attenu_guard import AuditLog, Authority, EgressRank, Guard, RowLimit, evidence
from attenu_guard.adapters.langchain import GuardedDelegation, ToolPolicy
from attenu_guard.cli import main as attenu_guard_cli
from attenu_guard.wire import Ed25519Signer

EXIT_OK, EXIT_FAIL, EXIT_PREMISE_CHANGED = 0, 1, 3

_GUARD_MIDDLEWARE_MODULE = "attenu_guard.adapters.langchain"


# ---------------------------------------------------------------------------
# The scripted model. No API key, no network, deterministic.
# ---------------------------------------------------------------------------
class ScriptedModel(BaseChatModel):
    """Replays a fixed list of messages, one per turn — the model's "decisions"."""

    responses: list
    i: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        message = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):
        return self

    @property
    def _llm_type(self) -> str:
        return "attenu-scripted-model"


def call(name: str, args: dict, call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


def spawn(subagent_type: str, description: str, call_id: str) -> AIMessage:
    """The supervisor's delegation: deepagents' `task(description, subagent_type)` tool."""
    return call("task", {"description": description, "subagent_type": subagent_type}, call_id)


# ---------------------------------------------------------------------------
# The tools. Each body records into a sink — that sink is the side-effect oracle.
# ---------------------------------------------------------------------------
def make_tools(sink: list) -> list[BaseTool]:
    @tool
    def web_search(query: str) -> str:
        """Search the web for `query` and return the results."""
        sink.append(("web_search", query))
        return f"3 results for {query!r}"

    @tool
    def write_brief(content: str) -> str:
        """Write the research brief."""
        sink.append(("write_brief", content))
        return "brief written"

    return [web_search, write_brief]


# ---------------------------------------------------------------------------
# The authority declarations — one map for the whole tree.
# ---------------------------------------------------------------------------
SUPERVISOR = Authority(
    scopes={"web.search", "brief.write"},
    ceilings=[RowLimit(50), EgressRank("any")], ttl=3600)

# What each subagent may REQUEST. The granted authority is always
# `meet(parent, request)`, so an over-broad request can never widen a narrow parent —
# `researcher` asks for `web.*`, 10,000 rows and a 9,999s ttl and gets none of it.
RESEARCHER_REQUEST = Authority(
    scopes={"web.*", "admin.export"},
    ceilings=[RowLimit(10_000), EgressRank("any")], ttl=9_999)
WRITER_REQUEST = Authority(
    scopes={"brief.write"},
    ceilings=[RowLimit(50), EgressRank("none")], ttl=900)

# The MAP says which scope a tool needs; the GUARD says whether this agent still holds it.
POLICIES = {
    "web_search": ToolPolicy("web.search", lambda a: {"egress": "internal", "rows": 10}),
    "write_brief": ToolPolicy("brief.write", lambda a: {"egress": "none"}),
}


# ---------------------------------------------------------------------------
# The scripts — the supervisor delegates twice; the writer takes the bait.
# ---------------------------------------------------------------------------
ATTACKER_QUERY = "site:exfil.example internal customer list"


def supervisor_script(*, spawn_researcher: bool = True) -> list:
    steps = []
    if spawn_researcher:
        steps.append(spawn("researcher", "Find three sources on the Q3 market.", "t1"))
    steps.append(spawn("writer", "Write the brief from the notes. Do not search.", "t2"))
    steps.append(AIMessage(content="Brief delivered."))
    return steps


def researcher_script() -> list:
    return [call("web_search", {"query": "q3 market outlook"}, "r1"),
            AIMessage(content="Found three sources.")]


def writer_script(*, search_attempts: int = 1, search_tool: str = "web_search") -> list:
    """The injection: the note the writer is handed tells it to search and send.
    The scripted model 'decides' to obey — that decision is the attack."""
    return ([call(search_tool, {"query": ATTACKER_QUERY}, f"w{i}") for i in range(search_attempts)]
            + [call("write_brief", {"content": "Q3 brief."}, "wb"),
               AIMessage(content="Brief written.")])


# ---------------------------------------------------------------------------
# Building the tree. `guarded=None` builds the unguarded control.
# ---------------------------------------------------------------------------
def build_agent(sink: list, *, guarded: GuardedDelegation | None = None,
                supervisor_tools: Sequence[str] = ("write_brief",),
                subagent_tools: Sequence[str] = ("web_search", "write_brief"),
                extra_tools: Sequence[BaseTool] = (),
                spawn_researcher: bool = True, search_attempts: int = 1,
                search_tool: str = "web_search",
                guard_subagents: Sequence[str] = ("researcher", "writer"),
                check: bool = True):
    """A supervisor with two subagents-as-tools, per LangChain's multi-agent guide.

    The supervisor is handed only `supervisor_tools`; each subagent spec lists
    `subagent_tools`. Nothing in the framework relates the two lists — that is the
    point of step [1], and the thing the guard middleware supplies in step [2].
    """
    by_name = {t.name: t for t in make_tools(sink)}
    by_name.update({t.name: t for t in extra_tools})
    mw = guarded.middleware() if guarded is not None else None

    def spec(name: str, description: str, model) -> dict:
        s: dict[str, Any] = {"name": name, "description": description,
                             "system_prompt": f"You are the {name}.", "model": model,
                             "tools": [by_name[n] for n in subagent_tools if n in by_name]}
        if mw is not None and name in guard_subagents:
            s["middleware"] = [mw]
        return s

    subagents = [spec("researcher", "Finds and cites sources.",
                      ScriptedModel(responses=researcher_script())),
                 spec("writer", "Writes the brief from notes.",
                      ScriptedModel(responses=writer_script(search_attempts=search_attempts,
                                                            search_tool=search_tool)))]
    sub_mw = SubAgentMiddleware(backend=StateBackend(), subagents=subagents)
    middleware = [sub_mw] + ([mw] if mw is not None else [])
    if check:
        require_guard(middleware, subagents)
    agent = create_agent(
        ScriptedModel(responses=supervisor_script(spawn_researcher=spawn_researcher)),
        tools=[by_name[n] for n in supervisor_tools if n in by_name],
        middleware=middleware)
    return agent, subagents


def new_chain(audit_path=None) -> tuple[Guard, GuardedDelegation]:
    root = Guard.issue("supervisor", SUPERVISOR, task="research brief", audit_path=audit_path)
    guarded = GuardedDelegation(
        root, tools=POLICIES,
        subagents={"researcher": RESEARCHER_REQUEST, "writer": WRITER_REQUEST},
        delegation_tool="task", subagent_arg="subagent_type", task_arg="description")
    return root, guarded


def is_guard_middleware(m: object) -> bool:
    return type(m).__module__ == _GUARD_MIDDLEWARE_MODULE and "DelegationGuard" in type(m).__qualname__


def require_guard(middleware: Iterable[object], subagents: Iterable[dict]) -> None:
    """Fail closed: refuse to build an agent whose supervisor — or any subagent — is ungated.

    A subagent runs its own agent loop, so the middleware must be installed on the
    subagent spec too. A spec without it is a hole, not a narrowing.
    """
    if not any(is_guard_middleware(m) for m in middleware):
        raise RuntimeError(
            "attenu-guard: the supervisor's middleware stack carries no delegation guard — "
            "refusing to run unguarded")
    for spec in subagents:
        if not any(is_guard_middleware(m) for m in spec.get("middleware") or []):
            raise RuntimeError(
                f"attenu-guard: subagent {spec['name']!r} has no delegation guard in its "
                "middleware list — refusing to run unguarded")


# ---------------------------------------------------------------------------
# Runs.
# ---------------------------------------------------------------------------
def run_unguarded(**kw) -> tuple[dict, list]:
    sink: list = []
    agent, _ = build_agent(sink, check=False, spawn_researcher=kw.pop("spawn_researcher", False), **kw)
    return agent.invoke({"messages": [("user", "Prepare the Q3 research brief.")]}), sink


def run_guarded(audit_path=None, **kw) -> tuple[dict, list, Guard, GuardedDelegation]:
    sink: list = []
    root, guarded = new_chain(audit_path)
    agent, _ = build_agent(sink, guarded=guarded, **kw)
    out = agent.invoke({"messages": [("user", "Prepare the Q3 research brief.")]})
    return out, sink, root, guarded


def denials(root: Guard) -> list[dict]:
    return [e for e in root.audit_log().entries if e["event"] == "deny"]


def decisions(root: Guard) -> list[tuple[str, str, str, str]]:
    """(event, tool, scope, reason) for every tool decision on the ledger."""
    return [(e["event"], e.get("tool") or "", e.get("scope") or "", e.get("reason") or "")
            for e in root.audit_log().entries if e["event"] in ("allow", "deny") and e.get("tool")]


# ---------------------------------------------------------------------------
def main() -> int:
    import importlib.metadata as md

    print(f"[1] langchain {md.version('langchain')} + deepagents {md.version('deepagents')}, no guard")
    print("    supervisor holds write_brief; the `writer` subagent's spec also lists web_search")
    try:
        import langchain.agents.middleware as lcm
        if any("subagent" in n.lower() for n in dir(lcm)):
            print("    langchain now ships a subagent middleware — the premise changed (see README: freshness).")
            return EXIT_PREMISE_CHANGED
    except ImportError:                                     # pragma: no cover - compatibility tier covers this
        print("    langchain.agents.middleware is not importable"); return EXIT_FAIL

    _, sink = run_unguarded()
    print(f"    writer's tool bodies that ran: {sink}")
    if not any(name == "web_search" for name, _ in sink):
        print("    the subagent's search did not run — a subagent's tools may now be constrained "
              "to the parent's (see README: freshness).")
        return EXIT_PREMISE_CHANGED

    print("\n[2] same tree, one more middleware — GuardedDelegation.middleware()")
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.jsonl"
        _out, sink, root, guarded = run_guarded(audit_path=log)
        researcher, writer = guarded.child("researcher"), guarded.child("writer")
        print(f"    researcher requested {sorted(RESEARCHER_REQUEST.scopes)}, "
              f"{RESEARCHER_REQUEST.ceiling('max_rows').max_rows} rows, ttl {RESEARCHER_REQUEST.ttl}")
        print(f"    researcher GRANTED   {sorted(researcher.authority.scopes)}, "
              f"{researcher.authority.ceiling('max_rows').max_rows} rows, ttl {researcher.authority.ttl}")
        print(f"    writer     GRANTED   {sorted(writer.authority.scopes)}")
        print(f"    researcher ⊆ supervisor: {researcher.is_narrower_than(root)} · "
              f"writer ⊆ supervisor: {writer.is_narrower_than(root)}")
        print("    decisions on the ledger (a subagent's transcript is collapsed into one")
        print("    ToolMessage for the supervisor, so the ledger is where its calls surface):")
        for event, tool_name, scope, reason in decisions(root):
            print(f"      {'ALLOW ' if event == 'allow' else 'DENY  '} {tool_name:<12} scope={scope}"
                  + (f"  ({reason})" if reason else ""))
        print(f"    the writer's search never ran; tool bodies that ran: {sink}")

        denied = denials(root)
        search_ctx = {"egress": "internal", "rows": 10}
        ok = (sink == [("web_search", "q3 market outlook"), ("write_brief", "Q3 brief.")]
              and researcher.is_narrower_than(root) and writer.is_narrower_than(root)
              and researcher.authority.scopes == {"web.search"}
              and researcher.authority.ceiling("max_rows").max_rows == 50
              and any(e.get("tool") == "web_search" for e in denied)
              and bool(researcher.would_allow("web.search", context=search_ctx))
              and not writer.would_allow("web.search", context=search_ctx))

        print("\n[3] evidence")
        entries = root.audit_log().entries
        chain_ok, err = AuditLog.verify(entries)
        print(f"    hash chain verifies: {chain_ok} ({len(entries)} events, {log.name}) {err or ''}")
        # Ed25519, not a shared-secret HS256 test signer: a recipe that demonstrates "anyone can
        # verify this offline" while signing with a symmetric key would be teaching the wrong
        # thing -- anyone who CAN verify a symmetric-key signature can also forge one. Ed25519 is
        # public-key: a verifier only ever needs the public half. Verified through the packaged
        # `attenu-guard verify` CLI -- the same command a reader would actually run.
        signer = Ed25519Signer.generate(kid="demo")
        pubkey = signer.public_bytes_raw().hex()
        bundle = evidence.export_bundle(root.audit_log(), signer)
        bundle_path = Path(td) / "evidence-bundle.json"
        bundle_path.write_text(json.dumps(bundle, indent=2))
        print(f"    verifying with the packaged command: attenu-guard verify "
              f"{bundle_path.name} --pubkey {pubkey[:16]}…")
        try:
            verify_rc = attenu_guard_cli(["verify", str(bundle_path), "--pubkey", pubkey])
        except SystemExit as exc:
            # A bare sys.exit() carries code=None, which Python treats as success (exit status
            # 0) -- mirror that here so the `ok` check below agrees with process exit semantics.
            verify_rc = 0 if exc.code is None else (exc.code if isinstance(exc.code, int) else 1)
        # the except branch above already maps a bare sys.exit() to 0, so None is unreachable
        ok = bool(ok) and chain_ok and verify_rc == 0

    print("\nRESULT:", "OK" if ok else "FAIL")
    return EXIT_OK if ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
