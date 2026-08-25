#!/usr/bin/env python3
"""attenu-guard as a Claude Code hook — the receipt for what subagents were allowed to do.

Claude Code already narrows subagents: `tools:` / `disallowedTools:` in a subagent's
frontmatter, `Agent(name)` to restrict spawning, `mcpServers` scoped per subagent, and
session-wide hooks that fire inside subagents too. That narrowing is the first line and
it stays the first line. This script adds three things Claude Code's own configuration
does not carry:

  1. DERIVED — every permission set here is computed from the project's declared
     structure (`.claude/agents/*.md` frontmatter and `.claude/settings.json`
     `permissions`), never written a second time by hand. Each subagent's Authority is
     `meet(root, derived)`, so a subagent can never hold more than the session root.
  2. RECORDED — every PreToolUse decision, allow or deny, is appended to a hash-chained
     ledger under the project's `.attenu/`. Each hook invocation is a fresh process, so
     the ledger is reloaded and re-verified on every call, and appended under a file lock.
  3. VERIFIABLE — at SubagentStop / SessionEnd the ledger is exported as a signed
     evidence bundle that a third party checks with `attenu_guard.evidence.verify_bundle`
     (integrity, child-subset-of-parent, containment) without this script, this project,
     or any service.

This is a SECOND, INDEPENDENT check. Claude Code's own allowlist decides first; a call it
already refuses never reaches a tool body regardless of what happens here. What this adds
is the record — and a decision derived from the same declaration, so the two cannot drift.

Verified against the Claude Code docs on 2026-08-25:
  https://code.claude.com/docs/en/hooks       — event names, stdin JSON, return JSON, exit codes
  https://code.claude.com/docs/en/sub-agents  — frontmatter fields, tool resolution, hooks in subagents
  https://code.claude.com/docs/en/settings    — settings precedence, `permissions`, `hooks`
The exact fields relied on are pinned in `contract.json` next to this file.

Install (see README.md and settings.snippet.json):

    {"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/attenu_hook.py"}]}]}}

Run standalone (what demo.py does):

    echo '{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"...","tool_name":"Read",
           "tool_input":{"file_path":"a.py"},"agent_type":"reviewer","agent_id":"a1"}' | python3 hook.py

Stdlib + attenu_guard only. No network. Exit code is always 0: the decision is carried in
the JSON on stdout, which is what the documented contract asks for (exit 2 would also block,
but it cannot carry a structured reason).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

from attenu_guard import Authority, AuditLog, Disposition, Guard, ReasonCode
from attenu_guard import evidence
from attenu_guard.audit import GENESIS, _hash as _chain_hash

try:                                                     # POSIX advisory locking; absent on Windows
    import fcntl
except ImportError:                                      # pragma: no cover - platform fallback
    fcntl = None                                         # type: ignore[assignment]

__all__ = [
    "AgentSpec", "Roster", "Ledger", "LedgerError",
    "parse_frontmatter", "scope_for_tool", "scopes_for_declaration", "resolve_agent_scopes",
    "derive_roster", "find_project_root", "decide", "handle", "require_hook_installed",
    "export_evidence", "signer_for", "SCOPE_MAP", "DOC_SOURCES",
]

# --------------------------------------------------------------------------------------
# The documented contract this script reads and writes (pinned; see contract.json)
# --------------------------------------------------------------------------------------
DOC_SOURCES = {
    "hooks": "https://code.claude.com/docs/en/hooks",
    "sub_agents": "https://code.claude.com/docs/en/sub-agents",
    "settings": "https://code.claude.com/docs/en/settings",
    "verified_on": "2026-08-25",
}

#: Hook events this script handles. `PreToolUse` is the only one whose JSON output is a
#: decision; the docs state SubagentStart's JSON output is ignored and SubagentStop is
#: non-blocking, so those two are used for their side effects (structure and export) only.
HANDLED_EVENTS = ("PreToolUse", "SubagentStart", "SubagentStop", "SessionEnd")

#: Fields read from the stdin payload, per the hooks doc.
INPUT_FIELDS = ("session_id", "transcript_path", "cwd", "permission_mode", "hook_event_name",
                "tool_name", "tool_input", "tool_use_id", "agent_id", "agent_type")

#: Fields written to stdout, per the hooks doc.
OUTPUT_FIELDS = ("hookSpecificOutput", "hookEventName", "permissionDecision",
                 "permissionDecisionReason", "systemMessage")

#: The built-in tool called to spawn a subagent. Renamed from "Task" to "Agent" in
#: Claude Code v2.1.63; both names are recognised because the old one still appears in
#: older transcripts and tool lists.
DELEGATION_TOOLS = ("Agent", "Task")


# --------------------------------------------------------------------------------------
# 1. Tool name -> scope. A total function: an unknown tool gets a scope nobody declared,
#    which is therefore held by nobody and denied by default.
# --------------------------------------------------------------------------------------
SCOPE_MAP: dict[str, str] = {
    "Read": "fs.read",
    "Glob": "fs.glob",
    "Grep": "fs.grep",
    "Write": "fs.write",
    "Edit": "fs.edit",
    "MultiEdit": "fs.edit",
    "NotebookEdit": "fs.notebook_edit",
    "Bash": "exec.bash",
    "BashOutput": "exec.bash_output",
    "KillShell": "exec.kill",
    "WebFetch": "net.fetch",
    "WebSearch": "net.search",
    "TodoWrite": "session.todo",
    "Skill": "session.skill",
    "SlashCommand": "session.slash_command",
    "SendMessage": "agent.message",
}


def _mcp_scope(name: str) -> str | None:
    """`mcp__server__tool` -> `mcp.server.tool`; `mcp__server` -> `mcp.server.*`; `mcp__*` -> `mcp.*`."""
    if not name.startswith("mcp__"):
        return None
    rest = name[len("mcp__"):]
    if rest in ("*", ""):
        return "mcp.*"
    server, _, tool = rest.partition("__")
    if not tool or tool == "*":
        return f"mcp.{server}.*"
    return f"mcp.{server}.{tool}"


def scope_for_tool(tool_name: str, tool_input: Mapping[str, Any] | None = None) -> str:
    """The scope a live tool CALL is checked against."""
    mcp = _mcp_scope(tool_name)
    if mcp is not None:
        return mcp
    if tool_name in DELEGATION_TOOLS:
        subagent = str((tool_input or {}).get("subagent_type") or "").strip()
        return f"agent.delegate.{subagent}" if subagent else "agent.delegate"
    return SCOPE_MAP.get(tool_name, f"tool.{tool_name}")


_DECL_RE = re.compile(r"^\s*([A-Za-z0-9_*]+)\s*(?:\((?P<args>.*)\))?\s*$")


def scopes_for_declaration(entry: str) -> tuple[set[str], str | None]:
    """One DECLARED tool entry -> (scopes, unrepresented_note).

    Declarations come from `tools:` / `disallowedTools:` frontmatter and from
    `permissions.allow` / `permissions.deny` in settings.json. Bare names and
    `Agent(a, b)` are represented exactly. An argument-scoped rule such as
    `Bash(npm run lint)` or `Read(./.env)` is NOT folded in at tool granularity: reading
    it as a bare `Bash` grant would widen it, and reading a bare `Read` denial from
    `Read(./.env)` would narrow more than the operator wrote. Those rules stay Claude
    Code's to enforce and are reported here as unrepresented, never guessed at.
    """
    entry = entry.strip()
    if not entry:
        return set(), None
    mcp = _mcp_scope(entry)
    if mcp is not None:
        return {mcp}, None
    m = _DECL_RE.match(entry)
    if not m:
        return set(), f"{entry} (unparsed rule)"
    name, args = m.group(1), m.group("args")
    if name in DELEGATION_TOOLS:
        if args is None or not args.strip():
            return {"agent.delegate.*"}, None
        types = [t.strip() for t in args.split(",") if t.strip()]
        return {f"agent.delegate.{t}" for t in types}, None
    if args is not None and args.strip():
        # argument-scoped rule — representable only by Claude Code's own matcher
        return set(), entry
    return {scope_for_tool(name)}, None


def _covers(pattern: str, scope: str) -> bool:
    """Does a declared scope pattern cover a concrete scope? Mirrors Authority's `x.*` rule."""
    if pattern == scope:
        return True
    if pattern.endswith(".*"):
        return scope.startswith(pattern[:-1])
    return False


def _subtract(scopes: Iterable[str], patterns: Iterable[str]) -> set[str]:
    """Remove every scope covered by any pattern. Pattern-aware on purpose: an exact-string
    difference would leave `mcp.github.create_issue` in place under a `mcp.*` denial."""
    pats = list(patterns)
    return {s for s in scopes if not any(_covers(p, s) for p in pats)}


# --------------------------------------------------------------------------------------
# 2. Frontmatter — a minimal, total parser for the documented subagent fields.
# --------------------------------------------------------------------------------------
def parse_frontmatter(text: str) -> dict[str, Any]:
    """Parse the YAML frontmatter block of a subagent file.

    Handles exactly what the documented fields need: `key: scalar`, `key: a, b, c` inline
    lists, and `key:` followed by `  - item` block lists. Any nested mapping (for example
    an inline `mcpServers` definition) is skipped rather than half-parsed — this script
    only derives from `tools`, `disallowedTools` and `name`, and a field it cannot read
    is never treated as a grant.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    body: list[str] = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        body.append(line)
    out: dict[str, Any] = {}
    i = 0
    while i < len(body):
        raw = body[i]
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[:1] in (" ", "\t"):                      # continuation of a block we already consumed
            continue
        key, sep, value = raw.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if value:
            out[key] = value
            continue
        items: list[str] = []
        while i < len(body) and (not body[i].strip() or body[i][:1] in (" ", "\t")):
            item = body[i].strip()
            i += 1
            if item.startswith("- "):
                inner = item[2:].strip()
                if not inner.endswith(":"):             # skip a nested mapping under a list item
                    items.append(inner)
        out[key] = items
    return out


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [p.strip() for p in str(value).split(",") if p.strip()]


# --------------------------------------------------------------------------------------
# 3. Derivation — the project's declared structure becomes Authorities.
# --------------------------------------------------------------------------------------
class AgentSpec:
    """One declared subagent, as read from its file."""

    __slots__ = ("name", "path", "tools", "disallowed", "description")

    def __init__(self, name: str, path: Path, tools: list[str] | None,
                 disallowed: list[str], description: str) -> None:
        self.name = name
        self.path = path
        self.tools = tools                       # None means "inherits the session pool"
        self.disallowed = disallowed
        self.description = description

    def declaration(self) -> dict[str, Any]:
        return {"name": self.name, "tools": self.tools, "disallowedTools": self.disallowed}


def resolve_agent_scopes(spec: AgentSpec, session_pool: set[str]) -> tuple[set[str], list[str]]:
    """Claude Code's documented resolution order, in scope space.

    From the sub-agents doc: "`disallowedTools` is applied first (removes from default
    pool); then `tools` is resolved against the remaining pool; a tool listed in both is
    removed." With `tools` omitted the subagent inherits the pool.
    """
    unrepresented: list[str] = []
    denied: set[str] = set()
    for entry in spec.disallowed:
        s, note = scopes_for_declaration(entry)
        denied |= s
        if note:
            unrepresented.append(f"{spec.name}: disallowedTools {note}")
    pool = _subtract(session_pool, denied)
    if spec.tools is None:
        return pool, unrepresented
    declared: set[str] = set()
    for entry in spec.tools:
        s, note = scopes_for_declaration(entry)
        declared |= s
        if note:
            unrepresented.append(f"{spec.name}: tools {note}")
    return _subtract(declared, denied), unrepresented


class Roster:
    """The derived permission sets for one project, plus the digest that identifies them.

    `root` is the session's authority: the union of everything the declared subagents may
    hold, plus the operator's own bare-name `permissions.allow` entries, plus one
    `agent.delegate.<name>` scope per declared agent — minus every bare-name
    `permissions.deny` entry. The union matters: a parent cannot delegate what it does
    not hold, so the root must hold the families of its own delegation subtree or
    `meet()` would strip every subagent down to nothing.
    """

    def __init__(self, project_dir: Path, agents: dict[str, AgentSpec],
                 allow: list[str], deny: list[str]) -> None:
        self.project_dir = project_dir
        self.agents = agents
        self.unrepresented: list[str] = []

        operator_allow: set[str] = set()
        for entry in allow:
            s, note = scopes_for_declaration(entry)
            operator_allow |= s
            if note:
                self.unrepresented.append(f"settings permissions.allow {note}")
        operator_deny: set[str] = set()
        for entry in deny:
            s, note = scopes_for_declaration(entry)
            operator_deny |= s
            if note:
                self.unrepresented.append(f"settings permissions.deny {note}")

        # Pass 1: what each agent declares for itself, independent of any pool.
        declared: dict[str, set[str]] = {}
        for name, spec in agents.items():
            if spec.tools is None:
                declared[name] = set()               # inherits; resolved in pass 2
            else:
                scopes, notes = resolve_agent_scopes(spec, set())
                declared[name] = scopes
                self.unrepresented += notes

        pool = set(operator_allow)
        for scopes in declared.values():
            pool |= scopes
        pool |= {f"agent.delegate.{name}" for name in agents}
        pool = _subtract(pool, operator_deny)
        self.root_scopes = pool

        # Pass 2: each agent against the resolved pool (this is where an inheriting agent
        # and every `disallowedTools` entry actually land).
        self.agent_scopes: dict[str, set[str]] = {}
        for name, spec in agents.items():
            scopes, notes = resolve_agent_scopes(spec, pool)
            self.agent_scopes[name] = _subtract(scopes, operator_deny)
            if spec.tools is None:
                self.unrepresented += notes

        self.unrepresented = sorted(set(self.unrepresented))

    # ---- authorities -------------------------------------------------------------
    def root_authority(self) -> Authority:
        return Authority(scopes=frozenset(self.root_scopes))

    def agent_authority(self, name: str) -> Authority | None:
        scopes = self.agent_scopes.get(name)
        return None if scopes is None else Authority(scopes=frozenset(scopes))

    def digest(self) -> str:
        """A stable fingerprint of the derivation. It goes into the chain id, so a mid-session
        edit to an agent file starts a visibly different chain in the same ledger rather than
        silently continuing under permissions that no longer match the files."""
        body = json.dumps(
            {"root": sorted(self.root_scopes),
             "agents": {k: sorted(v) for k, v in sorted(self.agent_scopes.items())}},
            sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    def summary(self) -> dict[str, Any]:
        return {"root": sorted(self.root_scopes),
                "agents": {k: sorted(v) for k, v in sorted(self.agent_scopes.items())},
                "unrepresented": list(self.unrepresented),
                "digest": self.digest()}


def find_project_root(start: str | Path) -> Path:
    """Walk up from `start` looking for a `.claude` directory, the way Claude Code discovers
    project subagents. Falls back to `start` itself."""
    p = Path(start).resolve()
    for candidate in (p, *p.parents):
        if (candidate / ".claude").is_dir():
            return candidate
    return p


def _read_settings(project_dir: Path) -> tuple[list[str], list[str]]:
    """`permissions.allow` / `permissions.deny` from `.claude/settings.json` and
    `.claude/settings.local.json` (local overlays, so its entries are merged on top)."""
    allow: list[str] = []
    deny: list[str] = []
    for name in ("settings.json", "settings.local.json"):
        path = project_dir / ".claude" / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue                                    # an unreadable settings file grants nothing
        perms = data.get("permissions") or {}
        allow += [str(x) for x in (perms.get("allow") or [])]
        deny += [str(x) for x in (perms.get("deny") or [])]
    return allow, deny


def derive_roster(project_dir: str | Path) -> Roster:
    """Read `.claude/agents/*.md` and `.claude/settings.json` and compute every permission set."""
    root = Path(project_dir)
    agents: dict[str, AgentSpec] = {}
    agents_dir = root / ".claude" / "agents"
    if agents_dir.is_dir():
        for path in sorted(agents_dir.rglob("*.md")):
            try:
                fm = parse_frontmatter(path.read_text(encoding="utf-8"))
            except OSError:
                continue
            name = str(fm.get("name") or path.stem).strip()
            if not name:
                continue
            tools = _as_list(fm["tools"]) if "tools" in fm else None
            agents[name] = AgentSpec(name, path, tools,
                                     _as_list(fm.get("disallowedTools")),
                                     str(fm.get("description") or ""))
    allow, deny = _read_settings(root)
    return Roster(root, agents, allow, deny)


# --------------------------------------------------------------------------------------
# 4. The ledger — file-backed, hash-chained, reloaded and re-verified every invocation.
# --------------------------------------------------------------------------------------
class LedgerError(RuntimeError):
    """The ledger could not be read, verified, or written. Always fails the call closed."""


_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_session_name(session_id: str) -> str:
    """A session id arrives in the hook payload; it must never be able to steer a write out
    of `.attenu/`. Everything outside `[A-Za-z0-9_.-]` is replaced and the result is
    truncated, so `../../etc/passwd` becomes a flat, harmless file name."""
    cleaned = _SAFE.sub("_", str(session_id or "session"))[:64]
    return cleaned or "session"


class Ledger:
    """One hash-chained JSONL file, shared by every hook process in a session.

    Each hook invocation is a fresh process, so nothing can be held in memory between
    calls. The sequence is: take an exclusive lock, load and verify the whole chain,
    re-chain the new entries onto its head, append, release. A chain that does not verify
    on load is not appended to — the call is denied instead.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh = None

    # ---- locking ----------------------------------------------------------------
    def __enter__(self) -> "Ledger":
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path.parent / (self.path.name + ".lock"), "a+")
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            raise LedgerError(f"cannot lock the ledger at {self.path.name}: {exc}") from exc
        return self

    def __exit__(self, *exc_info) -> None:
        if self._fh is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None

    # ---- read / write -----------------------------------------------------------
    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise LedgerError(f"cannot read the ledger: {exc}") from exc
        entries = []
        for i, line in enumerate(raw.splitlines()):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise LedgerError(f"ledger line {i + 1} is not valid JSON: {exc}") from exc
        ok, why = AuditLog.verify(entries)
        if not ok:
            raise LedgerError(f"ledger chain does not verify: {why}")
        return entries

    @staticmethod
    def rechain(new_entries: list[dict], prev_hash: str, next_seq: int) -> list[dict]:
        """Renumber and re-hash `new_entries` so they continue an existing chain.

        The Guard writes into a fresh in-memory AuditLog that always starts at GENESIS with
        seq 0. Re-chaining is not tampering — no field of an entry is changed except the two
        that express its position in the chain, and the hash is recomputed over the result.
        """
        out = []
        prev = prev_hash
        seq = next_seq
        for entry in new_entries:
            e = {k: v for k, v in entry.items() if k != "hash"}
            e["seq"] = seq
            e["prev_hash"] = prev
            e["hash"] = _chain_hash(prev, e)
            prev = e["hash"]
            seq += 1
            out.append(e)
        return out

    def append(self, entries: list[dict], existing: list[dict]) -> list[dict]:
        if not entries:
            return []
        prev = existing[-1]["hash"] if existing else GENESIS
        seq = existing[-1]["seq"] + 1 if existing else 0
        chained = self.rechain(entries, prev, seq)
        try:
            with self.path.open("a", encoding="utf-8") as f:
                for e in chained:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as exc:
            raise LedgerError(f"cannot write the ledger: {exc}") from exc
        return chained


# --------------------------------------------------------------------------------------
# 5. Signing — a project-local anchor key for the evidence bundle.
# --------------------------------------------------------------------------------------
def signer_for(attenu_dir: Path):
    """The anchor signer for this project, created on first use under `.attenu/`.

    With `attenu-guard[crypto]` installed this is an Ed25519 key and the public half is
    written to `anchor.pub`, so a reviewer verifies the bundle holding only the public
    key. Without it, an HMAC key is used and verification needs that shared key — the
    bundle records which, so nobody has to guess.
    """
    attenu_dir.mkdir(parents=True, exist_ok=True)
    key_path = attenu_dir / "anchor.key"
    stored = None
    if key_path.exists():
        try:
            stored = json.loads(key_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            stored = None

    def _write(alg: str, raw: bytes) -> None:
        key_path.write_text(json.dumps({"alg": alg, "kid": KID, "key": raw.hex()}), encoding="utf-8")
        os.chmod(key_path, 0o600)

    KID = "attenu-local-1"
    if stored is None or stored.get("alg") == "EdDSA":
        try:
            from attenu_guard.wire import Ed25519Signer              # needs `cryptography`
            if stored is not None:
                signer = Ed25519Signer.from_private_bytes(bytes.fromhex(stored["key"]), kid=KID)
            else:
                signer = Ed25519Signer.generate(kid=KID)
                _write("EdDSA", signer.private_bytes_raw())
            (attenu_dir / "anchor.pub").write_text(
                json.dumps({"alg": "EdDSA", "kid": signer.kid,
                            "public_key": signer.public_bytes_raw().hex()}), encoding="utf-8")
            return signer
        except Exception:                                            # noqa: BLE001 - no cryptography -> HMAC
            if stored is not None:
                raise                                                # an EdDSA key exists but cannot be loaded
    from attenu_guard.wire import HS256TestSigner
    if stored is not None and stored.get("alg") == "HS256":
        raw = bytes.fromhex(stored["key"])
    else:
        raw = os.urandom(32)
        _write("HS256", raw)
    return HS256TestSigner(raw, kid=KID)


def export_evidence(attenu_dir: Path, ledger_path: Path, out_path: Path | None = None) -> dict:
    """Export the ledger as a signed, offline-verifiable evidence bundle."""
    entries = AuditLog.load(ledger_path) if Path(ledger_path).exists() else []
    log = AuditLog()
    log._entries = list(entries)                     # a carrier for the entries; nothing is re-derived
    signer = signer_for(attenu_dir)
    bundle = evidence.export_bundle(log, signer)
    if out_path is not None:
        Path(out_path).write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return bundle


# --------------------------------------------------------------------------------------
# 6. Configuration
# --------------------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # observe: record only · shadow: evaluate the derived permissions, deny nothing ·
    # enforce: deny what is outside the derived permissions.
    "mode": "enforce",
    # Subagents are what this recipe narrows; the main thread's permissions are the
    # operator's own and are recorded, not enforced, unless this is turned on.
    "enforce_main_thread": False,
    # Write the evidence bundle when a subagent stops and when the session ends.
    "export_on_stop": True,
}


def read_config(attenu_dir: Path) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    path = attenu_dir / "config.json"
    if path.is_file():
        try:
            cfg.update(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass                                     # an unreadable config keeps the safe defaults
    return cfg


def require_hook_installed(project_dir: str | Path, *, hook_name: str = "attenu_hook.py") -> None:
    """Refuse to proceed unless this hook is actually wired into the project's settings.

    A hook that is not installed does not fail loudly: it simply never runs, and every tool
    call proceeds with no record at all. This is the `require_guard()` of the recipe — call
    it from a project's own start-up check. Note the honest boundary: the real gate is the
    presence of the entry in `settings.json`, which only Claude Code reads. This function
    tells an operator that the wiring is missing; it cannot make Claude Code call a hook.
    """
    root = Path(project_dir)
    for name in ("settings.json", "settings.local.json"):
        path = root / ".claude" / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for handler in (data.get("hooks") or {}).get("PreToolUse") or []:
            for hook in handler.get("hooks") or []:
                if hook_name in str(hook.get("command") or ""):
                    return
    raise RuntimeError(
        f"attenu-guard: no PreToolUse hook running {hook_name} is configured in "
        f".claude/settings.json — refusing to run unrecorded")


# --------------------------------------------------------------------------------------
# 7. The decision
# --------------------------------------------------------------------------------------
def _build_chain(roster: Roster, chain_id: str, log_path=None) -> tuple[Guard, dict[str, Guard]]:
    """Materialise the whole declared roster as a delegation chain, in a fixed order.

    Deterministic by construction: the same roster always yields the same node ids
    (`<chain_id>:n0`, `:n1`, ...), which is what lets a fresh process append to a ledger
    written by an earlier one and have the node references still line up.
    """
    root = Guard.issue("session", roster.root_authority(), task="claude-code session",
                       chain_id=chain_id, audit_path=log_path)
    children: dict[str, Guard] = {}
    for name in sorted(roster.agents):
        authority = roster.agent_authority(name)
        if authority is None:                          # unreachable; kept so the loop is total
            continue
        children[name] = root.delegate(name, authority, task=f"subagent:{name}")
    return root, children


def _disposition(scope: str, roster: Roster) -> str:
    """Held-or-over-reach, from the declared structure alone. `out_of_authority` means the
    project declares this capability somewhere but not for this agent; `unresolved` means
    nothing in the project declares it at all, so it is denied by default."""
    if any(_covers(s, scope) for s in roster.root_scopes):
        return Disposition.OUT_OF_AUTHORITY
    return Disposition.UNRESOLVED


def decide(payload: Mapping[str, Any], roster: Roster, root: Guard,
           children: Mapping[str, Guard], config: Mapping[str, Any]) -> tuple[bool, str, str]:
    """The whole policy decision, framework-free.

    Returns `(denied, reason, scope)`. Every allow and deny is written to the Guard's audit
    log by `check()`; the caller persists them.
    """
    tool_name = str(payload.get("tool_name") or "")
    tool_input = dict(payload.get("tool_input") or {})
    agent_type = payload.get("agent_type")
    scope = scope_for_tool(tool_name, tool_input)
    enforcing = config.get("mode") == "enforce"

    if not agent_type:
        # The main thread. Its permissions are the operator's own; recorded by default.
        decision = root.check(scope, context={"tool": tool_name}, tool=tool_name,
                              disposition=_disposition(scope, roster))
        if decision or not (enforcing and config.get("enforce_main_thread")):
            return False, "recorded", scope
        return True, decision.explain(), scope

    guard = children.get(str(agent_type))
    if guard is None:
        # A subagent the project does not declare holds no permissions at all. Fail closed.
        msg = (f"subagent {agent_type!r} is not declared in .claude/agents — "
               f"no permission set could be derived for it")
        root.record_denial(ReasonCode.NO_AUTHORITY, msg, scope=scope, tool=tool_name,
                           disposition=Disposition.UNRESOLVED)
        return (True, msg, scope) if enforcing else (False, f"shadow: {msg}", scope)

    decision = guard.check(scope, context={"tool": tool_name}, tool=tool_name,
                           disposition=_disposition(scope, roster))
    if decision:
        return False, f"{scope} is within {agent_type}'s derived permissions", scope
    reason = (f"{tool_name} needs {scope}, which is not in the permission set derived for "
              f"subagent {agent_type!r} from .claude/agents/. {decision.explain()}")
    return (True, reason, scope) if enforcing else (False, f"shadow: {reason}", scope)


def handle(payload: Mapping[str, Any], *, project_dir: str | Path | None = None) -> dict:
    """One hook invocation, start to finish. Returns the JSON to print on stdout."""
    event = str(payload.get("hook_event_name") or "")
    cwd = project_dir or os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or "."
    root_dir = find_project_root(cwd)
    attenu_dir = root_dir / ".attenu"
    config = read_config(attenu_dir)
    session = safe_session_name(payload.get("session_id"))
    ledger_path = attenu_dir / f"ledger-{session}.jsonl"

    if event not in HANDLED_EVENTS:
        return {}

    try:
        roster = derive_roster(root_dir)
        chain_id = f"cc-{session}-{roster.digest()[:8]}"

        if event in ("SubagentStop", "SessionEnd"):
            # Non-blocking events: the docs state JSON output is not a decision here, so
            # this is used for its side effect only.
            if config.get("export_on_stop") and ledger_path.exists():
                out = attenu_dir / f"bundle-{session}.json"
                bundle = export_evidence(attenu_dir, ledger_path, out)
                report = evidence.verify_bundle(bundle, signer_for(attenu_dir))
                return {"systemMessage":
                        f"attenu-guard: evidence bundle written to .attenu/{out.name} "
                        f"({len(bundle['entries'])} decisions, verifies={report['ok']})"}
            return {}

        with Ledger(ledger_path) as ledger:
            existing = ledger.load()
            structural_present = any(e.get("chain_id") == chain_id for e in existing)
            root, children = _build_chain(roster, chain_id)
            structural = len(root.audit_log().entries)   # root + one spawn per declared agent

            if event == "SubagentStart":
                # Cannot deny here (the docs state SubagentStart's JSON output is ignored),
                # so this only makes sure the derived structure is on the ledger before the
                # subagent's first tool call.
                new = [] if structural_present else root.audit_log().entries
                ledger.append(new, existing)
                if str(payload.get("agent_type") or "") not in children:
                    return {"systemMessage":
                            f"attenu-guard: subagent {payload.get('agent_type')!r} is not declared in "
                            f".claude/agents — every tool call it makes will be denied."}
                return {}

            denied, reason, scope = decide(payload, roster, root, children, config)
            entries = root.audit_log().entries
            new = entries[structural:] if structural_present else entries
            ledger.append(new, existing)

    except LedgerError as exc:
        # Fail closed: with no record, there is no allow. A denial the operator can read is
        # a better outcome than a tool call nobody can account for. Only PreToolUse carries a
        # decision, so on any other event this is reported rather than dressed up as one.
        return _fail(event, f"the decision could not be recorded ({exc}); denying rather than "
                            f"running an action that leaves no record")
    except Exception as exc:                                   # noqa: BLE001 - same rule
        return _fail(event, f"the derivation or the ledger failed ({type(exc).__name__}: {exc}); "
                            f"denying rather than running an unrecorded action")

    if denied:
        return _deny(reason)
    # Allow is silence. Returning an explicit "allow" would SKIP Claude Code's own remaining
    # permission machinery, which would make this hook widen the session instead of
    # recording it. `{}` means "attenu-guard has no objection"; the project's own rules and
    # the subagent's own tool list still apply on top.
    return {}


def _deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"attenu-guard: {reason}",
        },
        "systemMessage": "attenu-guard denied this call and recorded the denial in .attenu/.",
    }


def _fail(event: str, reason: str) -> dict:
    """A failure on the one event whose JSON is a decision becomes a denial; on the others —
    which the docs describe as non-blocking — it is reported and nothing is claimed."""
    if event == "PreToolUse":
        return _deny(reason)
    return {"systemMessage": f"attenu-guard: {reason}"}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--derive":                  # `hook.py --derive [project]` prints the derivation
        roster = derive_roster(find_project_root(argv[1] if len(argv) > 1 else "."))
        print(json.dumps(roster.summary(), indent=2))
        return 0
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        print(json.dumps(_deny(f"the hook payload was not valid JSON ({exc})")))
        return 0
    if not isinstance(payload, dict):
        print(json.dumps(_deny("the hook payload was not a JSON object")))
        return 0
    out = handle(payload)
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
