# scenarios/ — declarative authorization scenarios

A scenario file describes a delegation tree (who delegates to whom, and how
each delegation attenuates authority) plus a list of assertions ("this
node, checking this scope in this context, must allow/deny — and if it
denies, for exactly this reason"). It's run by `attenu_guard.scenarios`:

```bash
PYTHONPATH=src python3 -m attenu_guard.scenarios scenarios/crm_summarizer.json
PYTHONPATH=src python3 -m attenu_guard.scenarios scenarios/crm_summarizer.json --coverage
```

Exit code is `0` iff every assertion in every file given passed. `--coverage`
additionally prints which `ReasonCode` values (from `attenu_guard.ReasonCode`
— `scope_not_granted`, `ceiling_exceeded`, `expired`, `revoked`, ...) were
actually exercised by the file(s), so you can see at a glance which denial
paths your scenario suite does and doesn't cover.

This directory ships two copies of the same scenario — the worked example
from `docs/DEVX-REVIEW.md` (planner delegates a read-only, row-capped task to
a summarizer):

- **`crm_summarizer.json`** — stdlib-only, always loadable.
- **`crm_summarizer.yaml`** — identical content, YAML; requires `pyyaml`
  (`pip install pyyaml`). `attenu_guard.scenarios` imports `yaml` lazily,
  only when a `.yaml`/`.yml` file is actually loaded, so the library never
  requires it and gives you a clear "install pyyaml or use JSON" error if
  you point it at a `.yaml` file without PyYAML installed.

## Why this doubles as three things at once

1. **A DevX onboarding artifact.** New users read (or write) a scenario file
   to understand a policy before touching a line of Python — copy the
   `crm_summarizer` example, change the scopes/ceilings/assertions, run it.
2. **A living authorization test.** Check scenario files into your own repo
   next to the code they protect and run them in CI
   (`python3 -m attenu_guard.scenarios policies/*.json` — non-zero exit
   fails the build) the same way you'd run any other regression test — except
   the "test" is a policy fixture a security reviewer can read without
   knowing Python.
3. **An IETF-interop-adjacent fixture.** Every `expect: deny` with a
   `because:` is a MUST-be-rejected test vector in the sense
   `docs/STANDARDS-ALIGNMENT.md` and the Internet-Draft
   (`docs/draft-asor-wimse-agent-delegation-chain-00.md`) care about — a
   scope-widening attempt, an exceeded ceiling, an unrecognised constraint —
   expressed independently of Python, the same shape an offline verifier in
   any language would need to reject.

## Schema

```jsonc
{
  "root": {
    "agent": "planner",                 // required: the root agent id
    "authority": {                      // required (may be {})
      "scopes": ["crm.read", "crm.write"],
      "ceilings": [{"key": "max_rows", "max": 1000}],
      "ttl": 3600                       // seconds; omit for unbounded (discouraged)
    },
    "task": "root"                      // optional, defaults to "root"
    // optional, advanced: "chain_id", "max_depth", "max_fanout"
    // (same meaning as the matching Guard.issue() keyword)
  },

  "delegations": [
    {
      "as": "summarizer",               // required: this node's name, used
                                         // in later "from"/"node" references
                                         // and in reports
      "from": "root",                   // optional, defaults to "root";
                                         // must name "root" or an earlier
                                         // delegations[].as (file order)
      "agent": "summarizer-agent",      // optional, defaults to the "as" name
      "task": "summarize",              // optional, defaults to the "as" name
      "attenuate": {                    // required (may be {}): the
                                         // REQUESTED authority passed to
                                         // Guard.delegate() -- the actual
                                         // grant is parent.authority.meet()
                                         // of this, so it can only narrow,
                                         // never widen, whatever it asks for
        "scopes": ["crm.read"],
        "ceilings": [{"key": "max_rows", "max": 100}]
      }
    }
  ],

  "assertions": [
    {
      "node": "summarizer",             // required: "root" or a delegations[].as
      "check": {
        "scope": "crm.read",            // required
        "context": {"rows": 50},        // optional, default {}
        "tool": "sql"                   // optional
      },
      "expect": "allow",                // required: "allow" | "deny"
      "because": "scope_not_granted"    // optional; only checked when
                                         // expect == "deny" -- must equal
                                         // decision.reasons[0].code
    }
  ]
}
```

`"ceilings"` entries are ceiling **wire objects** — exactly what
`Authority.to_wire()["constraints"]` emits and `ceilings.ceiling_from_wire`
consumes, e.g. `{"key": "max_rows", "max": 1000}`,
`{"key": "egress", "rank": "none"}`, or a generic
`{"key": "region", "type": "allow", "one_of": ["eu", "us"]}`. An entry whose
`key`/`type` this build doesn't recognise still loads — it becomes an
always-denying placeholder (fail-closed, per the constraint vocabulary in
the Internet-Draft), so a typo in a ceiling shows up as an unexpected
`unknown_constraint` denial in the report rather than a crash or a silently
unenforced ceiling.

YAML files use the identical shape (YAML is just another syntax for the same
tree/mapping/list values) — see `crm_summarizer.yaml` for a fully worked
example, including notes on two places it deliberately differs from the
early sketch in `docs/DEVX-REVIEW.md` (ceilings as a list, not a
`{max_rows: N}` shorthand; ttl as plain seconds, not a `"1h"` string) to
match the authoritative schema in `docs/V0.2-SPEC.md`.

## A scenario assertion, precisely

An assertion **passes** iff:

1. `bool(decision) == (expect == "allow")`, **and**
2. if `expect == "deny"` **and** `because` was given, then
   `decision.reasons[0].code == because`.

(`because` on an `expect: allow` assertion is meaningless and ignored — an
allow carries no reasons to check it against.)

## Programmatic use

For anything more dynamic than a file — building a scenario in memory, or
needing to advance a clock or revoke a node mid-scenario (time- and
revocation-based outcomes aren't expressible as static file content) — use
the composable pieces `run_scenarios()` is built from directly:

```python
from attenu_guard.scenarios import build_tree, run_assertions, run_scenarios

# run_scenarios() also accepts an already-parsed dict, not just a path:
result = run_scenarios({"root": {...}, "delegations": [...], "assertions": [...]})
print(result.format_report())
assert result.ok

# lower-level: build the tree, mutate it, THEN assert
nodes = build_tree(spec)
nodes["summarizer"].revoke()
outcomes = run_assertions(nodes, [
    {"node": "summarizer", "check": {"scope": "crm.read"},
     "expect": "deny", "because": "revoked"},
])
```

See `tests/test_scenarios.py` for full worked examples, including
ceiling-exceeded, scope-not-granted, revoked, and expired cases.
