"""
adapters — thin, optional framework integrations for delegation-guard.

Each submodule here wraps ONE framework's node/tool-callable convention
around the core `Guard.check`/`Guard.enforce` surface (docs/DEVX-REVIEW.md
principle 7: "framework-agnostic core, thin adapters"). Today that's
`adapters.langgraph`; MCP and FastAPI are the natural next additions, and
would live at `adapters/mcp.py` / `adapters/fastapi.py` following the same
shape.

Two things make these genuinely "thin, optional extras" rather than a back
door that quietly drags a framework dependency into the core:

  * This package lives OUTSIDE `src/delegation_guard/` — a sibling of it,
    not a subpackage — so nothing in the installable core package ever
    imports `adapters`, regardless of what's installed. `delegation_guard`
    itself stays exactly as dependency-free with `adapters/` present as
    without it.
  * Each adapter submodule lazy-imports its target framework from inside
    the specific function/method that needs it (never at module import
    time), so `import adapters.langgraph` — and every bit of its
    authorization-wrapping logic — works with zero third-party packages
    installed. Only code paths that hand you back a *real* framework
    object need the framework itself, and only import it when called.
"""
