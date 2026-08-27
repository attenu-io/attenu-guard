# An authorization adapter for Agent Framework's function middleware

We maintain [attenu-guard](https://github.com/attenu-io/attenu-guard) (Apache-2.0), a
library that enforces one rule across sub-agent delegation: a child's permissions must
be a subset of its parent's. We just added an Agent Framework adapter and wanted to
share what it hooks, in case the approach is useful or wrong.

**What it hooks.** `FunctionMiddleware.process` is the whole gate. The tool body is
reachable only through `final_wrapper` in `FunctionMiddlewarePipeline.execute`, so
returning without awaiting `call_next()` stops it before `FunctionTool.invoke`. Because
`Agent.as_tool()` returns a plain `FunctionTool` and each handoff edge is a
`handoff_to_<target>` tool, the same hook also covers delegation — the child's narrowed
permission set is minted there, before `self.run(...)` starts the sub-agent.

**Denial shape.** Default is `context.result`, so the model can react. `on_deny="failure"`
raises `MiddlewareFailure`; we avoid plain exceptions because the loop converts those
into tool-error results and keeps running.

**Log.** Every allow and deny lands in a hash-chained file that verifies with the
library absent.

Tested against 1.15.0; the demo and tests run offline with a scripted client. Notes on
sub-agent permissions: https://attenu.io/docs/sub-agent-permissions/

Two things we could not gate: hosted tools (filtered before the seam) and
`as_mcp_server()`, which calls `agent_tool.invoke` directly. Corrections welcome.
