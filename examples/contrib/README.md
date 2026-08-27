# Samples written for other people's repositories

Each directory here is a self-contained sample built to the contribution
rules of the repository named in its path, and kept in this repository so
it is versioned, tested and reviewable alongside the library. The
contents of each leaf directory are meant to be copied across verbatim.

| Directory | Written for | Lands at |
|---|---|---|
| `adk-samples/attenu-guard/` | [google/adk-samples](https://github.com/google/adk-samples) | `contrib/python/attenu-guard/` |
| `agentcore-samples/attenu-guard/` | [awslabs/agentcore-samples](https://github.com/awslabs/agentcore-samples) | `03-integrations/agentic-frameworks/strands-agents/attenu-guard/` |

Both run offline by default, with a scripted model in place of a real
one, so neither needs an API key, a cloud account or a network
connection. Each carries its own README, tests and dependency manifest in
the shape its target repository expects — a `manifest.yaml`,
`pyproject.toml` and `uv.lock` for adk-samples; a `requirements.txt` and
an `agentcore` entrypoint for agentcore-samples.

Neither has been submitted upstream. Both target repositories require a
Contributor Licence Agreement and their own review; read their
`CONTRIBUTING.md` before opening anything.
