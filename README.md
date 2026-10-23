# mockdata-mcp

Tooling for QA testers and developers to generate **synthetic** test data for
regression and load testing, with the data contract inferred from code and from
dev-database **metadata**. No real data may reach the LLM or any external endpoint.

| Phase | What | Where | Status |
|---|---|---|---|
| 1 | Metadata-only SQL Server MCP server | [`mcp-server/`](mcp-server/) | Built, pending InfoSec review |
| 1 | Shared data-like pattern detectors | [`shared/dlp_patterns/`](shared/dlp_patterns/) | Built |
| 2 | Claude Code lockdown (permissions, hooks) | [`claude/`](claude/) | Not started |
| 3 | Data contract | [`contract/`](contract/) | Not started |
| 4 | QA test-data skill + deterministic generator | [`skill/`](skill/) | Not started |
| 5 | Pass-by-reference real-data features | — | Future |

Start with [docs/architecture.md](docs/architecture.md) and
[docs/threat-model.md](docs/threat-model.md).

## Quick start (development)

```bash
uv venv && source .venv/bin/activate        # or python -m venv
uv pip install -e shared/dlp_patterns -e "mcp-server[dev]"
cd mcp-server && pytest                     # unit tests, no database needed
```

Integration tests against a disposable SQL Server: see
[mcp-server/tests/integration/README.md](mcp-server/tests/integration/README.md).

## Governance

- InfoSec reviews the MCP server code and accepts the residual risk
  ([threat model](docs/threat-model.md)) before the first dev connection.
- Changes to `mcp-server/`, `shared/` and `claude/` require code-owner review;
  see [SECURITY.md](SECURITY.md) for the branch protection this relies on.
