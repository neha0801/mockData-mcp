# Security

## Reporting

Report suspected leaks or vulnerabilities privately to the repository owner and
InfoSec. Do not open a public issue, and do not paste suspected real data into
issues, PRs, commits or chat with an AI assistant.

## Rules for this repository

- No real data, credentials, connection strings with passwords, or production
  hostnames are ever committed. The server's config file refuses secret keys.
- Test fixtures use synthetic **canary** values only.
- The MCP server code is changed only through reviewed pull requests.

## Required branch protection on `main`

GitHub → Settings → Branches (or Rules → Rulesets) → `main`:

- Require a pull request before merging; at least 1 approval.
- Require review from Code Owners (see [CODEOWNERS](CODEOWNERS)).
- Dismiss stale approvals when new commits are pushed.
- Require status checks to pass: `lint`, `unit`, `integration`.
- Require branches to be up to date before merging.
- Block force pushes and deletions; include administrators.
- Optional but recommended: require signed commits.

Replace the placeholder owner in `CODEOWNERS` with the InfoSec reviewers' team
once it exists, so `mcp-server/` and `shared/` changes always need their approval.

## Residual risk

See [docs/threat-model.md](docs/threat-model.md). InfoSec accepts it before
the first connection to a dev database.
