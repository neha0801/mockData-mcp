# Architecture

## Goal

Generate synthetic regression and load-test data whose shape follows the real
data contract, without real data ever reaching the LLM or any external endpoint.

## Data flow

```
                      ┌──────────────────────── developer / QA workstation ────────────────────────┐
                      │                                                                             │
 Dev SQL Server ◄─────┼── sqlmeta-mcp (Phase 1) ◄── stdio ── Claude Code (locked down, Phase 2)     │
  (metadata reader:   │   fixed sys.* queries         ▲            │                                │
   VIEW DEFINITION,   │   scrub literals              │            │ reads code, DDL, XSD/JSON/Avro │
   DENY on schemas)   │   output check, audit log     │            ▼                                │
                      │                         PostToolUse   contract file (Phase 3, versioned)    │
                      │                         pattern check      │                                │
                      │                                            ▼                                │
                      │                          scenario catalogue → user confirms (Phase 4)       │
                      │                                            │                                │
                      │                                            ▼                                │
                      │      deterministic generator script ──► data/ output/ (agent cannot read)   │
                      │                    │                                                        │
                      │                    └──► summary only: paths, counts, pass/fail ──► agent    │
                      └─────────────────────────────────────────────────────────────────────────────┘
```

What crosses into the LLM context: code from this repo, **masked** catalog
metadata, the contract, the scenario catalogue, and generator summaries.
What never does: rows from any user table, literal values from database code,
generated data files.

## Layers of control for database access (Phase 1)

| # | Layer | Holds if… |
|---|---|---|
| 1 | Database principal: `VIEW DEFINITION` + `GRANT SELECT ON sys.sql_expression_dependencies`; `DENY` SELECT/INSERT/UPDATE/DELETE/EXECUTE/ALTER/REFERENCES on every user schema; no role membership | …everything in this repo is wrong |
| 2 | Only eight tools; none takes SQL; arguments are names only | …the client is malicious |
| 3 | Names validated, checked against the schema policy, then resolved to ids with a parameterised catalog lookup | …a name is crafted for injection |
| 4 | `query_guard`: only registered query objects run; each re-checked as catalog-only | …a future change adds a careless call |
| 5 | Static test with a real T-SQL parser over every query | …a future query reads a user table (CI fails) |
| 6 | Literal scrubber on all expression and module text | …database code embeds real values |
| 7 | Output check with `dlp_patterns` | …a value slips through 6 or sits in a name |
| 8 | PostToolUse hook re-scans every tool result (Phase 2) | …the server itself is compromised or buggy |
| 9 | Audit log of every call | detection, not prevention |

## Repository layout

```
mcp-server/            Phase 1 server (Python, MCP SDK 2.x, pyodbc)
shared/dlp_patterns/   detectors shared by the server and the Phase 2 hook
claude/                Phase 2: settings, hooks
contract/              Phase 3: contract schema and versioned contracts
skill/                 Phase 4: skill definition and generator
docs/                  architecture, threat model, ADRs
```
