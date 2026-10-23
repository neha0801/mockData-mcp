# sqlmeta-mcp

A metadata-only SQL Server MCP server. It describes schemas; it cannot read rows.

## Tools

All tools are read-only and take only object names (`schema`, `table`, `name`).

| Tool | Returns |
|---|---|
| `list_schemas` | User schemas and owners |
| `list_tables(schema)` | Tables and views, type, create/modify dates (no row counts) |
| `describe_table(schema, table)` | Columns: type, length, precision, nullability, identity, computed/default expressions |
| `get_constraints(schema, table)` | PK, unique, FK, check and default constraints |
| `get_indexes(schema, table)` | Key/included columns, uniqueness, filter |
| `list_procedures(schema)` | Procedures and functions |
| `get_procedure_definition(schema, name)` | Parameters and source of a procedure, function, view or trigger |
| `get_dependencies(schema, name)` | Expression dependencies both ways, FK parents and children |

Every expression or module text is passed through the literal scrubber: string,
numeric and binary literals become `'<STR>'`, `<NUM>`, `<BIN>`; comments are
removed; account-like values, emails, GUIDs and similar inside identifiers are
masked.

## How a call is handled

```
args ──► validate names + schema policy ──► resolve name → object_id (parameterised catalog lookup)
     ──► registered sys.* queries only (query_guard) ──► scrub literals
     ──► output check (dlp_patterns) ──► audit log ──► JSON text to client
```

Failures return a short code (`refused`, `blocked`, `db_error`, `internal_error`)
and never the driver's message, which can contain values.

## Install and run

```bash
pip install -e ../shared/dlp_patterns -e ".[db]"      # add ,keyring for sql-keyring auth
cp config.example.toml ~/sqlmeta-mcp.toml             # edit; keep it outside the repo
sqlmeta-mcp --config ~/sqlmeta-mcp.toml               # stdio transport
sqlmeta-mcp --verify-audit ~/.local/state/sqlmeta-mcp/audit.jsonl
```

Needs Microsoft ODBC Driver 18 for SQL Server.

Before the first connection, a DBA runs [`sql/metadata_reader_login.sql`](sql/metadata_reader_login.sql)
for the service principal: `VIEW DEFINITION` only, with `DENY` on every user schema.
That principal is the control that holds even if this code is wrong.

Claude Code registration (Phase 2 will pin this in managed settings):

```json
{ "mcpServers": { "sqlmeta": { "command": "sqlmeta-mcp", "args": ["--config", "/path/outside/repo/sqlmeta-mcp.toml"] } } }
```

## Code map

| Module | Role |
|---|---|
| `queries.py` | The only SQL in the package, as frozen constants; checked at import |
| `query_guard.py` | The only `execute()` call; runs a registered query object or nothing |
| `catalog.py` | Name validation, schema allow/deny, name → id resolution |
| `scrubber.py` | T-SQL tokenizer that masks literals and removes comments |
| `output_guard.py` | Blocks responses containing data-like patterns |
| `audit.py` | Hash-chained local JSONL audit log (no response content) |
| `config.py`, `credentials.py`, `connection.py` | Config without secrets; integrated auth or OS keychain; read-only connection |
| `tools.py`, `server.py` | The eight tools and their MCP registration |

## Tests

```bash
pytest                    # unit: 200+ tests, no database
pytest -m integration     # real SQL Server; see tests/integration/README.md
```

What the key tests prove:

- `test_queries_static.py`: every query parses (sqlglot, T-SQL) as a single SELECT
  over `sys.*` / `INFORMATION_SCHEMA`; inputs are bound parameters; only
  `query_guard` calls `execute()`.
- `test_user_table_reads_refused.py`: ad-hoc or forged queries never reach the
  driver; injection strings are bound, not concatenated; denied schemas refused.
- `test_literals_masked.py`: literals and comments are masked in procedure,
  view, constraint, default, computed-column and index-filter text.
- `integration/test_no_canary_leak.py`: on a real server, every tool on every
  object returns no canary value, and the locked-down principal cannot read,
  write or execute user objects even over a raw connection.
