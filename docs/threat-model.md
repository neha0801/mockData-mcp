# Threat model: sqlmeta-mcp (Phase 1)

Scope: the metadata MCP server, its database principal and its local audit log.
Claude Code lockdown (Phase 2) is referenced where it adds a control.

## Assets

1. Row data in dev databases (may contain copies of production data).
2. Literal values embedded in database code: client IDs, account numbers,
   thresholds, names in comments.
3. Database credentials.

## Threats and controls

| Threat | Control | Test |
|---|---|---|
| LLM or prompt-injected instructions ask for rows | No tool accepts SQL; arguments are names only | `test_tool_surface.py` |
| SQL injection through an object name | Names validated, bound as parameters to a catalog lookup, replaced by integer ids | `test_injected_names_are_bound_not_concatenated` |
| A future change adds a query that reads a user table | Import-time regex check; parser-based static test; registry is frozen; only `query_guard` executes | `test_queries_static.py`, `test_guard_*` |
| Code bug bypasses all of the above | Principal has `DENY` on every user schema and no role membership | `test_database_layer_refuses_data_access_for_reader` (real server) |
| Literals in procedures, views, constraints, defaults, computed columns, index filters | Tokenizing scrubber masks string/numeric/binary literals, removes comments; patterns in identifiers masked | `test_literals_masked.py`, `test_every_tool_on_every_object_leaks_nothing` |
| Data-like values in names or anything the scrubber misses | Output check blocks the whole response; Phase 2 hook re-checks | `test_output_guard.py` |
| Driver error messages carrying values (e.g. conversion errors) | Client sees only the SQLSTATE; audit log stores only the SQLSTATE | `ToolRunner.call` |
| Values revealed through statistics, row counts, parameter defaults, plans | Not queried; `DENY SHOWPLAN` on the principal | `queries.py` docstring |
| Prompt injection planted in database code | Comments removed and string literals masked before text reaches the LLM | `test_comments_removed_including_nested` |
| Credential exposure to the LLM or repo | Integrated auth preferred (no secret); otherwise OS keychain read by the server process; config refuses secret keys; no env-var source | `test_secrets_in_config_refused` |
| Connection string injection via config values | ODBC values brace-quoted | `test_values_cannot_inject_keywords` |
| Writes / DDL | Principal denied; `ApplicationIntent=ReadOnly`; every query rolled back | integration tests |
| Untraceable use | Hash-chained local audit log of every call and outcome; no response content | `test_audit.py` |

## Residual risks (for InfoSec acceptance)

1. **Object names are returned unmasked.** Table, column and procedure names can
   themselves be sensitive (e.g. a table named after a client). The output check
   only catches names that match a data pattern. Mitigation: `denied_schemas` /
   `allowed_schemas`.
2. **Pattern detection is heuristic.** Unusual account formats, non-Latin or
   uncommon personal names, or free text without a recognisable pattern can pass
   the output check. Literal masking (not detection) is the primary control for
   module text; detection is a backstop.
3. **The audit log is tamper-evident, not tamper-proof.** A local user can
   rewrite the whole file and chain. Ship it to a central log store if that matters.
4. **Metadata is disclosed by design.** Structure, names, dependencies and
   create/modify dates are visible to the LLM.
5. **Masking removes enum values and thresholds.** `CHECK (Status IN ('O','C'))`
   becomes `'<STR>'`. Phase 3 must take enum values and limits from code, XSD,
   JSON Schema or Avro, or InfoSec may approve a narrower rule (e.g. keep
   literals of at most N characters in CHECK constraints only).
6. **New schemas.** The lockdown script denies the schemas that exist when it
   runs. A later schema is not explicitly denied; the principal still has no
   grant on it unless `[public]` or a role is granted access. Re-run the script
   after creating schemas.
7. **Supply chain.** Depends on the MCP Python SDK 2.x and pyodbc. Pin versions
   (`uv.lock`) and review updates.
8. **Scrubbing happens inside the server process.** The process sees full module
   text (it needs `VIEW DEFINITION`). A compromised workstation or server process
   can read it; this is the same exposure as a developer using SSMS with that login.

## Out of scope for Phase 1

Claude Code permissions and hooks (Phase 2), generated data handling (Phase 4),
real-data handles (Phase 5).
