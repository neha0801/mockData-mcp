# ADR 0001: Build the metadata MCP server on the MCP SDK rather than forking

- Status: accepted
- Date: 2026-10-23

## Context

The brief asked to fork an existing SQL Server MCP server and strip every tool
that accepts free-form SQL. The common open-source servers (for example
`RichardHan/mssql_mcp_server` in Python, or Microsoft's MSSQL MCP samples in
Node/.NET) are built around an `execute_sql` / `read_data` style tool plus
convenience tools that also take SQL or table names that go straight into
queries.

## Decision

Build a small server directly on the official MCP Python SDK (`mcp` 2.x,
`MCPServer`) with pyodbc, rather than forking.

## Reasons

- After removing every free-form SQL tool, almost nothing of a fork remains
  except transport and connection setup, which the SDK already provides.
- InfoSec reviews less code, and all of it was written for this threat model.
  No dormant code paths or upstream defaults to audit.
- No need to track an upstream whose direction (more SQL tools) runs against ours.
- Python matches the planned Phase 4 generator and the Phase 2 hooks, which reuse
  `shared/dlp_patterns`.

## Consequences

- We own the connection handling and must keep the SDK and pyodbc pinned and patched.
- Governance stays as planned: changes to `mcp-server/` require code-owner review.
- If a fork is required by policy, the same modules can be dropped into one;
  the tests stay valid because they test behaviour, not structure.
