"""MCP server: registers exactly the eight metadata tools. No tool accepts SQL."""

from __future__ import annotations

from collections.abc import Callable

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .audit import AuditLog
from .config import Config
from .query_guard import Connection
from .tools import ConnectionManager, MetadataTools, ToolFailure, ToolRunner

INSTRUCTIONS = (
    "Read-only SQL Server metadata. Tools return schema structure only: names, types, keys, "
    "indexes, dependencies and procedure text with every literal masked. They never return rows. "
    "There is no way to run SQL through this server."
)

_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def build_server(
    cfg: Config,
    connection_factory: Callable[[], Connection] | None = None,
    audit: AuditLog | None = None,
) -> MCPServer:
    if connection_factory is None:
        from .connection import connect

        def connection_factory() -> Connection:
            return connect(cfg)  # type: ignore[no-any-return]

    connections = ConnectionManager(connection_factory)
    tools = MetadataTools(
        connections,
        allowed_schemas=cfg.allowed_schemas,
        denied_schemas=cfg.denied_schemas,
        max_definition_chars=cfg.max_definition_chars,
    )
    runner = ToolRunner(tools, connections, audit or AuditLog(cfg.audit_log))
    mcp = MCPServer(name="sqlmeta", instructions=INSTRUCTIONS, version="0.1.0")

    def call(tool: str, **args: str) -> str:
        try:
            return runner.call(tool, **args)
        except ToolFailure as e:
            raise ToolError(f"{e.code}: {e}") from None

    @mcp.tool(annotations=_READ_ONLY)
    def list_schemas() -> str:
        """List user schemas in the database (system schemas excluded)."""
        return call("list_schemas")

    @mcp.tool(annotations=_READ_ONLY)
    def list_tables(schema: str) -> str:
        """List tables and views in a schema, with type and create/modify dates. No row counts."""
        return call("list_tables", schema=schema)

    @mcp.tool(annotations=_READ_ONLY)
    def describe_table(schema: str, table: str) -> str:
        """Columns of a table or view: type, length, nullability, identity, computed and default expressions (literals masked)."""
        return call("describe_table", schema=schema, table=table)

    @mcp.tool(annotations=_READ_ONLY)
    def get_constraints(schema: str, table: str) -> str:
        """Primary key, unique, foreign key, check and default constraints of a table (literals masked)."""
        return call("get_constraints", schema=schema, table=table)

    @mcp.tool(annotations=_READ_ONLY)
    def get_indexes(schema: str, table: str) -> str:
        """Indexes of a table or view: key and included columns, uniqueness, filter (literals masked)."""
        return call("get_indexes", schema=schema, table=table)

    @mcp.tool(annotations=_READ_ONLY)
    def list_procedures(schema: str) -> str:
        """List stored procedures and functions in a schema."""
        return call("list_procedures", schema=schema)

    @mcp.tool(annotations=_READ_ONLY)
    def get_procedure_definition(schema: str, name: str) -> str:
        """Parameters and source of a procedure, function, view or trigger, with all literals masked and comments removed."""
        return call("get_procedure_definition", schema=schema, name=name)

    @mcp.tool(annotations=_READ_ONLY)
    def get_dependencies(schema: str, name: str) -> str:
        """Objects this object depends on and objects that depend on it, including foreign-key parents and children."""
        return call("get_dependencies", schema=schema, name=name)

    return mcp
