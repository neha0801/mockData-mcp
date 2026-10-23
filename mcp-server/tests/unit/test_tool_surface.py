"""The server exposes exactly eight metadata tools, and none of them accepts SQL."""

from __future__ import annotations

import json

from sqlmeta_mcp.audit import AuditLog
from sqlmeta_mcp.server import build_server
from sqlmeta_mcp.tools import TOOL_NAMES

SQL_LIKE_PARAMS = {"sql", "query", "statement", "command", "text", "where", "filter", "expression", "script"}


def _server(cfg, db, audit_path):
    return build_server(cfg, connection_factory=lambda: db, audit=AuditLog(audit_path))


async def test_exactly_the_eight_tools(cfg, db, audit_path) -> None:
    tools = await _server(cfg, db, audit_path).list_tools()
    assert sorted(t.name for t in tools) == sorted(TOOL_NAMES)
    assert len(tools) == 8


async def test_no_tool_accepts_sql_and_all_params_are_names(cfg, db, audit_path) -> None:
    for t in await _server(cfg, db, audit_path).list_tools():
        props = t.input_schema.get("properties", {})
        assert not SQL_LIKE_PARAMS & {p.lower() for p in props}, t.name
        assert set(props) <= {"schema", "table", "name"}, t.name
        for p in props.values():
            assert p.get("type") == "string"


async def test_tools_are_annotated_read_only(cfg, db, audit_path) -> None:
    for t in await _server(cfg, db, audit_path).list_tools():
        assert t.annotations and t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False


async def test_call_through_mcp(cfg, db, audit_path) -> None:
    result = await _server(cfg, db, audit_path).call_tool("describe_table", {"schema": "dbo", "table": "Accounts"})
    assert not result.is_error
    text = result.content[0].text
    assert json.loads(text)["table"] == "Accounts"


async def test_errors_through_mcp_are_safe(cfg, db, audit_path) -> None:
    import pytest
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError) as e:
        await _server(cfg, db, audit_path).call_tool("describe_table", {"schema": "dbo", "table": "Nope"})
    assert str(e.value).endswith("refused: object dbo.Nope not found")
