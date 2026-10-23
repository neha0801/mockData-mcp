"""Proof that user-table reads are refused, at every layer the code controls.

(The database permission layer is proven by tests/integration.)
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from sqlmeta_mcp import queries, query_guard
from sqlmeta_mcp.queries import NotCatalogOnly, Query, assert_catalog_only
from sqlmeta_mcp.query_guard import QueryRefused
from sqlmeta_mcp.tools import ToolFailure, ToolRunner

USER_TABLE_READS = [
    "SELECT * FROM dbo.Accounts",
    "SELECT * FROM [dbo].[Accounts]",
    "SELECT * FROM Accounts",
    "SELECT name FROM sys.objects UNION SELECT AccountNo FROM dbo.Accounts",
    "SELECT o.name FROM sys.objects o JOIN dbo.Accounts a ON 1=1",
    "SELECT * FROM sys.objects; SELECT * FROM dbo.Accounts",
    "SELECT * FROM sys.objects WHERE 1=1 -- comment",
    "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT * FROM dbo.Accounts')",
    "SELECT * INTO sys.x FROM sys.objects",
    "EXEC sp_executesql N'SELECT * FROM dbo.Accounts'",
    "DELETE FROM sys.objects",
    "WITH a AS (SELECT * FROM dbo.Accounts) SELECT * FROM a",
    "SELECT * FROM AppDb.dbo.Accounts",
]


@pytest.mark.parametrize("sql", USER_TABLE_READS)
def test_catalog_check_rejects_user_table_sql(sql: str) -> None:
    with pytest.raises(NotCatalogOnly):
        assert_catalog_only(sql)


@pytest.mark.parametrize("sql", USER_TABLE_READS)
def test_guard_refuses_unregistered_query_objects(db, sql: str) -> None:
    with pytest.raises(QueryRefused):
        query_guard.run(db, Query("adhoc", sql, ()))
    assert db.executed == [], "nothing may reach the driver"


def test_guard_refuses_plain_strings(db) -> None:
    with pytest.raises(QueryRefused):
        query_guard.run(db, "SELECT * FROM dbo.Accounts")  # type: ignore[arg-type]
    assert db.executed == []


def test_guard_refuses_registered_name_with_edited_sql(db) -> None:
    forged = replace(queries.LIST_SCHEMAS, sql="SELECT * FROM dbo.Accounts")
    with pytest.raises(QueryRefused):
        query_guard.run(db, forged)
    equal_copy = Query(queries.LIST_SCHEMAS.name, queries.LIST_SCHEMAS.sql, queries.LIST_SCHEMAS.params)
    with pytest.raises(QueryRefused):
        query_guard.run(db, equal_copy)  # only the registered object itself is accepted
    assert db.executed == []


def test_guard_refuses_wrong_parameter_count_or_type(db) -> None:
    with pytest.raises(QueryRefused):
        query_guard.run(db, queries.DESCRIBE_COLUMNS, ())
    with pytest.raises(QueryRefused):
        query_guard.run(db, queries.DESCRIBE_COLUMNS, (1, 2))
    with pytest.raises(QueryRefused):
        query_guard.run(db, queries.DESCRIBE_COLUMNS, (b"\x01",))
    assert db.executed == []


def test_guard_rolls_back_after_every_query(db) -> None:
    query_guard.run(db, queries.LIST_SCHEMAS)
    query_guard.run(db, queries.RESOLVE_SCHEMA, ("dbo",))
    assert db.rollbacks == 2


ALL_CALLS = [
    ("list_schemas", {}),
    ("list_tables", {"schema": "dbo"}),
    ("describe_table", {"schema": "dbo", "table": "Accounts"}),
    ("get_constraints", {"schema": "dbo", "table": "Accounts"}),
    ("get_indexes", {"schema": "dbo", "table": "Accounts"}),
    ("list_procedures", {"schema": "dbo"}),
    ("get_procedure_definition", {"schema": "dbo", "name": "usp_Route"}),
    ("get_dependencies", {"schema": "dbo", "name": "usp_Route"}),
]


@pytest.mark.parametrize(("tool", "args"), ALL_CALLS, ids=[c[0] for c in ALL_CALLS])
def test_tools_against_user_tables_only_run_registered_catalog_sql(runner: ToolRunner, db, tool: str, args: dict) -> None:
    runner.call(tool, **args)
    registered = {q.sql for q in queries.REGISTRY.values()}
    assert db.executed, "the tool ran something"
    for sql, _params in db.executed:
        assert sql in registered
        assert "Accounts" not in sql, "user object names never appear in SQL text"


INJECTIONS = [
    "Accounts; SELECT * FROM dbo.Accounts--",
    "Accounts' OR '1'='1",
    "Accounts]; DROP TABLE dbo.Accounts;--",
    "x' UNION SELECT AccountNo FROM dbo.Accounts --",
]


@pytest.mark.parametrize("name", INJECTIONS)
def test_injected_names_are_bound_not_concatenated(runner: ToolRunner, db, name: str) -> None:
    with pytest.raises(ToolFailure) as e:
        runner.call("describe_table", schema="dbo", table=name)
    assert e.value.code == "refused"
    assert len(db.executed) == 1, "only the resolution lookup ran"
    sql, params = db.executed[0]
    assert sql == queries.RESOLVE_OBJECT.sql
    assert params == ("dbo", name)
    assert name not in sql


def test_bad_names_refused_without_connecting(db, audit_path) -> None:
    from sqlmeta_mcp.audit import AuditLog
    from sqlmeta_mcp.tools import ConnectionManager, MetadataTools

    opened = []
    cm = ConnectionManager(lambda: opened.append(1) or db)
    r = ToolRunner(MetadataTools(cm, denied_schemas=("secret",)), cm, AuditLog(audit_path))
    for args in ({"schema": "dbo", "table": "x\x00"}, {"schema": "secret", "table": "Keys"}, {"schema": " dbo", "table": "t"}):
        with pytest.raises(ToolFailure) as e:
            r.call("describe_table", **args)
        assert e.value.code == "refused"
    assert opened == [], "no connection is opened for a request that fails validation"


def test_denied_schema_is_refused_before_any_sql(runner: ToolRunner, db) -> None:
    with pytest.raises(ToolFailure) as e:
        runner.call("describe_table", schema="secret", table="Keys")
    assert e.value.code == "refused"
    assert db.executed == []


def test_denied_schema_hidden_from_listings(runner: ToolRunner) -> None:
    schemas = json.loads(runner.call("list_schemas"))["schemas"]
    assert [s["schema_name"] for s in schemas] == ["dbo"]
    deps = json.loads(runner.call("get_dependencies", schema="dbo", name="usp_Route"))
    assert all(d["referenced_schema_name"] != "secret" for d in deps["depends_on"])
    fks = json.loads(runner.call("get_constraints", schema="dbo", table="Accounts"))["foreign_keys"]
    assert all(f["referenced_schema"] != "secret" for f in fks)
