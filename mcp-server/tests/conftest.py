"""Fake DB-API connection for unit tests.

It answers only the registered catalog queries, from canned catalog rows, and
fails the test if any other SQL reaches it. The canned procedure text and
defaults are seeded with CANARY values that must never appear in tool output.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlmeta_mcp import queries
from sqlmeta_mcp.audit import AuditLog
from sqlmeta_mcp.config import Config
from sqlmeta_mcp.tools import ConnectionManager, MetadataTools, ToolRunner

CANARIES = (
    "99887766",
    "CANARY",
    "canary.person@example.com",
    "GB82WEST12345698765432",
    "5493001KJTIIGC8Y1R12",
    "Jane Canary",
    "4111111111111111",
    "123-45-6789",
)

SCHEMAS = {"dbo": 1, "secret": 5}
OBJECTS = {
    ("dbo", "Accounts"): (101, "U"),
    ("dbo", "vAccounts"): (102, "V"),
    ("dbo", "usp_Route"): (103, "P"),
    ("secret", "Keys"): (201, "U"),
}

PROC_TEXT = """CREATE PROCEDURE dbo.usp_Route @Client NVARCHAR(50), @Amount DECIMAL(18,2) AS
-- Hard-coded for client CANARY, contact canary.person@example.com
/* temp fix for Jane Canary, acct 99887766 */
BEGIN
  IF @Client = N'CANARY-ACCT-99887766' OR @Client = 'GB82WEST12345698765432'
     SELECT 'ROUTE_A' AS route WHERE @Amount > 250000.00
  ELSE IF @Client = '5493001KJTIIGC8Y1R12' SELECT 0x4111111111111111
  ELSE IF @Client = "123-45-6789" SELECT 'Jane Canary'
END"""

Rows = tuple[list[str], list[tuple[Any, ...]]]


def _handlers() -> dict[str, Callable[[tuple[Any, ...]], Rows]]:
    def resolve_schema(p: tuple[Any, ...]) -> Rows:
        sid = SCHEMAS.get(p[0])
        return ["schema_id", "name"], ([(sid, p[0])] if sid else [])

    def resolve_object(p: tuple[Any, ...]) -> Rows:
        hit = OBJECTS.get((p[0], p[1]))
        return ["object_id", "type", "schema_name", "object_name"], ([(hit[0], hit[1], p[0], p[1])] if hit else [])

    def list_schemas(p: tuple[Any, ...]) -> Rows:
        return ["schema_name", "owner"], [("dbo", "dbo"), ("secret", "dbo")]

    def list_tables(p: tuple[Any, ...]) -> Rows:
        cols = ["table_name", "type_desc", "temporal_type_desc", "create_date", "modify_date"]
        if p[0] == 1:
            return cols, [("Accounts", "USER_TABLE", "NON_TEMPORAL_TABLE", "2024-01-01T10:00:00", "2024-02-01T10:00:00")]
        return cols, []

    def describe_columns(p: tuple[Any, ...]) -> Rows:
        cols = [
            "column_id",
            "column_name",
            "data_type",
            "base_type",
            "max_length",
            "precision",
            "scale",
            "is_nullable",
            "is_identity",
            "is_computed",
            "is_sparse",
            "collation_name",
            "default_definition",
            "computed_definition",
        ]
        return cols, [
            (1, "AccountId", "int", "int", 4, 10, 0, False, True, False, False, None, None, None),
            (
                2,
                "AccountNo",
                "varchar",
                "varchar",
                34,
                0,
                0,
                False,
                False,
                False,
                False,
                "Latin1_General_CI_AS",
                "('GB82WEST12345698765432')",
                None,
            ),
            (3, "Status", "char", "char", 1, 0, 0, False, False, False, False, "Latin1_General_CI_AS", "('O')", None),
            (4, "Limit", "decimal", "decimal", 9, 18, 2, True, False, True, False, None, None, "([Base]*(99887766))"),
        ]

    def key_constraints(p: tuple[Any, ...]) -> Rows:
        return ["constraint_name", "type_desc", "key_ordinal", "column_name"], [("PK_Accounts", "PRIMARY_KEY_CONSTRAINT", 1, "AccountId")]

    def foreign_keys(p: tuple[Any, ...]) -> Rows:
        cols = [
            "constraint_name",
            "constraint_column_id",
            "column_name",
            "referenced_schema",
            "referenced_table",
            "referenced_column",
            "delete_referential_action_desc",
            "update_referential_action_desc",
            "is_disabled",
            "is_not_trusted",
        ]
        return cols, [
            ("FK_Accounts_Client", 1, "ClientId", "dbo", "Clients", "ClientId", "NO_ACTION", "NO_ACTION", False, False),
            ("FK_Accounts_Key", 1, "KeyId", "secret", "Keys", "KeyId", "NO_ACTION", "NO_ACTION", False, False),
        ]

    def check_constraints(p: tuple[Any, ...]) -> Rows:
        return ["constraint_name", "column_name", "definition", "is_disabled", "is_not_trusted"], [
            ("CK_Accounts_Status", "Status", "([Status]='C' OR [Status]='O')", False, False),
            ("CK_Accounts_NotBlocked", "AccountNo", "([AccountNo]<>'CANARY-ACCT-99887766')", False, False),
        ]

    def default_constraints(p: tuple[Any, ...]) -> Rows:
        return ["constraint_name", "column_name", "definition"], [("DF_Accounts_No", "AccountNo", "('canary.person@example.com')")]

    def indexes(p: tuple[Any, ...]) -> Rows:
        cols = [
            "index_name",
            "type_desc",
            "is_unique",
            "is_primary_key",
            "is_unique_constraint",
            "has_filter",
            "filter_definition",
            "key_ordinal",
            "is_included_column",
            "is_descending_key",
            "column_name",
        ]
        return cols, [
            ("PK_Accounts", "CLUSTERED", True, True, False, False, None, 1, False, False, "AccountId"),
            ("IX_Accounts_No", "NONCLUSTERED", True, False, False, True, "([AccountNo]<>'99887766')", 1, False, False, "AccountNo"),
            ("IX_Accounts_No", "NONCLUSTERED", True, False, False, True, "([AccountNo]<>'99887766')", 0, True, False, "Status"),
        ]

    def list_procedures(p: tuple[Any, ...]) -> Rows:
        return ["object_name", "type_desc", "create_date", "modify_date"], [
            ("usp_Route", "SQL_STORED_PROCEDURE", "2024-01-01", "2024-01-02")
        ]

    def module_definition(p: tuple[Any, ...]) -> Rows:
        return ["definition", "uses_quoted_identifier", "is_schema_bound"], [(PROC_TEXT, False, False)]

    def module_parameters(p: tuple[Any, ...]) -> Rows:
        cols = [
            "parameter_id",
            "parameter_name",
            "data_type",
            "max_length",
            "precision",
            "scale",
            "is_output",
            "has_default_value",
            "is_nullable",
        ]
        return cols, [(1, "@Client", "nvarchar", 100, 0, 0, False, False, True), (2, "@Amount", "decimal", 9, 18, 2, False, False, True)]

    def depends_on(p: tuple[Any, ...]) -> Rows:
        cols = [
            "referenced_server_name",
            "referenced_database_name",
            "referenced_schema_name",
            "referenced_entity_name",
            "referenced_type",
            "is_ambiguous",
            "is_caller_dependent",
        ]
        return cols, [
            (None, None, "dbo", "Accounts", "USER_TABLE", False, False),
            (None, None, "secret", "Keys", "USER_TABLE", False, False),
        ]

    def referenced_by(p: tuple[Any, ...]) -> Rows:
        return ["referencing_schema", "referencing_entity", "referencing_type"], []

    def fk_parents(p: tuple[Any, ...]) -> Rows:
        return ["constraint_name", "referenced_schema", "referenced_table"], []

    def fk_children(p: tuple[Any, ...]) -> Rows:
        return ["constraint_name", "referencing_schema", "referencing_table"], []

    return {k: v for k, v in locals().items() if callable(v)}


class FakeCursor:
    def __init__(self, db: FakeDB) -> None:
        self._db = db
        self.description: list[tuple[str]] = []
        self._rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str, *params: Any) -> None:
        self._db.executed.append((sql, params))
        match = [q for q in queries.REGISTRY.values() if q.sql == sql]
        if not match:
            raise AssertionError(f"unregistered SQL reached the driver: {sql!r}")
        cols, rows = self._db.handlers[match[0].name](params)
        self.description = [(c,) for c in cols]
        self._rows = rows

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)

    def close(self) -> None:
        pass


class FakeDB:
    def __init__(self) -> None:
        self.handlers = _handlers()
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.rollbacks = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        pass


@pytest.fixture
def db() -> FakeDB:
    return FakeDB()


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


@pytest.fixture
def cfg(audit_path: Path) -> Config:
    return Config(server="dev-sql", database="AppDb", audit_log=audit_path)


@pytest.fixture
def runner(db: FakeDB, audit_path: Path) -> ToolRunner:
    cm = ConnectionManager(lambda: db)
    return ToolRunner(MetadataTools(cm, denied_schemas=("secret",)), cm, AuditLog(audit_path))


def assert_no_canary(text: str) -> None:
    for c in CANARIES:
        assert c.lower() not in text.lower(), f"canary {c!r} leaked: {text}"
