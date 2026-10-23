from __future__ import annotations

import pytest
from sqlmeta_mcp import catalog
from sqlmeta_mcp.catalog import Catalog, InvalidName, NotFound, SchemaNotAllowed, validate_identifier


@pytest.mark.parametrize(
    "bad",
    [None, 1, b"dbo", "", "x" * 129, " dbo", "dbo ", "db\x00o", "db\no", "db\x1bo", "db\x7fo", ["dbo"]],
)
def test_invalid_identifiers_rejected(bad: object) -> None:
    with pytest.raises(InvalidName):
        validate_identifier(bad, "schema")


@pytest.mark.parametrize("ok", ["dbo", "Order Details", "x" * 128, "Säljare", "a]b", "it's"])
def test_valid_identifiers_accepted(ok: str) -> None:
    assert validate_identifier(ok, "name") == ok


def test_invalid_name_fails_before_any_sql(db) -> None:
    with pytest.raises(InvalidName):
        Catalog(db).resolve_object("dbo", "x\x00", catalog.TABLE_TYPES)
    assert db.executed == []


def test_unknown_object(db) -> None:
    with pytest.raises(NotFound):
        Catalog(db).resolve_object("dbo", "Nope", catalog.TABLE_TYPES)


def test_unknown_schema(db) -> None:
    with pytest.raises(NotFound):
        Catalog(db).resolve_schema("nope")


def test_wrong_object_type_is_not_found(db) -> None:
    with pytest.raises(NotFound):
        Catalog(db).resolve_object("dbo", "usp_Route", catalog.TABLE_TYPES)


def test_resolves_to_id(db) -> None:
    ref = Catalog(db).resolve_object("dbo", "Accounts", catalog.TABLE_TYPES)
    assert (ref.object_id, ref.type, ref.schema, ref.name) == (101, "U", "dbo", "Accounts")


def test_allow_list(db) -> None:
    cat = Catalog(db, allowed_schemas=["dbo"])
    assert cat.schema_allowed("DBO")
    with pytest.raises(SchemaNotAllowed):
        cat.resolve_schema("secret")
    assert db.executed == []


def test_deny_list_wins_over_allow_list(db) -> None:
    cat = Catalog(db, allowed_schemas=["dbo", "secret"], denied_schemas=["Secret"])
    with pytest.raises(SchemaNotAllowed):
        cat.resolve_object("secret", "Keys", catalog.TABLE_TYPES)
