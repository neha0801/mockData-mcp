"""The single place in the package that sends SQL to the database.

A statement runs only if it is one of the Query objects registered in queries.py,
unchanged, with exactly the declared number of parameters. Ad-hoc strings, copies
with edited SQL and anything that reads a non-catalog object are refused.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from .queries import REGISTRY, Query, assert_catalog_only


class QueryRefused(PermissionError):
    pass


class Cursor(Protocol):
    description: Any

    def execute(self, sql: str, *params: Any) -> Any: ...
    def fetchall(self) -> list[Any]: ...
    def close(self) -> None: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...
    def rollback(self) -> None: ...


Row = dict[str, Any]


def check(query: object, params: Sequence[Any]) -> Query:
    if not isinstance(query, Query):
        raise QueryRefused("only registered queries may run")
    registered = REGISTRY.get(query.name)
    if registered is None or registered is not query or registered.sql != query.sql:
        raise QueryRefused(f"query {query.name!r} is not registered")
    if len(params) != len(query.params):
        raise QueryRefused(f"query {query.name!r} expects {len(query.params)} parameters")
    for p in params:
        if not isinstance(p, (str, int)) or isinstance(p, bool):
            raise QueryRefused("parameters must be str or int")
    # Defence in depth: re-check the text even though it was checked at import.
    assert_catalog_only(query.sql)
    return query


def run(conn: Connection, query: Query, params: Sequence[Any] = ()) -> list[Row]:
    """Run a registered catalog query and return rows as dicts. Always rolls back."""
    check(query, params)
    cur = conn.cursor()
    try:
        cur.execute(query.sql, *params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
    finally:
        try:
            cur.close()
        finally:
            conn.rollback()
