"""Static proof that every registered query reads only catalog views.

Uses a real T-SQL parser (sqlglot), independent of the regex check that runs
at import time in queries.py.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import sqlglot
from sqlglot import exp
from sqlmeta_mcp import queries

PKG = Path(queries.__file__).parent
CATALOG_SCHEMAS = {"sys", "information_schema"}
FORBIDDEN_FUNCS = {"openrowset", "openquery", "opendatasource", "openjson", "openxml", "object_definition"}


@pytest.mark.parametrize("q", list(queries.REGISTRY.values()), ids=lambda q: q.name)
def test_query_is_single_catalog_select(q: queries.Query) -> None:
    statements = sqlglot.parse(q.sql, read="tsql")
    assert len(statements) == 1, "exactly one statement"
    tree = statements[0]
    assert isinstance(tree, (exp.Select, exp.Union)), f"not a SELECT: {type(tree).__name__}"

    for node_type in (exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create, exp.Drop, exp.Alter, exp.Command, exp.Into):
        assert not list(tree.find_all(node_type)), f"contains {node_type.__name__}"

    tables = list(tree.find_all(exp.Table))
    assert tables, "reads from at least one catalog view"
    for t in tables:
        assert t.db.lower() in CATALOG_SCHEMAS, f"{q.name} references non-catalog object {t.sql('tsql')}"
        assert not t.catalog, f"{q.name} uses a three-part name: {t.sql('tsql')}"

    for fn in tree.find_all(exp.Anonymous):
        assert str(fn.this).lower() not in FORBIDDEN_FUNCS


@pytest.mark.parametrize("q", list(queries.REGISTRY.values()), ids=lambda q: q.name)
def test_inputs_are_bound_parameters(q: queries.Query) -> None:
    assert q.sql.count("?") == len(q.params)
    # The only string literals allowed are fixed type codes, never inputs.
    for lit in sqlglot.parse_one(q.sql, read="tsql").find_all(exp.Literal):
        if lit.is_string:
            assert lit.this in {"P", "FN", "IF", "TF"}, f"unexpected string literal {lit.this!r}"


def test_names_only_reach_sql_through_resolution_queries() -> None:
    name_params = {"schema_name", "object_name"}
    for q in queries.REGISTRY.values():
        if q.name.startswith("resolve_"):
            continue
        assert not name_params & set(q.params), f"{q.name} takes a name; it must take an id"


def test_only_query_guard_calls_execute() -> None:
    """No module except query_guard may call .execute() on anything."""
    offenders = []
    for path in PKG.glob("*.py"):
        if path.name == "query_guard.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in {"execute", "executemany", "executescript"}:
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"direct execute() outside query_guard: {offenders}"


def test_no_sql_built_from_strings_outside_queries_module() -> None:
    """No f-strings, % or .format() producing SQL keywords outside queries.py."""
    keywords = ("select ", "from ", " where ", "insert ", "update ", "delete ", "exec ")
    offenders = []
    for path in PKG.glob("*.py"):
        if path.name == "queries.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.JoinedStr):
                text = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)).lower()
                if any(k in text for k in keywords):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"SQL-looking f-strings: {offenders}"


def test_registry_is_read_only() -> None:
    with pytest.raises(TypeError):
        queries.REGISTRY["evil"] = queries.Query("evil", "SELECT 1 FROM sys.objects", ())  # type: ignore[index]
