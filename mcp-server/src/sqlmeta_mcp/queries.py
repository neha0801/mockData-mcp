"""Every SQL statement this server can run. Nothing else is ever sent to the database.

Rules (enforced at import time below, and again by tests/unit/test_queries_static.py
with a real SQL parser):
  * SELECT only, against sys.* catalog views or INFORMATION_SCHEMA.
  * Inputs are bound as ``?`` parameters. Object names are resolved to an
    ``object_id`` / ``schema_id`` first (see catalog.py); later queries take only ids.
  * No string formatting, no concatenation, no dynamic SQL.

Deliberately NOT exposed: row counts (sys.partitions), statistics histograms
(DBCC SHOW_STATISTICS / sys.dm_db_stats_histogram) and column default values of
parameters, because each of them can reveal values from user tables.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class Query:
    name: str
    sql: str
    params: tuple[str, ...]


_Q: dict[str, Query] = {}


def _register(name: str, sql: str, params: tuple[str, ...] = ()) -> Query:
    q = Query(name=name, sql=" ".join(sql.split()), params=params)
    if name in _Q:
        raise RuntimeError(f"duplicate query name: {name}")
    assert_catalog_only(q.sql)
    if q.sql.count("?") != len(params):
        raise RuntimeError(f"{name}: placeholder count does not match params")
    _Q[name] = q
    return q


# Lightweight runtime check, independent of the parser-based test.
_FROM_TARGET = re.compile(r"\b(?:FROM|JOIN|APPLY)\s+([^\s(),]+)", re.IGNORECASE)
_FORBIDDEN = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE|GRANT|REVOKE|DENY|"
    r"OPENROWSET|OPENQUERY|OPENDATASOURCE|OPENJSON|OPENXML|BULK|INTO|WAITFOR|DBCC|SP_\w+|XP_\w+|"
    r"BACKUP|RESTORE|SHUTDOWN|KILL|USE|DECLARE|SET)\b|;|--|/\*",
    re.IGNORECASE,
)
_ALLOWED_PREFIXES = ("sys.", "information_schema.")


class NotCatalogOnly(ValueError):
    pass


def assert_catalog_only(sql: str) -> None:
    """Raise unless ``sql`` is a single SELECT that reads only sys.* / INFORMATION_SCHEMA."""
    if not sql.lstrip().upper().startswith("SELECT "):
        raise NotCatalogOnly("only SELECT statements are allowed")
    bad = _FORBIDDEN.search(sql)
    if bad:
        raise NotCatalogOnly(f"forbidden token: {bad.group(0)!r}")
    targets = _FROM_TARGET.findall(sql)
    if not targets:
        raise NotCatalogOnly("no FROM target")
    for t in targets:
        if not t.lower().replace("[", "").replace("]", "").startswith(_ALLOWED_PREFIXES):
            raise NotCatalogOnly(f"references a non-catalog object: {t}")


# --- name resolution (catalog.py) -------------------------------------------

RESOLVE_SCHEMA = _register(
    "resolve_schema",
    """
    SELECT s.schema_id, s.name
    FROM sys.schemas AS s
    WHERE s.name = ? AND s.schema_id NOT IN (2, 3, 4) AND s.schema_id < 16384
    """,
    ("schema_name",),
)

RESOLVE_OBJECT = _register(
    "resolve_object",
    """
    SELECT o.object_id, RTRIM(o.type) AS type, s.name AS schema_name, o.name AS object_name
    FROM sys.objects AS o
    JOIN sys.schemas AS s ON s.schema_id = o.schema_id
    WHERE s.name = ? AND o.name = ? AND o.is_ms_shipped = 0
    """,
    ("schema_name", "object_name"),
)

# --- tools --------------------------------------------------------------------

LIST_SCHEMAS = _register(
    "list_schemas",
    """
    SELECT s.name AS schema_name, p.name AS owner
    FROM sys.schemas AS s
    LEFT JOIN sys.database_principals AS p ON p.principal_id = s.principal_id
    WHERE s.schema_id NOT IN (2, 3, 4) AND s.schema_id < 16384
    ORDER BY s.name
    """,
)

LIST_TABLES = _register(
    "list_tables",
    """
    SELECT t.name AS table_name, t.type_desc, t.temporal_type_desc, t.create_date, t.modify_date
    FROM sys.tables AS t
    WHERE t.schema_id = ? AND t.is_ms_shipped = 0
    UNION ALL
    SELECT v.name, v.type_desc, NULL, v.create_date, v.modify_date
    FROM sys.views AS v
    WHERE v.schema_id = ? AND v.is_ms_shipped = 0
    ORDER BY 1
    """,
    ("schema_id", "schema_id"),
)

DESCRIBE_COLUMNS = _register(
    "describe_columns",
    """
    SELECT c.column_id, c.name AS column_name, ty.name AS data_type, bt.name AS base_type,
           c.max_length, c.precision, c.scale, c.is_nullable, c.is_identity, c.is_computed,
           c.is_sparse, c.collation_name, dc.definition AS default_definition,
           cc.definition AS computed_definition
    FROM sys.columns AS c
    JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
    LEFT JOIN sys.types AS bt ON bt.user_type_id = ty.system_type_id
    LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
    LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
    WHERE c.object_id = ?
    ORDER BY c.column_id
    """,
    ("object_id",),
)

KEY_CONSTRAINTS = _register(
    "key_constraints",
    """
    SELECT kc.name AS constraint_name, kc.type_desc, ic.key_ordinal, col.name AS column_name
    FROM sys.key_constraints AS kc
    JOIN sys.index_columns AS ic ON ic.object_id = kc.parent_object_id AND ic.index_id = kc.unique_index_id
    JOIN sys.columns AS col ON col.object_id = ic.object_id AND col.column_id = ic.column_id
    WHERE kc.parent_object_id = ?
    ORDER BY kc.name, ic.key_ordinal
    """,
    ("object_id",),
)

FOREIGN_KEYS = _register(
    "foreign_keys",
    """
    SELECT fk.name AS constraint_name, fkc.constraint_column_id, pc.name AS column_name,
           rs.name AS referenced_schema, ro.name AS referenced_table, rc.name AS referenced_column,
           fk.delete_referential_action_desc, fk.update_referential_action_desc,
           fk.is_disabled, fk.is_not_trusted
    FROM sys.foreign_keys AS fk
    JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id
    JOIN sys.columns AS pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
    JOIN sys.objects AS ro ON ro.object_id = fkc.referenced_object_id
    JOIN sys.schemas AS rs ON rs.schema_id = ro.schema_id
    JOIN sys.columns AS rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
    WHERE fk.parent_object_id = ?
    ORDER BY fk.name, fkc.constraint_column_id
    """,
    ("object_id",),
)

CHECK_CONSTRAINTS = _register(
    "check_constraints",
    """
    SELECT cc.name AS constraint_name, col.name AS column_name, cc.definition,
           cc.is_disabled, cc.is_not_trusted
    FROM sys.check_constraints AS cc
    LEFT JOIN sys.columns AS col ON col.object_id = cc.parent_object_id AND col.column_id = cc.parent_column_id
    WHERE cc.parent_object_id = ?
    ORDER BY cc.name
    """,
    ("object_id",),
)

DEFAULT_CONSTRAINTS = _register(
    "default_constraints",
    """
    SELECT dc.name AS constraint_name, col.name AS column_name, dc.definition
    FROM sys.default_constraints AS dc
    JOIN sys.columns AS col ON col.object_id = dc.parent_object_id AND col.column_id = dc.parent_column_id
    WHERE dc.parent_object_id = ?
    ORDER BY dc.name
    """,
    ("object_id",),
)

INDEXES = _register(
    "indexes",
    """
    SELECT i.name AS index_name, i.type_desc, i.is_unique, i.is_primary_key, i.is_unique_constraint,
           i.has_filter, i.filter_definition, ic.key_ordinal, ic.is_included_column,
           ic.is_descending_key, c.name AS column_name
    FROM sys.indexes AS i
    JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
    JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
    WHERE i.object_id = ? AND i.index_id > 0 AND i.is_hypothetical = 0
    ORDER BY i.index_id, ic.is_included_column, ic.key_ordinal, ic.index_column_id
    """,
    ("object_id",),
)

LIST_PROCEDURES = _register(
    "list_procedures",
    """
    SELECT o.name AS object_name, o.type_desc, o.create_date, o.modify_date
    FROM sys.objects AS o
    WHERE o.schema_id = ? AND o.is_ms_shipped = 0 AND o.type IN ('P', 'FN', 'IF', 'TF')
    ORDER BY o.name
    """,
    ("schema_id",),
)

MODULE_DEFINITION = _register(
    "module_definition",
    """
    SELECT m.definition, m.uses_quoted_identifier, m.is_schema_bound
    FROM sys.sql_modules AS m
    WHERE m.object_id = ?
    """,
    ("object_id",),
)

MODULE_PARAMETERS = _register(
    "module_parameters",
    """
    SELECT pr.parameter_id, pr.name AS parameter_name, ty.name AS data_type, pr.max_length,
           pr.precision, pr.scale, pr.is_output, pr.has_default_value, pr.is_nullable
    FROM sys.parameters AS pr
    JOIN sys.types AS ty ON ty.user_type_id = pr.user_type_id
    WHERE pr.object_id = ?
    ORDER BY pr.parameter_id
    """,
    ("object_id",),
)

DEPENDS_ON = _register(
    "depends_on",
    """
    SELECT d.referenced_server_name, d.referenced_database_name, d.referenced_schema_name,
           d.referenced_entity_name, o.type_desc AS referenced_type,
           d.is_ambiguous, d.is_caller_dependent
    FROM sys.sql_expression_dependencies AS d
    LEFT JOIN sys.objects AS o ON o.object_id = d.referenced_id
    WHERE d.referencing_id = ?
    ORDER BY d.referenced_schema_name, d.referenced_entity_name
    """,
    ("object_id",),
)

REFERENCED_BY = _register(
    "referenced_by",
    """
    SELECT DISTINCT s.name AS referencing_schema, o.name AS referencing_entity,
           o.type_desc AS referencing_type
    FROM sys.sql_expression_dependencies AS d
    JOIN sys.objects AS o ON o.object_id = d.referencing_id
    JOIN sys.schemas AS s ON s.schema_id = o.schema_id
    WHERE d.referenced_id = ?
    ORDER BY 1, 2
    """,
    ("object_id",),
)

FK_PARENTS = _register(
    "fk_parents",
    """
    SELECT DISTINCT fk.name AS constraint_name, rs.name AS referenced_schema, ro.name AS referenced_table
    FROM sys.foreign_keys AS fk
    JOIN sys.objects AS ro ON ro.object_id = fk.referenced_object_id
    JOIN sys.schemas AS rs ON rs.schema_id = ro.schema_id
    WHERE fk.parent_object_id = ?
    ORDER BY 1
    """,
    ("object_id",),
)

FK_CHILDREN = _register(
    "fk_children",
    """
    SELECT DISTINCT fk.name AS constraint_name, ps.name AS referencing_schema, po.name AS referencing_table
    FROM sys.foreign_keys AS fk
    JOIN sys.objects AS po ON po.object_id = fk.parent_object_id
    JOIN sys.schemas AS ps ON ps.schema_id = po.schema_id
    WHERE fk.referenced_object_id = ?
    ORDER BY 1
    """,
    ("object_id",),
)

# A frozen copy: anything registered after import is never accepted by query_guard.
REGISTRY: MappingProxyType[str, Query] = MappingProxyType(dict(_Q))
