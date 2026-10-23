"""The eight metadata tools, and the runner that wraps every call.

Each call goes: validate + resolve names (catalog.py) -> registered catalog
queries only (query_guard.py) -> scrub definitions (scrubber.py) -> output check
(output_guard.py) -> audit (audit.py). Nothing returns row data from user tables,
because no query can read one.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import dlp_patterns

from . import catalog, queries, query_guard, scrubber
from .audit import AuditLog
from .catalog import Catalog, InvalidName, NotFound, SchemaNotAllowed
from .output_guard import OutputBlocked
from .output_guard import check as output_check
from .query_guard import Connection, QueryRefused

log = logging.getLogger(__name__)

TOOL_NAMES = (
    "list_schemas",
    "list_tables",
    "describe_table",
    "get_constraints",
    "get_indexes",
    "list_procedures",
    "get_procedure_definition",
    "get_dependencies",
)


class ToolFailure(Exception):
    """A failure whose message is safe to return to the client."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ConnectionManager:
    def __init__(self, factory: Callable[[], Connection]) -> None:
        self._factory = factory
        self._conn: Connection | None = None
        self._lock = threading.Lock()

    def get(self) -> Connection:
        with self._lock:
            if self._conn is None:
                self._conn = self._factory()
            return self._conn

    def reset(self) -> None:
        with self._lock:
            conn, self._conn = self._conn, None
        close = getattr(conn, "close", None)
        if close is not None:
            try:
                close()
            except Exception:
                log.debug("error closing connection", exc_info=True)


def _scrubbed(text: str | None, *, quoted_identifier: bool = False) -> tuple[str | None, int]:
    if text is None:
        return None, 0
    r = scrubber.scrub(text, quoted_identifier=quoted_identifier)
    return r.text, r.masked


class MetadataTools:
    def __init__(
        self,
        connections: ConnectionManager,
        *,
        allowed_schemas: tuple[str, ...] | None = None,
        denied_schemas: tuple[str, ...] = (),
        max_definition_chars: int = 200_000,
    ) -> None:
        self._connections = connections
        self._allowed = allowed_schemas
        self._denied = denied_schemas
        self._max_def = max_definition_chars

    def precheck(self, args: dict[str, Any]) -> None:
        """Validate names and the schema policy before any connection is opened."""
        for key, value in args.items():
            catalog.validate_identifier(value, key)
        if "schema" in args:
            catalog.SchemaPolicy(self._allowed, self._denied).check(args["schema"])

    def _ctx(self) -> tuple[Connection, Catalog]:
        conn = self._connections.get()
        return conn, Catalog(conn, allowed_schemas=self._allowed, denied_schemas=self._denied)

    # -- tools -----------------------------------------------------------------

    def list_schemas(self) -> dict[str, Any]:
        conn, cat = self._ctx()
        rows = query_guard.run(conn, queries.LIST_SCHEMAS)
        return {"schemas": [r for r in rows if cat.schema_allowed(str(r["schema_name"]))]}

    def list_tables(self, schema: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        ref = cat.resolve_schema(schema)
        rows = query_guard.run(conn, queries.LIST_TABLES, (ref.schema_id, ref.schema_id))
        return {"schema": ref.name, "tables": rows}

    def describe_table(self, schema: str, table: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        obj = cat.resolve_object(schema, table, catalog.TABLE_OR_VIEW_TYPES)
        masked = 0
        columns = []
        for r in query_guard.run(conn, queries.DESCRIBE_COLUMNS, (obj.object_id,)):
            r["default_definition"], m1 = _scrubbed(r["default_definition"])
            r["computed_definition"], m2 = _scrubbed(r["computed_definition"])
            masked += m1 + m2
            columns.append(r)
        return {"schema": obj.schema, "table": obj.name, "type": obj.type, "columns": columns, "masked_literals": masked}

    def get_constraints(self, schema: str, table: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        obj = cat.resolve_object(schema, table, catalog.TABLE_TYPES)
        oid = (obj.object_id,)
        masked = 0

        keys: dict[str, dict[str, Any]] = {}
        for r in query_guard.run(conn, queries.KEY_CONSTRAINTS, oid):
            k = keys.setdefault(r["constraint_name"], {"name": r["constraint_name"], "type": r["type_desc"], "columns": []})
            k["columns"].append(r["column_name"])

        fks: dict[str, dict[str, Any]] = {}
        for r in query_guard.run(conn, queries.FOREIGN_KEYS, oid):
            f = fks.setdefault(
                r["constraint_name"],
                {
                    "name": r["constraint_name"],
                    "columns": [],
                    "referenced_schema": r["referenced_schema"],
                    "referenced_table": r["referenced_table"],
                    "referenced_columns": [],
                    "on_delete": r["delete_referential_action_desc"],
                    "on_update": r["update_referential_action_desc"],
                    "is_disabled": r["is_disabled"],
                    "is_not_trusted": r["is_not_trusted"],
                },
            )
            f["columns"].append(r["column_name"])
            f["referenced_columns"].append(r["referenced_column"])

        checks = []
        for r in query_guard.run(conn, queries.CHECK_CONSTRAINTS, oid):
            r["definition"], m = _scrubbed(r["definition"])
            masked += m
            checks.append(r)

        defaults = []
        for r in query_guard.run(conn, queries.DEFAULT_CONSTRAINTS, oid):
            r["definition"], m = _scrubbed(r["definition"])
            masked += m
            defaults.append(r)

        return {
            "schema": obj.schema,
            "table": obj.name,
            "primary_and_unique": list(keys.values()),
            "foreign_keys": [f for f in fks.values() if cat.schema_allowed(f["referenced_schema"])],
            "checks": checks,
            "defaults": defaults,
            "masked_literals": masked,
        }

    def get_indexes(self, schema: str, table: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        obj = cat.resolve_object(schema, table, catalog.TABLE_OR_VIEW_TYPES)
        masked = 0
        indexes: dict[str, dict[str, Any]] = {}
        for r in query_guard.run(conn, queries.INDEXES, (obj.object_id,)):
            ix = indexes.get(r["index_name"])
            if ix is None:
                flt, m = _scrubbed(r["filter_definition"])
                masked += m
                ix = indexes[r["index_name"]] = {
                    "name": r["index_name"],
                    "type": r["type_desc"],
                    "is_unique": r["is_unique"],
                    "is_primary_key": r["is_primary_key"],
                    "is_unique_constraint": r["is_unique_constraint"],
                    "filter": flt,
                    "key_columns": [],
                    "included_columns": [],
                }
            if r["is_included_column"]:
                ix["included_columns"].append(r["column_name"])
            else:
                ix["key_columns"].append({"column": r["column_name"], "descending": r["is_descending_key"]})
        return {"schema": obj.schema, "table": obj.name, "indexes": list(indexes.values()), "masked_literals": masked}

    def list_procedures(self, schema: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        ref = cat.resolve_schema(schema)
        rows = query_guard.run(conn, queries.LIST_PROCEDURES, (ref.schema_id,))
        return {"schema": ref.name, "routines": rows}

    def get_procedure_definition(self, schema: str, name: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        obj = cat.resolve_object(schema, name, catalog.MODULE_TYPES)
        oid = (obj.object_id,)
        params = query_guard.run(conn, queries.MODULE_PARAMETERS, oid)
        rows = query_guard.run(conn, queries.MODULE_DEFINITION, oid)
        definition = rows[0]["definition"] if rows else None
        quoted = bool(rows[0]["uses_quoted_identifier"]) if rows else False
        truncated = False
        if definition is not None and len(definition) > self._max_def:
            definition, truncated = definition[: self._max_def], True
        result = scrubber.scrub(definition, quoted_identifier=quoted) if definition is not None else None
        return {
            "schema": obj.schema,
            "name": obj.name,
            "type": obj.type,
            "parameters": params,
            # NULL definition means the module is encrypted or not visible to this login.
            "definition": result.text if result else None,
            "masked": (
                {"strings": result.strings, "numbers": result.numbers, "comments": result.comments, "patterns": len(result.patterns)}
                if result
                else None
            ),
            "truncated": truncated,
        }

    def get_dependencies(self, schema: str, name: str) -> dict[str, Any]:
        conn, cat = self._ctx()
        obj = cat.resolve_object(schema, name, catalog.DEPENDENCY_TYPES)
        oid = (obj.object_id,)

        def allowed(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
            return [r for r in rows if r.get(key) is None or cat.schema_allowed(str(r[key]))]

        return {
            "schema": obj.schema,
            "name": obj.name,
            "type": obj.type,
            "depends_on": allowed(query_guard.run(conn, queries.DEPENDS_ON, oid), "referenced_schema_name"),
            "referenced_by": allowed(query_guard.run(conn, queries.REFERENCED_BY, oid), "referencing_schema"),
            "fk_parents": allowed(query_guard.run(conn, queries.FK_PARENTS, oid), "referenced_schema"),
            "fk_children": allowed(query_guard.run(conn, queries.FK_CHILDREN, oid), "referencing_schema"),
        }


def _is_db_error(exc: BaseException) -> bool:
    try:
        import pyodbc
    except ImportError:  # pragma: no cover
        return False
    return isinstance(exc, pyodbc.Error)


class ToolRunner:
    """Wraps every tool call with error mapping, the output check and the audit log."""

    def __init__(self, tools: MetadataTools, connections: ConnectionManager, audit: AuditLog) -> None:
        self.tools = tools
        self._connections = connections
        self._audit = audit
        # pyodbc connections must not be used from two threads at once (threadsafety = 1),
        # and the SDK may run sync tools concurrently. Metadata calls are short; serialise them.
        self._call_lock = threading.Lock()

    def call(self, tool: str, **args: Any) -> str:
        if tool not in TOOL_NAMES:
            raise ToolFailure("unknown_tool", "unknown tool")
        start = time.perf_counter()

        def done(outcome: str, reason: str | None = None, text: str | None = None, extra: dict[str, Any] | None = None) -> None:
            self._audit.record(
                tool=tool,
                args=args,
                outcome=outcome,
                reason=reason,
                response_text=text,
                duration_ms=(time.perf_counter() - start) * 1000,
                extra=extra,
            )

        try:
            self.tools.precheck(args)
            with self._call_lock:
                payload = getattr(self.tools, tool)(**args)
            checked = output_check(payload)
        except (InvalidName, NotFound, SchemaNotAllowed) as e:
            msg = dlp_patterns.mask(str(e))[0]
            done("refused", type(e).__name__)
            raise ToolFailure("refused", msg) from None
        except QueryRefused as e:
            done("refused", f"QueryRefused: {e}")
            raise ToolFailure("refused", "query refused by guard") from None
        except OutputBlocked as e:
            done("blocked", "output_guard", extra={"kinds": e.kinds})
            raise ToolFailure("blocked", f"response blocked: data-like content detected ({', '.join(e.kinds)})") from None
        except Exception as e:
            if _is_db_error(e):
                self._connections.reset()
                sqlstate = e.args[0] if getattr(e, "args", None) else "unknown"
                done("error", f"db_error sqlstate={sqlstate}")
                raise ToolFailure("db_error", f"database error (SQLSTATE {sqlstate})") from None
            log.exception("unexpected error in %s", tool)
            done("error", type(e).__name__)
            raise ToolFailure("internal_error", "internal error; see the server's audit log") from None
        done("ok", text=checked.text)
        return checked.text
