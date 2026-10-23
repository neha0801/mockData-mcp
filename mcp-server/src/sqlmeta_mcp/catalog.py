"""Validate object-name inputs and resolve them to catalog ids.

Names supplied by the client are only ever bound as query parameters to the
RESOLVE_* catalog lookups. Every other query receives the resulting integer id,
so a name can never become part of SQL text.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from . import queries, query_guard
from .query_guard import Connection

MAX_IDENTIFIER_LEN = 128  # sysname

# sys.objects.type codes
TABLE_TYPES = frozenset({"U"})
TABLE_OR_VIEW_TYPES = frozenset({"U", "V"})
MODULE_TYPES = frozenset({"P", "V", "FN", "IF", "TF", "TR"})
ROUTINE_TYPES = frozenset({"P", "FN", "IF", "TF"})
DEPENDENCY_TYPES = frozenset({"U", "V", "P", "FN", "IF", "TF", "TR"})


class InvalidName(ValueError):
    pass


class NotFound(LookupError):
    pass


class SchemaNotAllowed(PermissionError):
    pass


@dataclass(frozen=True)
class SchemaRef:
    schema_id: int
    name: str


@dataclass(frozen=True)
class ObjectRef:
    object_id: int
    type: str
    schema: str
    name: str


def validate_identifier(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise InvalidName(f"{what} must be a string")
    if not value or len(value) > MAX_IDENTIFIER_LEN:
        raise InvalidName(f"{what} must be 1-{MAX_IDENTIFIER_LEN} characters")
    if value != value.strip():
        raise InvalidName(f"{what} must not have leading or trailing whitespace")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InvalidName(f"{what} must not contain control characters")
    return value


class SchemaPolicy:
    """Configured allow/deny lists. Deny wins. Needs no database connection."""

    def __init__(self, allowed: Collection[str] | None = None, denied: Collection[str] = ()) -> None:
        self._allowed = {s.lower() for s in allowed} if allowed is not None else None
        self._denied = {s.lower() for s in denied}

    def allows(self, name: str) -> bool:
        key = name.lower()
        if key in self._denied:
            return False
        return self._allowed is None or key in self._allowed

    def check(self, name: str) -> None:
        if not self.allows(name):
            raise SchemaNotAllowed(f"schema {name!r} is not available through this server")


class Catalog:
    def __init__(
        self,
        conn: Connection,
        *,
        allowed_schemas: Collection[str] | None = None,
        denied_schemas: Collection[str] = (),
    ) -> None:
        self._conn = conn
        self.policy = SchemaPolicy(allowed_schemas, denied_schemas)

    def schema_allowed(self, name: str) -> bool:
        return self.policy.allows(name)

    def _check_schema(self, name: str) -> None:
        self.policy.check(name)

    def resolve_schema(self, schema: object) -> SchemaRef:
        name = validate_identifier(schema, "schema")
        self._check_schema(name)
        rows = query_guard.run(self._conn, queries.RESOLVE_SCHEMA, (name,))
        if not rows:
            raise NotFound(f"schema {name!r} not found")
        return SchemaRef(schema_id=int(rows[0]["schema_id"]), name=str(rows[0]["name"]))

    def resolve_object(self, schema: object, name: object, allowed_types: Collection[str]) -> ObjectRef:
        s = validate_identifier(schema, "schema")
        o = validate_identifier(name, "name")
        self._check_schema(s)
        rows = query_guard.run(self._conn, queries.RESOLVE_OBJECT, (s, o))
        if not rows:
            raise NotFound(f"object {s}.{o} not found")
        row = rows[0]
        obj_type = str(row["type"]).strip()
        if obj_type not in allowed_types:
            raise NotFound(f"object {s}.{o} is not one of the supported types for this tool")
        return ObjectRef(
            object_id=int(row["object_id"]),
            type=obj_type,
            schema=str(row["schema_name"]),
            name=str(row["object_name"]),
        )
