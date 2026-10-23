"""Server configuration, loaded from a TOML file.

The file holds connection *coordinates* only (server, database, auth mode).
Secrets are refused: a password, if one is needed at all, is fetched at runtime
by credentials.py from the OS keychain.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

AuthMode = Literal["windows", "entra-integrated", "entra-interactive", "entra-msi", "sql-keyring"]
AUTH_MODES: tuple[str, ...] = AuthMode.__args__  # type: ignore[attr-defined]

CONFIG_ENV = "SQLMETA_MCP_CONFIG"
_SECRET_KEYS = {"password", "pwd", "secret", "token", "connection_string", "connstr", "access_token"}


class ConfigError(ValueError):
    pass


def _default_state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "sqlmeta-mcp"


@dataclass(frozen=True)
class Config:
    server: str
    database: str
    auth: AuthMode = "windows"
    driver: str = "ODBC Driver 18 for SQL Server"
    username: str | None = None  # sql-keyring login, or client id for a user-assigned managed identity
    keyring_service: str = "sqlmeta-mcp"
    encrypt: bool = True
    trust_server_certificate: bool = False
    login_timeout_s: int = 15
    query_timeout_s: int = 30
    allowed_schemas: tuple[str, ...] | None = None
    denied_schemas: tuple[str, ...] = ()
    max_definition_chars: int = 200_000
    audit_log: Path = field(default_factory=lambda: _default_state_dir() / "audit.jsonl")


def _find_secrets(data: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            p = f"{path}.{k}" if path else str(k)
            if str(k).lower() in _SECRET_KEYS:
                hits.append(p)
            hits.extend(_find_secrets(v, p))
    return hits


def from_mapping(data: dict[str, Any]) -> Config:
    secrets = _find_secrets(data)
    if secrets:
        raise ConfigError(
            f"secrets are not allowed in the config file ({', '.join(secrets)}); "
            "use auth = 'windows' / 'entra-*', or 'sql-keyring' with the password in the OS keychain"
        )
    merged: dict[str, Any] = dict(data)
    unknown = set(merged) - set(Config.__dataclass_fields__)
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")
    for req in ("server", "database"):
        if not isinstance(merged.get(req), str) or not merged[req]:
            raise ConfigError(f"'{req}' is required")
    if merged.get("auth", "windows") not in AUTH_MODES:
        raise ConfigError(f"auth must be one of {', '.join(AUTH_MODES)}")
    if merged.get("auth") == "sql-keyring" and not merged.get("username"):
        raise ConfigError("auth = 'sql-keyring' needs 'username'")
    for key in ("allowed_schemas", "denied_schemas"):
        if key in merged and merged[key] is not None:
            merged[key] = tuple(merged[key])
    if "audit_log" in merged:
        merged["audit_log"] = Path(merged["audit_log"]).expanduser()
    return Config(**merged)


def load(path: str | os.PathLike[str] | None = None) -> Config:
    p = path or os.environ.get(CONFIG_ENV)
    if not p:
        raise ConfigError(f"no config file: pass --config or set {CONFIG_ENV}")
    with open(p, "rb") as f:
        return from_mapping(tomllib.load(f))
