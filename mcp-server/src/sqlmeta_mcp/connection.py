"""Read-only connection factory.

The real read-only guarantee is the database principal (sql/metadata_reader_login.sql:
VIEW DEFINITION only, DENY on user schemas). This module adds what the client
side can: ApplicationIntent=ReadOnly, encryption on, no autocommit, timeouts,
and a rollback after every query (query_guard.run).
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .credentials import CredentialProvider, KeyringProvider

_AUTH_KEYWORDS = {
    "windows": {"Trusted_Connection": "yes"},
    "entra-integrated": {"Authentication": "ActiveDirectoryIntegrated"},
    "entra-interactive": {"Authentication": "ActiveDirectoryInteractive"},
    "entra-msi": {"Authentication": "ActiveDirectoryMsi"},
    "sql-keyring": {},
}


def odbc_value(value: str) -> str:
    """Quote an ODBC connection-string value so it cannot inject further keywords."""
    return "{" + value.replace("}", "}}") + "}"


def connection_string(cfg: Config, password: str | None = None) -> str:
    parts: dict[str, str] = {
        "Driver": odbc_value(cfg.driver),
        "Server": odbc_value(cfg.server),
        "Database": odbc_value(cfg.database),
        "ApplicationIntent": "ReadOnly",
        "Encrypt": "yes" if cfg.encrypt else "no",
        "TrustServerCertificate": "yes" if cfg.trust_server_certificate else "no",
        "Application Name": odbc_value("sqlmeta-mcp"),
    }
    parts.update(_AUTH_KEYWORDS[cfg.auth])
    if cfg.auth == "sql-keyring":
        if not cfg.username or password is None:
            raise ValueError("sql-keyring auth needs a username and a password from the keychain")
        parts["UID"] = odbc_value(cfg.username)
        parts["PWD"] = odbc_value(password)
    elif cfg.auth == "entra-msi" and cfg.username:
        parts["UID"] = odbc_value(cfg.username)  # client id of a user-assigned identity
    return ";".join(f"{k}={v}" for k, v in parts.items()) + ";"


def connect(cfg: Config, credentials: CredentialProvider | None = None) -> Any:
    import pyodbc

    password = None
    if cfg.auth == "sql-keyring":
        assert cfg.username
        password = (credentials or KeyringProvider(cfg.keyring_service)).password(cfg.username)
    conn = pyodbc.connect(
        connection_string(cfg, password),
        autocommit=False,
        readonly=True,
        timeout=cfg.login_timeout_s,
    )
    del password
    conn.timeout = cfg.query_timeout_s
    return conn
