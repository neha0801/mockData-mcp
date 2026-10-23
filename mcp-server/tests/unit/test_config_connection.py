from __future__ import annotations

from pathlib import Path

import pytest
from sqlmeta_mcp import config
from sqlmeta_mcp.config import Config, ConfigError
from sqlmeta_mcp.connection import connection_string, odbc_value


def test_minimal_config(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text('server = "dev-sql"\ndatabase = "AppDb"\ndenied_schemas = ["audit"]\n')
    cfg = config.load(p)
    assert cfg.auth == "windows" and cfg.denied_schemas == ("audit",) and cfg.encrypt


@pytest.mark.parametrize("key", ["password", "PWD", "connection_string", "token"])
def test_secrets_in_config_refused(key: str) -> None:
    with pytest.raises(ConfigError, match="secrets are not allowed"):
        config.from_mapping({"server": "s", "database": "d", key: "x"})


def test_unknown_keys_and_bad_auth_refused() -> None:
    with pytest.raises(ConfigError, match="unknown"):
        config.from_mapping({"server": "s", "database": "d", "free_sql": True})
    with pytest.raises(ConfigError, match="auth"):
        config.from_mapping({"server": "s", "database": "d", "auth": "anonymous"})
    with pytest.raises(ConfigError, match="username"):
        config.from_mapping({"server": "s", "database": "d", "auth": "sql-keyring"})


def test_no_config_source(monkeypatch) -> None:
    monkeypatch.delenv(config.CONFIG_ENV, raising=False)
    with pytest.raises(ConfigError):
        config.load()


def test_connection_string_read_only_and_encrypted() -> None:
    cs = connection_string(Config(server="dev-sql", database="AppDb"))
    assert "ApplicationIntent=ReadOnly" in cs
    assert "Encrypt=yes" in cs and "TrustServerCertificate=no" in cs
    assert "Trusted_Connection=yes" in cs
    assert "PWD" not in cs


def test_entra_modes() -> None:
    assert "Authentication=ActiveDirectoryIntegrated" in connection_string(Config(server="s", database="d", auth="entra-integrated"))


def test_values_cannot_inject_keywords() -> None:
    cs = connection_string(Config(server="s;Database=master", database="d}x"))
    assert "Server={s;Database=master}" in cs
    assert "Database={d}}x}" in cs
    assert odbc_value("a}b") == "{a}}b}"


def test_sql_keyring_needs_password() -> None:
    cfg = Config(server="s", database="d", auth="sql-keyring", username="svc")
    with pytest.raises(ValueError):
        connection_string(cfg)
    assert "PWD={p}}w}" in connection_string(cfg, "p}w")


def test_example_config_is_valid() -> None:
    cfg = config.load(Path(__file__).parents[2] / "config.example.toml")
    assert cfg.auth == "windows" and cfg.denied_schemas == ("audit", "security")
