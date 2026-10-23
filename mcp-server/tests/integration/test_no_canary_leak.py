"""End-to-end against a real SQL Server. See README.md in this directory."""

from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pyodbc = pytest.importorskip("pyodbc")

from sqlmeta_mcp.audit import AuditLog  # noqa: E402
from sqlmeta_mcp.config import Config  # noqa: E402
from sqlmeta_mcp.connection import connect  # noqa: E402
from sqlmeta_mcp.tools import ConnectionManager, MetadataTools, ToolFailure, ToolRunner  # noqa: E402

pytestmark = pytest.mark.integration

HERE = Path(__file__).parent
LOCKDOWN_SQL = HERE.parent.parent / "sql" / "metadata_reader_login.sql"
SERVER = os.environ.get("SQLMETA_IT_SERVER")
SA_PASSWORD = os.environ.get("SQLMETA_IT_SA_PASSWORD")
DRIVER = os.environ.get("SQLMETA_IT_DRIVER", "ODBC Driver 18 for SQL Server")
DB = "MockdataIT"
READER = "sqlmeta_it_reader"

CANARIES = (
    "canary",
    "99887766",
    "55443322",
    "11223344",
    "66778899",
    "12121212",
    "34343434",
    "250000",
    "canary.person@example.com",
    "GB82WEST12345698765432",
    "GB33BUKB20201555555555",
    "5493001KJTIIGC8Y1R12",
    "ROUTE_A",
    "4111111111111111",
)

if not (SERVER and SA_PASSWORD):
    pytest.skip("set SQLMETA_IT_SERVER and SQLMETA_IT_SA_PASSWORD to run integration tests", allow_module_level=True)


class _StaticPassword:
    def __init__(self, pw: str) -> None:
        self._pw = pw

    def password(self, username: str) -> str:
        return self._pw


def _admin(database: str = "master") -> Any:
    cs = f"Driver={{{DRIVER}}};Server={SERVER};Database={database};UID=sa;PWD={{{SA_PASSWORD}}};Encrypt=yes;TrustServerCertificate=yes;"
    return pyodbc.connect(cs, autocommit=True, timeout=30)


def _batches(script: str) -> list[str]:
    return [b for b in re.split(r"^\s*GO\s*$", script, flags=re.MULTILINE | re.IGNORECASE) if b.strip()]


@pytest.fixture(scope="module")
def reader_password() -> Iterator[str]:
    pw = "Rd1!" + secrets.token_hex(16)
    with _admin() as conn:
        cur = conn.cursor()
        for batch in _batches((HERE / "seed.sql").read_text()):
            cur.execute(batch)
        cur.execute(f"IF SUSER_ID(N'{READER}') IS NOT NULL DROP LOGIN [{READER}]")
        cur.execute(f"CREATE LOGIN [{READER}] WITH PASSWORD = N'{pw}', CHECK_POLICY = OFF, DEFAULT_DATABASE = [{DB}]")
    lockdown = LOCKDOWN_SQL.read_text()
    lockdown = re.sub(r"DECLARE @principal sysname = N'[^']*';", f"DECLARE @principal sysname = N'{READER}';", lockdown)
    lockdown = re.sub(r"DECLARE @login     sysname = N'[^']*';", f"DECLARE @login     sysname = N'{READER}';", lockdown)
    with _admin(DB) as conn:
        cur = conn.cursor()
        cur.execute(lockdown)
        while cur.nextset():
            pass
    yield pw


@pytest.fixture(scope="module")
def cfg(tmp_path_factory: pytest.TempPathFactory) -> Config:
    return Config(
        server=SERVER or "",
        database=DB,
        driver=DRIVER,
        auth="sql-keyring",
        username=READER,
        trust_server_certificate=True,  # throwaway container with a self-signed certificate
        denied_schemas=("secret",),
        audit_log=tmp_path_factory.mktemp("audit") / "audit.jsonl",
    )


@pytest.fixture(scope="module")
def runner(cfg: Config, reader_password: str) -> ToolRunner:
    cm = ConnectionManager(lambda: connect(cfg, _StaticPassword(reader_password)))
    tools = MetadataTools(cm, denied_schemas=cfg.denied_schemas)
    return ToolRunner(tools, cm, AuditLog(cfg.audit_log))


@pytest.fixture
def raw_reader(cfg: Config, reader_password: str) -> Iterator[Any]:
    conn = connect(cfg, _StaticPassword(reader_password))
    yield conn
    conn.close()


def _assert_clean(text: str) -> None:
    low = text.lower()
    for c in CANARIES:
        assert c.lower() not in low, f"canary {c!r} leaked"


def test_every_tool_on_every_object_leaks_nothing(runner: ToolRunner) -> None:
    outputs: list[str] = []

    def call(tool: str, **args: str) -> dict[str, Any]:
        text = runner.call(tool, **args)
        outputs.append(text)
        return json.loads(text)  # type: ignore[no-any-return]

    schemas = [s["schema_name"] for s in call("list_schemas")["schemas"]]
    assert "app" in schemas and "secret" not in schemas

    tables = [t["table_name"] for t in call("list_tables", schema="app")["tables"]]
    assert {"Accounts", "Clients", "vBigAccounts"} <= set(tables)
    for t in tables:
        call("describe_table", schema="app", table=t)
        call("get_indexes", schema="app", table=t)
        call("get_dependencies", schema="app", name=t)
        if not t.startswith("v"):
            call("get_constraints", schema="app", table=t)

    routines = [r["object_name"] for r in call("list_procedures", schema="app")["routines"]]
    assert {"usp_Route", "fn_Fee", "usp_Encrypted"} <= set(routines)
    for name in [*routines, "vBigAccounts", "trg_Accounts"]:
        call("get_procedure_definition", schema="app", name=name)
        call("get_dependencies", schema="app", name=name)

    for text in outputs:
        _assert_clean(text)


def test_metadata_is_still_useful(runner: ToolRunner) -> None:
    cols = {c["column_name"]: c for c in json.loads(runner.call("describe_table", schema="app", table="Accounts"))["columns"]}
    assert cols["AccountNo"]["data_type"] == "varchar" and cols["AccountNo"]["max_length"] == 34
    assert cols["AccountNo"]["default_definition"] == "('<STR>')"
    assert cols["CreditLimit"]["is_computed"]

    cons = json.loads(runner.call("get_constraints", schema="app", table="Accounts"))
    assert cons["foreign_keys"][0]["referenced_table"] == "Clients"
    checks = {c["constraint_name"]: c["definition"] for c in cons["checks"]}
    assert checks["CK_Accounts_Status"] == "([Status]='<STR>' OR [Status]='<STR>')"

    proc = json.loads(runner.call("get_procedure_definition", schema="app", name="usp_Route"))
    assert [p["parameter_name"] for p in proc["parameters"]] == ["@Client", "@Amount"]
    assert "@Client" in proc["definition"] and "app.Accounts" in proc["definition"]

    deps = json.loads(runner.call("get_dependencies", schema="app", name="usp_Route"))
    assert any(d["referenced_entity_name"] == "Accounts" for d in deps["depends_on"])


def test_encrypted_module_has_no_definition(runner: ToolRunner) -> None:
    out = json.loads(runner.call("get_procedure_definition", schema="app", name="usp_Encrypted"))
    assert out["definition"] is None


def test_denied_schema_refused(runner: ToolRunner) -> None:
    with pytest.raises(ToolFailure) as e:
        runner.call("describe_table", schema="secret", table="Keys")
    assert e.value.code == "refused"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM app.Accounts",
        "SELECT * FROM app.Clients",
        "SELECT * FROM app.vBigAccounts",
        "SELECT * FROM secret.Keys",
        "INSERT app.Clients (Lei, FullName) VALUES ('X', 'Y')",
        "EXEC app.usp_Route @Client = N'x', @Amount = 1",
        "SELECT app.fn_Fee(1)",
        "CREATE TABLE app.Evil (x int)",
    ],
)
def test_database_layer_refuses_data_access_for_reader(raw_reader: Any, sql: str) -> None:
    """Even with a raw connection (bypassing every guard in this package), the principal cannot read or change data."""
    cur = raw_reader.cursor()
    with pytest.raises(pyodbc.Error) as e:
        cur.execute(sql)
        cur.fetchall()
    assert "permission" in str(e.value).lower() or "denied" in str(e.value).lower()
    raw_reader.rollback()


def test_reader_can_read_catalog(raw_reader: Any) -> None:
    cur = raw_reader.cursor()
    cur.execute("SELECT COUNT(*) FROM sys.tables")
    assert cur.fetchone()[0] >= 3
    raw_reader.rollback()
