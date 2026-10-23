from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from sqlmeta_mcp import audit
from sqlmeta_mcp.audit import AuditLog
from sqlmeta_mcp.tools import ToolFailure, ToolRunner


def _entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_every_call_is_logged_with_outcome(runner: ToolRunner, audit_path: Path) -> None:
    runner.call("list_schemas")
    with pytest.raises(ToolFailure):
        runner.call("describe_table", schema="dbo", table="Nope")
    with pytest.raises(ToolFailure):
        runner.call("describe_table", schema="secret", table="Keys")
    entries = _entries(audit_path)
    assert [(e["tool"], e["outcome"]) for e in entries] == [
        ("list_schemas", "ok"),
        ("describe_table", "refused"),
        ("describe_table", "refused"),
    ]
    assert entries[0]["response_sha256"] and entries[0]["response_bytes"] > 0
    assert entries[1]["args"] == {"schema": "dbo", "table": "Nope"}


def test_response_content_never_logged(runner: ToolRunner, audit_path: Path) -> None:
    out = runner.call("get_procedure_definition", schema="dbo", name="usp_Route")
    log = audit_path.read_text()
    assert "@Client" in out
    assert "@Client" not in log and "<STR>" not in log


def test_data_like_args_masked_in_log(runner: ToolRunner, audit_path: Path) -> None:
    with pytest.raises(ToolFailure):
        runner.call("describe_table", schema="dbo", table="jane.doe@example.com")
    assert "jane.doe" not in audit_path.read_text()


def test_blocked_output_logged(runner: ToolRunner, db, audit_path: Path) -> None:
    db.handlers["list_schemas"] = lambda p: (["schema_name", "owner"], [("dbo", "GB82WEST12345698765432")])
    with pytest.raises(ToolFailure):
        runner.call("list_schemas")
    e = _entries(audit_path)[-1]
    assert e["outcome"] == "blocked" and e["extra"]["kinds"] == ["iban"]
    assert "GB82" not in audit_path.read_text()


def test_hash_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.record(tool="list_schemas", args={"i": i}, outcome="ok", response_text="x")
    assert audit.verify(path) == (True, 3)

    # A new process continues the chain from the last line.
    AuditLog(path).record(tool="list_schemas", args={}, outcome="ok")
    assert audit.verify(path) == (True, 4)

    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], *lines[2:]]) + "\n")
    ok, count = audit.verify(path)
    assert not ok and count == 1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_log_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    AuditLog(path).record(tool="t", args={}, outcome="ok")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
