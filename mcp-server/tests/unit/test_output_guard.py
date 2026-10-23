from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal

import pytest
from sqlmeta_mcp import output_guard
from sqlmeta_mcp.output_guard import OutputBlocked
from sqlmeta_mcp.tools import ToolFailure, ToolRunner


def test_clean_metadata_passes() -> None:
    payload = {
        "columns": [
            {
                "column_name": "AccountNo",
                "data_type": "varchar",
                "max_length": 34,
                "create_date": datetime(2024, 1, 1, 10, 0, 0, 123000),
                "scale": Decimal("2"),
            }
        ]
    }
    text = output_guard.check(payload).text
    assert json.loads(text)["columns"][0]["column_name"] == "AccountNo"


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("jane.doe@example.com", "email"),
        ("GB82WEST12345698765432", "iban"),
        ("5493001KJTIIGC8Y1R12", "lei"),
        ("4111 1111 1111 1111", "payment_card"),
        ("123-45-6789", "us_ssn"),
        ("Acct12345678", "account_like"),
        ("John Smith", "person_name"),
    ],
)
def test_data_like_values_blocked(value: str, kind: str) -> None:
    with pytest.raises(OutputBlocked) as e:
        output_guard.check({"x": [{"definition": f"text {value} text"}]})
    assert kind in e.value.kinds


def test_patterns_in_keys_blocked() -> None:
    with pytest.raises(OutputBlocked):
        output_guard.check({"jane.doe@example.com": 1})


def test_binary_refused() -> None:
    with pytest.raises(TypeError):
        output_guard.check({"x": b"\x00"})


def test_runner_blocks_and_does_not_echo_content(runner: ToolRunner, db) -> None:
    def leaky(p):
        return ["schema_name", "owner"], [("dbo", "jane.doe@example.com")]

    db.handlers["list_schemas"] = leaky
    with pytest.raises(ToolFailure) as e:
        runner.call("list_schemas")
    assert e.value.code == "blocked"
    assert "jane" not in str(e.value) and "email" in str(e.value)
