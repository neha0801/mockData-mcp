"""Proof that literals are masked in procedure, view, constraint and default text."""

from __future__ import annotations

import json

import pytest
from conftest import assert_no_canary
from sqlmeta_mcp.scrubber import BIN, NUM, STR, TRUNCATED, scrub
from sqlmeta_mcp.tools import ToolRunner


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("@x = 'ACME'", f"@x = {STR}"),
        ("@x = N'ACME'", f"@x = N{STR}"),
        ("@x = 'O''Brien'", f"@x = {STR}"),
        ("@x = ''", f"@x = {STR}"),
        ("@n > 1000", f"@n > {NUM}"),
        ("@n > 1000.50", f"@n > {NUM}"),
        ("@n > .5", f"@n > {NUM}"),
        ("@n > 1.5e-3", f"@n > {NUM}"),
        ("@m = $12.50", f"@m = {NUM}"),
        ("@b = 0xDEADBEEF", f"@b = {BIN}"),
        ("((0))", f"(({NUM}))"),
        ("([Status]='C' OR [Status]='O')", f"([Status]={STR} OR [Status]={STR})"),
        ("SELECT col1, [col 2], @var3 FROM dbo.t4", "SELECT col1, [col 2], @var3 FROM dbo.t4"),
        ("SELECT [it's]", "SELECT [it's]"),
        ("SELECT [a]]b]", "SELECT [a]]b]"),
    ],
)
def test_scrub_cases(src: str, expected: str) -> None:
    assert scrub(src).text == expected


def test_comments_removed_including_nested() -> None:
    r = scrub("SELECT 1 -- acct 99887766\n/* a /* b */ c */ SELECT 2")
    assert "99887766" not in r.text and " a " not in r.text and " c " not in r.text
    assert r.comments == 2


def test_double_quotes_follow_quoted_identifier_setting() -> None:
    assert scrub('SELECT "secret"').text == f"SELECT {STR}"
    assert scrub('SELECT "ColName"', quoted_identifier=True).text == 'SELECT "ColName"'


@pytest.mark.parametrize("src", ["SELECT 'unterminated 99887766", "SELECT [unterminated", "SELECT 1 /* open 99887766"])
def test_unterminated_tokens_mask_to_end(src: str) -> None:
    r = scrub(src)
    assert r.text.endswith(TRUNCATED)
    assert "99887766" not in r.text and "unterminated" not in r.text.split("SELECT", 1)[1].replace(TRUNCATED, "")


def test_patterns_in_identifiers_masked() -> None:
    r = scrub("SELECT [Acct12345678], [jane.doe@corp.com], [6F9619FF-8B86-D011-B42D-00C04FC964FF] FROM t")
    assert "12345678" not in r.text
    assert "jane.doe@corp.com" not in r.text
    assert "6F9619FF" not in r.text
    assert {"account_like", "email", "guid"} <= set(r.patterns)


def test_identifiers_with_short_digits_kept() -> None:
    assert scrub("SELECT Addr2, Line3 FROM dbo.T2").text == "SELECT Addr2, Line3 FROM dbo.T2"


def test_none_definition() -> None:
    assert scrub(None).text == ""


def test_procedure_definition_tool_masks_every_literal(runner: ToolRunner) -> None:
    out = runner.call("get_procedure_definition", schema="dbo", name="usp_Route")
    assert_no_canary(out)
    data = json.loads(out)
    d = data["definition"]
    assert "ROUTE_A" not in d and "250000" not in d
    assert d.count(STR) >= 5
    assert "-- <comment removed>" in d and "/* <comment removed> */" in d
    assert data["masked"]["strings"] >= 5 and data["masked"]["comments"] == 2
    # Structure survives for contract inference.
    assert "@Client" in d and "IF" in d and "SELECT" in d


def test_constraint_and_default_text_masked(runner: ToolRunner) -> None:
    out = runner.call("get_constraints", schema="dbo", table="Accounts")
    assert_no_canary(out)
    checks = {c["constraint_name"]: c["definition"] for c in json.loads(out)["checks"]}
    assert checks["CK_Accounts_Status"] == f"([Status]={STR} OR [Status]={STR})"


def test_column_defaults_and_computed_masked(runner: ToolRunner) -> None:
    out = runner.call("describe_table", schema="dbo", table="Accounts")
    assert_no_canary(out)
    cols = {c["column_name"]: c for c in json.loads(out)["columns"]}
    assert cols["AccountNo"]["default_definition"] == f"({STR})"
    assert cols["Limit"]["computed_definition"] == f"([Base]*({NUM}))"
    assert cols["AccountNo"]["max_length"] == 34  # metadata itself is kept


def test_index_filter_masked(runner: ToolRunner) -> None:
    out = runner.call("get_indexes", schema="dbo", table="Accounts")
    assert_no_canary(out)
    ix = {i["name"]: i for i in json.loads(out)["indexes"]}
    assert ix["IX_Accounts_No"]["filter"] == f"([AccountNo]<>{STR})"
    assert ix["IX_Accounts_No"]["included_columns"] == ["Status"]
