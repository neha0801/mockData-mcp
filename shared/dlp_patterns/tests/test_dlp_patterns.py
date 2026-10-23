from __future__ import annotations

import dlp_patterns as d
import pytest


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("jane.doe@example.com", "email"),
        ("GB82WEST12345698765432", "iban"),
        ("GB82 WEST 1234 5698 7654 32", "iban"),
        ("DE89370400440532013000", "iban"),
        ("5493001KJTIIGC8Y1R12", "lei"),
        ("529900T8BM49AURSDO55", "lei"),
        ("4111111111111111", "payment_card"),
        ("4111-1111-1111-1111", "payment_card"),
        ("123-45-6789", "us_ssn"),
        ("AB123456C", "uk_nino"),
        ("+44 20 7946 0958", "phone"),
        ("6F9619FF-8B86-D011-B42D-00C04FC964FF", "guid"),
        ("99887766", "account_like"),
        ("Acct12345678", "account_like"),
        ("John Smith", "person_name"),
        ("Priya Sharma-Iyer", "person_name"),
    ],
)
def test_detects(text: str, kind: str) -> None:
    assert [f.kind for f in d.scan(text)] == [kind]


@pytest.mark.parametrize(
    "text",
    [
        "NVARCHAR",
        "customer_email",
        "AccountNo",
        "2024-01-01T10:00:00.123000",
        "max_length 8000",
        "'<STR>'",
        "<NUM>",
        "dbo.Accounts",
        "Grace Period",
        "Grant Select",
        "PRIMARY_KEY_CONSTRAINT",
        "Latin1_General_CI_AS",
        "ABCDEFGHIJKLMNOPQR12",  # bad LEI checksum
        "1234567",  # 7 digits: below account threshold
        "SQL_STORED_PROCEDURE",
    ],
)
def test_does_not_flag_metadata(text: str) -> None:
    assert d.scan(text) == []


@pytest.mark.parametrize(
    ("text", "not_kind"),
    [("GB82WEST12345698765433", "iban"), ("4111111111111112", "payment_card")],
)
def test_bad_checksums_not_classified(text: str, not_kind: str) -> None:
    # Still caught as a long digit run: fail-safe, just not mislabelled.
    assert [f.kind for f in d.scan(text)] == ["account_like"]
    assert not_kind not in {f.kind for f in d.scan(text)}


def test_mask_replaces_with_kind() -> None:
    masked, findings = d.mask("send to jane@example.com, acct 12345678")
    assert masked == "send to <EMAIL>, acct <ACCOUNT_LIKE>"
    assert [f.kind for f in findings] == ["email", "account_like"]


def test_overlaps_keep_longest() -> None:
    # The IBAN contains a long digit run; only the IBAN is reported.
    assert [f.kind for f in d.scan("GB82WEST12345698765432")] == ["iban"]


def test_scan_obj_walks_keys_and_values() -> None:
    kinds = {f.kind for f in d.scan_obj({"a": ["x", {"jane@example.com": 12345678}], "b": None, "c": True})}
    assert kinds == {"email", "account_like"}
