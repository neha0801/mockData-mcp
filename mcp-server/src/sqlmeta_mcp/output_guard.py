"""Last check before a response leaves the server.

The payload is serialised once; the guard scans that exact text and every
individual value, and either returns the text unchanged or a refusal that names
only the kinds of pattern found, never the matched content.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import dlp_patterns


class OutputBlocked(Exception):
    def __init__(self, kinds: list[str]) -> None:
        super().__init__(f"response blocked: data-like content detected ({', '.join(kinds)})")
        self.kinds = kinds


@dataclass(frozen=True)
class Checked:
    text: str


def _default(o: Any) -> Any:
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return str(o)
    if isinstance(o, (bytes, bytearray, memoryview)):
        # Catalog queries never return binary; refuse rather than encode it.
        raise TypeError("binary values are not allowed in responses")
    raise TypeError(f"unsupported type in response: {type(o).__name__}")


def serialise(payload: Any) -> str:
    return json.dumps(payload, default=_default, ensure_ascii=False, sort_keys=False)


def check(payload: Any) -> Checked:
    text = serialise(payload)
    findings = dlp_patterns.scan_obj(json.loads(text)) + dlp_patterns.scan(text)
    if findings:
        raise OutputBlocked(sorted({f.kind for f in findings}))
    return Checked(text=text)
