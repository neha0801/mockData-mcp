"""Detectors for data-like values: account numbers, emails, names, LEIs and similar.

Used in two places:
  * the MCP server's output check (block before a response leaves the server), and
  * the Claude Code PostToolUse hook (Phase 2), as a second, independent check.

The detectors favour recall over precision: a false positive blocks a metadata
response, which is cheap; a false negative leaks data, which is not.
Checksums (Luhn, ISO 7064 mod 97-10) are used where a format defines one, to
keep false positives on ordinary identifiers low.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

__all__ = ["DETECTORS", "Detector", "Finding", "kinds", "mask", "scan", "scan_obj"]


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern[str]
    validate: Callable[[str], bool] | None = None


def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def luhn_ok(s: str) -> bool:
    digits = _digits(s)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mod97(s: str) -> int:
    # ISO 7064 mod 97-10: letters map to 10..35.
    return int("".join(str(int(ch, 36)) for ch in s)) % 97


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    return 15 <= len(s) <= 34 and _mod97(s[4:] + s[:4]) == 1


def lei_ok(s: str) -> bool:
    return len(s) == 20 and _mod97(s.upper()) == 1


# Given names that are not also common English words or SQL terms, so that
# phrases like "Grace Period" or "Grant Select" do not trip the detector.
_GIVEN_NAMES = (
    "Aaron Adam Adrian Ahmed Aisha Alan Albert Alex Alexander Alice Alicia Amanda Amit Amy Andrea "
    "Andrew Angela Anil Anita Ann Anna Anne Anthony Antonio Arjun Arthur Ashley Barbara Benjamin "
    "Brian Bruce Carlos Carol Caroline Catherine Charles Charlotte Chen Christina Christine "
    "Christopher Claire Daniel David Deborah Deepak Diana Donald Dorothy Douglas Edward Elena "
    "Elizabeth Emily Emma Eric Fatima Francesco Frank Gary George Giulia Hannah Harry Helen Henry "
    "Hiroshi Ian Isabella Jack James Jane Janet Jason Jennifer Jessica John Jonathan Jose Joseph "
    "Joshua Juan Julia Karen Kenneth Kevin Laura Linda Lisa Lucas Luis Manoj Margaret Maria Marie "
    "Martin Mary Matthew Michael Michelle Mohammed Muhammad Nancy Natalie Nicholas Nicole Olivia "
    "Oliver Pamela Paul Peter Priya Rachel Rahul Rajesh Rebecca Richard Robert Ronald Ryan Sandra "
    "Sanjay Sarah Scott Sharon Simon Sophie Stephen Steven Susan Thomas Timothy Victoria Vikram "
    "Wei William Yuki Zhang"
).split()

_DETECTORS: list[Detector] = [
    Detector("email", re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
    Detector("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"), iban_ok),
    Detector("lei", re.compile(r"\b[A-Z0-9]{18}\d{2}\b"), lei_ok),
    Detector("payment_card", re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])"), luhn_ok),
    Detector("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    Detector("uk_nino", re.compile(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b")),
    Detector("phone", re.compile(r"(?<![\w+])\+\d{1,3}[ -]?\d(?:[ -]?\d){6,13}\b")),
    Detector("guid", re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")),
    # Long digit runs, also inside identifiers (e.g. Acct12345678): account and reference numbers.
    Detector("account_like", re.compile(r"(?<!\d)\d{8,}(?!\d)")),
    Detector("person_name", re.compile(r"\b(?:" + "|".join(_GIVEN_NAMES) + r")\s+[A-Z][a-z]{1,30}(?:-[A-Z][a-z]+)?\b")),
]

DETECTORS: tuple[Detector, ...] = tuple(_DETECTORS)


def kinds() -> tuple[str, ...]:
    return tuple(d.kind for d in DETECTORS)


def scan(text: str, detectors: Iterable[Detector] = DETECTORS) -> list[Finding]:
    """Return non-overlapping findings, longest match first where they overlap."""
    raw: list[Finding] = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            if det.validate is None or det.validate(m.group(0)):
                raw.append(Finding(det.kind, m.start(), m.end()))
    raw.sort(key=lambda f: (f.start, -(f.end - f.start)))
    out: list[Finding] = []
    last_end = -1
    for f in raw:
        if f.start >= last_end:
            out.append(f)
            last_end = f.end
    return out


def mask(text: str, detectors: Iterable[Detector] = DETECTORS) -> tuple[str, list[Finding]]:
    """Replace every finding with ``<KIND>``. Returns the masked text and the findings."""
    findings = scan(text, detectors)
    if not findings:
        return text, findings
    parts: list[str] = []
    pos = 0
    for f in findings:
        parts.append(text[pos : f.start])
        parts.append(f"<{f.kind.upper()}>")
        pos = f.end
    parts.append(text[pos:])
    return "".join(parts), findings


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)
    elif obj is not None and not isinstance(obj, bool):
        yield str(obj)


def scan_obj(obj: Any, detectors: Iterable[Detector] = DETECTORS) -> list[Finding]:
    """Scan every key and scalar value of a JSON-like structure.

    Values are scanned one at a time, so a match cannot span two fields.
    Offsets in the findings refer to the individual value, not the whole object.
    """
    dets = tuple(detectors)
    found: list[Finding] = []
    for s in _strings(obj):
        found.extend(scan(s, dets))
    return found
