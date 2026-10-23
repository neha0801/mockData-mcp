"""Mask literals in procedure, view, function, constraint and default text.

A small T-SQL tokenizer walks the text and:
  * replaces every string literal (including N'..' and escaped '') with '<STR>',
  * replaces numeric, money and binary literals with <NUM> / <BIN>,
  * removes comments (-- and nested /* */), which can hold anything,
  * keeps keywords, identifiers, variables and [bracketed] names, but runs the
    dlp_patterns detectors over them so account numbers, emails, GUIDs and the like
    embedded in names are masked too.

Unterminated strings, identifiers or comments mask everything to the end of the
text: if the tokenizer is unsure, it hides more, not less.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dlp_patterns

STR = "'<STR>'"
NUM = "<NUM>"
BIN = "<BIN>"
LINE_COMMENT = "-- <comment removed>"
BLOCK_COMMENT = "/* <comment removed> */"
TRUNCATED = "<masked to end>"


@dataclass
class ScrubResult:
    text: str
    strings: int = 0
    numbers: int = 0
    comments: int = 0
    patterns: list[str] = field(default_factory=list)

    @property
    def masked(self) -> int:
        return self.strings + self.numbers + self.comments + len(self.patterns)


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch in "_@#"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch in "_@#$"


def scrub(text: str | None, *, quoted_identifier: bool = False) -> ScrubResult:
    """Mask literals in T-SQL ``text``.

    ``quoted_identifier`` mirrors the module's QUOTED_IDENTIFIER setting
    (sys.sql_modules.uses_quoted_identifier). When it is off, or unknown,
    "double quoted" text is a string literal and is masked.
    """
    if text is None:
        return ScrubResult(text="")
    res = ScrubResult(text="")
    out: list[str] = []
    i, n = 0, len(text)

    def emit_ident(s: str) -> None:
        masked, findings = dlp_patterns.mask(s)
        res.patterns.extend(f.kind for f in findings)
        out.append(masked)

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if ch == "-" and nxt == "-":
            j = text.find("\n", i)
            i = n if j == -1 else j
            out.append(LINE_COMMENT)
            res.comments += 1
            continue

        if ch == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            res.comments += 1
            if depth:
                out.append(TRUNCATED)
                break
            out.append(BLOCK_COMMENT)
            i = j
            continue

        if ch == "'" or (ch == '"' and not quoted_identifier):
            j = i + 1
            closed = False
            while j < n:
                if text[j] == ch:
                    if j + 1 < n and text[j + 1] == ch:
                        j += 2
                        continue
                    closed = True
                    break
                j += 1
            res.strings += 1
            if not closed:
                out.append(TRUNCATED)
                break
            out.append(STR)
            i = j + 1
            continue

        if ch == "[" or (ch == '"' and quoted_identifier):
            close = "]" if ch == "[" else '"'
            j = i + 1
            closed = False
            while j < n:
                if text[j] == close:
                    if j + 1 < n and text[j + 1] == close:
                        j += 2
                        continue
                    closed = True
                    break
                j += 1
            if not closed:
                out.append(TRUNCATED)
                break
            emit_ident(text[i : j + 1])
            i = j + 1
            continue

        if ch == "0" and nxt in "xX":
            j = i + 2
            while j < n and text[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(BIN)
            res.numbers += 1
            i = j
            continue

        if ch.isdigit() or (ch == "." and nxt.isdigit()) or (ch == "$" and (nxt.isdigit() or nxt == ".")):
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            if j < n and text[j] in "eE":
                k = j + 1
                if k < n and text[k] in "+-":
                    k += 1
                if k < n and text[k].isdigit():
                    j = k
                    while j < n and text[j].isdigit():
                        j += 1
            # A digit run glued to letters (e.g. 1abc) is not valid T-SQL; mask it whole.
            while j < n and _is_ident_part(text[j]):
                j += 1
            out.append(NUM)
            res.numbers += 1
            i = j
            continue

        if _is_ident_start(ch):
            j = i + 1
            while j < n and _is_ident_part(text[j]):
                j += 1
            emit_ident(text[i:j])
            i = j
            continue

        out.append(ch)
        i += 1

    # Final pass over the whole result: catches patterns split across tokens,
    # e.g. an email written as [jane].[doe]@... or digits separated by operators.
    final, findings = dlp_patterns.mask("".join(out))
    res.patterns.extend(f.kind for f in findings)
    res.text = final
    return res
