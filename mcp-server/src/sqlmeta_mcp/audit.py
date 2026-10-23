"""Local, append-only audit log of every tool call.

One JSON object per line. Each entry records the tool, its (masked) arguments,
the outcome, the size and SHA-256 of the response, and the SHA-256 of the
previous line, so deleting or editing a line breaks the chain (see verify()).
Response content is never written.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dlp_patterns

GENESIS = "0" * 64


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _last_line(path: Path) -> str | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buf = b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            lines = buf.rstrip(b"\n").split(b"\n")
            if len(lines) > 1 or pos == 0:
                return lines[-1].decode("utf-8")
    return None


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create with owner-only permissions; never loosen an existing file.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        last = _last_line(self.path)
        self._prev = _sha256(last) if last else GENESIS
        self._lock = threading.Lock()
        self._user = getpass.getuser()
        self._host = socket.gethostname()

    def record(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        outcome: str,
        reason: str | None = None,
        response_text: str | None = None,
        duration_ms: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        safe_args = {k: dlp_patterns.mask(str(v))[0] for k, v in args.items()}
        with self._lock:
            entry: dict[str, Any] = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "id": str(uuid.uuid4()),
                "user": self._user,
                "host": self._host,
                "pid": os.getpid(),
                "tool": tool,
                "args": safe_args,
                "outcome": outcome,
                "reason": reason,
                "response_bytes": len(response_text.encode("utf-8")) if response_text is not None else None,
                "response_sha256": _sha256(response_text) if response_text is not None else None,
                "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
                "prev": self._prev,
            }
            if extra:
                entry["extra"] = extra
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev = _sha256(line)
        return entry


def verify(path: Path) -> tuple[bool, int]:
    """Check the hash chain. Returns (ok, number_of_valid_lines_before_first_break)."""
    prev = GENESIS
    count = 0
    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, count
            if entry.get("prev") != prev:
                return False, count
            prev = _sha256(line)
            count += 1
    return True, count
