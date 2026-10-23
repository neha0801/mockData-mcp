"""Entry point: ``sqlmeta-mcp --config path/to/config.toml`` (stdio transport)."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import audit, config
from .server import build_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sqlmeta-mcp", description=__doc__)
    parser.add_argument("--config", help=f"TOML config file (default: ${config.CONFIG_ENV})")
    parser.add_argument("--verify-audit", metavar="PATH", help="check an audit log's hash chain and exit")
    args = parser.parse_args(argv)

    # stdout carries the MCP protocol; all logging goes to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.verify_audit:
        ok, count = audit.verify(Path(args.verify_audit))
        print(f"{'OK' if ok else 'BROKEN'}: {count} valid entries", file=sys.stderr)
        return 0 if ok else 1

    cfg = config.load(args.config)
    build_server(cfg).run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
