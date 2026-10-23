# Phase 2: Claude Code lockdown (not started)

Planned contents:

- `settings.json`: deny Bash for `sqlcmd`, `bcp`, `osql`, `Invoke-Sqlcmd` and
  database drivers; disable web fetch; allow only approved MCP servers;
  deny reads on `data/` and `output/`.
- `hooks/pre_tool_use.py`: block any tool outside the allowlist.
- `hooks/post_tool_use.py`: scan every tool result with `shared/dlp_patterns`
  and block data-like content.
