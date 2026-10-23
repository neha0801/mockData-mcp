# Integration tests

These run the server against a real SQL Server seeded with canary data
(`seed.sql`) and a principal locked down by `../../sql/metadata_reader_login.sql`.
They prove, end to end, that:

- every tool on every object returns metadata with no canary value in it;
- the locked-down principal cannot `SELECT`, `INSERT` or `EXEC` against user
  objects even with a raw connection (the database layer holds on its own);
- encrypted modules return no definition.

## Run locally

```bash
export SQLMETA_IT_SA_PASSWORD="$(python -c 'import secrets; print("It1!" + secrets.token_hex(12))')"
docker compose -f tests/integration/docker-compose.yml up -d
export SQLMETA_IT_SERVER="127.0.0.1,14333"
pytest -m integration          # from mcp-server/
docker compose -f tests/integration/docker-compose.yml down
```

Needs Microsoft ODBC Driver 18 for SQL Server on the host.
The tests are skipped unless `SQLMETA_IT_SERVER` and `SQLMETA_IT_SA_PASSWORD`
are set. The SA password is for a throwaway container only. The reader
principal's password is generated randomly per run and passed to the server
in-process, never through the environment.
