/*
  Metadata-only database principal for sqlmeta-mcp.

  Run in the target DEV database, as a member of db_owner, after editing the two
  variables below. Requires SQL Server 2017+ (STRING_AGG).

  The principal ends up with:
    * VIEW DEFINITION on the database (catalog metadata and module text), and
    * explicit DENY of SELECT/INSERT/UPDATE/DELETE/EXECUTE/ALTER/... on every
      user schema, plus database-level DENY on changes and UNMASK.
  It is removed from every database role, so no role can grant data access.

  DENY on a schema overrides any GRANT on objects inside it, including grants to
  [public]. Re-run this script after creating a new schema.
  The integration tests (tests/integration) run this script and then prove that
  the principal cannot read a user table.
*/
SET NOCOUNT ON;

DECLARE @principal sysname = N'CONTOSO\svc-sqlmeta';  -- database user to create / lock down
DECLARE @login     sysname = N'CONTOSO\svc-sqlmeta';  -- server login; set to NULL for an Entra ID principal

DECLARE @sql nvarchar(max);

IF DATABASE_PRINCIPAL_ID(@principal) IS NULL
BEGIN
    SET @sql = CASE WHEN @login IS NULL
        THEN N'CREATE USER ' + QUOTENAME(@principal) + N' FROM EXTERNAL PROVIDER;'
        ELSE N'CREATE USER ' + QUOTENAME(@principal) + N' FOR LOGIN ' + QUOTENAME(@login) + N';'
    END;
    EXEC (@sql);
END;

-- No role membership: roles such as db_datareader would grant data access.
SET @sql = NULL;
SELECT @sql = STRING_AGG(CONVERT(nvarchar(max),
           N'ALTER ROLE ' + QUOTENAME(r.name) + N' DROP MEMBER ' + QUOTENAME(@principal) + N';'), N' ')
FROM sys.database_role_members AS rm
JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id
WHERE rm.member_principal_id = DATABASE_PRINCIPAL_ID(@principal);
IF @sql IS NOT NULL EXEC (@sql);

-- Metadata visibility only. sys.sql_expression_dependencies additionally needs an
-- explicit SELECT (by default only db_owner has it); it is a catalog view, not data.
SET @sql = N'GRANT VIEW DEFINITION TO ' + QUOTENAME(@principal) + N'; '
         + N'GRANT SELECT ON sys.sql_expression_dependencies TO ' + QUOTENAME(@principal) + N';';
EXEC (@sql);

-- Database-wide: no changes, no unmasking of dynamic data masking, no plans
-- (plans can carry parameter values).
SET @sql = N'DENY INSERT, UPDATE, DELETE, ALTER, CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, '
         + N'CREATE FUNCTION, CREATE SCHEMA, CREATE TYPE, ALTER ANY SCHEMA, UNMASK, SHOWPLAN TO '
         + QUOTENAME(@principal) + N';';
EXEC (@sql);

-- Every user schema: no data access at all.
-- Not CONTROL: denying CONTROL also denies the VIEW DEFINITION it implies, which
-- would hide the very metadata this principal exists to read.
SET @sql = NULL;
SELECT @sql = STRING_AGG(CONVERT(nvarchar(max),
           N'DENY SELECT, INSERT, UPDATE, DELETE, EXECUTE, ALTER, TAKE OWNERSHIP, REFERENCES ON SCHEMA::'
           + QUOTENAME(s.name) + N' TO ' + QUOTENAME(@principal) + N';'), N' ')
FROM sys.schemas AS s
WHERE s.schema_id NOT IN (2, 3, 4) AND s.schema_id < 16384;
IF @sql IS NOT NULL EXEC (@sql);

-- Review: effective grants and denies for the principal.
SELECT p.state_desc, p.permission_name, p.class_desc,
       CASE p.class WHEN 3 THEN SCHEMA_NAME(p.major_id) WHEN 1 THEN OBJECT_SCHEMA_NAME(p.major_id) + N'.' + OBJECT_NAME(p.major_id) END AS securable
FROM sys.database_permissions AS p
WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID(@principal)
ORDER BY p.state_desc, p.class_desc, securable, p.permission_name;
