-- SEC-06 — least-privilege database roles.
--
-- Two roles with different jobs:
--   netsecops_migrate  owns the schema and is the only role that may run DDL (Alembic).
--   netsecops_app      reads and writes rows, and can never alter the schema.
--
-- The bootstrap superuser (`netsecops`) remains for administration and backups only.
-- Passwords come from the environment; a deployment overrides them via
-- deploy/postgres/init/ or by running these statements against a managed database.

\set app_password `echo "${APP_DB_PASSWORD:-netsecops_app}"`
\set migrate_password `echo "${MIGRATE_DB_PASSWORD:-netsecops_migrate}"`

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'netsecops_migrate') THEN
        CREATE ROLE netsecops_migrate LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'netsecops_app') THEN
        CREATE ROLE netsecops_app LOGIN;
    END IF;
END
$$;

ALTER ROLE netsecops_migrate WITH PASSWORD :'migrate_password';
ALTER ROLE netsecops_app     WITH PASSWORD :'app_password';

-- Schema ownership sits with the migration role.
ALTER SCHEMA public OWNER TO netsecops_migrate;
GRANT USAGE ON SCHEMA public TO netsecops_app;

-- The app role gets DML on everything the migration role creates, now and in future,
-- but never CREATE/ALTER/DROP.
ALTER DEFAULT PRIVILEGES FOR ROLE netsecops_migrate IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO netsecops_app;
ALTER DEFAULT PRIVILEGES FOR ROLE netsecops_migrate IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO netsecops_app;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
