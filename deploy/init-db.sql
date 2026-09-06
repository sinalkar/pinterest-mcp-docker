-- Run with psql as the provisioning administrator, with MCP_DB_PASSWORD supplied privately.
-- Never echo SQL/variables or include this provisioning run's output in public artifacts.
\set ON_ERROR_STOP on
\getenv mcp_db_password MCP_DB_PASSWORD
-- Missing variables fail parsing; empty passwords fail before any role/database change.
SELECT 1 / CASE WHEN length(:'mcp_db_password') > 0 THEN 1 ELSE 0 END AS password_check \gset

SELECT format('CREATE ROLE mcp_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', :'mcp_db_password')
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mcp_app')\gexec
\unset mcp_db_password

SELECT 'CREATE DATABASE mcp OWNER mcp_app'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'mcp')\gexec

REVOKE ALL ON DATABASE mcp FROM PUBLIC;
GRANT CONNECT ON DATABASE mcp TO mcp_app;
\connect mcp
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO mcp_app;
