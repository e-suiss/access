#!/usr/bin/env bash
# OP-73, MD-5, R-7
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v db="$ACCESS_DB_NAME" \
    -v owner_password="$ACCESS_OWNER_PASSWORD" \
    -v app_password="$ACCESS_APP_PASSWORD" <<'SQL'
CREATE ROLE access_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'owner_password';
CREATE ROLE access_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';

CREATE DATABASE :"db" OWNER access_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO access_app;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$ACCESS_DB_NAME" <<'SQL'
-- Nobody but the owner creates objects in `public`.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO access_app;

-- Privileges on everything access_owner creates from now on.
-- OP-73: SELECT, INSERT and UPDATE only. DELETE and TRUNCATE are never granted.
ALTER DEFAULT PRIVILEGES FOR ROLE access_owner
    GRANT USAGE ON SCHEMAS TO access_app;
ALTER DEFAULT PRIVILEGES FOR ROLE access_owner
    GRANT SELECT, INSERT, UPDATE ON TABLES TO access_app;
ALTER DEFAULT PRIVILEGES FOR ROLE access_owner
    GRANT USAGE, SELECT ON SEQUENCES TO access_app;
ALTER DEFAULT PRIVILEGES FOR ROLE access_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE access_owner
    GRANT EXECUTE ON FUNCTIONS TO access_app;
SQL
