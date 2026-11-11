-- SEC19, SA-51, §17.8.2, OP-157 m.3 (k): operators read the database only as access_operator, and
-- every statement and connection of that role is logged. It logs in with a client certificate
-- (pg_hba-operator.conf), never with a password; it is read-only, holds no table grant by
-- default and is never a superuser (OP-46, OP-54-RL10). Run once by the database administrator.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'access_operator') THEN
    CREATE ROLE access_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION
      NOINHERIT CONNECTION LIMIT 4;
  END IF;
END
$$;
ALTER ROLE access_operator PASSWORD NULL;
ALTER ROLE access_operator SET log_statement = 'all';
ALTER ROLE access_operator SET log_connections = 'on';
ALTER ROLE access_operator SET log_disconnections = 'on';
ALTER ROLE access_operator SET default_transaction_read_only = 'on';
ALTER ROLE access_operator SET statement_timeout = '60s';
