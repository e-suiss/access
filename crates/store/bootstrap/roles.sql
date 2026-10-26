-- OP-130 m.2: cluster roles, created once by the database administrator; idempotent
DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['access_migrator', 'access_sequencer', 'access_app', 'access_archive'] LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION', r);
    END IF;
  END LOOP;
END
$$;
