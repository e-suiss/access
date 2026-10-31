-- OP-130 m.2, OP-131 m.3, OP-132 m.3, OP-134 m.3, OP-141 m.22 (k): cluster roles, created once by the database administrator; idempotent
DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['access_migrator', 'access_sequencer', 'access_app', 'access_archive', 'access_outbox_reader', 'access_router', 'access_checkpointer', 'access_deriver'] LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION', r);
    END IF;
  END LOOP;
END
$$;
