-- OP-130 m.2: per-database setup, run once by the database administrator before the first migration
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS access AUTHORIZATION access_migrator;
REVOKE ALL ON SCHEMA access FROM PUBLIC;
GRANT USAGE ON SCHEMA access TO access_sequencer, access_app, access_archive, access_outbox_reader;
CREATE SCHEMA IF NOT EXISTS access_ops AUTHORIZATION access_migrator;
REVOKE ALL ON SCHEMA access_ops FROM PUBLIC;
GRANT USAGE ON SCHEMA access_ops TO access_app, access_outbox_reader;
