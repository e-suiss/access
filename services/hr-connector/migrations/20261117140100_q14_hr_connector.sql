-- OP-156 m.3 (q): the HR connector's own run history, in its own database. A run is recorded
-- once it ended, with counts only, never a record's content. No row is ever updated or removed
-- (OP-73).
CREATE SCHEMA hr_connector;

CREATE TABLE hr_connector.runs (
  run bytea PRIMARY KEY CHECK (octet_length(run) = 16),
  connector text NOT NULL CHECK (connector ~ '^[a-z][a-z0-9-]{0,62}$'),
  started_ms bigint NOT NULL CHECK (started_ms >= 0),
  ended_ms bigint NOT NULL CHECK (ended_ms >= started_ms),
  outcome text NOT NULL CHECK (outcome IN ('done', 'failed')),
  read integer NOT NULL CHECK (read >= 0),
  left_out integer NOT NULL CHECK (left_out >= 0),
  pushed integer NOT NULL CHECK (pushed >= 0),
  refused integer NOT NULL CHECK (refused >= 0),
  batches integer NOT NULL CHECK (batches >= 0),
  reason text CHECK (char_length(reason) <= 256),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX runs_connector ON hr_connector.runs (connector, ended_ms DESC);

CREATE FUNCTION hr_connector.append_only() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'HR connector runs are append-only' USING ERRCODE = 'restrict_violation';
END
$$;
CREATE TRIGGER runs_append_only BEFORE UPDATE OR DELETE ON hr_connector.runs
  FOR EACH ROW EXECUTE FUNCTION hr_connector.append_only();
CREATE TRIGGER runs_no_truncate BEFORE TRUNCATE ON hr_connector.runs
  FOR EACH STATEMENT EXECUTE FUNCTION hr_connector.append_only();
