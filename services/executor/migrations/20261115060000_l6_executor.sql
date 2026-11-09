-- E62, E63, OP-154 m.3 (u): the executor's own job history. A job runs one allowed Exercise; its
-- events are appended in order and never changed, and replay folds them into the job's state.
-- No row is ever updated or removed (OP-73): the history is the job.
CREATE SCHEMA executor;

-- E62 (1), OP-154 m.3 (u): one job per Exercise
CREATE TABLE executor.jobs (
  job bytea PRIMARY KEY CHECK (octet_length(job) = 16),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  exercise bytea NOT NULL CHECK (octet_length(exercise) = 32),
  kind text NOT NULL CHECK (kind IN ('cloud', 'customer', 'local')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (domain_id, exercise)
);

-- E62 (1), TI-6: the append-only history; an event is committed before the effect it announces
CREATE TABLE executor.events (
  job bytea NOT NULL REFERENCES executor.jobs (job),
  seq integer NOT NULL CHECK (seq >= 0),
  event text NOT NULL CHECK (char_length(event) BETWEEN 2 AND 262144),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (job, seq)
);

-- OP-73, E62 (1)
CREATE FUNCTION executor.append_only() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'executor history is append-only' USING ERRCODE = 'restrict_violation';
END
$$;
CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON executor.events
  FOR EACH ROW EXECUTE FUNCTION executor.append_only();
CREATE TRIGGER jobs_append_only BEFORE UPDATE OR DELETE ON executor.jobs
  FOR EACH ROW EXECUTE FUNCTION executor.append_only();
