-- OP-129 m.2: notification and operational jobs; no semantic timers (TI-10)
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.jobs (
  id bigint GENERATED ALWAYS AS IDENTITY,
  kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
  subject text NOT NULL CHECK (subject ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  dedup_key text NOT NULL CHECK (octet_length(dedup_key) BETWEEN 1 AND 200),
  run_at timestamptz NOT NULL,
  claimed_by text,
  claimed_until timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  done_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (dedup_key)
);
CREATE INDEX jobs_due ON access_ops.jobs (run_at) WHERE done_at IS NULL;

ALTER TABLE access_ops.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.jobs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.jobs FROM PUBLIC;
CREATE POLICY rows ON access_ops.jobs AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.jobs AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));
GRANT SELECT, INSERT, UPDATE ON access_ops.jobs TO access_app;

RESET ROLE;
