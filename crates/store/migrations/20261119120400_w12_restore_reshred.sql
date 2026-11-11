-- OP-42, OP-57, OP-158 m.3 (r): after a restore the environment opens to traffic only once the
-- shred list has been applied again. Each restore and each re-shred is one row, never changed;
-- a restore generation above the latest re-shred generation keeps the server closed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.restore_generations (
  kind text NOT NULL CHECK (kind IN ('restore', 'reshred')),
  generation bigint NOT NULL CHECK (generation > 0),
  at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, generation)
);
ALTER TABLE access_ops.restore_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.restore_generations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.restore_generations FROM PUBLIC;
CREATE POLICY rows ON access_ops.restore_generations AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.restore_generations AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.restore_generations
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.restore_generations
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access_ops.restore_generations TO access_app;

RESET ROLE;
