-- OP-37, OP-38, U52, OP-158 m.3 (w): every publication of an identity audit checkpoint to a
-- declared target (witness, hook, object-locked store), one row per target and size; the latest
-- row of a target is how far it has the log
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.audit_publications (
  sink text NOT NULL CHECK (sink ~ '^[a-z0-9][a-z0-9:._-]{0,62}$'),
  size bigint NOT NULL CHECK (size > 0),
  published_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (sink, size)
);
ALTER TABLE access_ops.audit_publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.audit_publications FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.audit_publications FROM PUBLIC;
CREATE POLICY rows ON access_ops.audit_publications AS PERMISSIVE USING (true);
CREATE POLICY checkpointer_only ON access_ops.audit_publications AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.audit_publications
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.audit_publications
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access_ops.audit_publications TO access_checkpointer;

RESET ROLE;
