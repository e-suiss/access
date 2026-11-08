-- OP-152 m.5 (k), OP-38, OP-44: one writer per cell audit chain. The replica holding a chain's
-- lease is the only one whose checkpoints that chain accepts; the lease expires unless renewed,
-- and its epoch grows on every change of holder (OP-73: rows are updated, never removed).
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.audit_checkpoint_lease (
  chain text PRIMARY KEY CHECK (chain IN ('identity-audit', 'authority-operational')),
  holder text NOT NULL CHECK (octet_length(holder) BETWEEN 1 AND 128),
  epoch bigint NOT NULL CHECK (epoch > 0),
  expires_at timestamptz NOT NULL
);

ALTER TABLE access_ops.audit_checkpoint_lease ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.audit_checkpoint_lease FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.audit_checkpoint_lease FROM PUBLIC;
CREATE POLICY rows ON access_ops.audit_checkpoint_lease AS PERMISSIVE USING (true);
CREATE POLICY checkpointer_only ON access_ops.audit_checkpoint_lease AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));
CREATE TRIGGER no_delete BEFORE DELETE ON access_ops.audit_checkpoint_lease
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.audit_checkpoint_lease
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE ON access_ops.audit_checkpoint_lease TO access_checkpointer;

RESET ROLE;
