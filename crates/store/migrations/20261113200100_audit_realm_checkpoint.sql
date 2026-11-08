-- OP-152 m.7 (d), Ek B 2527: each realm's own audit tree, its rows in the cell's integration
-- order, signed by the cell key under the realm's origin. A realm proves inclusion of its events
-- against it without learning the cell tree's size; the cell checkpoint it follows is named by
-- digest only.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.audit_realm_checkpoint (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  frontier bytea[] NOT NULL,
  xid xid8 NOT NULL,
  id bigint NOT NULL,
  cell_size bigint NOT NULL CHECK (cell_size >= size),
  note text NOT NULL CHECK (octet_length(note) <= 4096),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, size)
);
ALTER TABLE access_ops.audit_realm_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.audit_realm_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.audit_realm_checkpoint FROM PUBLIC;
CREATE POLICY rows ON access_ops.audit_realm_checkpoint AS PERMISSIVE USING (true);
CREATE POLICY checkpointer_only ON access_ops.audit_realm_checkpoint AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.audit_realm_checkpoint
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.audit_realm_checkpoint
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access_ops.audit_realm_checkpoint TO access_checkpointer;

RESET ROLE;
