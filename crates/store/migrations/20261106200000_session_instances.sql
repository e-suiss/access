-- OP-149 m.32, OP-150 m.14 (f), INV-13, §5.1 eki, §12.12/7: a later session that proves a known
-- device key is bound to that key's existing Instance; the binding is its own row, the key row
-- is untouched (OP-73). One active binding per session and realm; the key's retirement releases
-- it (status only). Rows are never deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.session_instances (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  binding_id uuid NOT NULL DEFAULT uuidv7(),
  session_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  device_id uuid NOT NULL,
  instance_id bytea NOT NULL CHECK (octet_length(instance_id) = 16),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
  created_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, binding_id),
  FOREIGN KEY (tenant_id, realm_id, device_id)
    REFERENCES access.device_keys (tenant_id, realm_id, device_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX session_instances_one_active_per_session
  ON access.session_instances (tenant_id, realm_id, session_id)
  WHERE status = 'active';
CREATE INDEX session_instances_instance
  ON access.session_instances (tenant_id, realm_id, instance_id)
  WHERE status = 'active';

ALTER TABLE access.session_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.session_instances FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.session_instances FROM PUBLIC;
CREATE POLICY rows ON access.session_instances AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.session_instances AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY realm_scope ON access.session_instances AS RESTRICTIVE TO access_app
  USING (realm_id = (SELECT access.realm_scope()))
  WITH CHECK (realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.session_instances
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.session_instances
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE (status, released_at) ON access.session_instances TO access_app;

RESET ROLE;
