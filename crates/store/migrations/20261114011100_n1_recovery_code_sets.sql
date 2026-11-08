-- TN-59, OP-153 m.3 (d), Ek B 3539, 3969: every set of registered recovery codes is shown once and
-- waits for the owner's "I saved them"; the acknowledgement is written once and never undone.
-- Rows are never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.recovery_code_sets (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  set_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  acknowledged_at timestamptz,
  CHECK (acknowledged_at IS NULL OR acknowledged_at >= issued_at),
  PRIMARY KEY (tenant_id, realm_id, set_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX recovery_code_sets_subject
  ON access.recovery_code_sets (tenant_id, realm_id, subject_id, issued_at DESC);

CREATE FUNCTION access.recovery_code_set_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'recovery_code_sets: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.acknowledged_at IS NOT NULL
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.set_id IS DISTINCT FROM OLD.set_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at THEN
    RAISE EXCEPTION 'recovery_code_sets: only one acknowledgement is written' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

ALTER TABLE access.recovery_code_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.recovery_code_sets FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.recovery_code_sets FROM PUBLIC;
CREATE POLICY rows ON access.recovery_code_sets AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.recovery_code_sets AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY realm_scope ON access.recovery_code_sets AS RESTRICTIVE TO access_app
  USING (realm_id = (SELECT access.realm_scope()))
  WITH CHECK (realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER rules BEFORE UPDATE OR DELETE ON access.recovery_code_sets
  FOR EACH ROW EXECUTE FUNCTION access.recovery_code_set_rules();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.recovery_code_sets
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE (acknowledged_at) ON access.recovery_code_sets TO access_app;

RESET ROLE;
