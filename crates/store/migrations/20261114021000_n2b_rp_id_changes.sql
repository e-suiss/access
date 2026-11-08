-- RR-45, TN-17, OP-153 m.13 (e): a change of a realm's WebAuthn RP ID is a security event that
-- sends every user to their weakest recovery path at once; the identity plane records each one
-- so that recovery is tightened for the period after it. Written once, never changed or deleted
-- (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_rp_id_changes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  change_id uuid NOT NULL DEFAULT uuidv7(),
  previous text CHECK (previous IS NULL OR octet_length(previous) BETWEEN 1 AND 253),
  rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (previous IS DISTINCT FROM rp_id),
  PRIMARY KEY (tenant_id, realm_id, change_id)
);
CREATE INDEX realm_rp_id_changes_at ON access.realm_rp_id_changes (tenant_id, realm_id, changed_at);

ALTER TABLE access.realm_rp_id_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_rp_id_changes FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_rp_id_changes FROM PUBLIC;
CREATE POLICY rows ON access.realm_rp_id_changes AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_rp_id_changes AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_rp_id_changes
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.realm_rp_id_changes
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.realm_rp_id_changes TO access_app;
RESET ROLE;
