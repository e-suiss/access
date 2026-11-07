-- TN-110, EI-25, TN-16, INV-32, OP-151 m.2 M2, m.3 (m): the `idp.platform.*` Exercise that opened
-- a realm. A retry of a committed provisioning Exercise finishes only the realm that Exercise
-- opened; a slug held by any other realm is taken. Ids and digests only; written once with the
-- realm, never changed or deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_provisions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  exercise_id bytea NOT NULL CHECK (octet_length(exercise_id) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

ALTER TABLE access.realm_provisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_provisions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_provisions FROM PUBLIC;
CREATE POLICY rows ON access.realm_provisions AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_provisions AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY realm_scope ON access.realm_provisions AS RESTRICTIVE TO access_app
  USING (realm_id = (SELECT access.realm_scope()))
  WITH CHECK (realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.realm_provisions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.realm_provisions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.realm_provisions TO access_app;

RESET ROLE;
