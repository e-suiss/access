-- OP-149 m.34 (b), MD-10: a tenant realm's API client has no service Party, so the `sub` a
-- platform product reads of it in a service token is a pairwise pseudonym of the client itself: a
-- random value per client and sector (the product), stored on first use, never derived. Nothing
-- is deleted or changed (OP-73). The authorization server of any realm reads a platform product
-- client's internal id across tenants, as it reads its product and status (m.26 (f)).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.client_subjects (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  sector uuid NOT NULL,
  value text NOT NULL CHECK (value ~ '^[A-Za-z0-9_-]{43}$'),
  PRIMARY KEY (tenant_id, realm_id, client_uuid, sector),
  UNIQUE (tenant_id, realm_id, value),
  FOREIGN KEY (tenant_id, realm_id, client_uuid)
    REFERENCES access.idp_clients (tenant_id, realm_id, client_uuid)
);

ALTER TABLE access.client_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.client_subjects FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.client_subjects FROM PUBLIC;
CREATE POLICY rows ON access.client_subjects AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.client_subjects AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.client_subjects
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.client_subjects
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.client_subjects TO access_app;
GRANT SELECT (client_uuid) ON access.idp_clients TO access_outbox_reader;

RESET ROLE;
