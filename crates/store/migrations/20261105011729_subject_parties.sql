-- OP-149 m.16 (a), L0-META-7: the actor binding of a realm's users. A session subject's device
-- Instances belong to one Party of the realm's governing domain; the identity plane records it
-- once that Party's self-signed registration has committed, and from then on forwards only
-- registrations for that Party. Ids only, no personal data; never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.subject_party (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, subject_id),
  UNIQUE (tenant_id, realm_id, party_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

ALTER TABLE access.subject_party ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.subject_party FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.subject_party FROM PUBLIC;
CREATE POLICY rows ON access.subject_party AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.subject_party AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY realm_scope ON access.subject_party AS RESTRICTIVE TO access_app
  USING (realm_id = (SELECT access.realm_scope()))
  WITH CHECK (realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.subject_party
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.subject_party
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.subject_party TO access_app;

RESET ROLE;
