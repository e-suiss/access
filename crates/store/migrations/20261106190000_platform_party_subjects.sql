-- OP-149 m.31 (a), MD-10, OP-146 m.5 (b): the `sub` a product reads of another product's service
-- Party in a realm is a pairwise subject like a user's: a random value per Party and sector (the
-- reading client), stored on first use, never derived. The Party is the one `platform_party`
-- bound at pairing. Nothing is deleted or changed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.platform_party_subjects (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  sector uuid NOT NULL,
  value text NOT NULL CHECK (value ~ '^[A-Za-z0-9_-]{43}$'),
  PRIMARY KEY (tenant_id, realm_id, party_id, sector),
  UNIQUE (tenant_id, realm_id, value),
  FOREIGN KEY (tenant_id, realm_id, party_id)
    REFERENCES access.platform_party (tenant_id, realm_id, party_id)
);

ALTER TABLE access.platform_party_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.platform_party_subjects FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.platform_party_subjects FROM PUBLIC;
CREATE POLICY rows ON access.platform_party_subjects AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.platform_party_subjects AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.platform_party_subjects
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.platform_party_subjects
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.platform_party_subjects TO access_app;

RESET ROLE;
