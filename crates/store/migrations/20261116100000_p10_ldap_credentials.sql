-- OP-155 m.3 (n), §10.6.3, IDP-16: the LDAP credential class. A person issues one credential per
-- application on the account surface (S11); only these bind on the LDAP gateway, never the primary
-- password. The secret is kept as an Argon2id PHC string; RFC 3062 replaces it in place. A
-- credential is revoked, never deleted (OP-73); the subject and the application are fixed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.ldap_credentials (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  application text NOT NULL CHECK (char_length(application) BETWEEN 1 AND 200),
  phc text NOT NULL CHECK (phc LIKE '$argon2id$%' AND char_length(phc) <= 256),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  rotated_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, credential_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX ldap_credentials_subject ON access.ldap_credentials (tenant_id, realm_id, subject_id);

CREATE FUNCTION access.ldap_credential_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.application IS DISTINCT FROM OLD.application
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR OLD.status = 'revoked' THEN
    RAISE EXCEPTION 'ldap credential %: the subject and application are fixed and a revoked credential stays revoked',
      OLD.credential_id;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER ldap_credential_fixed BEFORE UPDATE ON access.ldap_credentials
  FOR EACH ROW EXECUTE FUNCTION access.ldap_credential_fixed();
CREATE TRIGGER append_only_row BEFORE DELETE ON access.ldap_credentials
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.ldap_credentials
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.ldap_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.ldap_credentials FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.ldap_credentials FROM PUBLIC;
CREATE POLICY rows ON access.ldap_credentials AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.ldap_credentials AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.ldap_credentials TO access_app;
GRANT UPDATE (phc, status, rotated_at, last_used_at, revoked_at) ON access.ldap_credentials
  TO access_app;

RESET ROLE;
