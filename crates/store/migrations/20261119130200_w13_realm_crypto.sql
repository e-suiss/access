-- OP-158 m.3 (a), (y), m.6 (b), CR-15, CR-36, OP-33: one row per idp.realm.crypto_profile or
-- idp.realm.hash_profile. Each row carries both settings, the other one copied from the row
-- before; the newest version is what the realm hashes passwords with. The hash profile only
-- rises (the admin plane refuses a lower one with hash-profile-downgrade). Nothing is deleted
-- (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_crypto (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  fips boolean NOT NULL,
  hash_profile text NOT NULL CHECK (hash_profile IN ('canonical', 'high-memory')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.realm_crypto
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.crypto_profile',
                                                 'idp.realm.hash_profile');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_crypto
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.realm_crypto
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.realm_crypto ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_crypto FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_crypto FROM PUBLIC;
CREATE POLICY rows ON access.realm_crypto AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_crypto AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.realm_crypto TO access_app;

RESET ROLE;
