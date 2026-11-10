-- OP-155 m.3 (m), §10.2.5, §10.4.3, MD-8: certificate, PIV and CAC sign-in per realm, and whether
-- the realm publishes mtls_endpoint_aliases. A certificate login version is written only under a
-- committed idp.realm.certificate_login ALLOW, an alias version only under idp.realm.mtls_aliases;
-- the newest version is the setting. The CAs are DER certificates, each trusted only through the
-- governing domain's actor-binding Acceptance of its issuer id. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_certificate_login_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  rule text NOT NULL CHECK (rule IN ('san_email', 'san_upn')),
  anchors bytea[] NOT NULL CHECK (cardinality(anchors) <= 16),
  piv_policies text[] NOT NULL CHECK (cardinality(piv_policies) <= 16),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (NOT enabled OR cardinality(anchors) >= 1),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_certificate_login_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.certificate_login');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_certificate_login_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.idp_mtls_alias_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  published boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_mtls_alias_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.mtls_aliases');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_mtls_alias_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_certificate_login_settings', 'idp_mtls_alias_settings'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT ON access.idp_certificate_login_settings, access.idp_mtls_alias_settings
  TO access_app;

RESET ROLE;
