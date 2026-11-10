-- OP-156 m.3 (t), §8.17.6.5, IA-1, X6: the coordinator a realm's hub links pending approvals
-- to. A version is written only under a committed idp.realm.coordinator ALLOW; it names the
-- coordinator's public Needs Attention endpoint (https), or none. Access keeps no approval queue:
-- the count is always the coordinator's. Append-only; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_coordinator_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  attention_url text CHECK (attention_url IS NULL
                            OR (octet_length(attention_url) <= 2048 AND attention_url LIKE 'https://%')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_coordinator_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.coordinator');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_coordinator_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.idp_coordinator_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.idp_coordinator_settings FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.idp_coordinator_settings FROM PUBLIC;
CREATE POLICY rows ON access.idp_coordinator_settings AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.idp_coordinator_settings AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.idp_coordinator_settings
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.idp_coordinator_settings TO access_app;

RESET ROLE;
