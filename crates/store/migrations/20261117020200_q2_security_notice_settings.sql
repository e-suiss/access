-- OP-156 m.3 (c), Ek B 5294: the realm's switch for immediate security authority notices, as
-- decided by idp.realm.security_notices (on) or security_notices_close (off). No row means on.
-- Append-only versions (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.relay_notice_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.relay_notice_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.security_notices',
                                                 'idp.realm.security_notices_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.relay_notice_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.relay_notice_settings
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.relay_notice_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.relay_notice_settings FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.relay_notice_settings FROM PUBLIC;
CREATE POLICY rows ON access.relay_notice_settings AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.relay_notice_settings AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));

GRANT SELECT, INSERT ON access.relay_notice_settings TO access_app;

RESET ROLE;
