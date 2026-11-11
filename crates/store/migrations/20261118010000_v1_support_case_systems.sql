-- OP-157 m.3 (e): one row per idp.support.case_system_register or case_system_retire. A case
-- system is a Claim issuer of support_case Claims; they count only once the domain accepts them
-- as predicate-input. A retired name is never reused; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.support_case_systems (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  provider text NOT NULL CHECK (provider IN ('zendesk', 'freshdesk', 'servicenow',
                                             'jira-service-management')),
  issuer bytea NOT NULL CHECK (octet_length(issuer) = 16),
  format text NOT NULL CHECK (format IN ('product-seam/v1')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.support_case_systems
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.support.case_system_register',
                                                 'idp.support.case_system_retire');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.support_case_systems
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.support_case_systems
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.support_case_systems ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.support_case_systems FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.support_case_systems FROM PUBLIC;
CREATE POLICY rows ON access.support_case_systems AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.support_case_systems AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.support_case_systems TO access_app;

RESET ROLE;
