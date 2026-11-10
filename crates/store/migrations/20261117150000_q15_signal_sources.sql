-- OP-156 m.3 (r): one row per idp.signal.source_register or source_retire. A signal source is a
-- Claim issuer (KYC, MDM, risk, DLP); its Claims count only once the domain accepts them. A
-- retired name is never reused; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.signal_sources (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  kind text NOT NULL CHECK (kind IN ('kyc', 'mdm', 'risk', 'dlp')),
  provider text NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 64),
  issuer bytea NOT NULL CHECK (octet_length(issuer) = 16),
  format text NOT NULL CHECK (format IN ('claim', 'intune', 'jamf', 'okta-ssf', 'onfido',
                                         'persona')),
  transmitter text CHECK (transmitter IS NULL OR char_length(transmitter) BETWEEN 1 AND 2048),
  expected_interval_s integer NOT NULL CHECK (expected_interval_s BETWEEN 60 AND 2592000),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.signal_sources
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.signal.source_register',
                                                 'idp.signal.source_retire');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.signal_sources
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.signal_sources
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.signal_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.signal_sources FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.signal_sources FROM PUBLIC;
CREATE POLICY rows ON access.signal_sources AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.signal_sources AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.signal_sources TO access_app;

RESET ROLE;
