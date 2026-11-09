-- OP-155 m.3 (c), IDP-26, IDI-11, MD-1: the protocol gateways a realm registered. A gateway's
-- internal identity is its client certificate on the edge channel: the SAN URI
-- urn:suiss:access:gw:<kind>:<name> and the SHA-256 of the certificate. Each row is one
-- idp.gateway.register or idp.gateway.retire; the newest version is the gateway. The router role
-- reads the registry across tenants to name the realm of a connecting gateway. Nothing is deleted
-- (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.edge_gateways (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('saml', 'ldap', 'kerberos', 'radius')),
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  cert_sha256 bytea NOT NULL CHECK (octet_length(cert_sha256) = 32),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, kind, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX edge_gateways_cert ON access.edge_gateways (cert_sha256);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.edge_gateways
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.gateway.register', 'idp.gateway.retire');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.edge_gateways
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.edge_gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.edge_gateways FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.edge_gateways FROM PUBLIC;
CREATE POLICY rows ON access.edge_gateways AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.edge_gateways AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
-- OP-132 m.3: the router names a gateway's realm and reads nothing else
CREATE POLICY router_reads ON access.edge_gateways AS RESTRICTIVE TO access_router
  USING (true) WITH CHECK (false);
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.edge_gateways
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.edge_gateways TO access_app;
GRANT SELECT (tenant_id, realm_id, kind, name, version, state, cert_sha256)
  ON access.edge_gateways TO access_router;

RESET ROLE;
