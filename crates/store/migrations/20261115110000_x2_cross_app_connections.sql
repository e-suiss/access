-- OP-154 m.3 (a), (n), AG-28, §11.11.2: the realm's cross-app connections for ID-JAG. A
-- connection names the requesting client, the Resource authorization server it may ask an
-- ID-JAG for and the resource there; its scopes are a hint only. Without a live connection the
-- realm issues no ID-JAG to that client for that audience and resource. Each row is one
-- idp.client.cross_app_connection or cross_app_connection_retire; the newest version is the
-- connection. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_cross_app_connections (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 2048),
  audience text NOT NULL CHECK (length(audience) BETWEEN 9 AND 2048 AND audience ~ '^https://'),
  resource text NOT NULL CHECK (length(resource) BETWEEN 9 AND 2048 AND resource ~ '^https://'),
  scopes text[] NOT NULL CHECK (cardinality(scopes) <= 64),
  subject_policy text NOT NULL CHECK (subject_policy = 'pairwise'),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX idp_cross_app_connections_client
  ON access.idp_cross_app_connections (tenant_id, realm_id, client_id);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_cross_app_connections
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.cross_app_connection',
                                                 'idp.client.cross_app_connection_retire');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_cross_app_connections
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.idp_cross_app_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.idp_cross_app_connections FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.idp_cross_app_connections FROM PUBLIC;
CREATE POLICY rows ON access.idp_cross_app_connections AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.idp_cross_app_connections AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.idp_cross_app_connections
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.idp_cross_app_connections TO access_app;

RESET ROLE;
