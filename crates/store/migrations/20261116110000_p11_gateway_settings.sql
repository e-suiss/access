-- OP-155 m.3 (f), (o), IDP-17, IDP-18: what the RADIUS and Kerberos gateways of a realm are held
-- to. A RadSec client is registered with its RADIUS gateway by the SHA-256 of its TLS certificate
-- (idp.gateway.radius_client_register). A Kerberos gateway's keytab policy names the one SPN it
-- accepts tickets for, how often its keytab rotates, and the lowest key version still accepted
-- (idp.gateway.keytab_policy; idp.gateway.keytab_emergency raises the floor at once). The keytab
-- itself never reaches the database. Every row is one decision; the newest version holds.
-- Key versions seen in accepted tickets are tracked so that a rotated key stops being accepted.
-- Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.edge_radius_clients (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  gateway text NOT NULL CHECK (gateway ~ '^[a-z][a-z0-9-]{0,62}$'),
  client text NOT NULL CHECK (client ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  cert_sha256 bytea NOT NULL CHECK (octet_length(cert_sha256) = 32),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, gateway, client, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX edge_radius_clients_cert ON access.edge_radius_clients (tenant_id, realm_id, gateway, cert_sha256);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.edge_radius_clients
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.gateway.radius_client_register');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.edge_radius_clients
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.edge_radius_clients
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.edge_keytab_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  gateway text NOT NULL CHECK (gateway ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  spn text NOT NULL CHECK (char_length(spn) BETWEEN 3 AND 512),
  rotate_days integer NOT NULL CHECK (rotate_days BETWEEN 1 AND 365),
  kvno_floor bigint NOT NULL CHECK (kvno_floor BETWEEN 0 AND 4294967295),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, gateway, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.edge_keytab_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.gateway.keytab_policy', 'idp.gateway.keytab_emergency');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.edge_keytab_policies
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.edge_keytab_policies
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.edge_keytab_kvnos (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  gateway text NOT NULL CHECK (gateway ~ '^[a-z][a-z0-9-]{0,62}$'),
  kvno bigint NOT NULL CHECK (kvno BETWEEN 0 AND 4294967295),
  first_seen_ms bigint NOT NULL CHECK (first_seen_ms >= 0),
  PRIMARY KEY (tenant_id, realm_id, gateway, kvno),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.edge_keytab_kvnos
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.edge_keytab_kvnos
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['edge_radius_clients', 'edge_keytab_policies', 'edge_keytab_kvnos'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format(
      'CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app
         USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
         WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))',
      t);
    EXECUTE format('GRANT SELECT, INSERT ON access.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
