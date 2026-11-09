-- OP-154 m.3 (d), (r), AG-30, L25, U20: workload clients of the realm and the SPIFFE bundles it
-- keeps. A workload client authenticates with a JWT-SVID or an X.509-SVID
-- (draft-ietf-oauth-spiffe-client-auth, §11.12.1); its SPIFFE ID selector, the trust domain's
-- Bundle Endpoint and the agent Party its workloads are Instances of are realm configuration,
-- written by idp.client.register and idp.client.update only. A kept bundle is a cache of what
-- the endpoint served, never configuration. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients DROP CONSTRAINT idp_clients_auth_method_check;
ALTER TABLE access.idp_clients ADD CONSTRAINT idp_clients_auth_method_check
  CHECK (auth_method IN ('none', 'private_key_jwt', 'client_secret_basic', 'spiffe_jwt',
                         'spiffe_x509')) NOT VALID;
ALTER TABLE access.idp_clients VALIDATE CONSTRAINT idp_clients_auth_method_check;

-- §11.12.1, MD-4: the selector is an identifier or a whole-segment prefix written …/*
CREATE TABLE access.idp_client_workloads (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  spiffe_id text NOT NULL CHECK (length(spiffe_id) BETWEEN 10 AND 2048
    AND spiffe_id ~ '^(spiffe|wimse)://[a-z0-9._-]+/'),
  bundle_endpoint text NOT NULL CHECK (length(bundle_endpoint) BETWEEN 9 AND 2048
    AND bundle_endpoint ~ '^https://'),
  agent_party bytea NOT NULL CHECK (octet_length(agent_party) = 16),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  PRIMARY KEY (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id, client_uuid)
    REFERENCES access.idp_clients (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_client_workloads
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.register', 'idp.client.update');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_client_workloads
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.update');

CREATE FUNCTION access.idp_client_workload_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR (NEW.tenant_id, NEW.realm_id, NEW.client_uuid)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.client_uuid) THEN
    RAISE EXCEPTION 'idp_client_workloads: a workload client keeps its client'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER idp_client_workload_fixed BEFORE UPDATE OR DELETE ON access.idp_client_workloads
  FOR EACH ROW EXECUTE FUNCTION access.idp_client_workload_fixed();

-- OP-154 m.3 (r): one kept bundle per trust domain, refreshed after its refresh hint
CREATE TABLE access.oauth_workload_bundles (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  trust_domain text NOT NULL CHECK (trust_domain ~ '^[a-z0-9._-]{1,255}$'),
  bundle_endpoint text NOT NULL CHECK (length(bundle_endpoint) BETWEEN 9 AND 2048
    AND bundle_endpoint ~ '^https://'),
  document bytea NOT NULL CHECK (octet_length(document) BETWEEN 2 AND 262144),
  fetched_ms bigint NOT NULL CHECK (fetched_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, trust_domain),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

CREATE FUNCTION access.oauth_workload_bundle_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR (NEW.tenant_id, NEW.realm_id, NEW.trust_domain)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.trust_domain) THEN
    RAISE EXCEPTION 'oauth_workload_bundles: a kept bundle is only replaced'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_workload_bundle_rules BEFORE UPDATE OR DELETE
  ON access.oauth_workload_bundles
  FOR EACH ROW EXECUTE FUNCTION access.oauth_workload_bundle_rules();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_client_workloads', 'oauth_workload_bundles'] LOOP
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

REVOKE ALL ON FUNCTION access.idp_client_workload_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.oauth_workload_bundle_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_client_workloads, access.oauth_workload_bundles TO access_app;
GRANT UPDATE (spiffe_id, bundle_endpoint, agent_party, domain_id, decision_pos)
  ON access.idp_client_workloads TO access_app;
GRANT UPDATE (bundle_endpoint, document, fetched_ms) ON access.oauth_workload_bundles TO access_app;

RESET ROLE;
