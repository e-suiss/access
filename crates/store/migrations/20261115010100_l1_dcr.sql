-- OP-154 m.3 (j), §11.4.5 #31-35, AS-A1, §10.1.2: the dynamic client registration profile, kept
-- only for backward compatibility and off by default. A policy version is written only under a
-- committed idp.client.dcr_policy or dcr_policy_tighten ALLOW; it names the digests of the
-- initial access tokens that open the registration endpoint (a gate, never authority). A DCR
-- client is the client its registration made, stamped with the issuer it was registered at.
-- Nothing is deleted (OP-73): an unused or no longer admitted client retires, once.
SET LOCAL ROLE access_migrator;

-- OP-154 m.3 (j): one row per decided policy; the newest version rules
CREATE TABLE access.idp_dcr_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  domains text[] NOT NULL CHECK (cardinality(domains) <= 64),
  tokens bytea[] NOT NULL CHECK (cardinality(tokens) <= 16),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_dcr_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.dcr_policy',
                                                 'idp.client.dcr_policy_tighten');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_dcr_policies
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- §11.4.5 #31-35: a client registered at /register; its metadata as accepted, the issuer it is
-- stamped with, the initial access token digest and the IP prefix it came with
CREATE TABLE access.oauth_dcr_clients (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL DEFAULT uuidv7(),
  client_id text NOT NULL UNIQUE CHECK (client_id ~ '^dcr_[A-Za-z0-9_-]{43}$'),
  metadata bytea NOT NULL CHECK (octet_length(metadata) BETWEEN 2 AND 5120),
  issuer text NOT NULL CHECK (issuer ~ '^https://'),
  token bytea NOT NULL CHECK (octet_length(token) = 32),
  ip_prefix text NOT NULL CHECK (length(ip_prefix) BETWEEN 1 AND 64),
  registered_ms bigint NOT NULL CHECK (registered_ms > 0),
  last_used_ms bigint NOT NULL CHECK (last_used_ms >= registered_ms),
  retired_ms bigint CHECK (retired_ms >= registered_ms),
  retire_reason text CHECK (retire_reason IN ('unused', 'policy')),
  CHECK ((retired_ms IS NULL) = (retire_reason IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE INDEX oauth_dcr_clients_ip ON access.oauth_dcr_clients (tenant_id, realm_id, ip_prefix, registered_ms);
CREATE INDEX oauth_dcr_clients_live ON access.oauth_dcr_clients (tenant_id, realm_id)
  WHERE retired_ms IS NULL;

CREATE FUNCTION access.oauth_dcr_client_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.retired_ms IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.client_uuid, NEW.client_id, NEW.metadata, NEW.issuer,
         NEW.token, NEW.ip_prefix, NEW.registered_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.client_uuid, OLD.client_id,
                          OLD.metadata, OLD.issuer, OLD.token, OLD.ip_prefix, OLD.registered_ms) THEN
    RAISE EXCEPTION 'oauth_dcr_clients: a registration is fixed and a retired client stays retired'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_dcr_client_rules BEFORE UPDATE OR DELETE ON access.oauth_dcr_clients
  FOR EACH ROW EXECUTE FUNCTION access.oauth_dcr_client_rules();

-- IDP-1: a grant is the code exchange of a registered, a CIMD or a DCR client of the realm
CREATE OR REPLACE FUNCTION access.oauth_grant_client() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.idp_clients c
                  WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                    AND c.client_uuid = NEW.client_uuid)
     AND NOT EXISTS (SELECT 1 FROM access.oauth_cimd_clients c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.client_uuid = NEW.client_uuid)
     AND NOT EXISTS (SELECT 1 FROM access.oauth_dcr_clients c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.client_uuid = NEW.client_uuid) THEN
    RAISE EXCEPTION 'oauth_grants: client % is not a client of the realm', NEW.client_uuid
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END
$$;

-- P58: a DCR client's consent record says so
ALTER TABLE access.oauth_consent_records DROP CONSTRAINT oauth_consent_records_source_check;
ALTER TABLE access.oauth_consent_records ADD CONSTRAINT oauth_consent_records_source_check
  CHECK (source IN ('cimd', 'registered', 'dcr'));

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_dcr_policies', 'oauth_dcr_clients'] LOOP
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

REVOKE ALL ON FUNCTION access.oauth_dcr_client_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.oauth_grant_client() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_dcr_policies, access.oauth_dcr_clients TO access_app;
GRANT UPDATE (last_used_ms, retired_ms, retire_reason) ON access.oauth_dcr_clients TO access_app;

RESET ROLE;
