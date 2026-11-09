-- OP-154 m.3 (i), (k), AG-3…AG-8, IDP-1, IDI-10, P48, P58: the realm's protected resources, the
-- CIMD clients the authorization server resolved, and the server-side consent records. A CIMD
-- client is the client its URL names, never an actor (§11.3); its row keeps the snapshot of the
-- document it was last seen with. A consent record is a UI record, never authority: it names
-- the Grant the person issued with their AAS. Nothing is deleted (OP-73): a client retires and a
-- consent ends, once.
SET LOCAL ROLE access_migrator;

-- AG-8, §11.4.3: a protected resource or MCP server by its canonical URI, registered by
-- idp.client.resource_register
CREATE TABLE access.idp_protected_resources (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  resource text NOT NULL CHECK (length(resource) BETWEEN 9 AND 2048
    AND resource ~ '^https://[a-z0-9.-]+(:[0-9]{1,5})?(/[^#?[:space:]]*)?$' AND resource !~ '/$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, resource),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_protected_resources
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.resource_register');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_protected_resources
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- AG-3, AG-5, OP-154 m.3 (i): a CIMD client; the URL is its identity, simple string comparison
CREATE TABLE access.oauth_cimd_clients (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL DEFAULT uuidv7(),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 10 AND 2048 AND client_id ~ '^https://'),
  document bytea NOT NULL CHECK (octet_length(document) BETWEEN 2 AND 5120),
  document_hash bytea NOT NULL CHECK (octet_length(document_hash) = 32),
  authority_hash bytea NOT NULL CHECK (octet_length(authority_hash) = 32),
  visual_hash bytea NOT NULL CHECK (octet_length(visual_hash) = 32),
  logo bytea CHECK (octet_length(logo) BETWEEN 1 AND 262144),
  logo_type text CHECK (logo_type IN ('image/png', 'image/jpeg', 'image/webp')),
  first_seen_ms bigint NOT NULL CHECK (first_seen_ms > 0),
  fetched_ms bigint NOT NULL CHECK (fetched_ms >= first_seen_ms),
  fresh_until_ms bigint NOT NULL CHECK (fresh_until_ms > fetched_ms),
  visual_changed_ms bigint CHECK (visual_changed_ms >= first_seen_ms),
  retired_ms bigint CHECK (retired_ms >= first_seen_ms),
  retire_reason text CHECK (retire_reason IN ('domain_policy', 'disabled')),
  CHECK ((retired_ms IS NULL) = (retire_reason IS NULL)),
  CHECK ((logo IS NULL) = (logo_type IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
-- AG-5, §11.3.6: a URL that changes hands is a new client; the retired one is never reused
CREATE UNIQUE INDEX oauth_cimd_clients_live ON access.oauth_cimd_clients (tenant_id, realm_id, client_id)
  WHERE retired_ms IS NULL;

CREATE FUNCTION access.oauth_cimd_client_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.retired_ms IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.client_uuid, NEW.client_id, NEW.first_seen_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.client_uuid, OLD.client_id,
                          OLD.first_seen_ms) THEN
    RAISE EXCEPTION 'oauth_cimd_clients: the URL is the identity and a retired client stays retired'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_cimd_client_rules BEFORE UPDATE OR DELETE ON access.oauth_cimd_clients
  FOR EACH ROW EXECUTE FUNCTION access.oauth_cimd_client_rules();

-- IDP-1: a grant is the code exchange of a registered or a CIMD client of the realm
ALTER TABLE access.oauth_grants DROP CONSTRAINT oauth_grants_tenant_id_realm_id_client_uuid_fkey;

CREATE FUNCTION access.oauth_grant_client() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.idp_clients c
                  WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                    AND c.client_uuid = NEW.client_uuid)
     AND NOT EXISTS (SELECT 1 FROM access.oauth_cimd_clients c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.client_uuid = NEW.client_uuid) THEN
    RAISE EXCEPTION 'oauth_grants: client % is not a client of the realm', NEW.client_uuid
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_grant_client BEFORE INSERT ON access.oauth_grants
  FOR EACH ROW EXECUTE FUNCTION access.oauth_grant_client();

-- §9.14.5 k.3, §11.6, P58: (user, client, resource, scopes, source, metadata_hash, grant_ref);
-- it spares asking again and is never authority: the redirect waits on grant_ref being live
CREATE TABLE access.oauth_consent_records (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  consent_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  source text NOT NULL CHECK (source IN ('cimd', 'registered')),
  resource text NOT NULL CHECK (length(resource) BETWEEN 9 AND 2048),
  scopes text[] NOT NULL CHECK (cardinality(scopes) <= 32),
  metadata_hash bytea NOT NULL CHECK (octet_length(metadata_hash) = 32),
  grant_domain bytea NOT NULL CHECK (octet_length(grant_domain) = 32),
  grant_ref bytea NOT NULL CHECK (octet_length(grant_ref) = 16),
  exercise bytea NOT NULL CHECK (octet_length(exercise) = 32),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  ended_ms bigint,
  end_reason text CHECK (end_reason IN ('replaced', 'metadata_changed', 'client_retired',
                                        'grant_ended', 'stopped')),
  CHECK ((ended_ms IS NULL) = (end_reason IS NULL)),
  CHECK (ended_ms IS NULL OR ended_ms >= created_ms),
  PRIMARY KEY (tenant_id, realm_id, consent_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX oauth_consent_records_live
  ON access.oauth_consent_records (tenant_id, realm_id, subject_id, client_uuid, resource)
  WHERE ended_ms IS NULL;
CREATE INDEX oauth_consent_records_client
  ON access.oauth_consent_records (tenant_id, realm_id, client_uuid)
  WHERE ended_ms IS NULL;

CREATE FUNCTION access.oauth_consent_record_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.ended_ms IS NOT NULL OR NEW.ended_ms IS NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.consent_id, NEW.subject_id, NEW.client_uuid, NEW.source,
         NEW.resource, NEW.scopes, NEW.metadata_hash, NEW.grant_domain, NEW.grant_ref,
         NEW.exercise, NEW.created_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.consent_id, OLD.subject_id,
                          OLD.client_uuid, OLD.source, OLD.resource, OLD.scopes,
                          OLD.metadata_hash, OLD.grant_domain, OLD.grant_ref, OLD.exercise,
                          OLD.created_ms) THEN
    RAISE EXCEPTION 'oauth_consent_records: a record only ends, once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_consent_record_rules BEFORE UPDATE OR DELETE ON access.oauth_consent_records
  FOR EACH ROW EXECUTE FUNCTION access.oauth_consent_record_rules();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_protected_resources', 'oauth_cimd_clients',
                           'oauth_consent_records'] LOOP
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

REVOKE ALL ON FUNCTION access.oauth_cimd_client_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.oauth_grant_client() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.oauth_consent_record_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_protected_resources, access.oauth_cimd_clients,
  access.oauth_consent_records TO access_app;
GRANT UPDATE (document, document_hash, authority_hash, visual_hash, logo, logo_type, fetched_ms,
  fresh_until_ms, visual_changed_ms, retired_ms, retire_reason) ON access.oauth_cimd_clients
  TO access_app;
GRANT UPDATE (ended_ms, end_reason) ON access.oauth_consent_records TO access_app;

RESET ROLE;
