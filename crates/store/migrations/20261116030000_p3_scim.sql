-- OP-155 m.3 (g), IDP-23, IDP-29, MD-14: the SCIM server's clients and resources, and the outbound
-- SCIM client's targets and log. Clients and targets change only under idp.scim.* decisions: each
-- row is one version and the newest is the client or target. A client's bearer secret is kept as
-- its SHA-256 only; a target's secret is sealed under the realm KEK. Resources are written by the
-- clients' requests; a DELETE is a soft delete whose id is never used again and which later reads
-- answer 404 (OP-73, INV-32, TN-76). A User's attributes are sealed under its subject's profile
-- key (OP-153 m.3 (aa)). Nothing is deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.scim_clients (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  secret_sha256 bytea NOT NULL CHECK (octet_length(secret_sha256) = 32),
  profile text CHECK (profile ~ '^scim\.[a-z0-9][a-z0-9_-]{0,62}$'),
  issuer uuid NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX scim_clients_secret ON access.scim_clients (tenant_id, realm_id, secret_sha256);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.scim_clients
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound(
    'idp.scim.client_register', 'idp.scim.token_rotate', 'idp.scim.client_retire');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.scim_clients
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.scim_clients
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.scim_resources (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  client_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user', 'group', 'device')),
  subject_id uuid,
  -- pii:none
  external_index bytea CHECK (octet_length(external_index) = 32),
  display_name text CHECK (char_length(display_name) <= 2048),
  body jsonb,
  body_nonce bytea,
  -- pii:profile
  body_ciphertext bytea,
  version bigint NOT NULL CHECK (version >= 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  modified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  deleted_at timestamptz,
  CHECK ((kind = 'user') = (subject_id IS NOT NULL)),
  CHECK ((kind = 'user') = (body IS NULL)),
  CHECK ((body_ciphertext IS NULL) = (body_nonce IS NULL)),
  CHECK (kind <> 'user' OR body_ciphertext IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, resource_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX scim_resources_external ON access.scim_resources
  (tenant_id, realm_id, client_name, kind, external_index)
  WHERE deleted_at IS NULL AND external_index IS NOT NULL;
CREATE UNIQUE INDEX scim_resources_subject ON access.scim_resources (tenant_id, realm_id, subject_id)
  WHERE deleted_at IS NULL AND subject_id IS NOT NULL;
CREATE INDEX scim_resources_page ON access.scim_resources
  (tenant_id, realm_id, client_name, kind, resource_id) WHERE deleted_at IS NULL;
-- OP-73, INV-32: a deleted resource stays deleted
CREATE FUNCTION access.scim_resource_guard() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'scim resource % is deleted', OLD.resource_id USING ERRCODE = 'P0001';
  END IF;
  IF NEW.resource_id <> OLD.resource_id OR NEW.client_name <> OLD.client_name
     OR NEW.kind <> OLD.kind OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.version <= OLD.version THEN
    RAISE EXCEPTION 'scim resource % keeps its identity', OLD.resource_id USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scim_resource_guard BEFORE UPDATE ON access.scim_resources
  FOR EACH ROW EXECUTE FUNCTION access.scim_resource_guard();
CREATE TRIGGER append_only_row BEFORE DELETE ON access.scim_resources
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.scim_resources
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.scim_targets (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  base_url text NOT NULL CHECK (base_url ~ '^https://' AND char_length(base_url) <= 2048),
  secret_wrapped_dek bytea NOT NULL,
  secret_nonce bytea NOT NULL CHECK (octet_length(secret_nonce) = 12),
  secret_sealed bytea NOT NULL,
  kek_id text NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.scim_targets
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.scim.outbound_register', 'idp.scim.outbound_retire');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.scim_targets
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.scim_targets
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- IDP-29: where a pushed resource lives at a target, so later pushes address it
CREATE TABLE access.scim_target_links (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  target text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user', 'group')),
  local_id uuid NOT NULL,
  remote_id text NOT NULL CHECK (char_length(remote_id) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, target, kind, local_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.scim_target_links
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.scim_target_links
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- IDP-29: each push and the target's answer; a report, never authority
CREATE TABLE access.scim_outbound_log (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  entry_id uuid NOT NULL DEFAULT uuidv7(),
  target text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user', 'group')),
  local_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN ('create', 'replace', 'deactivate', 'delete')),
  status integer CHECK (status BETWEEN 100 AND 599),
  outcome text NOT NULL CHECK (outcome IN ('done', 'retry', 'failed')),
  attempt integer NOT NULL CHECK (attempt >= 1),
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, entry_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.scim_outbound_log
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.scim_outbound_log
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scim_clients', 'scim_resources', 'scim_targets', 'scim_target_links',
                           'scim_outbound_log'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
      'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
      'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT ON access.scim_clients, access.scim_targets, access.scim_target_links,
  access.scim_outbound_log TO access_app;
GRANT SELECT, INSERT, UPDATE ON access.scim_resources TO access_app;

RESET ROLE;
