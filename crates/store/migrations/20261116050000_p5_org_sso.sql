-- OP-155 m.3 (i), TN-94, TN-95, TN-134, OP-153 m.3 (p): an organization's enterprise SSO on the
-- identity plane. SSO enforcement is a versioned row each idp.org.sso_enforce or sso_enforce_lift
-- writes; the newest version is the organization's state and names the pending invitations' fate.
-- A setup link is kept as the SHA-256 of its token, bound to one organization, valid 72 hours, and
-- bound to the first browser that submits a step. An organization's SCIM source is the realm SCIM
-- client registered for it; while it is bound, invitations are closed. The connection drafts take
-- SAML too. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.org_sso_enforcements (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  org_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enforced boolean NOT NULL,
  invites text CHECK (invites IS NULL OR invites IN ('cancel', 'redirect_to_sso')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (enforced = (invites IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, org_id, version),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.org_sso_enforcements
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.org.sso_enforce', 'idp.org.sso_enforce_lift');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.org_sso_enforcements
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.org_setup_links (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  link_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  created_exercise bytea NOT NULL CHECK (octet_length(created_exercise) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  browser_hash bytea CHECK (browser_hash IS NULL OR octet_length(browser_hash) = 32),
  opened_at timestamptz,
  finished_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '72 hours'),
  CHECK ((browser_hash IS NULL) = (opened_at IS NULL)),
  CHECK (finished_at IS NULL OR opened_at IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, link_id),
  UNIQUE (tenant_id, realm_id, token_hash),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id)
);
CREATE INDEX org_setup_links_org ON access.org_setup_links (tenant_id, realm_id, org_id, created_at);

-- TN-134: a link is opened by one browser once and finished once; its organization, token and
-- expiry never change
CREATE FUNCTION access.org_setup_link_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.org_id <> OLD.org_id OR NEW.token_hash <> OLD.token_hash
     OR NEW.expires_at <> OLD.expires_at OR NEW.created_exercise <> OLD.created_exercise
     OR OLD.finished_at IS NOT NULL
     OR (OLD.browser_hash IS NOT NULL AND NEW.browser_hash IS DISTINCT FROM OLD.browser_hash)
     OR (OLD.opened_at IS NOT NULL AND NEW.opened_at IS DISTINCT FROM OLD.opened_at) THEN
    RAISE EXCEPTION 'setup link transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER org_setup_link_transition BEFORE UPDATE ON access.org_setup_links
  FOR EACH ROW EXECUTE FUNCTION access.org_setup_link_transition();

-- TN-95: the SCIM client an organization's membership answers to; registering it binds it,
-- retiring the client ends the binding
CREATE TABLE access.org_scim_sources (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  org_id uuid NOT NULL,
  client_name text NOT NULL CHECK (client_name ~ '^[a-z][a-z0-9-]{0,62}$'),
  created_exercise bytea NOT NULL CHECK (octet_length(created_exercise) = 32),
  bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, org_id, client_name, bound_at),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id)
);
CREATE UNIQUE INDEX org_scim_sources_open
  ON access.org_scim_sources (tenant_id, realm_id, client_name) WHERE ended_at IS NULL;

CREATE FUNCTION access.org_scim_source_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.ended_at IS NOT NULL OR NEW.org_id <> OLD.org_id OR NEW.client_name <> OLD.client_name
     OR NEW.bound_at <> OLD.bound_at OR NEW.created_exercise <> OLD.created_exercise THEN
    RAISE EXCEPTION 'scim source transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER org_scim_source_transition BEFORE UPDATE ON access.org_scim_sources
  FOR EACH ROW EXECUTE FUNCTION access.org_scim_source_transition();

-- OP-153 m.3 (p), OP-155 m.3 (i): a connection draft is OIDC (issuer and client id) or SAML (the
-- identity provider's entity ID and metadata URL), drafted by the connection manager or through
-- a setup link
ALTER TABLE access.org_sso_drafts
  DROP CONSTRAINT org_sso_drafts_protocol_check,
  ALTER COLUMN issuer DROP NOT NULL,
  ALTER COLUMN client_id DROP NOT NULL,
  ADD COLUMN saml_entity_id text CHECK (saml_entity_id IS NULL
    OR (char_length(saml_entity_id) BETWEEN 1 AND 1024 AND saml_entity_id !~ '[[:cntrl:][:space:]]')),
  ADD COLUMN saml_metadata_url text CHECK (saml_metadata_url IS NULL
    OR (char_length(saml_metadata_url) <= 2048 AND saml_metadata_url ~ '^https://[^\s#]+$')),
  ADD COLUMN provider text CHECK (provider IS NULL OR provider ~ '^[a-z][a-z0-9-]{0,31}$'),
  ADD COLUMN setup_link uuid,
  ADD CONSTRAINT org_sso_drafts_shape CHECK (
    (protocol = 'oidc' AND issuer IS NOT NULL AND client_id IS NOT NULL
      AND saml_entity_id IS NULL AND saml_metadata_url IS NULL)
    OR (protocol = 'saml' AND issuer IS NULL AND client_id IS NULL
      AND saml_entity_id IS NOT NULL AND saml_metadata_url IS NOT NULL)) NOT VALID,
  ADD CONSTRAINT org_sso_drafts_link FOREIGN KEY (tenant_id, realm_id, setup_link)
    REFERENCES access.org_setup_links (tenant_id, realm_id, link_id) NOT VALID;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_sso_enforcements', 'org_setup_links', 'org_scim_sources'] LOOP
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
CREATE TRIGGER no_delete BEFORE DELETE ON access.org_setup_links
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.org_scim_sources
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.org_setup_link_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.org_scim_source_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.org_sso_enforcements, access.org_setup_links,
  access.org_scim_sources TO access_app;
GRANT UPDATE (browser_hash, opened_at, finished_at) ON access.org_setup_links TO access_app;
GRANT UPDATE (ended_at) ON access.org_scim_sources TO access_app;

RESET ROLE;
