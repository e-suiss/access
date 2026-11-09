-- OP-154 m.3 (t), MD-13, E36, EI-26, AG-32, AG-39, AG-40, §11.13: the token vault. A Resource is
-- realm configuration written only under a committed idp.vault.* ALLOW; a connection is one
-- person's account at an upstream; a TokenSet is that account's upstream tokens sealed under the
-- person's subject DEK; a release is the projection row of a release decided against an allowed
-- Exercise. None of these rows is authority (AGI-2). Nothing is deleted (OP-73): a Resource gets a
-- new version, a connection is disconnected, a TokenSet is superseded and then shredded, a
-- release is a written fact.
SET LOCAL ROLE access_migrator;

-- OP-154 m.3 (t), AG-39: one row per idp.vault.resource_enable, resource_register or
-- resource_disable; the newest version is the Resource
CREATE TABLE access.vault_resources (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$'),
  version bigint NOT NULL CHECK (version >= 1),
  upstream text NOT NULL CHECK (upstream ~ '^[a-z][a-z0-9_-]{0,63}$'),
  origin text NOT NULL CHECK (origin IN ('catalog', 'realm')),
  state text NOT NULL CHECK (state IN ('enabled', 'disabled')),
  definition bytea CHECK (octet_length(definition) BETWEEN 1 AND 65536),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((state = 'enabled') = (definition IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.vault_resources
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.vault.resource_enable',
                                                 'idp.vault.resource_register',
                                                 'idp.vault.resource_disable');

-- OP-154 m.3 (t): path (b) is open only under idp.vault.release_mode_open; the newest row rules
CREATE TABLE access.vault_release_modes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  mode text NOT NULL CHECK (mode IN ('open', 'closed')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.vault_release_modes
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.vault.release_mode_open',
                                                 'idp.vault.release_mode_close');

-- §8.8, §8.9, AS-M15: one person's account at an upstream, for the agent client they consented to
CREATE TABLE access.vault_connections (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  connection_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  resource text NOT NULL CHECK (resource ~ '^[a-z][a-z0-9_-]{0,63}$'),
  resource_version bigint NOT NULL CHECK (resource_version >= 1),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 2048),
  scopes text[] NOT NULL CHECK (cardinality(scopes) <= 64),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'needs_reconnect', 'disconnected')),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  status_ms bigint NOT NULL CHECK (status_ms >= created_ms),
  refresh_lease_ms bigint,
  PRIMARY KEY (tenant_id, realm_id, connection_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, resource, resource_version)
    REFERENCES access.vault_resources (tenant_id, realm_id, name, version)
);
CREATE INDEX vault_connections_subject
  ON access.vault_connections (tenant_id, realm_id, subject_id) WHERE status <> 'disconnected';

-- §10.2.6: the upstream redirect of a connection is bound to the browser that started it, once
CREATE TABLE access.vault_connect_attempts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  state_hash bytea NOT NULL CHECK (octet_length(state_hash) = 32),
  device_hash bytea NOT NULL CHECK (octet_length(device_hash) = 32),
  connection_id uuid NOT NULL,
  verifier text NOT NULL CHECK (length(verifier) = 43),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'used')),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  used_ms bigint,
  CHECK ((status = 'used') = (used_ms IS NOT NULL)),
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 600000),
  PRIMARY KEY (tenant_id, realm_id, state_hash),
  FOREIGN KEY (tenant_id, realm_id, connection_id)
    REFERENCES access.vault_connections (tenant_id, realm_id, connection_id)
);

-- §11.13, OP-73: a connection's upstream tokens, sealed under the subject DEK; a newer version
-- supersedes the live one, and a superseded or disconnected one is shredded, never deleted
CREATE TABLE access.vault_token_sets (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  kek_id text NOT NULL CHECK (length(kek_id) BETWEEN 1 AND 128),
  wrapped_dek bytea CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 512),
  nonce bytea CHECK (octet_length(nonce) = 12),
  -- pii:credential
  ciphertext bytea CHECK (octet_length(ciphertext) BETWEEN 1 AND 32768),
  access_expires_ms bigint,
  refreshable boolean NOT NULL,
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  superseded_ms bigint,
  shredded_ms bigint,
  CHECK ((wrapped_dek IS NULL) = (shredded_ms IS NOT NULL)
         AND (nonce IS NULL) = (shredded_ms IS NOT NULL)
         AND (ciphertext IS NULL) = (shredded_ms IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, connection_id, version),
  FOREIGN KEY (tenant_id, realm_id, connection_id)
    REFERENCES access.vault_connections (tenant_id, realm_id, connection_id)
);
CREATE UNIQUE INDEX vault_token_sets_live
  ON access.vault_token_sets (tenant_id, realm_id, connection_id) WHERE superseded_ms IS NULL;
CREATE INDEX vault_token_sets_due
  ON access.vault_token_sets (tenant_id, realm_id, access_expires_ms)
  WHERE superseded_ms IS NULL AND refreshable;

-- G59, EI-26, AG-32, §11.13 step 4: the release record, a projection of the allowed Exercise;
-- one release per Exercise (one step)
CREATE TABLE access.vault_releases (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  release_id uuid NOT NULL DEFAULT uuidv7(),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  exercise bytea NOT NULL CHECK (octet_length(exercise) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos >= 0),
  intent_digest bytea NOT NULL CHECK (octet_length(intent_digest) = 32),
  actor bytea CHECK (octet_length(actor) = 16),
  connection_id uuid NOT NULL,
  token_set_version bigint NOT NULL CHECK (token_set_version >= 1),
  pep text NOT NULL CHECK (length(pep) BETWEEN 1 AND 256),
  path text NOT NULL CHECK (path IN ('executor', 'agent')),
  tier smallint NOT NULL CHECK (tier BETWEEN 0 AND 3),
  use_until_ms bigint NOT NULL CHECK (use_until_ms > 0),
  released_ms bigint NOT NULL CHECK (released_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, release_id),
  FOREIGN KEY (tenant_id, realm_id, connection_id, token_set_version)
    REFERENCES access.vault_token_sets (tenant_id, realm_id, connection_id, version)
);
CREATE UNIQUE INDEX vault_releases_exercise
  ON access.vault_releases (tenant_id, realm_id, domain_id, exercise);
CREATE INDEX vault_releases_connection
  ON access.vault_releases (tenant_id, realm_id, connection_id, released_ms);
CREATE INDEX vault_releases_actor
  ON access.vault_releases (tenant_id, realm_id, actor) WHERE actor IS NOT NULL;

-- OP-73: a disconnected connection stays disconnected; the person and the Resource never change
CREATE FUNCTION access.vault_connection_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.status = 'disconnected'
     OR (NEW.tenant_id, NEW.realm_id, NEW.connection_id, NEW.subject_id, NEW.party, NEW.resource,
         NEW.resource_version, NEW.client_id, NEW.created_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.connection_id, OLD.subject_id, OLD.party,
                          OLD.resource, OLD.resource_version, OLD.client_id, OLD.created_ms) THEN
    RAISE EXCEPTION 'vault_connections: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER vault_connection_transition BEFORE UPDATE OR DELETE ON access.vault_connections
  FOR EACH ROW EXECUTE FUNCTION access.vault_connection_transition();

-- §10.2.6: an attempt is used once
CREATE FUNCTION access.vault_attempt_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.status <> 'open' OR NEW.status <> 'used'
     OR (NEW.tenant_id, NEW.realm_id, NEW.state_hash, NEW.device_hash, NEW.connection_id,
         NEW.verifier, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.state_hash, OLD.device_hash,
                          OLD.connection_id, OLD.verifier, OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'vault_connect_attempts: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER vault_attempt_transition BEFORE UPDATE OR DELETE ON access.vault_connect_attempts
  FOR EACH ROW EXECUTE FUNCTION access.vault_attempt_transition();

-- OP-73: a TokenSet is superseded once and shredded once; nothing else about it changes
CREATE FUNCTION access.vault_token_set_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.shredded_ms IS NOT NULL
     OR (OLD.superseded_ms IS NOT NULL AND NEW.superseded_ms IS DISTINCT FROM OLD.superseded_ms)
     OR (NEW.shredded_ms IS NULL AND (NEW.wrapped_dek, NEW.nonce, NEW.ciphertext)
           IS DISTINCT FROM (OLD.wrapped_dek, OLD.nonce, OLD.ciphertext))
     OR (NEW.tenant_id, NEW.realm_id, NEW.connection_id, NEW.version, NEW.kek_id,
         NEW.access_expires_ms, NEW.refreshable, NEW.created_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.connection_id, OLD.version, OLD.kek_id,
                          OLD.access_expires_ms, OLD.refreshable, OLD.created_ms) THEN
    RAISE EXCEPTION 'vault_token_sets: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER vault_token_set_transition BEFORE UPDATE OR DELETE ON access.vault_token_sets
  FOR EACH ROW EXECUTE FUNCTION access.vault_token_set_transition();

CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.vault_resources
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.vault_release_modes
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.vault_releases
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['vault_resources', 'vault_release_modes', 'vault_connections',
                           'vault_connect_attempts', 'vault_token_sets', 'vault_releases'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.vault_connection_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.vault_attempt_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.vault_token_set_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.vault_resources, access.vault_release_modes, access.vault_releases,
  access.vault_connections, access.vault_connect_attempts, access.vault_token_sets TO access_app;
GRANT UPDATE (scopes, status, status_ms, refresh_lease_ms) ON access.vault_connections TO access_app;
GRANT UPDATE (status, used_ms) ON access.vault_connect_attempts TO access_app;
GRANT UPDATE (wrapped_dek, nonce, ciphertext, superseded_ms, shredded_ms)
  ON access.vault_token_sets TO access_app;

RESET ROLE;
