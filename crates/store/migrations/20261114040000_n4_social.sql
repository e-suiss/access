-- OP-153 m.3 (l), (m); IDP-31, P-ID-9, TN-65, TN-66, TN-67, TN-87: social sign-in, linked sign-ins
-- and combined accounts. Nothing here is ever deleted (OP-73): a provider is disabled, a link
-- ends, an attempt is used or expires, a combination is a written fact.
SET LOCAL ROLE access_migrator;

-- IDP-31, OP-153 m.3 (l): the social presets a realm enabled through idp.social.*; a NULL client
-- names the operator's shared development client, which only a sandbox realm may use
CREATE TABLE access.idp_social_providers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  preset text NOT NULL CHECK (preset ~ '^[a-z][a-z0-9_-]{0,63}$'),
  client_id text CHECK (length(client_id) BETWEEN 1 AND 255),
  client_secret_ref text CHECK (client_secret_ref ~ '^secret://[A-Za-z0-9/._-]{1,246}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  -- TN-87: the client id before the last change and when it changed
  previous_client_id text CHECK (length(previous_client_id) BETWEEN 1 AND 255),
  client_changed_ms bigint,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  CHECK ((client_id IS NULL) = (client_secret_ref IS NULL)),
  CHECK ((previous_client_id IS NULL) = (client_changed_ms IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, preset),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_social_providers
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.social.enable');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_social_providers
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.social.enable', 'idp.social.update',
                                                 'idp.social.disable');

-- P-ID-9, TN-66: an external identity linked to an account, keyed by the digest of
-- (provider, provider_subject_id) and never by an address; verified_ms is when control of it was
-- last proven. A link ends once (unlinked, or moved by a combination) and is never reopened.
CREATE TABLE access.identity_federated (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  link_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{0,63}$'),
  -- pii:none
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  verified_ms bigint NOT NULL CHECK (verified_ms >= created_ms),
  ended_ms bigint,
  end_reason text CHECK (end_reason IN ('unlinked', 'combined')),
  -- OP-153 m.3 (l): the address the provider gave, sealed under the account's contact key; an
  -- unvouched one stays unconfirmed until our own code proves it
  address_nonce bytea CHECK (octet_length(address_nonce) = 12),
  -- pii:contact
  address_ciphertext bytea CHECK (octet_length(address_ciphertext) <= 4096),
  -- pii:none
  address_index bytea CHECK (octet_length(address_index) = 32),
  address_vouched boolean,
  CHECK ((ended_ms IS NULL) = (end_reason IS NULL)),
  CHECK ((address_ciphertext IS NULL) = (address_nonce IS NULL)
         AND (address_ciphertext IS NULL) = (address_index IS NULL)
         AND (address_ciphertext IS NULL) = (address_vouched IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, link_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX identity_federated_live
  ON access.identity_federated (tenant_id, realm_id, identity_key) WHERE ended_ms IS NULL;
CREATE INDEX identity_federated_subject
  ON access.identity_federated (tenant_id, realm_id, subject_id);

CREATE FUNCTION access.identity_federated_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_federated: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.realm_id, NEW.link_id, NEW.subject_id, NEW.provider, NEW.identity_key,
      NEW.created_ms, NEW.address_nonce, NEW.address_ciphertext, NEW.address_index,
      NEW.address_vouched)
     IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.link_id, OLD.subject_id, OLD.provider,
                       OLD.identity_key, OLD.created_ms, OLD.address_nonce, OLD.address_ciphertext,
                       OLD.address_index, OLD.address_vouched)
     OR NEW.verified_ms < OLD.verified_ms
     OR (OLD.ended_ms IS NOT NULL AND (NEW.ended_ms, NEW.end_reason, NEW.verified_ms)
                                      IS DISTINCT FROM (OLD.ended_ms, OLD.end_reason, OLD.verified_ms)) THEN
    RAISE EXCEPTION 'identity_federated: a link only proves itself again and ends once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_federated_transition BEFORE UPDATE OR DELETE ON access.identity_federated
  FOR EACH ROW EXECUTE FUNCTION access.identity_federated_transition();

-- OP-153 m.3 (l), (m): one redirect to a provider, bound to the browser's flow device and used
-- once; a link attempt names the signed-in subject it links to
CREATE TABLE access.identity_social_attempts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  attempt_id uuid NOT NULL DEFAULT uuidv7(),
  state_hash bytea NOT NULL CHECK (octet_length(state_hash) = 32),
  device_hash bytea NOT NULL CHECK (octet_length(device_hash) = 32),
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{0,63}$'),
  purpose text NOT NULL CHECK (purpose IN ('signin', 'link')),
  subject_id uuid,
  nonce text NOT NULL CHECK (length(nonce) = 43),
  verifier text NOT NULL CHECK (length(verifier) = 43),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'used')),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  used_ms bigint,
  CHECK ((purpose = 'link') = (subject_id IS NOT NULL)),
  CHECK ((status = 'used') = (used_ms IS NOT NULL)),
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 600000),
  PRIMARY KEY (tenant_id, realm_id, attempt_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX identity_social_attempts_state
  ON access.identity_social_attempts (tenant_id, realm_id, state_hash);

CREATE FUNCTION access.identity_social_attempt_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_social_attempts: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status <> 'open' OR NEW.status <> 'used'
     OR (NEW.tenant_id, NEW.realm_id, NEW.attempt_id, NEW.state_hash, NEW.device_hash, NEW.provider,
         NEW.purpose, NEW.subject_id, NEW.nonce, NEW.verifier, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.attempt_id, OLD.state_hash, OLD.device_hash,
                          OLD.provider, OLD.purpose, OLD.subject_id, OLD.nonce, OLD.verifier,
                          OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'identity_social_attempts: an attempt is used once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_social_attempt_transition BEFORE UPDATE OR DELETE ON access.identity_social_attempts
  FOR EACH ROW EXECUTE FUNCTION access.identity_social_attempt_transition();

-- OP-153 m.3 (m): the absorbed account's half of a combination, issued to its own fresh session
-- and spent once by the surviving account's fresh session within five minutes
CREATE TABLE access.identity_combine_tickets (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  ticket_hash bytea NOT NULL CHECK (octet_length(ticket_hash) = 32),
  subject_id uuid NOT NULL,
  auth_ms bigint NOT NULL CHECK (auth_ms > 0),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  used_ms bigint,
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 300000),
  PRIMARY KEY (tenant_id, realm_id, ticket_hash),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

CREATE FUNCTION access.identity_combine_ticket_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.used_ms IS NOT NULL OR NEW.used_ms IS NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.ticket_hash, NEW.subject_id, NEW.auth_ms, NEW.created_ms,
         NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.ticket_hash, OLD.subject_id, OLD.auth_ms,
                          OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'identity_combine_tickets: a ticket is spent once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_combine_ticket_transition BEFORE UPDATE OR DELETE ON access.identity_combine_tickets
  FOR EACH ROW EXECUTE FUNCTION access.identity_combine_ticket_transition();

-- TN-67, INV-39, OP-153 m.3 (m): a combination, written before anything moves; the snapshot is
-- what each account held (opaque ids and counts, no identifier values) and its digest
CREATE TABLE access.identity_combinations (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  combination_id uuid NOT NULL DEFAULT uuidv7(),
  survivor_id uuid NOT NULL,
  absorbed_id uuid NOT NULL,
  snapshot jsonb NOT NULL CHECK (octet_length(snapshot::text) <= 65536),
  snapshot_digest bytea NOT NULL CHECK (octet_length(snapshot_digest) = 32),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  CHECK (survivor_id <> absorbed_id),
  PRIMARY KEY (tenant_id, realm_id, combination_id),
  FOREIGN KEY (tenant_id, realm_id, survivor_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, absorbed_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX identity_combinations_absorbed
  ON access.identity_combinations (tenant_id, realm_id, absorbed_id);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_social_providers', 'identity_federated', 'identity_social_attempts',
                           'identity_combine_tickets', 'identity_combinations'] LOOP
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

CREATE TRIGGER no_delete BEFORE DELETE ON access.idp_social_providers
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.identity_combinations
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.identity_federated_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.identity_social_attempt_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.identity_combine_ticket_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_social_providers, access.identity_federated,
  access.identity_social_attempts, access.identity_combine_tickets,
  access.identity_combinations TO access_app;
GRANT UPDATE (client_id, client_secret_ref, status, previous_client_id, client_changed_ms,
  domain_id, decision_pos) ON access.idp_social_providers TO access_app;
GRANT UPDATE (verified_ms, ended_ms, end_reason) ON access.identity_federated TO access_app;
GRANT UPDATE (status, used_ms) ON access.identity_social_attempts TO access_app;
GRANT UPDATE (used_ms) ON access.identity_combine_tickets TO access_app;

RESET ROLE;
