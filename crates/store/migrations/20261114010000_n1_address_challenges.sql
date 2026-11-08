-- OP-153 m.3 (g), (i); TN-64, TN-66, TN-69, TN-76, TN-80: proving control of an e-mail address
-- before it means anything. A self-service registration creates no account row until its code
-- returns (TN-80 invariant 1); an e-mail change takes effect only when the new address answers.
-- Each challenge has its own DEK under the realm KEK: the address it names and the code message
-- Relay delivers are sealed under it, and it is shredded when the challenge ends. Nothing here
-- is ever deleted (OP-73): a challenge ends once, softly, as completed, expired or failed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_address_challenges (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  challenge_id uuid NOT NULL DEFAULT uuidv7(),
  purpose text NOT NULL CHECK (purpose IN ('registration', 'email_change')),
  flow_hash bytea NOT NULL CHECK (octet_length(flow_hash) = 32),
  device_hash bytea NOT NULL CHECK (octet_length(device_hash) = 32),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  wrapped_dek bytea,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  -- pii:contact
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) <= 4096),
  -- pii:none
  address_index bytea NOT NULL CHECK (octet_length(address_index) = 32),
  -- pii:none
  canonical_index bytea NOT NULL CHECK (octet_length(canonical_index) = 32),
  code_digest bytea CHECK (code_digest IS NULL OR octet_length(code_digest) = 32),
  attempts_left smallint NOT NULL CHECK (attempts_left BETWEEN 0 AND 5),
  step_up boolean NOT NULL,
  score smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
  subject_id uuid,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed', 'expired', 'failed')),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  ended_ms bigint,
  shredded_at timestamptz,
  CHECK ((status = 'open') = (ended_ms IS NULL)),
  CHECK ((shredded_at IS NULL) = (wrapped_dek IS NOT NULL)),
  CHECK (shredded_at IS NULL OR status <> 'open'),
  CHECK (purpose = 'registration' OR subject_id IS NOT NULL),
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 900000),
  PRIMARY KEY (tenant_id, realm_id, challenge_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX identity_address_challenges_flow
  ON access.identity_address_challenges (tenant_id, realm_id, flow_hash);
CREATE INDEX identity_address_challenges_open
  ON access.identity_address_challenges (tenant_id, realm_id, expires_ms) WHERE status = 'open';

CREATE FUNCTION access.address_challenge_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_address_challenges: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.realm_id, NEW.challenge_id, NEW.purpose, NEW.flow_hash, NEW.device_hash,
      NEW.kek_id, NEW.nonce, NEW.ciphertext, NEW.address_index, NEW.canonical_index, NEW.code_digest,
      NEW.step_up, NEW.score, NEW.created_ms, NEW.expires_ms)
     IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.challenge_id, OLD.purpose, OLD.flow_hash,
                       OLD.device_hash, OLD.kek_id, OLD.nonce, OLD.ciphertext, OLD.address_index,
                       OLD.canonical_index, OLD.code_digest, OLD.step_up, OLD.score, OLD.created_ms,
                       OLD.expires_ms)
     OR NEW.attempts_left > OLD.attempts_left
     OR (OLD.status <> 'open' AND (NEW.status, NEW.ended_ms, NEW.subject_id, NEW.attempts_left)
                                  IS DISTINCT FROM (OLD.status, OLD.ended_ms, OLD.subject_id, OLD.attempts_left))
     OR (OLD.subject_id IS NOT NULL AND NEW.subject_id IS DISTINCT FROM OLD.subject_id)
     OR (OLD.shredded_at IS NOT NULL AND (NEW.wrapped_dek, NEW.shredded_at) IS DISTINCT FROM (OLD.wrapped_dek, OLD.shredded_at)) THEN
    RAISE EXCEPTION 'identity_address_challenges: a challenge only loses attempts, ends once and is shredded once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER address_challenge_transition BEFORE UPDATE OR DELETE ON access.identity_address_challenges
  FOR EACH ROW EXECUTE FUNCTION access.address_challenge_transition();

-- TN-66, TN-69, OP-153 m.3 (i): since when the account has owned each e-mail address it holds,
-- the time its control was proven; Relay mail carries it as RFC 7293 Require-Recipient-Valid-Since
CREATE TABLE access.identity_mailboxes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  identifier_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  owner_since_ms bigint NOT NULL CHECK (owner_since_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, identifier_id),
  FOREIGN KEY (tenant_id, realm_id, identifier_id)
    REFERENCES access.identity_identifiers (tenant_id, realm_id, identifier_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

-- TN-76 m.3, m.5, OP-153 m.3 (i): an identifier an account gave up stays taken by its keyed blind
-- index; a realm that keeps addresses for N days (N >= 365) frees it at `reusable_ms`
CREATE TABLE access.identity_identifier_tombstones (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  tombstone_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  value_index bytea NOT NULL CHECK (octet_length(value_index) = 32),
  subject_id uuid NOT NULL,
  retired_ms bigint NOT NULL CHECK (retired_ms > 0),
  reusable_ms bigint,
  CHECK (reusable_ms IS NULL OR reusable_ms >= retired_ms + 31536000000),
  PRIMARY KEY (tenant_id, realm_id, tombstone_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_identifier_tombstones_index
  ON access.identity_identifier_tombstones (tenant_id, realm_id, value_index);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['identity_address_challenges', 'identity_mailboxes',
                           'identity_identifier_tombstones'] LOOP
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

CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.identity_mailboxes
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.identity_identifier_tombstones
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.address_challenge_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_address_challenges, access.identity_mailboxes,
  access.identity_identifier_tombstones TO access_app;
GRANT UPDATE (attempts_left, subject_id, status, ended_ms, wrapped_dek, shredded_at)
  ON access.identity_address_challenges TO access_app;

RESET ROLE;
