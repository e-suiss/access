-- OP-151 m.3 (k), (l); TN-39…TN-43; §9.16; E30; OP-73.
-- (a) A stream's SSF profile: whether Access events go with or instead of their CAEP
--     counterparts, and the SET signing algorithm it asked for. A stream without a row is
--     `both` and signs with the realm's algorithm.
-- (b) The CAEP and RISC event types join the delivery queue.
-- (c) Inbound transmitters a realm takes SETs from, as `idp.upstream.register` declares them,
--     with their delay state; the SETs taken, by `jti`, for replay; and the link from an upstream
--     subject digest H(iss, sub) to the realm's subject, written by the federation adapter.
-- (d) Receiver acknowledgements beside delivery: semantic and authority-state acks.
-- Rows hold ids, digests and closed codes, no personal data; nothing is deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.event_subscription_ssf (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  profile text NOT NULL DEFAULT 'both' CHECK (profile IN ('access', 'caep', 'both')),
  alg text NOT NULL CHECK (alg IN ('ES256', 'Ed25519')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, subscription_id),
  FOREIGN KEY (tenant_id, realm_id, subscription_id)
    REFERENCES access.event_subscription (tenant_id, realm_id, subscription_id)
);

ALTER TABLE access.event_delivery DROP CONSTRAINT event_delivery_event_type_check;
ALTER TABLE access.event_delivery ADD CONSTRAINT event_delivery_event_type_check
  CHECK (event_type ~ '^urn:suiss:access:event:[a-z][a-z0-9_.-]{0,63}$'
         OR event_type = 'https://schemas.openid.net/secevent/ssf/event-type/verification'
         OR event_type ~ '^https://schemas\.openid\.net/secevent/(caep|risc)/event-type/[a-z][a-z-]{0,63}$');

CREATE TABLE access.ssf_transmitter (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  transmitter_id uuid NOT NULL,
  issuer text NOT NULL CHECK (issuer ~ '^https://' AND octet_length(issuer) <= 2048),
  jwks_uri text NOT NULL CHECK (jwks_uri ~ '^https://' AND octet_length(jwks_uri) <= 2048),
  audience text NOT NULL CHECK (octet_length(audience) BETWEEN 1 AND 512),
  events text[] NOT NULL,
  delivery text NOT NULL CHECK (delivery IN ('push', 'poll')),
  poll_endpoint text CHECK (poll_endpoint IS NULL OR (poll_endpoint ~ '^https://' AND octet_length(poll_endpoint) <= 2048)),
  secret_kek_id text,
  secret_wrapped_dek bytea,
  secret_nonce bytea CHECK (secret_nonce IS NULL OR octet_length(secret_nonce) = 12),
  secret_ciphertext bytea,
  expected_interval_s integer NOT NULL CHECK (expected_interval_s BETWEEN 60 AND 2592000),
  exercise bytea CHECK (exercise IS NULL OR octet_length(exercise) = 32),
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, transmitter_id),
  CHECK ((delivery = 'poll') = (poll_endpoint IS NOT NULL)),
  CHECK ((delivery = 'poll') = (secret_ciphertext IS NOT NULL))
);
CREATE UNIQUE INDEX ssf_transmitter_issuer ON access.ssf_transmitter (tenant_id, realm_id, issuer)
  WHERE disabled_at IS NULL;

CREATE TABLE access.ssf_inbound_set (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  transmitter_id uuid NOT NULL,
  jti_digest bytea NOT NULL CHECK (octet_length(jti_digest) = 32),
  event_type text NOT NULL CHECK (octet_length(event_type) <= 256),
  outcome text NOT NULL CHECK (outcome IN ('applied', 'ignored')),
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, transmitter_id, jti_digest),
  FOREIGN KEY (tenant_id, realm_id, transmitter_id)
    REFERENCES access.ssf_transmitter (tenant_id, realm_id, transmitter_id)
);

CREATE TABLE access.upstream_subject (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
  subject_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, subject_digest),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

CREATE TABLE access.event_ack (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_-]{22,43}$'),
  kind text NOT NULL CHECK (kind IN ('semantic', 'authority_state')),
  state text NOT NULL CHECK (state IN ('applied', 'ignored', 'current')),
  acked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, subscription_id, event_id, kind),
  FOREIGN KEY (tenant_id, realm_id, subscription_id)
    REFERENCES access.event_subscription (tenant_id, realm_id, subscription_id),
  CHECK ((kind = 'semantic') = (state IN ('applied', 'ignored')))
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['event_subscription_ssf', 'ssf_transmitter', 'ssf_inbound_set',
                           'upstream_subject', 'event_ack'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON access.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
