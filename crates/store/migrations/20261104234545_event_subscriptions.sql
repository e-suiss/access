-- OP-149 m.4, m.7, §9.16, MD-13, OP-73: event subscriptions and their delivery queue.
-- A subscription is one stream of one realm with one channel: the Suiss webhook profile, SSF
-- push (RFC 8935) or SSF poll (RFC 8936). It is never deleted: `disabled_at` ends it. The
-- webhook secret is sealed under its own DEK wrapped by the realm KEK; a poll stream's bearer
-- credential is kept only as its digest. A delivery is one event for one subscription, its id
-- the dedup key; the transmitter moves it from `pending` to `delivered`, `acknowledged` or
-- `failed`. Rows hold ids and the unsigned event, no personal data.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.event_subscription (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  channel text NOT NULL CHECK (channel IN ('webhook', 'ssf_push', 'ssf_poll')),
  endpoint text CHECK (endpoint IS NULL OR (endpoint ~ '^https://' AND octet_length(endpoint) <= 2048)),
  audience text NOT NULL CHECK (octet_length(audience) BETWEEN 1 AND 512),
  events text[] NOT NULL,
  description text CHECK (description IS NULL OR octet_length(description) <= 512),
  secret_kek_id text,
  secret_wrapped_dek bytea,
  secret_nonce bytea CHECK (secret_nonce IS NULL OR octet_length(secret_nonce) = 12),
  secret_ciphertext bytea,
  token_digest bytea CHECK (token_digest IS NULL OR octet_length(token_digest) = 32),
  status text NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'paused')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, subscription_id),
  CHECK ((channel = 'ssf_poll') = (endpoint IS NULL)),
  CHECK ((channel = 'webhook') = (secret_ciphertext IS NOT NULL)),
  CHECK ((channel = 'ssf_poll') = (token_digest IS NOT NULL))
);
CREATE UNIQUE INDEX event_subscription_token ON access.event_subscription (tenant_id, realm_id, token_digest)
  WHERE token_digest IS NOT NULL;

CREATE TABLE access.event_delivery (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  channel text NOT NULL CHECK (channel IN ('webhook', 'ssf_push', 'ssf_poll')),
  event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_-]{22,43}$'),
  event_type text NOT NULL CHECK (event_type ~ '^urn:suiss:access:event:[a-z][a-z0-9_.-]{0,63}$'),
  payload bytea NOT NULL,
  occurred_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'delivered', 'acknowledged', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status integer CHECK (last_status BETWEEN 100 AND 599),
  last_reason text CHECK (last_reason IS NULL OR last_reason IN ('rejected', 'refused', 'unreachable', 'receiver')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, subscription_id, event_id),
  FOREIGN KEY (tenant_id, realm_id, subscription_id)
    REFERENCES access.event_subscription (tenant_id, realm_id, subscription_id)
);
CREATE INDEX event_delivery_due ON access.event_delivery (next_attempt_at)
  WHERE state = 'pending' AND channel <> 'ssf_poll';
CREATE INDEX event_delivery_poll ON access.event_delivery (tenant_id, realm_id, subscription_id, created_at)
  WHERE state = 'pending' AND channel = 'ssf_poll';

CREATE TABLE access.event_domain_cursor (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos >= 0),
  idx integer NOT NULL CHECK (idx >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['event_subscription', 'event_delivery', 'event_domain_cursor'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

CREATE POLICY tenant_scope ON access.event_subscription AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY tenant_scope ON access.event_delivery AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY reader_reads ON access.event_delivery AS RESTRICTIVE TO access_outbox_reader
  USING (true) WITH CHECK (false);
CREATE POLICY domain_scope ON access.event_domain_cursor AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));

GRANT SELECT, INSERT, UPDATE ON access.event_subscription, access.event_delivery,
  access.event_domain_cursor TO access_app;
GRANT SELECT ON access.event_delivery TO access_outbox_reader;

RESET ROLE;
