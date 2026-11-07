-- TN-135, TN-136, OP-151 m.3 (i), (j), MD-14, EI-25, OP-73: inline hook and webhook
-- registrations are realm configuration, written only against a committed ALLOW of their idp.*
-- action. Nothing is deleted: a registration ends `retired`, a delivery ends in a final state, an
-- attempt row is never changed. Signing keys are sealed under their own DEK wrapped by the realm
-- KEK; only an Ed25519 public key is kept in clear. Deliveries hold the unsigned event (ids only)
-- and their attempts hold status and latency, never a request or response body.
SET LOCAL ROLE access_migrator;

-- TN-135, OP-151 m.3 (j): one live hook per call point; a URL change is a new registration
CREATE TABLE access.idp_hooks (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  hook_id uuid NOT NULL,
  point text NOT NULL CHECK (point IN ('pre_registration', 'token_issuance', 'post_login')),
  url text NOT NULL CHECK (url ~ '^https://' AND octet_length(url) <= 2048),
  on_no_answer text NOT NULL DEFAULT 'refuse'
    CHECK (on_no_answer IN ('refuse', 'continue_without_claims')),
  disclose text[] NOT NULL DEFAULT '{}' CHECK (disclose <@ ARRAY['email']::text[]),
  signing text NOT NULL CHECK (signing IN ('ed25519', 'hmac')),
  key_kek_id text NOT NULL,
  key_wrapped_dek bytea NOT NULL,
  key_nonce bytea NOT NULL CHECK (octet_length(key_nonce) = 12),
  key_ciphertext bytea NOT NULL,
  public_key bytea CHECK (public_key IS NULL OR octet_length(public_key) = 32),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  retired_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  CHECK (on_no_answer = 'refuse' OR point = 'token_issuance'),
  CHECK ((signing = 'ed25519') = (public_key IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, hook_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE UNIQUE INDEX idp_hooks_live_point ON access.idp_hooks (tenant_id, realm_id, point)
  WHERE status = 'active';

-- TN-136, OP-151 m.3 (i): webhook registrations
CREATE TABLE access.idp_webhooks (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  webhook_id uuid NOT NULL,
  url text NOT NULL CHECK (url ~ '^https://' AND octet_length(url) <= 2048),
  events text[] NOT NULL CHECK (cardinality(events) BETWEEN 1 AND 64),
  signing text NOT NULL CHECK (signing IN ('ed25519', 'hmac')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  retired_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, webhook_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- TN-136: a webhook's signing keys; a rotation keeps the old key valid until `not_after`
CREATE TABLE access.idp_webhook_keys (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  webhook_id uuid NOT NULL,
  key_id uuid NOT NULL,
  signing text NOT NULL CHECK (signing IN ('ed25519', 'hmac')),
  key_kek_id text NOT NULL,
  key_wrapped_dek bytea NOT NULL,
  key_nonce bytea NOT NULL CHECK (octet_length(key_nonce) = 12),
  key_ciphertext bytea NOT NULL,
  public_key bytea CHECK (public_key IS NULL OR octet_length(public_key) = 32),
  not_after timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((signing = 'ed25519') = (public_key IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, webhook_id, key_id),
  FOREIGN KEY (tenant_id, realm_id, webhook_id)
    REFERENCES access.idp_webhooks (tenant_id, realm_id, webhook_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- TN-136, TI-7: one event for one webhook, its id the dedup key and `webhook-id`
CREATE TABLE access.idp_webhook_deliveries (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  webhook_id uuid NOT NULL,
  event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9_-]{22,43}$'),
  event_type text NOT NULL CHECK (event_type ~ '^urn:suiss:access:event:[a-z][a-z0-9_.-]{0,63}$'),
  payload bytea NOT NULL,
  occurred_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'exhausted', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status integer CHECK (last_status BETWEEN 100 AND 599),
  last_latency_ms integer CHECK (last_latency_ms >= 0),
  last_reason text CHECK (last_reason IS NULL OR last_reason IN ('status', 'unreachable', 'refused', 'retired', 'unsigned')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, webhook_id, event_id),
  FOREIGN KEY (tenant_id, realm_id, webhook_id)
    REFERENCES access.idp_webhooks (tenant_id, realm_id, webhook_id)
);
CREATE INDEX idp_webhook_deliveries_due ON access.idp_webhook_deliveries (next_attempt_at)
  WHERE state = 'pending';

-- TN-136: the delivery log, one row per attempt, append-only
CREATE TABLE access.idp_webhook_attempts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  webhook_id uuid NOT NULL,
  event_id text NOT NULL,
  attempt integer NOT NULL CHECK (attempt >= 1),
  outcome text NOT NULL CHECK (outcome IN ('delivered', 'retry', 'exhausted', 'failed')),
  status integer CHECK (status BETWEEN 100 AND 599),
  latency_ms integer CHECK (latency_ms >= 0),
  reason text CHECK (reason IS NULL OR reason IN ('status', 'unreachable', 'refused', 'retired', 'unsigned')),
  attempted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, webhook_id, event_id, attempt),
  FOREIGN KEY (tenant_id, realm_id, webhook_id, event_id)
    REFERENCES access.idp_webhook_deliveries (tenant_id, realm_id, webhook_id, event_id)
);

-- EI-25: the registration's fixed columns never change; only its status and, for a webhook, its
-- url, events and keys move, each against its own decision
CREATE FUNCTION access.idp_hook_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.hook_id IS DISTINCT FROM OLD.hook_id OR NEW.point IS DISTINCT FROM OLD.point
     OR NEW.url IS DISTINCT FROM OLD.url OR NEW.on_no_answer IS DISTINCT FROM OLD.on_no_answer
     OR NEW.disclose IS DISTINCT FROM OLD.disclose OR NEW.signing IS DISTINCT FROM OLD.signing
     OR NEW.key_ciphertext IS DISTINCT FROM OLD.key_ciphertext OR OLD.status = 'retired' THEN
    RAISE EXCEPTION 'hook %: a registration is fixed and a retired one stays retired', OLD.hook_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION access.idp_webhook_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.webhook_id IS DISTINCT FROM OLD.webhook_id OR NEW.signing IS DISTINCT FROM OLD.signing
     OR OLD.status = 'retired' THEN
    RAISE EXCEPTION 'webhook %: the id and signing are fixed and a retired webhook stays retired', OLD.webhook_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION access.idp_webhook_key_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.key_id IS DISTINCT FROM OLD.key_id OR NEW.key_ciphertext IS DISTINCT FROM OLD.key_ciphertext
     OR NEW.public_key IS DISTINCT FROM OLD.public_key OR OLD.not_after IS NOT NULL THEN
    RAISE EXCEPTION 'webhook key %: a key is fixed and only ever gets one end', OLD.key_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_hooks
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.hook.register');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_hooks
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.hook.retire');
CREATE TRIGGER idp_hook_fixed BEFORE UPDATE ON access.idp_hooks
  FOR EACH ROW EXECUTE FUNCTION access.idp_hook_fixed();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_webhooks
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.webhook.register');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_webhooks
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.webhook.update', 'idp.webhook.retire');
CREATE TRIGGER idp_webhook_fixed BEFORE UPDATE ON access.idp_webhooks
  FOR EACH ROW EXECUTE FUNCTION access.idp_webhook_fixed();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_webhook_keys
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.webhook.register', 'idp.webhook.update');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_webhook_keys
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.webhook.update', 'idp.webhook.retire');
CREATE TRIGGER idp_webhook_key_fixed BEFORE UPDATE ON access.idp_webhook_keys
  FOR EACH ROW EXECUTE FUNCTION access.idp_webhook_key_fixed();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_hooks', 'idp_webhooks', 'idp_webhook_keys', 'idp_webhook_deliveries',
                           'idp_webhook_attempts'] LOOP
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
  END LOOP;
END
$$;

-- OP-17: an attempt is a record, never rewritten
CREATE TRIGGER append_only_row BEFORE UPDATE ON access.idp_webhook_attempts
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- OP-131: the courier finds due deliveries across tenants and reads nothing else
CREATE POLICY reader_reads ON access.idp_webhook_deliveries AS RESTRICTIVE TO access_outbox_reader
  USING (true) WITH CHECK (false);

REVOKE ALL ON FUNCTION access.idp_hook_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_webhook_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_webhook_key_fixed() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON access.idp_hooks, access.idp_webhooks, access.idp_webhook_keys,
  access.idp_webhook_deliveries TO access_app;
GRANT SELECT, INSERT ON access.idp_webhook_attempts TO access_app;
GRANT SELECT (tenant_id, realm_id, webhook_id, event_id, next_attempt_at, state, created_at)
  ON access.idp_webhook_deliveries TO access_outbox_reader;

RESET ROLE;
