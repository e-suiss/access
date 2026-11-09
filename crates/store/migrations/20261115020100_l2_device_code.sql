-- OP-154 m.3 (p), RFC 8628, TN-35, CR-38, CR-39: the device authorization grant, off by default.
-- A setting version is written only under a committed idp.realm.device_code or
-- device_code_close ALLOW. A device authorization keeps only the SHA-256 of its device_code and
-- of its user_code; it is approved or declined once by a signed-in person and redeemed once.
-- Wrong user codes are counted per IP prefix and per person for the entry limits. Nothing is
-- deleted (OP-73): rows end and are archived by retention.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_device_code_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_device_code_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.device_code',
                                                 'idp.realm.device_code_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_device_code_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- RFC 8628 §3.1-3.5, CR-38: one device authorization
CREATE TABLE access.oauth_device_codes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  device_id uuid NOT NULL DEFAULT uuidv7(),
  device_hash bytea NOT NULL CHECK (octet_length(device_hash) = 32),
  user_hash bytea NOT NULL CHECK (octet_length(user_hash) = 32),
  client_uuid uuid NOT NULL,
  scope text NOT NULL CHECK (length(scope) <= 2048),
  ip_prefix text NOT NULL CHECK (length(ip_prefix) BETWEEN 1 AND 64),
  country text CHECK (country ~ '^[A-Z]{2}$'),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  interval_s integer NOT NULL CHECK (interval_s BETWEEN 5 AND 600),
  polled_ms bigint,
  decision text CHECK (decision IN ('approved', 'denied')),
  decided_ms bigint,
  subject_id uuid,
  session_id uuid,
  used_ms bigint,
  CHECK ((decision IS NULL) = (decided_ms IS NULL)),
  CHECK ((decision = 'approved') = (subject_id IS NOT NULL AND session_id IS NOT NULL)),
  CHECK (used_ms IS NULL OR decision = 'approved'),
  PRIMARY KEY (tenant_id, realm_id, device_id),
  UNIQUE (tenant_id, realm_id, device_hash),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id, client_uuid)
    REFERENCES access.idp_clients (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX oauth_device_codes_user_live ON access.oauth_device_codes
  (tenant_id, realm_id, user_hash) WHERE decision IS NULL;

CREATE FUNCTION access.oauth_device_code_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.used_ms IS NOT NULL
     OR (OLD.decision IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision)
     OR (NEW.tenant_id, NEW.realm_id, NEW.device_id, NEW.device_hash, NEW.user_hash,
         NEW.client_uuid, NEW.scope, NEW.ip_prefix, NEW.country, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.device_id, OLD.device_hash,
                          OLD.user_hash, OLD.client_uuid, OLD.scope, OLD.ip_prefix, OLD.country,
                          OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'oauth_device_codes: decided once, redeemed once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_device_code_rules BEFORE UPDATE OR DELETE ON access.oauth_device_codes
  FOR EACH ROW EXECUTE FUNCTION access.oauth_device_code_rules();

-- OP-154 m.3 (p), CR-39: a wrong user code, counted per IP prefix and per person
CREATE TABLE access.oauth_device_misses (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  miss_id uuid NOT NULL DEFAULT uuidv7(),
  ip_prefix text NOT NULL CHECK (length(ip_prefix) BETWEEN 1 AND 64),
  subject_id uuid NOT NULL,
  at_ms bigint NOT NULL CHECK (at_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, miss_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE INDEX oauth_device_misses_ip ON access.oauth_device_misses (tenant_id, realm_id, ip_prefix, at_ms);
CREATE INDEX oauth_device_misses_subject ON access.oauth_device_misses (tenant_id, realm_id, subject_id, at_ms);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.oauth_device_misses
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_device_code_settings', 'oauth_device_codes',
                           'oauth_device_misses'] LOOP
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

REVOKE ALL ON FUNCTION access.oauth_device_code_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_device_code_settings, access.oauth_device_codes,
  access.oauth_device_misses TO access_app;
GRANT UPDATE (interval_s, polled_ms, decision, decided_ms, subject_id, session_id, used_ms)
  ON access.oauth_device_codes TO access_app;

RESET ROLE;
