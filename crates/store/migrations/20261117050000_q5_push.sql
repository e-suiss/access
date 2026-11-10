-- OP-156 m.3 (d), §10.1.3, §10.2.3, IDP-4, TN-100, TN-102: push verification with number matching.
-- An approver is any app that embeds the public SDK's approver module; its app-bound P-256 key is
-- kept here under the §10.1.3 device key schema and makes an authenticator_binding Claim. A push
-- challenge keeps only the SHA-256 of its id (CR-38), the number the sign-in page shows and how it
-- was answered; it lives 120 s, is answered once and completes one flow step once. The realm's
-- push setting is written only under a committed idp.realm.push or push_close ALLOW. Nothing is
-- deleted (OP-73): a key is retired, a challenge ends, both are archived by retention.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_push_settings (
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
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_push_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.push', 'idp.realm.push_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_push_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- §10.1.3: device_id, identity_subject_id, public_key, key_type, algorithm, attested_at, status,
-- created_at, last_seen; hardware_attested and pin_policy belong to the app-controlled factor
-- (OP-156 m.3 (e)).
CREATE TABLE access.identity_device_keys (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  device_id uuid NOT NULL,
  identity_subject_id uuid NOT NULL,
  thumbprint bytea NOT NULL CHECK (octet_length(thumbprint) = 32),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 65 AND get_byte(public_key, 0) = 4),
  key_type text NOT NULL CHECK (key_type = 'EC-P256'),
  algorithm text NOT NULL CHECK (algorithm = 'ES256'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  hardware_attested boolean NOT NULL DEFAULT false,
  pin_policy text CHECK (pin_policy IN ('none', 'app_pin')),
  attested_at timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen timestamptz,
  retired_at timestamptz,
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  CHECK (NOT hardware_attested OR attested_at IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, device_id),
  UNIQUE (tenant_id, realm_id, thumbprint),
  FOREIGN KEY (tenant_id, realm_id, identity_subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_device_keys_subject
  ON access.identity_device_keys (tenant_id, realm_id, identity_subject_id) WHERE status = 'active';

CREATE FUNCTION access.identity_device_key_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF (NEW.tenant_id, NEW.realm_id, NEW.device_id, NEW.identity_subject_id, NEW.thumbprint,
      NEW.public_key, NEW.key_type, NEW.algorithm, NEW.created_at)
     IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.device_id, OLD.identity_subject_id,
                       OLD.thumbprint, OLD.public_key, OLD.key_type, OLD.algorithm, OLD.created_at)
     OR OLD.status = 'retired' THEN
    RAISE EXCEPTION 'device key %: the key and its subject are fixed and a retired key stays retired',
      OLD.device_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_device_key_fixed BEFORE UPDATE ON access.identity_device_keys
  FOR EACH ROW EXECUTE FUNCTION access.identity_device_key_fixed();
CREATE TRIGGER append_only_row BEFORE DELETE ON access.identity_device_keys
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- OP-156 m.3 (d): one push challenge, 120 s, single use
CREATE TABLE access.push_challenges (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  challenge_id uuid NOT NULL DEFAULT uuidv7(),
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  subject_id uuid NOT NULL,
  flow_hash bytea NOT NULL CHECK (octet_length(flow_hash) = 32),
  number smallint NOT NULL CHECK (number BETWEEN 10 AND 99),
  origin_device uuid,
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms = created_ms + 120000),
  decision text CHECK (decision IN ('approve', 'deny', 'not_me', 'wrong_number')),
  decided_ms bigint,
  device_id uuid,
  used_ms bigint,
  CHECK ((decision IS NULL) = (decided_ms IS NULL)),
  CHECK ((decision IS NULL) = (device_id IS NULL)),
  CHECK (used_ms IS NULL OR decision = 'approve'),
  PRIMARY KEY (tenant_id, realm_id, challenge_id),
  UNIQUE (tenant_id, realm_id, challenge_hash),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, origin_device)
    REFERENCES access.identity_device_keys (tenant_id, realm_id, device_id),
  FOREIGN KEY (tenant_id, realm_id, device_id)
    REFERENCES access.identity_device_keys (tenant_id, realm_id, device_id)
);
CREATE INDEX push_challenges_subject ON access.push_challenges (tenant_id, realm_id, subject_id, created_ms);

CREATE FUNCTION access.push_challenge_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.used_ms IS NOT NULL
     OR (OLD.decision IS NOT NULL AND (NEW.decision, NEW.decided_ms, NEW.device_id)
         IS DISTINCT FROM (OLD.decision, OLD.decided_ms, OLD.device_id))
     OR (NEW.tenant_id, NEW.realm_id, NEW.challenge_id, NEW.challenge_hash, NEW.subject_id,
         NEW.flow_hash, NEW.number, NEW.origin_device, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.challenge_id, OLD.challenge_hash,
                          OLD.subject_id, OLD.flow_hash, OLD.number, OLD.origin_device,
                          OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'push_challenges: answered once, used once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER push_challenge_rules BEFORE UPDATE OR DELETE ON access.push_challenges
  FOR EACH ROW EXECUTE FUNCTION access.push_challenge_rules();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_push_settings', 'identity_device_keys', 'push_challenges'] LOOP
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

REVOKE ALL ON FUNCTION access.identity_device_key_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.push_challenge_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_push_settings, access.identity_device_keys,
  access.push_challenges TO access_app;
GRANT UPDATE (name, hardware_attested, pin_policy, attested_at, status, last_seen, retired_at)
  ON access.identity_device_keys TO access_app;
GRANT UPDATE (decision, decided_ms, device_id, used_ms) ON access.push_challenges TO access_app;

RESET ROLE;
