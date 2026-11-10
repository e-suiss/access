-- OP-156 m.3 (e)–(h), MD-11, IDP-3, IDP-4, IDP-9, SA-54: payment-class authentication.
-- The realm's SMS one-time code and Secure Payment Confirmation settings are written only under a
-- committed idp.realm.sms_otp / sms_otp_close / spc ALLOW. An SMS code keeps only its keyed
-- digest; it lives 5 minutes, takes at most 3 tries and is used once. An approver's answer that
-- declares the app PIN is kept beside its push challenge, so the flow can tell an app-controlled
-- factor from a plain push. A SIM change signal is the disclosed body of an admitted `sim_change`
-- Claim, appended after its `claim` record. The breach-range mirror's versions are kept with
-- their state; a replaced version is archived, never removed. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_sms_otp_settings (
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
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_sms_otp_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.sms_otp', 'idp.realm.sms_otp_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_sms_otp_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.idp_spc_settings (
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
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_spc_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.spc');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_spc_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- OP-156 m.3 (f): 6 digits, 5 minutes, 3 tries, single use
CREATE TABLE access.sms_codes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  code_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('sign_in', 'activation')),
  binding bytea NOT NULL CHECK (octet_length(binding) = 32),
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms = created_ms + 300000),
  attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  used_ms bigint,
  CHECK (used_ms IS NULL OR attempts BETWEEN 1 AND 3),
  PRIMARY KEY (tenant_id, realm_id, code_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX sms_codes_binding ON access.sms_codes (tenant_id, realm_id, binding, created_ms);
CREATE INDEX sms_codes_subject ON access.sms_codes (tenant_id, realm_id, subject_id, created_ms);

CREATE FUNCTION access.sms_code_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.used_ms IS NOT NULL OR OLD.attempts >= 3
     OR NEW.attempts <> OLD.attempts + 1
     OR (NEW.tenant_id, NEW.realm_id, NEW.code_id, NEW.subject_id, NEW.purpose, NEW.binding,
         NEW.code_hash, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.code_id, OLD.subject_id, OLD.purpose,
                          OLD.binding, OLD.code_hash, OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'sms_codes: one try at a time, at most three, used once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER sms_code_rules BEFORE UPDATE OR DELETE ON access.sms_codes
  FOR EACH ROW EXECUTE FUNCTION access.sms_code_rules();

-- OP-156 m.3 (e), MD-11: what an approver declared about its app PIN in one answer
CREATE TABLE access.app_factor_answers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  challenge_id uuid NOT NULL,
  device_id uuid NOT NULL,
  pin_verified boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, challenge_id),
  FOREIGN KEY (tenant_id, realm_id, challenge_id)
    REFERENCES access.push_challenges (tenant_id, realm_id, challenge_id),
  FOREIGN KEY (tenant_id, realm_id, device_id)
    REFERENCES access.identity_device_keys (tenant_id, realm_id, device_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.app_factor_answers
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_sms_otp_settings', 'idp_spc_settings', 'sms_codes',
                           'app_factor_answers'] LOOP
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

-- OP-156 m.3 (f), IDP-9, §10.3.4: the last SIM change of a Party's line, from an admitted
-- `sim_change` Claim's disclosed body; the decision reads the newest check
CREATE TABLE access.sim_change_signals (
  domain_id bytea NOT NULL,
  subject_id bytea NOT NULL CHECK (octet_length(subject_id) = 16),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  issuer_id bytea NOT NULL CHECK (octet_length(issuer_id) = 16),
  pos bigint NOT NULL CHECK (pos > 0),
  last_change_ms bigint NOT NULL CHECK (last_change_ms >= 0),
  checked_ms bigint NOT NULL CHECK (checked_ms >= last_change_ms),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, claim_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX sim_change_signals_subject ON access.sim_change_signals (domain_id, subject_id, checked_ms);

ALTER TABLE access.sim_change_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.sim_change_signals FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.sim_change_signals FROM PUBLIC;
CREATE POLICY rows ON access.sim_change_signals AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.sim_change_signals AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.sim_change_signals
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.sim_change_signals
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- OP-156 m.3 (h), IDP-3: one refresh of the breach-range mirror; the directory it fills is made
-- current in one rename and the one it replaces is archived in place
CREATE TABLE access_ops.hibp_mirror_versions (
  version_id uuid PRIMARY KEY DEFAULT uuidv7(),
  directory text NOT NULL CHECK (char_length(directory) BETWEEN 1 AND 4096),
  source_host text NOT NULL CHECK (char_length(source_host) BETWEEN 1 AND 253),
  status text NOT NULL DEFAULT 'staged'
    CHECK (status IN ('staged', 'current', 'archived', 'failed')),
  ranges integer CHECK (ranges >= 0),
  digest bytea CHECK (octet_length(digest) = 32),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  promoted_at timestamptz,
  archived_at timestamptz,
  ended_at timestamptz,
  CHECK ((status = 'current') <= (promoted_at IS NOT NULL AND ranges IS NOT NULL AND digest IS NOT NULL)),
  CHECK ((status = 'archived') = (archived_at IS NOT NULL)),
  CHECK ((status = 'failed') = (ended_at IS NOT NULL))
);
CREATE UNIQUE INDEX hibp_mirror_versions_current ON access_ops.hibp_mirror_versions (directory)
  WHERE status = 'current';

CREATE FUNCTION access.hibp_mirror_version_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR (NEW.version_id, NEW.directory, NEW.source_host, NEW.started_at)
        IS DISTINCT FROM (OLD.version_id, OLD.directory, OLD.source_host, OLD.started_at)
     OR NOT ((OLD.status = 'staged' AND NEW.status IN ('current', 'failed'))
             OR (OLD.status = 'current' AND NEW.status = 'archived'
                 AND (NEW.ranges, NEW.digest, NEW.promoted_at)
                     IS NOT DISTINCT FROM (OLD.ranges, OLD.digest, OLD.promoted_at))) THEN
    RAISE EXCEPTION 'hibp_mirror_versions: staged becomes current or failed, current becomes archived'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER hibp_mirror_version_rules BEFORE UPDATE OR DELETE ON access_ops.hibp_mirror_versions
  FOR EACH ROW EXECUTE FUNCTION access.hibp_mirror_version_rules();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.hibp_mirror_versions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access_ops.hibp_mirror_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.hibp_mirror_versions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.hibp_mirror_versions FROM PUBLIC;
CREATE POLICY rows ON access_ops.hibp_mirror_versions AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.hibp_mirror_versions AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));

REVOKE ALL ON FUNCTION access.sms_code_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.hibp_mirror_version_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_sms_otp_settings, access.idp_spc_settings, access.sms_codes,
  access.app_factor_answers TO access_app;
GRANT UPDATE (attempts, used_ms) ON access.sms_codes TO access_app;
GRANT SELECT, INSERT ON access.sim_change_signals TO access_sequencer;
GRANT SELECT ON access.sim_change_signals TO access_app;
GRANT SELECT, INSERT ON access_ops.hibp_mirror_versions TO access_app;
GRANT UPDATE (status, ranges, digest, promoted_at, archived_at, ended_at)
  ON access_ops.hibp_mirror_versions TO access_app;

RESET ROLE;
