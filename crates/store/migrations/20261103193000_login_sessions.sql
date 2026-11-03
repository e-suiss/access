-- OP-146 m.1 (I5), m.5 (f), m.10 (a); TN-36, TN-37, TN-50, TN-59, TN-64, TN-68, TN-96, TN-102, MD-7, X33,
-- CR-38, OP-73: authentication flows, login sessions, device markers, TOTP replay steps and the passkey registry
SET LOCAL ROLE access_migrator;

-- RFC 6238, §10.2.2: a used TOTP step is never accepted again
ALTER TABLE access.identity_credentials ADD COLUMN otp_last_step bigint CHECK (otp_last_step >= 0);
GRANT UPDATE (otp_last_step) ON access.identity_credentials TO access_app;

-- MD-7, OP-21: the epoch cache polls subjects whose session_epoch moved
ALTER TABLE access.identity_subjects ADD COLUMN session_epoch_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX identity_subjects_epoch_at ON access.identity_subjects (tenant_id, realm_id, session_epoch_at);
GRANT UPDATE (session_epoch_at) ON access.identity_subjects TO access_app;

-- TN-102, OP-146 m.5 (f): flow state is digests and internal ids only; one partition per day
CREATE TABLE access.auth_flows (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  day integer NOT NULL CHECK (day >= 0),
  flow_hash bytea NOT NULL CHECK (octet_length(flow_hash) = 32),
  device_hash bytea NOT NULL CHECK (octet_length(device_hash) = 32),
  resume_hash bytea CHECK (octet_length(resume_hash) = 32),
  version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done', 'abandoned')),
  expires_ms bigint NOT NULL CHECK (expires_ms > 0),
  state bytea NOT NULL CHECK (octet_length(state) <= 16384),
  PRIMARY KEY (tenant_id, realm_id, day, flow_hash)
) PARTITION BY RANGE (day);
CREATE UNIQUE INDEX auth_flows_resume ON access.auth_flows (tenant_id, realm_id, day, resume_hash)
  WHERE resume_hash IS NOT NULL;

CREATE TABLE access.auth_flows_default PARTITION OF access.auth_flows DEFAULT;

CREATE FUNCTION access.auth_flow_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'auth_flows: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status <> 'open' THEN
    RAISE EXCEPTION 'auth_flows: a finished flow never changes' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'auth_flows: every change takes the next version' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION access.secure_auth_flow_partition(t regclass) RETURNS void
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', t);
  EXECUTE format('REVOKE ALL ON %s FROM PUBLIC', t);
  EXECUTE format('CREATE POLICY rows ON %s AS PERMISSIVE USING (true)', t);
  EXECUTE format('CREATE POLICY tenant_scope ON %s AS RESTRICTIVE TO access_app '
                 'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                 'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
  EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON %s '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
END
$$;

SELECT access.secure_auth_flow_partition('access.auth_flows');
SELECT access.secure_auth_flow_partition('access.auth_flows_default');
-- cloned onto every partition
CREATE TRIGGER auth_flow_rules BEFORE UPDATE OR DELETE ON access.auth_flows
  FOR EACH ROW EXECUTE FUNCTION access.auth_flow_rules();

-- OP-146 m.5 (f): the archive role opens each day ahead
CREATE FUNCTION access.open_auth_flow_day(d integer) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  name text := format('auth_flows_d%s', d);
BEGIN
  IF d < 0 THEN
    RAISE EXCEPTION 'negative day' USING ERRCODE = 'check_violation';
  END IF;
  IF to_regclass(format('access.%I', name)) IS NOT NULL THEN
    RETURN name;
  END IF;
  EXECUTE format('CREATE TABLE access.%I PARTITION OF access.auth_flows FOR VALUES FROM (%s) TO (%s)',
                 name, d, d + 1);
  PERFORM access.secure_auth_flow_partition(format('access.%I', name)::regclass);
  RETURN name;
END
$$;

REVOKE ALL ON FUNCTION access.auth_flow_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.secure_auth_flow_partition(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.open_auth_flow_day(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.open_auth_flow_day(integer) TO access_archive;
GRANT SELECT, INSERT ON access.auth_flows TO access_app;
GRANT UPDATE (version, status, state, resume_hash) ON access.auth_flows TO access_app;

-- TN-36, CR-38: the cookie carries an opaque value; only its digest is stored. A session dies with
-- its subject's session_epoch (TN-50, MD-7) and is ended, never deleted (OP-73).
CREATE TABLE access.login_sessions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  session_id uuid NOT NULL DEFAULT uuidv7(),
  cookie_hash bytea NOT NULL CHECK (octet_length(cookie_hash) = 32),
  subject_id uuid NOT NULL,
  session_epoch bigint NOT NULL CHECK (session_epoch >= 0),
  keep_signed_in boolean NOT NULL,
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  auth_time_ms bigint NOT NULL CHECK (auth_time_ms > 0),
  last_seen_ms bigint NOT NULL CHECK (last_seen_ms > 0),
  idle_ms bigint NOT NULL CHECK (idle_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  assurance bytea NOT NULL CHECK (octet_length(assurance) <= 4096),
  ended_ms bigint,
  end_reason text CHECK (end_reason IN ('logout', 'epoch', 'admin')),
  CHECK ((ended_ms IS NULL) = (end_reason IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, session_id),
  UNIQUE (tenant_id, realm_id, cookie_hash),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX login_sessions_live ON access.login_sessions (tenant_id, realm_id, subject_id)
  WHERE ended_ms IS NULL;

CREATE FUNCTION access.login_session_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'login_sessions: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.ended_ms IS NOT NULL AND (NEW.ended_ms IS DISTINCT FROM OLD.ended_ms
       OR NEW.session_epoch IS DISTINCT FROM OLD.session_epoch) THEN
    RAISE EXCEPTION 'login_sessions: an ended session stays ended' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.session_epoch < OLD.session_epoch THEN
    RAISE EXCEPTION 'login_sessions: session_epoch only grows' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER login_session_rules BEFORE UPDATE OR DELETE ON access.login_sessions
  FOR EACH ROW EXECUTE FUNCTION access.login_session_rules();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.login_sessions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- X33: "don't ask for a second step on this device for 30 days"; a device-bound marker that dies
-- with the subject's session_epoch
CREATE TABLE access.device_markers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  marker_hash bytea NOT NULL CHECK (octet_length(marker_hash) = 32),
  subject_id uuid NOT NULL,
  session_epoch bigint NOT NULL CHECK (session_epoch >= 0),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  revoked_ms bigint,
  PRIMARY KEY (tenant_id, realm_id, marker_hash),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

-- §12.3.6 invariant 10, TN-17: the 64-byte WebAuthn user.id of a subject, random and never derived
CREATE TABLE access.webauthn_users (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  user_handle bytea NOT NULL CHECK (octet_length(user_handle) = 64),
  PRIMARY KEY (tenant_id, realm_id, subject_id),
  UNIQUE (tenant_id, realm_id, user_handle),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.webauthn_users
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.webauthn_users
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- CMP-15.7, OP-146 m.9, TN-68: realm-scoped public material of a passkey. Each row has a sibling
-- `identity_credentials` row of kind `webauthn` that carries the method's life cycle, so the
-- last-method rule covers passkeys. A credential ID stays taken after a soft delete (OP-73).
CREATE TABLE access.webauthn_credentials (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  raw_id bytea NOT NULL CHECK (octet_length(raw_id) BETWEEN 1 AND 1023),
  credential_id uuid NOT NULL,
  user_handle bytea NOT NULL CHECK (octet_length(user_handle) = 64),
  public_key bytea NOT NULL CHECK (octet_length(public_key) <= 2048),
  alg integer NOT NULL,
  sign_count bigint NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
  backup_eligible boolean NOT NULL,
  backup_state boolean NOT NULL,
  user_verified boolean NOT NULL,
  aaguid bytea NOT NULL CHECK (octet_length(aaguid) = 16),
  transports text[] NOT NULL CHECK (cardinality(transports) <= 8),
  attestation text NOT NULL CHECK (attestation IN ('none', 'verified') OR attestation ~ '^unverified:[A-Za-z0-9_.-]{1,32}$'),
  cred_protect smallint CHECK (cred_protect BETWEEN 1 AND 3),
  discoverable boolean,
  prf_enabled boolean,
  prf_first bytea CHECK (octet_length(prf_first) = 32),
  prf_second bytea CHECK (octet_length(prf_second) = 32),
  created_s bigint NOT NULL CHECK (created_s >= 0),
  last_used_s bigint,
  deleted_s bigint,
  PRIMARY KEY (tenant_id, realm_id, raw_id),
  UNIQUE (tenant_id, realm_id, credential_id),
  FOREIGN KEY (tenant_id, realm_id, credential_id)
    REFERENCES access.identity_credentials (tenant_id, realm_id, credential_id),
  FOREIGN KEY (tenant_id, realm_id, user_handle)
    REFERENCES access.webauthn_users (tenant_id, realm_id, user_handle)
);
CREATE INDEX webauthn_credentials_user ON access.webauthn_credentials (tenant_id, realm_id, user_handle)
  WHERE deleted_s IS NULL;

CREATE FUNCTION access.webauthn_credential_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'webauthn_credentials: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.deleted_s IS NOT NULL THEN
    RAISE EXCEPTION 'webauthn_credentials: a deleted credential never changes' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- IDI-5: BE never changes; the key and the owner are fixed
  IF NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.user_handle IS DISTINCT FROM OLD.user_handle OR NEW.credential_id IS DISTINCT FROM OLD.credential_id THEN
    RAISE EXCEPTION 'webauthn_credentials: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER webauthn_credential_rules BEFORE UPDATE OR DELETE ON access.webauthn_credentials
  FOR EACH ROW EXECUTE FUNCTION access.webauthn_credential_rules();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.webauthn_credentials
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE FUNCTION access.device_marker_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'device_markers: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.revoked_ms IS NOT NULL THEN
    RAISE EXCEPTION 'device_markers: a revoked marker stays revoked' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER device_marker_rules BEFORE UPDATE OR DELETE ON access.device_markers
  FOR EACH ROW EXECUTE FUNCTION access.device_marker_rules();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.device_markers
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['login_sessions', 'device_markers', 'webauthn_users', 'webauthn_credentials'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.login_session_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.webauthn_credential_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.device_marker_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.login_sessions, access.device_markers, access.webauthn_users,
  access.webauthn_credentials TO access_app;
GRANT UPDATE (session_epoch, last_seen_ms, auth_time_ms, assurance, ended_ms, end_reason)
  ON access.login_sessions TO access_app;
GRANT UPDATE (revoked_ms) ON access.device_markers TO access_app;
GRANT UPDATE (sign_count, backup_state, last_used_s, prf_enabled, prf_first, prf_second, deleted_s)
  ON access.webauthn_credentials TO access_app;

RESET ROLE;
