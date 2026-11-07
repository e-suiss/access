-- TN-128, TN-129, OP-151 m.3 (e), (f), m.12 (b): the console BFF's sessions on the management
-- listener. A row holds identifiers only: the cookie as a digest, the realm and subject it
-- signed in with the subject's session epoch then, the account's opaque external id, the network binding and its times, the device
-- Instance the browser registered (public key only) and the one pending registration challenge.
-- A session ends softly (ended_ms), never by DELETE (OP-73); the identity columns never change.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.console_sessions (
  session_id uuid NOT NULL DEFAULT uuidv7(),
  cookie_digest bytea NOT NULL CHECK (octet_length(cookie_digest) = 32),
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  login_session_id uuid NOT NULL,
  session_epoch bigint NOT NULL CHECK (session_epoch >= 0),
  slug text NOT NULL CHECK (char_length(slug) BETWEEN 1 AND 63),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  account text NOT NULL CHECK (char_length(account) BETWEEN 1 AND 128),
  binding bytea NOT NULL CHECK (octet_length(binding) BETWEEN 1 AND 64),
  auth_time_ms bigint NOT NULL CHECK (auth_time_ms > 0),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  last_seen_ms bigint NOT NULL CHECK (last_seen_ms >= created_ms),
  ended_ms bigint,
  end_reason text CHECK (end_reason IN ('signed_out', 'revoked', 'policy')),
  instance_kid bytea CHECK (octet_length(instance_kid) = 32),
  instance_key bytea CHECK (octet_length(instance_key) BETWEEN 1 AND 256),
  pending_challenge bytea CHECK (octet_length(pending_challenge) = 32),
  pending_key bytea CHECK (octet_length(pending_key) BETWEEN 1 AND 256),
  pending_party bytea CHECK (octet_length(pending_party) = 16),
  pending_from_ms bigint,
  pending_until_ms bigint,
  dbsc_key bytea CHECK (octet_length(dbsc_key) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id),
  UNIQUE (cookie_digest),
  CHECK ((ended_ms IS NULL) = (end_reason IS NULL)),
  CHECK ((instance_kid IS NULL) = (instance_key IS NULL)),
  CHECK ((pending_challenge IS NULL) = (pending_key IS NULL)
     AND (pending_challenge IS NULL) = (pending_party IS NULL)
     AND (pending_challenge IS NULL) = (pending_from_ms IS NULL)
     AND (pending_challenge IS NULL) = (pending_until_ms IS NULL))
);
CREATE INDEX console_sessions_subject ON access_ops.console_sessions
  (tenant_id, realm_id, subject_id) WHERE ended_ms IS NULL;

ALTER TABLE access_ops.console_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.console_sessions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.console_sessions FROM PUBLIC;
CREATE POLICY rows ON access_ops.console_sessions AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.console_sessions AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.console_sessions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access_ops.console_sessions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- INV-13: the device Instance is attached once and an ended session stays ended
CREATE FUNCTION access.console_session_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF OLD.instance_kid IS NOT NULL AND NEW.instance_kid IS DISTINCT FROM OLD.instance_kid THEN
    RAISE EXCEPTION 'console session instance is fixed' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.ended_ms IS NOT NULL AND (NEW.ended_ms IS DISTINCT FROM OLD.ended_ms
      OR NEW.end_reason IS DISTINCT FROM OLD.end_reason) THEN
    RAISE EXCEPTION 'console session ended' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER console_session_rules BEFORE UPDATE ON access_ops.console_sessions
  FOR EACH ROW EXECUTE FUNCTION access.console_session_rules();

GRANT SELECT, INSERT ON access_ops.console_sessions TO access_app;
GRANT UPDATE (last_seen_ms, ended_ms, end_reason, instance_kid, instance_key, pending_challenge,
  pending_key, pending_party, pending_from_ms, pending_until_ms)
  ON access_ops.console_sessions TO access_app;

RESET ROLE;
