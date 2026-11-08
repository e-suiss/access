-- OP-153 m.3 (t), (y); TN-33, TN-36, TN-50, TN-106, IDP-22, IDP-36, X36: lane N5. Why a sign-in
-- ended is a closed list the signed-out page reads ("Signed out because …"); a session can be tied
-- to one device key once (DBSC), after which only a short-lived bound cookie refreshed with a proof
-- from that key carries it; CSP violation reports of the hosted pages are kept pseudonymous for
-- 30 days. Nothing is deleted (OP-73): a session ends once, a binding is written once, a report
-- row only grows and lapses by its end time.
SET LOCAL ROLE access_migrator;

-- OP-153 m.3 (y): password changed, device mismatch, ended by an administrator or by the person
-- from another device, recovery; 'logout' and 'epoch' stay as before
ALTER TABLE access.login_sessions DROP CONSTRAINT login_sessions_end_reason_check;
ALTER TABLE access.login_sessions ADD CONSTRAINT login_sessions_end_reason_check
  CHECK (end_reason IN ('logout', 'epoch', 'admin', 'password', 'device', 'recovery', 'ended'))
  NOT VALID;
ALTER TABLE access.login_sessions VALIDATE CONSTRAINT login_sessions_end_reason_check;

-- TN-33, OP-153 m.3 (y): the DBSC key (uncompressed P-256 point), the pending challenge's digest
-- and the bound cookie's digest; the key is set once and never replaced
ALTER TABLE access.login_sessions
  ADD COLUMN dbsc_key bytea CHECK (octet_length(dbsc_key) = 65),
  ADD COLUMN dbsc_bound_ms bigint CHECK (dbsc_bound_ms > 0),
  ADD COLUMN dbsc_challenge bytea CHECK (octet_length(dbsc_challenge) = 32),
  ADD COLUMN dbsc_challenge_expires_ms bigint CHECK (dbsc_challenge_expires_ms > 0),
  ADD COLUMN dbsc_cookie_hash bytea CHECK (octet_length(dbsc_cookie_hash) = 32),
  ADD COLUMN dbsc_cookie_expires_ms bigint CHECK (dbsc_cookie_expires_ms > 0),
  ADD CONSTRAINT login_sessions_dbsc_bound CHECK ((dbsc_key IS NULL) = (dbsc_bound_ms IS NULL))
    NOT VALID;
ALTER TABLE access.login_sessions VALIDATE CONSTRAINT login_sessions_dbsc_bound;

CREATE FUNCTION access.login_session_dbsc_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF OLD.dbsc_key IS NOT NULL AND (NEW.dbsc_key IS DISTINCT FROM OLD.dbsc_key
       OR NEW.dbsc_bound_ms IS DISTINCT FROM OLD.dbsc_bound_ms) THEN
    RAISE EXCEPTION 'login_sessions: a session is tied to one device key, once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER login_session_dbsc_rules BEFORE UPDATE ON access.login_sessions
  FOR EACH ROW EXECUTE FUNCTION access.login_session_dbsc_rules();
REVOKE ALL ON FUNCTION access.login_session_dbsc_rules() FROM PUBLIC;

GRANT UPDATE (dbsc_key, dbsc_bound_ms, dbsc_challenge, dbsc_challenge_expires_ms,
  dbsc_cookie_hash, dbsc_cookie_expires_ms) ON access.login_sessions TO access_app;

-- OP-153 m.3 (t), IDP-36: a CSP report of a hosted page: the violated directive, the blocked
-- origin (never a full URL), the page path and the reporting address's keyed pseudonym; at most
-- 100 a minute per realm, kept until expires_ms (30 days)
CREATE TABLE access.csp_reports (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  report_id uuid NOT NULL DEFAULT uuidv7(),
  received_ms bigint NOT NULL CHECK (received_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > received_ms),
  disposition text NOT NULL CHECK (disposition IN ('enforce', 'report')),
  directive text NOT NULL CHECK (directive ~ '^[a-z-]{1,40}$'),
  blocked text NOT NULL CHECK (octet_length(blocked) <= 256),
  page_path text NOT NULL CHECK (octet_length(page_path) <= 256),
  source_pseudonym bytea NOT NULL CHECK (octet_length(source_pseudonym) = 32),
  PRIMARY KEY (tenant_id, realm_id, report_id)
);
CREATE INDEX csp_reports_recent ON access.csp_reports (tenant_id, realm_id, received_ms);

ALTER TABLE access.csp_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.csp_reports FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.csp_reports FROM PUBLIC;
CREATE POLICY rows ON access.csp_reports AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.csp_reports AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_update BEFORE UPDATE ON access.csp_reports
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.csp_reports
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.csp_reports
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.csp_reports TO access_app;

RESET ROLE;
