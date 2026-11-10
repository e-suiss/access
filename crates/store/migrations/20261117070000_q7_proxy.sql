-- OP-156 m.3 (l), IDP-30, B22: the forward-auth proxies a realm registered and their browser
-- sessions. A proxy is a PEP named by its transport identity (client certificate or DPoP key
-- thumbprint) for one application host; each row of proxy_registrations is one idp.proxy.*
-- decision and the newest version is the proxy. The router role names the realm of a proxy that
-- asks /proxy/v1/check/{engine}. A proxy session is the __Host-access-proxy cookie on the
-- application host: a sign-in row keeps the digest of its state and its PKCE verifier until the
-- callback takes it once; a session row keeps the digest of the cookie and the OAuth grant it
-- rides on. Nothing is deleted (OP-73): sign-ins are taken, sessions end, retention archives.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.proxy_registrations (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  engine text NOT NULL CHECK (engine IN ('nginx', 'traefik', 'caddy', 'envoy')),
  host text NOT NULL CHECK (length(host) BETWEEN 1 AND 260),
  pep text NOT NULL CHECK (length(pep) = 43),
  body text NOT NULL CHECK (length(body) BETWEEN 2 AND 65536),
  plain_headers boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX proxy_registrations_pep ON access.proxy_registrations (pep, host);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.proxy_registrations
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound(
    'idp.proxy.register', 'idp.proxy.update', 'idp.proxy.retire', 'idp.proxy.plain_headers',
    'idp.proxy.plain_headers_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.proxy_registrations
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.proxy_registrations
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.proxy_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.proxy_registrations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.proxy_registrations FROM PUBLIC;
CREATE POLICY rows ON access.proxy_registrations AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.proxy_registrations AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
-- OP-132 m.3: the router names a proxy's realm and reads nothing else
CREATE POLICY router_reads ON access.proxy_registrations AS RESTRICTIVE TO access_router
  USING (true) WITH CHECK (false);
GRANT SELECT, INSERT ON access.proxy_registrations TO access_app;
GRANT SELECT (tenant_id, realm_id, name, version, state, host, pep)
  ON access.proxy_registrations TO access_router;

CREATE TABLE access.proxy_sessions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  proxy_session_id uuid NOT NULL DEFAULT uuidv7(),
  proxy text NOT NULL CHECK (proxy ~ '^[a-z][a-z0-9-]{0,62}$'),
  kind text NOT NULL CHECK (kind IN ('sign_in', 'session')),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  verifier text CHECK (length(verifier) = 43),
  return_to text CHECK (length(return_to) BETWEEN 9 AND 8460),
  sid bytea CHECK (octet_length(sid) = 16),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  used_ms bigint,
  ended_ms bigint,
  CHECK ((kind = 'sign_in') = (verifier IS NOT NULL AND return_to IS NOT NULL)),
  CHECK ((kind = 'session') = (sid IS NOT NULL)),
  CHECK (used_ms IS NULL OR kind = 'sign_in'),
  PRIMARY KEY (tenant_id, realm_id, proxy_session_id),
  UNIQUE (tenant_id, realm_id, kind, digest),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE INDEX proxy_sessions_sid ON access.proxy_sessions (tenant_id, realm_id, sid)
  WHERE sid IS NOT NULL;

-- OP-73: a row is never removed; only its use or end is written, once
CREATE FUNCTION access.proxy_session_rules() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'proxy sessions are not deleted' USING ERRCODE = 'check_violation';
  END IF;
  IF (NEW.tenant_id, NEW.realm_id, NEW.proxy_session_id, NEW.proxy, NEW.kind, NEW.digest,
      NEW.verifier, NEW.return_to, NEW.sid, NEW.created_ms, NEW.expires_ms)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.realm_id, OLD.proxy_session_id, OLD.proxy, OLD.kind, OLD.digest,
      OLD.verifier, OLD.return_to, OLD.sid, OLD.created_ms, OLD.expires_ms)
     OR (OLD.used_ms IS NOT NULL AND NEW.used_ms IS DISTINCT FROM OLD.used_ms)
     OR (OLD.ended_ms IS NOT NULL AND NEW.ended_ms IS DISTINCT FROM OLD.ended_ms) THEN
    RAISE EXCEPTION 'a proxy session only records its use and end, once'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER proxy_session_rules BEFORE UPDATE OR DELETE ON access.proxy_sessions
  FOR EACH ROW EXECUTE FUNCTION access.proxy_session_rules();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.proxy_sessions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.proxy_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.proxy_sessions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.proxy_sessions FROM PUBLIC;
CREATE POLICY rows ON access.proxy_sessions AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.proxy_sessions AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.proxy_sessions TO access_app;
GRANT UPDATE (used_ms, ended_ms) ON access.proxy_sessions TO access_app;

RESET ROLE;
