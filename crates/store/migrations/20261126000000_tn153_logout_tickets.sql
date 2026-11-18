-- TN-153, OIDC RP-Initiated Logout §2, §5: the ticket an end-session request the client did not
-- tie to this browser's session waits on while the person confirms. It is kept as SHA-256 only,
-- bound to the browser's session cookie digest, lives five minutes, is used once and never
-- removed. `then_uri` is the client's checked post-logout redirect with its `state`;
-- `cancel_uri` the same redirect without it.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.oauth_logout_tickets (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  ticket_hash bytea NOT NULL CHECK (octet_length(ticket_hash) = 32),
  cookie_hash bytea NOT NULL CHECK (octet_length(cookie_hash) = 32),
  then_uri text CHECK (then_uri IS NULL OR length(then_uri) BETWEEN 1 AND 4096),
  cancel_uri text CHECK (cancel_uri IS NULL OR length(cancel_uri) BETWEEN 1 AND 4096),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  used_ms bigint,
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 600000),
  CHECK ((then_uri IS NULL) = (cancel_uri IS NULL)),
  PRIMARY KEY (tenant_id, environment_id, ticket_hash),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id)
);

-- TN-153: a ticket is used once; what it names never changes
CREATE FUNCTION access.oauth_logout_ticket_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'logout tickets are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.used_ms IS NOT NULL OR NEW.used_ms IS NULL
     OR (NEW.tenant_id, NEW.environment_id, NEW.ticket_hash, NEW.cookie_hash, NEW.then_uri,
         NEW.cancel_uri, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.environment_id, OLD.ticket_hash, OLD.cookie_hash,
                          OLD.then_uri, OLD.cancel_uri, OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'logout ticket transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_logout_ticket_transition BEFORE UPDATE OR DELETE
  ON access.oauth_logout_tickets
  FOR EACH ROW EXECUTE FUNCTION access.oauth_logout_ticket_transition();

ALTER TABLE access.oauth_logout_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.oauth_logout_tickets FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.oauth_logout_tickets FROM PUBLIC;
CREATE POLICY rows ON access.oauth_logout_tickets AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.oauth_logout_tickets AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-132 m.5
CREATE POLICY environment_scope ON access.oauth_logout_tickets AS RESTRICTIVE TO access_app
  USING (environment_id = (SELECT access.environment_scope()))
  WITH CHECK (environment_id = (SELECT access.environment_scope()));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.oauth_logout_tickets
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.oauth_logout_ticket_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.oauth_logout_tickets TO access_app;
GRANT UPDATE (used_ms) ON access.oauth_logout_tickets TO access_app;

RESET ROLE;
