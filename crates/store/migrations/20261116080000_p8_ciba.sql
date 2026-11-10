-- OP-155 m.3 (l), IDP-14, §10.5.3, §9.14.5 k.2: CIBA as an invitation, off by default. A setting
-- version is written only under a committed idp.realm.ciba or ciba_close ALLOW; it says whether a
-- free login_hint is accepted and which clients are told by ping at which endpoint. A backchannel
-- request keeps only the SHA-256 of its auth_req_id and carries the exercise_ref of the
-- REQUIRE_ACTION it invites the person to answer; a ping request also keeps the auth_req_id the
-- notification names. It is answered once on the Approval Surface,
-- with the contribution its AAS committed, and redeemed once. Nothing is deleted (OP-73): rows end
-- and are archived by retention.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_ciba_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  login_hint boolean NOT NULL,
  ping_clients uuid[] NOT NULL CHECK (cardinality(ping_clients) <= 64),
  ping_endpoints text[] NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (cardinality(ping_clients) = cardinality(ping_endpoints)),
  CHECK (enabled OR (NOT login_hint AND cardinality(ping_clients) = 0)),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_ciba_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.ciba', 'idp.realm.ciba_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_ciba_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- CIBA Core §7-§11, P54: one backchannel request
CREATE TABLE access.oauth_ciba_requests (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  ciba_id uuid NOT NULL DEFAULT uuidv7(),
  handle_hash bytea NOT NULL CHECK (octet_length(handle_hash) = 32),
  client_uuid uuid NOT NULL,
  subject_id uuid,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  nonce bytea NOT NULL CHECK (octet_length(nonce) BETWEEN 16 AND 64),
  intent bytea NOT NULL CHECK (octet_length(intent) = 32),
  details text NOT NULL CHECK (length(details) <= 4096),
  scope text NOT NULL CHECK (length(scope) <= 2048),
  binding_message text CHECK (char_length(binding_message) BETWEEN 1 AND 32),
  mode text NOT NULL CHECK (mode IN ('poll', 'ping')),
  notification_token text CHECK (length(notification_token) BETWEEN 1 AND 1024),
  ping_handle text CHECK (length(ping_handle) BETWEEN 1 AND 128),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  interval_s integer NOT NULL CHECK (interval_s BETWEEN 5 AND 600),
  polled_ms bigint,
  decision text CHECK (decision IN ('approved', 'denied')),
  decided_ms bigint,
  session_id uuid,
  contribution bytea CHECK (octet_length(contribution) = 32),
  pinged_ms bigint,
  used_ms bigint,
  CHECK ((decision IS NULL) = (decided_ms IS NULL)),
  CHECK ((decision = 'approved') = (session_id IS NOT NULL AND contribution IS NOT NULL)),
  CHECK (decision IS NULL OR subject_id IS NOT NULL),
  CHECK (used_ms IS NULL OR decision = 'approved'),
  CHECK ((mode = 'ping') = (notification_token IS NOT NULL AND ping_handle IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, ciba_id),
  UNIQUE (tenant_id, realm_id, handle_hash),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id, client_uuid)
    REFERENCES access.idp_clients (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
-- OP-154 m.13 (f): one answer per nonce, one use per contribution
CREATE UNIQUE INDEX oauth_ciba_requests_nonce_approved ON access.oauth_ciba_requests
  (tenant_id, realm_id, domain_id, nonce) WHERE decision = 'approved';
CREATE UNIQUE INDEX oauth_ciba_requests_contribution ON access.oauth_ciba_requests
  (tenant_id, realm_id, contribution) WHERE contribution IS NOT NULL;

CREATE FUNCTION access.oauth_ciba_request_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.used_ms IS NOT NULL
     OR (OLD.decision IS NOT NULL AND (NEW.decision, NEW.decided_ms, NEW.session_id, NEW.contribution)
         IS DISTINCT FROM (OLD.decision, OLD.decided_ms, OLD.session_id, OLD.contribution))
     OR (NEW.tenant_id, NEW.realm_id, NEW.ciba_id, NEW.handle_hash, NEW.client_uuid, NEW.subject_id,
         NEW.domain_id, NEW.nonce, NEW.intent, NEW.details, NEW.scope, NEW.binding_message,
         NEW.mode, NEW.notification_token, NEW.ping_handle, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.ciba_id, OLD.handle_hash,
                          OLD.client_uuid, OLD.subject_id, OLD.domain_id, OLD.nonce, OLD.intent,
                          OLD.details, OLD.scope, OLD.binding_message, OLD.mode,
                          OLD.notification_token, OLD.ping_handle, OLD.created_ms,
                          OLD.expires_ms) THEN
    RAISE EXCEPTION 'oauth_ciba_requests: answered once, redeemed once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_ciba_request_rules BEFORE UPDATE OR DELETE ON access.oauth_ciba_requests
  FOR EACH ROW EXECUTE FUNCTION access.oauth_ciba_request_rules();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_ciba_settings', 'oauth_ciba_requests'] LOOP
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

REVOKE ALL ON FUNCTION access.oauth_ciba_request_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_ciba_settings, access.oauth_ciba_requests TO access_app;
GRANT UPDATE (interval_s, polled_ms, decision, decided_ms, session_id, contribution, pinged_ms,
              used_ms)
  ON access.oauth_ciba_requests TO access_app;

RESET ROLE;
