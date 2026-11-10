-- OP-155 m.3 (a), (c), (e), (f), §10.6.1, IDP-15, IDI-7: the SAML identity provider and
-- WS-Federation. A service provider registration and the certificate policy are realm
-- configuration written only under a committed idp.saml.* ALLOW; a request identifier is kept
-- against replay; a flow is one browser exchange that access-server forwards to the SAML gateway
-- with a one-use attestation handle and decides itself. Nothing is deleted (OP-73): a
-- registration gets a new version and a retired entity ID is never reused, request identifiers
-- and flows stay and are archived by retention.
SET LOCAL ROLE access_migrator;

-- one row per idp.saml.sp_register, sp_mapping, sp_update or sp_retire; the newest version is the
-- registration
CREATE TABLE access.saml_sps (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  sp_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  entity_id text NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 1024),
  protocol text NOT NULL CHECK (protocol IN ('saml2', 'wsfed-saml11', 'wsfed-saml2')),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 2 AND 131072),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, sp_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX saml_sps_entity ON access.saml_sps (tenant_id, realm_id, entity_id);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.saml_sps
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.saml.sp_register', 'idp.saml.sp_mapping',
                                                 'idp.saml.sp_update', 'idp.saml.sp_retire');

-- idp.saml.cert_policy and the emergency replacement idp.saml.cert_emergency; the newest row
-- rules the scheduled two-phase rotation
CREATE TABLE access.saml_cert_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  rotate_days integer NOT NULL CHECK (rotate_days BETWEEN 30 AND 1825),
  overlap_days integer NOT NULL CHECK (overlap_days BETWEEN 14 AND 90),
  alg text NOT NULL CHECK (alg IN ('rsa-3072', 'p-256')),
  emergency boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.saml_cert_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.saml.cert_policy', 'idp.saml.cert_emergency');

-- §10.6.1: AuthnRequest and LogoutRequest identifiers seen from each service provider; a second
-- sighting is a replay. Kept 10 minutes for the decision, then archived, never deleted.
CREATE TABLE access.saml_request_ids (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  entity_id text NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 1024),
  request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
  kind text NOT NULL CHECK (kind IN ('authn', 'logout')),
  seen_ms bigint NOT NULL CHECK (seen_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, entity_id, request_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE INDEX saml_request_ids_seen ON access.saml_request_ids (seen_ms);

-- OP-155 m.3 (c), IDI-7: one browser exchange. access-server writes the raw binding values,
-- forwards them with a one-use handle and, when the gateway calls session_attest with that
-- handle, decides with the session it attested and keeps the outcome here; the browser only ever
-- sees an outcome access-server wrote.
CREATE TABLE access.saml_flows (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  flow_hash bytea NOT NULL CHECK (octet_length(flow_hash) = 32),
  binding text NOT NULL CHECK (binding IN ('redirect', 'post', 'soap', 'unsolicited', 'wsfed')),
  kind text NOT NULL CHECK (kind IN ('sso', 'slo')),
  params bytea NOT NULL CHECK (octet_length(params) BETWEEN 1 AND 131072),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  handle_hash bytea CHECK (octet_length(handle_hash) = 32),
  handle_expires_ms bigint,
  session_id uuid,
  subject_id uuid,
  session_epoch bigint,
  auth_time_ms bigint,
  aal smallint CHECK (aal BETWEEN 1 AND 3),
  decided_ms bigint,
  outcome bytea CHECK (octet_length(outcome) BETWEEN 1 AND 262144),
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 600000),
  CHECK ((handle_hash IS NULL) = (handle_expires_ms IS NULL)),
  CHECK ((decided_ms IS NULL) = (outcome IS NULL)),
  CHECK ((session_id IS NULL) = (subject_id IS NULL)
         AND (session_id IS NULL) = (session_epoch IS NULL)
         AND (session_id IS NULL) = (auth_time_ms IS NULL)
         AND (session_id IS NULL) = (aal IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, flow_hash),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE UNIQUE INDEX saml_flows_handle ON access.saml_flows (tenant_id, realm_id, handle_hash)
  WHERE handle_hash IS NOT NULL;

-- the raw values and the creation of a flow never change; a decided flow is final
CREATE FUNCTION access.saml_flow_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.decided_ms IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.flow_hash, NEW.binding, NEW.kind, NEW.params,
         NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.flow_hash, OLD.binding, OLD.kind,
                          OLD.params, OLD.created_ms, OLD.expires_ms) THEN
    RAISE EXCEPTION 'saml_flows: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER saml_flow_transition BEFORE UPDATE OR DELETE ON access.saml_flows
  FOR EACH ROW EXECUTE FUNCTION access.saml_flow_transition();

CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.saml_sps
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.saml_cert_policies
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.saml_request_ids
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['saml_sps', 'saml_cert_policies', 'saml_request_ids', 'saml_flows'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.saml_flow_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.saml_sps, access.saml_cert_policies, access.saml_request_ids,
  access.saml_flows TO access_app;
GRANT UPDATE (handle_hash, handle_expires_ms, session_id, subject_id, session_epoch, auth_time_ms,
  aal, decided_ms, outcome) ON access.saml_flows TO access_app;

RESET ROLE;
