-- OP-155 m.3 (h); IDP-27, IDP-34, TN-66, TN-95, TN-98, SEC9: the upstream federation broker. A
-- connection carries its own profile; its assurance map and the realm's home realm discovery
-- switch are versions written only under their committed idp.* ALLOW; the raw upstream assertion
-- is sealed under the subject's security_history key and only its digest leaves the identity
-- plane; a subject change at the upstream is a conflict record, never a relink; a session opened
-- through a connection is recorded so that cutting off its issuer ends it. Nothing here is ever
-- deleted (OP-73).
SET LOCAL ROLE access_migrator;

-- OP-155 m.3 (h): protocol, subject key, client authentication, preset, organization and the
-- SAML IdP of the connection, as canonical JSON the identity plane checks; NULL for a
-- registration made before
ALTER TABLE access.idp_upstreams
  ADD COLUMN profile text CHECK (octet_length(profile) <= 65536);

-- IDP-27, OP-155 m.3 (h): idp.upstream.assurance_map (reserved, CT3); the newest version is the
-- map, no version means the lowest class
CREATE TABLE access.idp_upstream_assurance_maps (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  map text NOT NULL CHECK (octet_length(map) <= 16384),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id, name) REFERENCES access.idp_upstreams (tenant_id, realm_id, name),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_upstream_assurance_maps
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.upstream.assurance_map');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_upstream_assurance_maps
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- TN-98, OP-155 m.3 (h): home realm discovery, off until idp.realm.hrd turns it on
CREATE TABLE access.idp_realm_hrd_settings (
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
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_hrd_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.hrd', 'idp.realm.hrd_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_realm_hrd_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- §10.1.2 rule 1, OP-155 m.3 (h): the raw ID token or SAML assertion of an upstream sign-in,
-- sealed under the subject's security_history key; the Claim carries only `evidence`
CREATE TABLE access.upstream_assertions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  assertion_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  connection text NOT NULL CHECK (connection ~ '^[a-z][a-z0-9_-]{0,63}$'),
  evidence bytea NOT NULL CHECK (octet_length(evidence) = 32),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  -- pii:security_history
  assertion_ciphertext bytea NOT NULL CHECK (octet_length(assertion_ciphertext) <= 131072),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, assertion_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX upstream_assertions_subject
  ON access.upstream_assertions (tenant_id, realm_id, subject_id);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.upstream_assertions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- TN-66, GHSA-x8cg-3c8h-gw55, OP-155 m.3 (h): a sign-in whose subject is new to the connection
-- but whose address a live link of the same connection holds; nothing is relinked, and only an
-- explicit link after a re-authentication resolves it
CREATE TABLE access.upstream_subject_conflicts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  conflict_id uuid NOT NULL DEFAULT uuidv7(),
  connection text NOT NULL CHECK (connection ~ '^[a-z][a-z0-9_-]{0,63}$'),
  subject_id uuid NOT NULL,
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  resolved_ms bigint,
  resolution text CHECK (resolution IN ('linked')),
  CHECK ((resolved_ms IS NULL) = (resolution IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, conflict_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX upstream_subject_conflicts_open
  ON access.upstream_subject_conflicts (tenant_id, realm_id, connection, identity_key)
  WHERE resolved_ms IS NULL;

CREATE FUNCTION access.upstream_conflict_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'upstream_subject_conflicts: % is not allowed', TG_OP
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.resolved_ms IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.conflict_id, NEW.connection, NEW.subject_id,
         NEW.identity_key, NEW.created_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.conflict_id, OLD.connection,
                          OLD.subject_id, OLD.identity_key, OLD.created_ms) THEN
    RAISE EXCEPTION 'upstream_subject_conflicts: a conflict is only resolved, once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER upstream_conflict_transition BEFORE UPDATE OR DELETE
  ON access.upstream_subject_conflicts
  FOR EACH ROW EXECUTE FUNCTION access.upstream_conflict_transition();

-- SEC9, OP-155 m.3 (h): the sessions an upstream connection opened, so that cutting off its
-- issuer ends them
CREATE TABLE access.upstream_sessions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  session_id uuid NOT NULL,
  connection text NOT NULL CHECK (connection ~ '^[a-z][a-z0-9_-]{0,63}$'),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, session_id),
  FOREIGN KEY (tenant_id, realm_id, session_id)
    REFERENCES access.login_sessions (tenant_id, realm_id, session_id)
);
CREATE INDEX upstream_sessions_connection
  ON access.upstream_sessions (tenant_id, realm_id, connection);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.upstream_sessions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- SEC9: a session its upstream's cutoff ended
ALTER TABLE access.login_sessions DROP CONSTRAINT login_sessions_end_reason_check;
ALTER TABLE access.login_sessions ADD CONSTRAINT login_sessions_end_reason_check
  CHECK (end_reason IN ('logout', 'epoch', 'admin', 'password', 'device', 'recovery', 'ended',
                        'upstream'))
  NOT VALID;
ALTER TABLE access.login_sessions VALIDATE CONSTRAINT login_sessions_end_reason_check;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_upstream_assurance_maps', 'idp_realm_hrd_settings',
                           'upstream_assertions', 'upstream_subject_conflicts',
                           'upstream_sessions'] LOOP
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

REVOKE ALL ON FUNCTION access.upstream_conflict_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_upstream_assurance_maps, access.idp_realm_hrd_settings,
  access.upstream_assertions, access.upstream_sessions TO access_app;
GRANT SELECT, INSERT ON access.upstream_subject_conflicts TO access_app;
GRANT UPDATE (resolved_ms, resolution) ON access.upstream_subject_conflicts TO access_app;

RESET ROLE;
