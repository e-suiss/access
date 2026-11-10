-- OP-156 m.3 (s), OP-41, X22: a realm's export sinks for the read-only SIEM projection and their
-- cursors. A sink is registered, replaced and retired only under a committed idp.export.* ALLOW;
-- each change is a new version. Its secret (an S3 secret key, a collector token) is sealed under
-- the realm KEK; a superseded version's secret is crypto-shredded. The cursor is the position in
-- the realm's audit log after the last batch the sink accepted: it moves only forward, and only
-- after the sink accepted the batch, so a sink that is down loses nothing. Nothing is deleted
-- (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.export_sinks (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  sink_uuid uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  adapter text NOT NULL CHECK (adapter IN ('s3_parquet', 'otlp', 'collector', 'syslog')),
  preset text CHECK (preset IN ('splunk', 'sentinel', 'datadog', 'elastic')),
  format text CHECK (format IN ('cef', 'leef')),
  endpoint text NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 2048),
  settings jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 4096),
  kek_id text,
  wrapped_dek bytea,
  secret_nonce bytea CHECK (octet_length(secret_nonce) = 12),
  secret_sealed bytea CHECK (octet_length(secret_sealed) <= 8192),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((kek_id IS NULL) = (secret_sealed IS NULL) AND (wrapped_dek IS NULL) = (secret_sealed IS NULL)
         AND (secret_nonce IS NULL) = (secret_sealed IS NULL)),
  CHECK ((adapter = 'syslog') = (format IS NOT NULL)),
  CHECK (preset IS NULL OR adapter = 'collector'),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX export_sinks_uuid ON access.export_sinks (tenant_id, realm_id, sink_uuid, version);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.export_sinks
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.export.sink_register',
                                                 'idp.export.sink_update',
                                                 'idp.export.sink_retire');

-- a version is fixed; the only change is shredding its sealed secret
CREATE FUNCTION access.export_sink_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.name IS DISTINCT FROM OLD.name OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.sink_uuid IS DISTINCT FROM OLD.sink_uuid OR NEW.state IS DISTINCT FROM OLD.state
     OR NEW.adapter IS DISTINCT FROM OLD.adapter OR NEW.preset IS DISTINCT FROM OLD.preset
     OR NEW.format IS DISTINCT FROM OLD.format OR NEW.endpoint IS DISTINCT FROM OLD.endpoint
     OR NEW.settings IS DISTINCT FROM OLD.settings OR NEW.domain_id IS DISTINCT FROM OLD.domain_id
     OR NEW.decision_pos IS DISTINCT FROM OLD.decision_pos
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.secret_sealed IS NOT NULL THEN
    RAISE EXCEPTION 'export_sinks: a version is fixed; its secret is only shredded'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER export_sink_fixed BEFORE UPDATE ON access.export_sinks
  FOR EACH ROW EXECUTE FUNCTION access.export_sink_fixed();

CREATE TABLE access.export_cursors (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  sink_uuid uuid NOT NULL,
  after_xid bigint NOT NULL DEFAULT 0 CHECK (after_xid >= 0),
  after_id bigint NOT NULL DEFAULT 0 CHECK (after_id >= 0),
  sent bigint NOT NULL DEFAULT 0 CHECK (sent >= 0),
  failures integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
  failed_since timestamptz,
  last_error text CHECK (char_length(last_error) <= 64),
  notified_at timestamptz,
  attempted_at timestamptz,
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((failures = 0) = (failed_since IS NULL)),
  CHECK (notified_at IS NULL OR failed_since IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, sink_uuid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

-- X22: the cursor moves only forward
CREATE FUNCTION access.export_cursor_forward() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.sink_uuid IS DISTINCT FROM OLD.sink_uuid OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (NEW.after_xid, NEW.after_id) < (OLD.after_xid, OLD.after_id) OR NEW.sent < OLD.sent THEN
    RAISE EXCEPTION 'export_cursors: a cursor only moves forward'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER export_cursor_forward BEFORE UPDATE ON access.export_cursors
  FOR EACH ROW EXECUTE FUNCTION access.export_cursor_forward();

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['export_sinks', 'export_cursors'] LOOP
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I
                      FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I
                      FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format(
      'CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app
         USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
         WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))',
      t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON access.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
