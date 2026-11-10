-- OP-156 m.3 (c), IDP-37 (4), B23, E42, Ek B 5305, 5337: the realm's İYS switch and its own
-- preference topics as decided, each İYS consent record Access gave Relay, and what Relay
-- reported back. Access never writes to İYS; Relay does. Every table only grows (OP-73).
SET LOCAL ROLE access_migrator;

-- idp.realm.iys (on, CT2) or iys_close (off, CT1); no row means off
CREATE TABLE access.iys_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  recipient_type text NOT NULL CHECK (recipient_type IN ('individual', 'merchant')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.iys_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.iys', 'idp.realm.iys_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.iys_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- idp.realm.preference_topics: the realm's own topics beside the built-in ones (OP-153 m.3 (ee))
CREATE TABLE access.preference_topics (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  topics text[] NOT NULL CHECK (cardinality(topics) <= 32),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.preference_topics
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.preference_topics');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.preference_topics
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- One İYS consent record per commercial channel a preference change touched: the Relay
-- message that carries it (its CloudEvents id), never the address, which only the sealed
-- message holds
CREATE TABLE access.iys_records (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  record_id uuid NOT NULL,
  -- pii:none
  subject_id uuid NOT NULL,
  channel text NOT NULL CHECK (channel IN ('sms', 'email', 'call')),
  -- pii:none
  consent boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, record_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX iys_records_subject
  ON access.iys_records (tenant_id, realm_id, subject_id, channel, created_at);

-- Relay's report on a record (POST /relay/v1/iys-status): it changes no preference
CREATE TABLE access.iys_status (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  status_id uuid NOT NULL DEFAULT uuidv7(),
  record_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('recorded', 'failed')),
  reason text CHECK (reason IS NULL OR reason ~ '^[a-z][a-z0-9_-]{0,63}$'),
  reported_ms bigint NOT NULL CHECK (reported_ms >= 0),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, status_id),
  FOREIGN KEY (tenant_id, realm_id, record_id)
    REFERENCES access.iys_records (tenant_id, realm_id, record_id)
);
CREATE INDEX iys_status_record ON access.iys_status (tenant_id, realm_id, record_id, status_id);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['iys_settings', 'preference_topics', 'iys_records', 'iys_status'] LOOP
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
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.iys_records
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.iys_status
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.iys_settings, access.preference_topics, access.iys_records,
  access.iys_status TO access_app;

RESET ROLE;
