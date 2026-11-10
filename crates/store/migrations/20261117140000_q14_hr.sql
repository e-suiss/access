-- OP-156 m.3 (q), IDP-35, TN-95, TN-109, AG-41: the HR-sourced lifecycle. An HR source is a Claim
-- issuer registered by idp.hr.source_register; its records arrive by idp.hr.import (a JSONL batch
-- or an RFC 4180 CSV file) and each becomes a version of the person's record under the source.
-- The HR job states the record's values as the source's HR Claims, activates an account on its
-- start date and suspends it on its end date. Selection effect is only the domain's CT3
-- subject-selection Acceptance of the source's issuer. Nothing is deleted (OP-73): sources and
-- connectors are versioned, records and due dates are append-only, the record's values are
-- sealed under the person's profile key and go with it when it is crypto-shredded.
SET LOCAL ROLE access_migrator;

-- one row per idp.hr.source_register or source_retire; a retired name is never reused
CREATE TABLE access.hr_sources (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  issuer bytea NOT NULL CHECK (octet_length(issuer) = 16),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.hr_sources
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.hr.source_register', 'idp.hr.source_retire');

-- one row per idp.hr.connector_register or connector_retire of services/hr-connector
CREATE TABLE access.hr_connectors (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  source text NOT NULL CHECK (source ~ '^[a-z][a-z0-9-]{0,62}$'),
  vendor text NOT NULL CHECK (vendor IN ('personio', 'bamboohr', 'hibob', 'workday',
                                         'successfactors', 'kolayik', 'logo')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.hr_connectors
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.hr.connector_register',
                                                 'idp.hr.connector_retire');

-- one row per idp.hr.import, written with its records in the decision's transaction
CREATE TABLE access.hr_imports (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  source text NOT NULL CHECK (source ~ '^[a-z][a-z0-9-]{0,62}$'),
  format text NOT NULL CHECK (format IN ('jsonl', 'csv')),
  file bytea NOT NULL CHECK (octet_length(file) = 32),
  records integer NOT NULL CHECK (records BETWEEN 1 AND 10000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.hr_imports
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.hr.import');

-- one row per version of a person's record under a source; the newest version is the record.
-- `person` is the realm's blind index of the source's employee id. The values the HR Claims
-- state are sealed under the subject's profile key; `issue_after_ms` holds a mover's new values
-- for the TN-109 cooling.
CREATE TABLE access.hr_records (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  source text NOT NULL CHECK (source ~ '^[a-z][a-z0-9-]{0,62}$'),
  -- pii:none
  person bytea NOT NULL CHECK (octet_length(person) = 32),
  version bigint NOT NULL CHECK (version >= 1),
  subject_id uuid NOT NULL,
  import_domain bytea NOT NULL,
  import_pos bigint NOT NULL,
  start_ms bigint,
  end_ms bigint,
  values_nonce bytea NOT NULL CHECK (octet_length(values_nonce) = 12),
  -- pii:profile
  values_ciphertext bytea NOT NULL CHECK (octet_length(values_ciphertext) <= 8192),
  issue_after_ms bigint NOT NULL CHECK (issue_after_ms >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, source, person, version),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, import_domain, import_pos)
    REFERENCES access.hr_imports (tenant_id, realm_id, domain_id, decision_pos)
);
CREATE INDEX hr_records_subject ON access.hr_records (tenant_id, realm_id, subject_id);
CREATE INDEX hr_records_issue ON access.hr_records (issue_after_ms);

-- one row once every HR Claim of a record version was answered by Claim Ingest ('issued'), or
-- once a newer version replaced a version still cooling ('skipped')
CREATE TABLE access.hr_record_claims (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  source text NOT NULL,
  person bytea NOT NULL,
  version bigint NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('issued', 'skipped')),
  issued_ms bigint NOT NULL CHECK (issued_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, source, person, version),
  FOREIGN KEY (tenant_id, realm_id, source, person, version)
    REFERENCES access.hr_records (tenant_id, realm_id, source, person, version)
);

-- one row per version of a start or end date; the newest version of (source, person, change)
-- says whether it is still to be applied, was applied, or was replaced by another date
CREATE TABLE access.hr_due (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  source text NOT NULL,
  person bytea NOT NULL CHECK (octet_length(person) = 32),
  change text NOT NULL CHECK (change IN ('start', 'end')),
  version bigint NOT NULL CHECK (version >= 1),
  subject_id uuid NOT NULL,
  due_ms bigint NOT NULL CHECK (due_ms >= 0),
  state text NOT NULL CHECK (state IN ('pending', 'applied', 'void')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, source, person, change, version),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX hr_due_at ON access.hr_due (due_ms) WHERE state = 'pending';

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['hr_sources', 'hr_connectors', 'hr_imports', 'hr_records',
                           'hr_record_claims', 'hr_due'] LOOP
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I
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
    EXECUTE format('GRANT SELECT, INSERT ON access.%I TO access_app', t);
  END LOOP;
END
$$;

-- the HR job finds the realms with work across tenants and reads nothing else
CREATE POLICY reader_reads ON access.hr_due AS RESTRICTIVE TO access_outbox_reader
  USING (true) WITH CHECK (false);
CREATE POLICY reader_reads ON access.hr_records AS RESTRICTIVE TO access_outbox_reader
  USING (true) WITH CHECK (false);
CREATE POLICY reader_reads ON access.hr_record_claims AS RESTRICTIVE TO access_outbox_reader
  USING (true) WITH CHECK (false);
GRANT SELECT (tenant_id, realm_id, source, person, change, version, due_ms, state)
  ON access.hr_due TO access_outbox_reader;
GRANT SELECT (tenant_id, realm_id, source, person, version, issue_after_ms)
  ON access.hr_records TO access_outbox_reader;
GRANT SELECT (tenant_id, realm_id, source, person, version, outcome)
  ON access.hr_record_claims TO access_outbox_reader;

RESET ROLE;
