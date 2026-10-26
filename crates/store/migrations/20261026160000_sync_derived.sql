-- §16.5.1, §16.5.2, §17.1.1 step 9, T9, TI-4, OP-14, OP-16: SYNC-DERIVED state written in the
-- commit transaction
SET LOCAL ROLE access_migrator;

CREATE TABLE access.authority_version (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  key bytea NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 512),
  version bigint NOT NULL CHECK (version > 0),
  PRIMARY KEY (domain_id, key),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
) WITH (fillfactor = 70);

CREATE TABLE access.authority_counter (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  key bytea NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 512),
  used bigint NOT NULL CHECK (used >= 0),
  PRIMARY KEY (domain_id, key),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
) WITH (fillfactor = 70);

CREATE TABLE access.authority_single_use (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  key bytea NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 512),
  pos bigint NOT NULL CHECK (pos > 0),
  PRIMARY KEY (domain_id, key),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['authority_version', 'authority_counter', 'authority_single_use'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access.%I AS RESTRICTIVE '
                   'USING (domain_id = (SELECT access.domain_scope())) '
                   'WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
  END LOOP;
END
$$;
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.authority_single_use
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.authority_single_use
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT ON access.authority_version, access.authority_counter, access.authority_single_use
  TO access_app, access_sequencer;
GRANT INSERT, UPDATE ON access.authority_version, access.authority_counter TO access_sequencer;
GRANT INSERT ON access.authority_single_use TO access_sequencer;

RESET ROLE;
