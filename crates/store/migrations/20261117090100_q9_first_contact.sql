-- OP-156 m.3 (z), E58, Ek B 4495: first-contact tokens (RFC 9578 type 0x0002). One issuer key
-- per realm and 30-day period, sealed under the realm KEK, and one row per issued token for the
-- per-identity daily limit. The spent set is Relay's; Access keeps only what it issued. A
-- token row names no blinded message and no token, so issuance links to no redemption. Every
-- table only grows (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.first_contact_keys (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  period bigint NOT NULL CHECK (period >= 0),
  token_key_id bytea NOT NULL CHECK (octet_length(token_key_id) = 32),
  token_key bytea NOT NULL CHECK (octet_length(token_key) = 342),
  sealed_key bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, period),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE UNIQUE INDEX first_contact_keys_id
  ON access.first_contact_keys (tenant_id, realm_id, token_key_id);

CREATE TABLE access.first_contact_issued (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  issue_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  subject_id uuid NOT NULL,
  day integer NOT NULL CHECK (day >= 0),
  period bigint NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, issue_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, period)
    REFERENCES access.first_contact_keys (tenant_id, realm_id, period)
);
CREATE INDEX first_contact_issued_day
  ON access.first_contact_issued (tenant_id, realm_id, subject_id, day);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['first_contact_keys', 'first_contact_issued'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT ON access.first_contact_keys, access.first_contact_issued TO access_app;

RESET ROLE;
