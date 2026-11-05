-- OP-150 L2, §10.1.3, §10.1.7, OP-144 carry-over: the identity plane as Claim issuer. A realm's
-- issuer Party, the Instances its issuer key holds in domains, the device keys of its users and
-- the Claims it has issued, each by line so a later Claim supersedes the earlier one. Ids and
-- digests only, no personal data; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_claim_issuer (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id),
  UNIQUE (tenant_id, party_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

CREATE TABLE access.claim_issuer_instance (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  kid bytea NOT NULL CHECK (octet_length(kid) = 32),
  instance_id bytea NOT NULL CHECK (octet_length(instance_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, domain_id, kid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realm_claim_issuer (tenant_id, realm_id)
);

CREATE TABLE access.device_keys (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  device_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 256),
  key_type text NOT NULL CHECK (key_type IN ('OKP', 'EC2')),
  algorithm text NOT NULL CHECK (algorithm IN ('Ed25519', 'ES256')),
  instance_id bytea NOT NULL CHECK (octet_length(instance_id) = 16),
  session_id uuid,
  attested_at timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz,
  PRIMARY KEY (tenant_id, realm_id, device_id),
  UNIQUE (tenant_id, realm_id, instance_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX device_keys_session ON access.device_keys (tenant_id, realm_id, session_id)
  WHERE session_id IS NOT NULL;

CREATE TABLE access.issued_claims (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  id bigint GENERATED ALWAYS AS IDENTITY,
  subject_id uuid NOT NULL,
  class text NOT NULL CHECK (class ~ '^[a-z][a-z0-9_]{0,62}$'),
  line bytea NOT NULL CHECK (octet_length(line) = 32),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  disposition text NOT NULL CHECK (disposition ~ '^[a-z][a-z0-9-]{0,62}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, id)
);
CREATE INDEX issued_claims_line ON access.issued_claims (tenant_id, realm_id, domain_id, line, id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['realm_claim_issuer', 'claim_issuer_instance', 'device_keys', 'issued_claims'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app
      USING (tenant_id = (SELECT access.tenant_scope()))
      WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
    EXECUTE format('CREATE POLICY realm_scope ON access.%I AS RESTRICTIVE TO access_app
      USING (realm_id = (SELECT access.realm_scope()))
      WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I
      FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END $$;

CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.realm_claim_issuer
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.claim_issuer_instance
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.issued_claims
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.device_keys
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.realm_claim_issuer TO access_app;
GRANT SELECT, INSERT ON access.claim_issuer_instance TO access_app;
GRANT SELECT, INSERT ON access.issued_claims TO access_app;
GRANT SELECT, INSERT, UPDATE (status, last_seen) ON access.device_keys TO access_app;

RESET ROLE;
