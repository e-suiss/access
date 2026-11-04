-- OP-149 m.4, m.16 (a), L0-META-7: a platform product pairs with a tenant's realm by signing its
-- own party_register and instance_create. A pairing row is the challenge Access handed out for
-- one realm, platform client and service key: its nonce (the challenge), the Party the Exercises
-- name, the validity window they sign over, and once they commit the Instance they opened.
-- platform_party is the actor binding of the identity plane: the platform client's one Party in
-- a realm. Ids only, no personal data; nothing is deleted (OP-73).
-- A platform client owns at most one live stream per channel and endpoint, so pairing with more
-- tenants opens no second stream (OP-149 m.17 (e)).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.platform_pairing (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  challenge bytea NOT NULL CHECK (octet_length(challenge) = 32),
  client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 128),
  kid bytea NOT NULL CHECK (octet_length(kid) = 32),
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  register boolean NOT NULL,
  valid_from_ms bigint NOT NULL CHECK (valid_from_ms >= 0),
  valid_until_ms bigint NOT NULL CHECK (valid_until_ms >= valid_from_ms),
  instance_id bytea CHECK (instance_id IS NULL OR octet_length(instance_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  paired_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, challenge),
  CHECK ((instance_id IS NULL) = (paired_at IS NULL))
);
CREATE INDEX platform_pairing_client ON access.platform_pairing (tenant_id, realm_id, client_id, kid);
CREATE UNIQUE INDEX platform_pairing_paired ON access.platform_pairing (tenant_id, realm_id, client_id, kid)
  WHERE instance_id IS NOT NULL;

CREATE TABLE access.platform_party (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 128),
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, client_id),
  UNIQUE (tenant_id, realm_id, party_id)
);

CREATE FUNCTION access.pairing_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.instance_id IS NOT NULL THEN
    RAISE EXCEPTION 'platform_pairing: a pairing is recorded once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['platform_pairing', 'platform_party'] LOOP
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

CREATE TRIGGER once BEFORE UPDATE OR DELETE ON access.platform_pairing
  FOR EACH ROW EXECUTE FUNCTION access.pairing_transition();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.platform_party
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.platform_pairing, access.platform_party TO access_app;
GRANT UPDATE (instance_id, paired_at) ON access.platform_pairing TO access_app;

CREATE UNIQUE INDEX event_subscription_platform_stream
  ON access.event_subscription (tenant_id, realm_id, owner_client_id, channel, endpoint)
  WHERE owner_client_id IS NOT NULL AND disabled_at IS NULL AND endpoint IS NOT NULL;

RESET ROLE;
