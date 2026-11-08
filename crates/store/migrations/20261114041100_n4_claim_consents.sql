-- OP-153 m.3 (z): claim release consent. A client the realm registered as a third party asks the
-- person before it receives identity claims ("Share with App"); the consent is kept per
-- (person, client, claim set) and ended from "Connected apps". A consent is identity data, never
-- authority. Nothing is deleted (OP-73): a consent ends once, stopped or replaced.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  ADD COLUMN third_party boolean NOT NULL DEFAULT false;

CREATE TABLE access.identity_claim_consents (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  consent_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  claims text[] NOT NULL CHECK (cardinality(claims) BETWEEN 1 AND 32),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  ended_ms bigint,
  end_reason text CHECK (end_reason IN ('stopped', 'replaced')),
  CHECK ((ended_ms IS NULL) = (end_reason IS NULL)),
  CHECK (ended_ms IS NULL OR ended_ms >= created_ms),
  PRIMARY KEY (tenant_id, realm_id, consent_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, client_uuid)
    REFERENCES access.idp_clients (tenant_id, realm_id, client_uuid)
);
CREATE UNIQUE INDEX identity_claim_consents_live
  ON access.identity_claim_consents (tenant_id, realm_id, subject_id, client_uuid)
  WHERE ended_ms IS NULL;

CREATE FUNCTION access.identity_claim_consent_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.ended_ms IS NOT NULL OR NEW.ended_ms IS NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.consent_id, NEW.subject_id, NEW.client_uuid, NEW.claims,
         NEW.created_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.consent_id, OLD.subject_id,
                          OLD.client_uuid, OLD.claims, OLD.created_ms) THEN
    RAISE EXCEPTION 'identity_claim_consents: a consent only ends, once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_claim_consent_transition BEFORE UPDATE OR DELETE
  ON access.identity_claim_consents
  FOR EACH ROW EXECUTE FUNCTION access.identity_claim_consent_transition();

ALTER TABLE access.identity_claim_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_claim_consents FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_claim_consents FROM PUBLIC;
CREATE POLICY rows ON access.identity_claim_consents AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_claim_consents AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.identity_claim_consents
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.identity_claim_consent_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_claim_consents TO access_app;
GRANT UPDATE (ended_ms, end_reason) ON access.identity_claim_consents TO access_app;

RESET ROLE;
