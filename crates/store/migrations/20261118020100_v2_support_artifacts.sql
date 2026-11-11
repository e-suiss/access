-- OP-157 m.3 (g), §8.16 #12, TN-74, INV-30: support artifacts. Uploads are open only under the
-- realm's committed idp.support.artifact_policy, each policy a new version written under its
-- decision. An artifact keeps only its redacted text, sealed under its own DEK wrapped by the
-- realm KEK, with the digest of that redacted text; the raw upload is never stored. Erasure is
-- crypto-shredding: the key and the ciphertext go, the row stays (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.support_artifact_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  open boolean NOT NULL,
  max_bytes integer CHECK (max_bytes IS NULL OR max_bytes BETWEEN 1 AND 10485760),
  retention_days integer CHECK (retention_days IS NULL OR retention_days BETWEEN 1 AND 365),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos),
  CHECK (open = (max_bytes IS NOT NULL AND retention_days IS NOT NULL))
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.support_artifact_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.support.artifact_policy',
                                                 'idp.support.artifact_policy_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.support_artifact_policies
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.support_artifact_policies
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.support_artifacts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  artifact_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  subject_id uuid NOT NULL,
  subject_party bytea NOT NULL CHECK (octet_length(subject_party) = 16),
  case_ref bytea NOT NULL CHECK (octet_length(case_ref) = 32),
  format text NOT NULL CHECK (format IN ('har', 'json', 'log')),
  size_bytes integer NOT NULL CHECK (size_bytes >= 0),
  redactions integer NOT NULL CHECK (redactions >= 0),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  upload_exercise bytea NOT NULL CHECK (octet_length(upload_exercise) = 32),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  wrapped_dek bytea,
  nonce bytea,
  -- pii:security_history
  ciphertext bytea,
  created_ms bigint NOT NULL CHECK (created_ms >= 0),
  retain_until_ms bigint NOT NULL CHECK (retain_until_ms > created_ms),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  shredded_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, artifact_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  CHECK ((shredded_at IS NULL) = (wrapped_dek IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL)),
  CHECK (shredded_at IS NOT NULL OR octet_length(nonce) = 12)
);
CREATE INDEX support_artifacts_retention
  ON access.support_artifacts (tenant_id, realm_id, retain_until_ms) WHERE shredded_at IS NULL;

-- OP-73: the one change allowed is shredding, once
CREATE FUNCTION access.support_artifact_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'support_artifacts: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.shredded_at IS NOT NULL
     OR NEW.shredded_at IS NULL
     OR NEW.wrapped_dek IS NOT NULL OR NEW.nonce IS NOT NULL OR NEW.ciphertext IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.artifact_id, NEW.subject_id, NEW.subject_party,
         NEW.case_ref, NEW.format, NEW.size_bytes, NEW.redactions, NEW.digest,
         NEW.upload_exercise, NEW.kek_id, NEW.created_ms, NEW.retain_until_ms, NEW.created_at)
        IS DISTINCT FROM
        (OLD.tenant_id, OLD.realm_id, OLD.artifact_id, OLD.subject_id, OLD.subject_party,
         OLD.case_ref, OLD.format, OLD.size_bytes, OLD.redactions, OLD.digest,
         OLD.upload_exercise, OLD.kek_id, OLD.created_ms, OLD.retain_until_ms, OLD.created_at) THEN
    RAISE EXCEPTION 'support_artifacts: only shredding the key and the ciphertext, once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.support_artifact_transition() FROM PUBLIC;

CREATE TRIGGER support_artifact_transition BEFORE UPDATE OR DELETE ON access.support_artifacts
  FOR EACH ROW EXECUTE FUNCTION access.support_artifact_transition();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.support_artifacts
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['support_artifact_policies', 'support_artifacts'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT ON access.support_artifact_policies, access.support_artifacts TO access_app;
GRANT UPDATE (wrapped_dek, nonce, ciphertext, shredded_at) ON access.support_artifacts TO access_app;

RESET ROLE;
