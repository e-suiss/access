-- OP-156 m.3 (w), E59, OP-78, Ek B 4552, 4553, 4631: One's cloud key permissions. A row is
-- the content-free record of the person's device Instance's `one.cloud_key/grant` Exercise:
-- the purpose, the class names, the window (at most 24 hours), the digests of the TEE
-- measurement and of its job key, and the Mandate it is bound to. No DEK, KEK or data is kept
-- here or anywhere Access holds. An end is its own row; both tables only grow (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.cloud_key_permissions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  permission_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  subject_id uuid NOT NULL,
  -- pii:none
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  domain bytea NOT NULL CHECK (octet_length(domain) = 32),
  exercise bytea NOT NULL CHECK (octet_length(exercise) = 32),
  purpose text NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
  classes text[] NOT NULL CHECK (cardinality(classes) BETWEEN 1 AND 8),
  valid_from bigint NOT NULL CHECK (valid_from >= 0),
  valid_until bigint NOT NULL CHECK (valid_until > valid_from AND valid_until - valid_from <= 86400000),
  tee_measurement bytea NOT NULL CHECK (octet_length(tee_measurement) = 32),
  job_key bytea NOT NULL CHECK (octet_length(job_key) = 32),
  mandate bytea NOT NULL CHECK (octet_length(mandate) = 16),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, permission_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX cloud_key_permissions_exercise
  ON access.cloud_key_permissions (tenant_id, realm_id, exercise);
CREATE INDEX cloud_key_permissions_subject
  ON access.cloud_key_permissions (tenant_id, realm_id, subject_id, valid_until);

CREATE TABLE access.cloud_key_permission_ends (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  permission_id uuid NOT NULL,
  how text NOT NULL CHECK (how IN ('revoked')),
  exercise bytea CHECK (exercise IS NULL OR octet_length(exercise) = 32),
  ended_at bigint NOT NULL CHECK (ended_at >= 0),
  PRIMARY KEY (tenant_id, realm_id, permission_id),
  FOREIGN KEY (tenant_id, realm_id, permission_id)
    REFERENCES access.cloud_key_permissions (tenant_id, realm_id, permission_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cloud_key_permissions', 'cloud_key_permission_ends'] LOOP
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

GRANT SELECT, INSERT ON access.cloud_key_permissions, access.cloud_key_permission_ends TO access_app;

RESET ROLE;
