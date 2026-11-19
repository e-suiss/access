-- TN-158: one account per national identity number in an environment. The number itself is
-- sealed among the account's profile fields; this table keeps only its environment-keyed blind
-- index, so a second account with the same number is refused without reading the first. A
-- released row stays (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_national_ids (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  record_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  scheme text NOT NULL CHECK (scheme ~ '^[a-z][a-z0-9:-]{0,47}$'),
  -- pii:none
  number_index bytea NOT NULL CHECK (octet_length(number_index) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  released_at timestamptz,
  PRIMARY KEY (tenant_id, environment_id, record_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id)
);
CREATE UNIQUE INDEX identity_national_ids_number
  ON access.identity_national_ids (tenant_id, environment_id, scheme, number_index)
  WHERE released_at IS NULL;
CREATE UNIQUE INDEX identity_national_ids_subject
  ON access.identity_national_ids (tenant_id, environment_id, subject_id)
  WHERE released_at IS NULL;

-- TN-158: a row is released once and names what it named
CREATE FUNCTION access.identity_national_id_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'national ids are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.released_at IS NOT NULL OR NEW.released_at IS NULL
     OR (NEW.tenant_id, NEW.environment_id, NEW.record_id, NEW.subject_id, NEW.scheme,
         NEW.number_index, NEW.created_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.environment_id, OLD.record_id, OLD.subject_id,
                          OLD.scheme, OLD.number_index, OLD.created_at) THEN
    RAISE EXCEPTION 'national id transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_national_id_transition BEFORE UPDATE OR DELETE
  ON access.identity_national_ids
  FOR EACH ROW EXECUTE FUNCTION access.identity_national_id_transition();

ALTER TABLE access.identity_national_ids ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_national_ids FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_national_ids FROM PUBLIC;
CREATE POLICY rows ON access.identity_national_ids AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_national_ids AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-132 m.5
CREATE POLICY environment_scope ON access.identity_national_ids AS RESTRICTIVE TO access_app
  USING (environment_id = (SELECT access.environment_scope()))
  WITH CHECK (environment_id = (SELECT access.environment_scope()));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_national_ids
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.identity_national_id_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_national_ids TO access_app;
GRANT UPDATE (released_at) ON access.identity_national_ids TO access_app;

RESET ROLE;
