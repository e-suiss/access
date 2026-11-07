-- TN-125, X20, OP-151 m.2 M1, OP-73: bulk jobs of the realm-admin surface. A job is a set of
-- writes, each its own Exercise with its own AIS; these rows only keep what each item did (the
-- Exercise reference or the refusal) for 7 days. Expiry is soft: an expired job is not shown and
-- nothing is deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.admin_jobs (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  job_id uuid NOT NULL DEFAULT uuidv7(),
  mode text NOT NULL CHECK (mode IN ('sequential', 'parallel')),
  actor bytea NOT NULL CHECK (octet_length(actor) = 32),
  item_count integer NOT NULL CHECK (item_count BETWEEN 1 AND 100),
  status text NOT NULL DEFAULT 'running'
    CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
  created_ms bigint NOT NULL,
  finished_ms bigint,
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  CHECK ((status = 'running') = (finished_ms IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, job_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

CREATE TABLE access.admin_job_items (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  job_id uuid NOT NULL,
  item_index integer NOT NULL CHECK (item_index BETWEEN 0 AND 99),
  operation text NOT NULL CHECK (operation ~ '^[a-zA-Z]{1,64}$'),
  resource_key text CHECK (length(resource_key) <= 256),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'committed', 'not_allowed', 'rejected', 'throttled',
                      'failed_dependency', 'unavailable')),
  http_status integer CHECK (http_status BETWEEN 100 AND 599),
  problem text CHECK (problem ~ '^[a-z_-]{1,64}$'),
  exercise_id text CHECK (length(exercise_id) <= 64),
  decision_pos bigint,
  CHECK ((status = 'pending') = (http_status IS NULL)),
  CHECK ((status = 'committed') = (exercise_id IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, job_id, item_index),
  FOREIGN KEY (tenant_id, realm_id, job_id)
    REFERENCES access.admin_jobs (tenant_id, realm_id, job_id)
);

-- A job finishes once; an item is recorded once
CREATE FUNCTION access.admin_job_once() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF OLD.status NOT IN ('running', 'pending')
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.job_id IS DISTINCT FROM OLD.job_id THEN
    RAISE EXCEPTION '%: a finished row stays as it is', TG_TABLE_NAME
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.admin_job_once() FROM PUBLIC;

CREATE TRIGGER admin_job_once BEFORE UPDATE ON access.admin_jobs
  FOR EACH ROW EXECUTE FUNCTION access.admin_job_once();
CREATE TRIGGER admin_job_once BEFORE UPDATE ON access.admin_job_items
  FOR EACH ROW EXECUTE FUNCTION access.admin_job_once();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['admin_jobs', 'admin_job_items'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
    EXECUTE format('CREATE POLICY realm_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE ON access.admin_jobs, access.admin_job_items TO access_app;

RESET ROLE;
