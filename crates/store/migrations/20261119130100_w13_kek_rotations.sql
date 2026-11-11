-- OP-138, OP-144, OP-158 m.3 (y): one row per realm KEK rotation. The job re-wraps each subject
-- DEK from `from_kek` to `to_kek` inside the HSM, counts what it moved and resumes from the rows
-- still under `from_kek`; the old KEK stays in the token, so a row the job has not reached is
-- still opened. A finished rotation is never reopened; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.kek_rotations (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  from_kek text NOT NULL CHECK (from_kek ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  to_kek text NOT NULL CHECK (to_kek ~ '^[A-Za-z0-9_.:-]{1,128}$' AND to_kek <> from_kek),
  rewrapped bigint NOT NULL DEFAULT 0 CHECK (rewrapped >= 0),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, to_kek),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE UNIQUE INDEX kek_rotations_one_open ON access.kek_rotations (tenant_id, realm_id)
  WHERE finished_at IS NULL;

CREATE FUNCTION access.kek_rotation_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'kek_rotations: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.realm_id, NEW.from_kek, NEW.to_kek, NEW.started_at)
       IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.from_kek, OLD.to_kek, OLD.started_at) THEN
    RAISE EXCEPTION 'kek_rotations: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.finished_at IS NOT NULL THEN
    RAISE EXCEPTION 'kek_rotations: a finished rotation is never reopened' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.rewrapped < OLD.rewrapped THEN
    RAISE EXCEPTION 'kek_rotations: the count only grows' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER kek_rotation_transition BEFORE UPDATE OR DELETE ON access.kek_rotations
  FOR EACH ROW EXECUTE FUNCTION access.kek_rotation_transition();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.kek_rotations
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.kek_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.kek_rotations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.kek_rotations FROM PUBLIC;
CREATE POLICY rows ON access.kek_rotations AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.kek_rotations AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.kek_rotations TO access_app;
GRANT UPDATE (rewrapped, finished_at) ON access.kek_rotations TO access_app;

RESET ROLE;
