-- TN-30, MD-8, OP-146 m.3, m.5 (f): DPoP replay cache; hash-only, no PII, one partition per day of the proof's iat
SET LOCAL ROLE access_migrator;

CREATE TABLE access.dpop_replay (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  day integer NOT NULL CHECK (day >= 0),
  key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  PRIMARY KEY (tenant_id, realm_id, day, key_hash)
) PARTITION BY RANGE (day);
ALTER TABLE access.dpop_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.dpop_replay FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.dpop_replay FROM PUBLIC;
CREATE POLICY rows ON access.dpop_replay AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.dpop_replay AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.dpop_replay
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.dpop_replay
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- OP-146 m.5 (f): no default partition, so a day nobody opened is a cache failure and the proof is rejected (TN-30)
CREATE FUNCTION access.open_dpop_replay_day(d integer) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  name text := format('dpop_replay_d%s', d);
BEGIN
  IF d < 0 THEN
    RAISE EXCEPTION 'negative day' USING ERRCODE = 'check_violation';
  END IF;
  IF to_regclass(format('access.%I', name)) IS NOT NULL THEN
    RETURN name;
  END IF;
  EXECUTE format('CREATE TABLE access.%I PARTITION OF access.dpop_replay FOR VALUES FROM (%s) TO (%s)',
                 name, d, d + 1);
  EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', name);
  EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', name);
  EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', name);
  EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                 'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                 'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', name);
  EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', name);
  RETURN name;
END
$$;

REVOKE ALL ON FUNCTION access.open_dpop_replay_day(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.open_dpop_replay_day(integer) TO access_archive;
GRANT INSERT, SELECT ON access.dpop_replay TO access_app;

RESET ROLE;
