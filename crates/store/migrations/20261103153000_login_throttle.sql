-- OP-35 (layer B), OP-146 m.5 (d)-(f), SA-30, TN-82, CR-36, MD-8: exact login counters in PostgreSQL.
-- Keys are digests only, no personal data; one partition per day; a key's state is carried
-- into the day it is next touched, so old partitions hold nothing live (OP-146 m.5 (f)).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.login_throttle (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  day date NOT NULL,
  key bytea NOT NULL CHECK (octet_length(key) = 32),
  tat_ms bigint NOT NULL DEFAULT 0 CHECK (tat_ms >= 0),
  failures integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
  last_failure_ms bigint NOT NULL DEFAULT 0 CHECK (last_failure_ms >= 0),
  blocked_until_ms bigint NOT NULL DEFAULT 0 CHECK (blocked_until_ms >= 0),
  locked boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, realm_id, key, day)
) PARTITION BY RANGE (day);

CREATE TABLE access.login_throttle_default PARTITION OF access.login_throttle DEFAULT;

CREATE FUNCTION access.secure_throttle_partition(t regclass) RETURNS void
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', t);
  EXECUTE format('REVOKE ALL ON %s FROM PUBLIC', t);
  EXECUTE format('CREATE POLICY rows ON %s AS PERMISSIVE USING (true)', t);
  EXECUTE format('CREATE POLICY tenant_scope ON %s AS RESTRICTIVE TO access_app '
                 'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                 'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
  EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON %s '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
END
$$;

SELECT access.secure_throttle_partition('access.login_throttle');
SELECT access.secure_throttle_partition('access.login_throttle_default');
-- cloned onto every partition
CREATE TRIGGER append_only_row BEFORE DELETE ON access.login_throttle
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- OP-146 m.5 (f): the archive role opens each day ahead
CREATE FUNCTION access.open_throttle_day(d date) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  name text := format('login_throttle_%s', to_char(d, 'YYYYMMDD'));
BEGIN
  IF to_regclass(format('access.%I', name)) IS NOT NULL THEN
    RETURN name;
  END IF;
  EXECUTE format('CREATE TABLE access.%I PARTITION OF access.login_throttle FOR VALUES FROM (%L) TO (%L)',
                 name, d, d + 1);
  PERFORM access.secure_throttle_partition(format('access.%I', name)::regclass);
  RETURN name;
END
$$;

REVOKE ALL ON FUNCTION access.secure_throttle_partition(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.open_throttle_day(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.open_throttle_day(date) TO access_archive;
GRANT SELECT, INSERT ON access.login_throttle TO access_app;
GRANT UPDATE (tat_ms, failures, last_failure_ms, blocked_until_ms, locked) ON access.login_throttle TO access_app;

RESET ROLE;
