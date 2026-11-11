-- OP-73 m.7, OP-146 m.5 (f), OP-158 m.3 (w): the archive job closes the day partitions of the
-- ephemeral protocol tables once their TTL has passed. A partition is detached, moved into
-- access_ephemeral and dropped there; only the tables named below qualify, and no data table is
-- one of them. Rows are never deleted.
SET LOCAL ROLE access_migrator;

-- OP-158 m.3 (w): TTL in whole days after the partition's day (PD); the login counters carry a
-- key's state from the last 30 days (FACTOR_HORIZON_DAYS), so they stay one day longer
CREATE FUNCTION access.close_ephemeral_days() RETURNS SETOF text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  today integer := floor(extract(epoch FROM now()) / 86400)::integer;
  family record;
  part record;
  d integer;
BEGIN
  FOR family IN
    SELECT f.parent, f.keep FROM (VALUES
      ('auth_flows', 2), ('oauth_requests', 2), ('oauth_codes', 2), ('client_assertion_replay', 2),
      ('dpop_replay', 2), ('claim_ingest', 2), ('login_throttle', 31)) AS f(parent, keep)
  LOOP
    FOR part IN
      SELECT c.relname::text AS name FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = p.relnamespace
       WHERE n.nspname = 'access' AND p.relname = family.parent
       ORDER BY 1
    LOOP
      IF family.parent = 'login_throttle' THEN
        CONTINUE WHEN part.name !~ '^login_throttle_[0-9]{8}$';
        d := to_date(substr(part.name, 16), 'YYYYMMDD') - date '1970-01-01';
      ELSE
        CONTINUE WHEN part.name !~ ('^' || family.parent || '_d[0-9]{1,9}$');
        d := substr(part.name, length(family.parent) + 3)::integer;
      END IF;
      CONTINUE WHEN d >= today - family.keep;
      BEGIN
        EXECUTE format('ALTER TABLE access.%I DETACH PARTITION access.%I', family.parent, part.name);
        EXECUTE format('ALTER TABLE access.%I SET SCHEMA access_ephemeral', part.name);
        -- OP-73-exception: ephemeral-protocol
        EXECUTE format('DROP TABLE access_ephemeral.%I', part.name);
        RETURN NEXT part.name;
      EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'ephemeral partition % not closed: %', part.name, SQLERRM;
      END;
    END LOOP;
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.close_ephemeral_days() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.close_ephemeral_days() TO access_archive;

RESET ROLE;
