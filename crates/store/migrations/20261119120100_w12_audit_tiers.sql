-- OP-40, OP-73 m.4, OP-138, OP-158 m.3 (w): the identity audit log's hot and cold tiers. Each new
-- month is sub-partitioned by tenant (LIST); a partition whose hot window has passed and whose
-- rows are all in a signed checkpoint is copied to the cold tier, the copy is verified against
-- the partition's Merkle root, and only then is the partition detached into access_audit_cold by
-- the archive role. Nothing is dropped or deleted.
SET LOCAL ROLE access_migrator;

-- OP-158 m.3 (a), (w): the hot window is at least 30 days, 90 by default; longer is free
ALTER TABLE access.tenants ALTER COLUMN audit_hot_days SET DEFAULT 90;
ALTER TABLE access.tenants DROP CONSTRAINT tenants_audit_hot_days_check;
ALTER TABLE access.tenants ADD CONSTRAINT tenants_audit_hot_days_check
  CHECK (audit_hot_days BETWEEN 30 AND 3660) NOT VALID;
ALTER TABLE access.tenants VALIDATE CONSTRAINT tenants_audit_hot_days_check;
ALTER TABLE access.realms DROP CONSTRAINT realms_audit_hot_days_check;
ALTER TABLE access.realms ADD CONSTRAINT realms_audit_hot_days_check
  CHECK (audit_hot_days BETWEEN 30 AND 3660) NOT VALID;
ALTER TABLE access.realms VALIDATE CONSTRAINT realms_audit_hot_days_check;

-- OP-158 m.3 (a), (w): a realm's idp.realm.audit_tier, one version per committed change; the
-- latest is in force. A closed tier (audit_tier_close) leaves both values null: the tenant's
-- window applies and the cell's cold tier keeps the copies.
CREATE TABLE access.idp_audit_tiers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  hot_days integer CHECK (hot_days BETWEEN 30 AND 3660),
  target text CHECK (octet_length(target) BETWEEN 1 AND 512),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((hot_days IS NULL) = (target IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
ALTER TABLE access.idp_audit_tiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.idp_audit_tiers FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.idp_audit_tiers FROM PUBLIC;
CREATE POLICY rows ON access.idp_audit_tiers AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.idp_audit_tiers AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_audit_tiers
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.idp_audit_tiers
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.idp_audit_tiers TO access_app;

-- OP-73 m.4: one row per partition moved; the copy's root and digest are what the cold tier is
-- checked against
CREATE TABLE access_ops.audit_tier_moves (
  partition text NOT NULL CHECK (partition ~ '^identity_audit_[0-9]{6}(_t[0-9a-f]{32}|_default)?$'),
  tenant_id uuid,
  month date NOT NULL,
  rows bigint NOT NULL CHECK (rows >= 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  object_key text NOT NULL CHECK (object_key ~ '^[A-Za-z0-9/_.-]+$' AND octet_length(object_key) <= 512),
  object_sha256 bytea NOT NULL CHECK (octet_length(object_sha256) = 32),
  last_xid xid8,
  last_id bigint,
  moved_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((last_xid IS NULL) = (last_id IS NULL)),
  CHECK ((rows = 0) = (last_id IS NULL)),
  PRIMARY KEY (partition)
);
ALTER TABLE access_ops.audit_tier_moves ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.audit_tier_moves FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.audit_tier_moves FROM PUBLIC;
CREATE POLICY rows ON access_ops.audit_tier_moves AS PERMISSIVE USING (true);
CREATE POLICY archive_only ON access_ops.audit_tier_moves AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_archive', 'MEMBER') OR current_user = 'access_migrator')
  WITH CHECK (current_user = 'access_migrator');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.audit_tier_moves
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.audit_tier_moves
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- OP-158 m.3 (w): the archive role's tier functions run as the migrator and read the checkpoint
-- cursors; writing them stays the checkpointer's
ALTER POLICY checkpointer_only ON access_ops.audit_checkpoint
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER') OR current_user = 'access_migrator')
  WITH CHECK (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));
ALTER POLICY checkpointer_only ON access_ops.audit_realm_checkpoint
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER') OR current_user = 'access_migrator')
  WITH CHECK (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));

-- OP-13b: the security of one identity audit partition, leaf or month
CREATE FUNCTION access.secure_audit_leaf(name text) RETURNS void
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', name);
  EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', name);
  EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', name);
  EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                 'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', name);
  EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', name);
END
$$;

-- OP-158 m.3 (w): a tenant's own partition of a sub-partitioned month; refused while the month's
-- default partition still holds that tenant's rows
CREATE FUNCTION access.open_audit_tenant(month date, tenant uuid) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  start date := date_trunc('month', month)::date;
  parent text := format('identity_audit_%s', to_char(start, 'YYYYMM'));
  name text := format('identity_audit_%s_t%s', to_char(start, 'YYYYMM'), replace(tenant::text, '-', ''));
BEGIN
  IF to_regclass(format('access.%I', name)) IS NOT NULL THEN
    RETURN name;
  END IF;
  IF (SELECT relkind FROM pg_class WHERE oid = to_regclass(format('access.%I', parent))) IS DISTINCT FROM 'p' THEN
    RAISE EXCEPTION 'month % is not partitioned by tenant', parent USING ERRCODE = 'check_violation';
  END IF;
  EXECUTE format('CREATE TABLE access.%I PARTITION OF access.%I FOR VALUES IN (%L)', name, parent, tenant);
  PERFORM access.secure_audit_leaf(name);
  RETURN name;
END
$$;

-- OP-13b, OP-158 m.3 (w): from now on a month is partitioned by tenant, with a default for
-- tenants created later in the month; months opened before stay as they are
CREATE OR REPLACE FUNCTION access.open_audit_month(month date) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  start date := date_trunc('month', month)::date;
  name text := format('identity_audit_%s', to_char(start, 'YYYYMM'));
  t uuid;
BEGIN
  IF to_regclass(format('access.%I', name)) IS NULL THEN
    EXECUTE format('CREATE TABLE access.%I PARTITION OF access.identity_audit FOR VALUES FROM (%L) TO (%L) '
                   'PARTITION BY LIST (tenant_id)', name, start, (start + interval '1 month')::date);
    PERFORM access.secure_audit_leaf(name);
    EXECUTE format('CREATE TABLE access.%I PARTITION OF access.%I DEFAULT', name || '_default', name);
    PERFORM access.secure_audit_leaf(name || '_default');
  END IF;
  IF (SELECT relkind FROM pg_class WHERE oid = to_regclass(format('access.%I', name))) = 'p' THEN
    FOR t IN SELECT tenant_id FROM access.tenants WHERE status <> 'deleted' ORDER BY tenant_id LOOP
      BEGIN
        PERFORM access.open_audit_tenant(start, t);
      EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'audit partition of tenant % in % not opened: %', t, name, SQLERRM;
      END;
    END LOOP;
  END IF;
  RETURN name;
END
$$;

-- OP-158 m.3 (w): the identity audit partition `name` if it is a leaf of access.identity_audit
-- other than its top default, with its tenant and month
CREATE FUNCTION access.audit_leaf(name text, OUT tenant uuid, OUT month date, OUT parent text)
  LANGUAGE plpgsql STABLE
  SET search_path = pg_catalog
  AS $$
DECLARE
  m text[];
BEGIN
  m := regexp_match(name, '^identity_audit_([0-9]{6})(_t([0-9a-f]{32})|_default)?$');
  IF m IS NULL OR NOT EXISTS (
       SELECT FROM pg_partition_tree('access.identity_audit') p
        WHERE p.relid = to_regclass(format('access.%I', name)) AND p.isleaf) THEN
    RAISE EXCEPTION 'not an identity audit partition: %', name USING ERRCODE = 'check_violation';
  END IF;
  month := to_date(m[1], 'YYYYMM');
  tenant := CASE WHEN m[3] IS NULL THEN NULL ELSE m[3]::uuid END;
  SELECT pc.relname INTO parent FROM pg_inherits i
    JOIN pg_class pc ON pc.oid = i.inhparent
   WHERE i.inhrelid = to_regclass(format('access.%I', name));
END
$$;

-- OP-40, OP-158 m.3 (w): the partitions whose month ended more than their hot window ago and
-- whose every row the cell checkpoint and its realm's tree checkpoint cover. A tenant's own
-- partition waits for the longest window of the tenant and its realms; a shared one for the
-- longest of all.
CREATE FUNCTION access.audit_partitions_due()
  RETURNS TABLE (partition text, tenant_id uuid, month date, rows bigint)
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  leaf record;
  hot integer;
  cell_xid xid8;
  cell_id bigint;
  open_rows boolean;
BEGIN
  SELECT c.xid, c.id INTO cell_xid, cell_id FROM access_ops.audit_checkpoint c ORDER BY c.size DESC LIMIT 1;
  FOR leaf IN
    SELECT c.relname::text AS name FROM pg_partition_tree('access.identity_audit') p
      JOIN pg_class c ON c.oid = p.relid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE p.isleaf AND n.nspname = 'access' AND c.relname <> 'identity_audit_default'
       AND c.relname ~ '^identity_audit_[0-9]{6}(_t[0-9a-f]{32}|_default)?$'
     ORDER BY 1
  LOOP
    partition := leaf.name;
    SELECT l.tenant, l.month INTO tenant_id, month FROM access.audit_leaf(leaf.name) l;
    SELECT greatest(coalesce(max(t.audit_hot_days), 90), coalesce(max(r.audit_hot_days), 0),
                    coalesce(max(v.hot_days), 0)) INTO hot
      FROM access.tenants t
      LEFT JOIN access.realms r ON r.tenant_id = t.tenant_id
      LEFT JOIN LATERAL (
        SELECT a.hot_days FROM access.idp_audit_tiers a
         WHERE a.tenant_id = r.tenant_id AND a.realm_id = r.realm_id
         ORDER BY a.version DESC LIMIT 1) v ON true
     WHERE audit_partitions_due.tenant_id IS NULL OR t.tenant_id = audit_partitions_due.tenant_id;
    CONTINUE WHEN (month + interval '1 month')::date + hot > current_date;
    EXECUTE format('SELECT count(*) FROM access.%I', leaf.name) INTO rows;
    IF rows > 0 THEN
      CONTINUE WHEN cell_xid IS NULL;
      EXECUTE format(
        'SELECT EXISTS (SELECT FROM access.%I a WHERE (a.xid, a.id) > ($1, $2)) '
        '    OR EXISTS (SELECT FROM access.%I a WHERE NOT EXISTS ('
        '         SELECT FROM access_ops.audit_realm_checkpoint r '
        '          WHERE r.tenant_id = a.tenant_id AND r.realm_id = a.realm_id AND (r.xid, r.id) >= (a.xid, a.id)))',
        leaf.name, leaf.name) INTO open_rows USING cell_xid, cell_id;
      CONTINUE WHEN open_rows;
    END IF;
    RETURN NEXT;
  END LOOP;
END
$$;

-- OP-158 m.3 (w): the rows of one partition in integration order, for its cold copy
CREATE FUNCTION access.audit_partition_rows(name text, after_xid xid8, after_id bigint, lim integer)
  RETURNS TABLE (tenant_id uuid, realm_id uuid, at timestamptz, id bigint, xid xid8, event_type text,
                 actor text, target text, correlation text)
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
BEGIN
  PERFORM access.audit_leaf(name);
  RETURN QUERY EXECUTE format(
    'SELECT a.tenant_id, a.realm_id, a.at, a.id, a.xid, a.event_type, a.actor, a.target, a.correlation '
    '  FROM access.%I a WHERE (a.xid, a.id) > ($1, $2) ORDER BY a.xid, a.id LIMIT $3', name)
    USING after_xid, after_id, least(greatest(lim, 0), 10000);
END
$$;

-- OP-73 m.4, OP-158 m.3 (w): records the verified cold copy of `name`, then detaches the
-- partition into access_audit_cold, where it stays read-only and unreachable by the application.
-- Refused when the partition changed since it was copied or is no longer due.
CREATE FUNCTION access.move_audit_partition(name text, copied bigint, root bytea, object_key text,
                                            object_sha256 bytea, last_xid xid8, last_id bigint)
  RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  leaf record;
  n bigint;
  tail_xid xid8;
  tail_id bigint;
BEGIN
  SELECT * INTO leaf FROM access.audit_leaf(name);
  IF NOT EXISTS (SELECT FROM access.audit_partitions_due() d WHERE d.partition = name) THEN
    RAISE EXCEPTION 'partition % is not due', name USING ERRCODE = 'check_violation';
  END IF;
  EXECUTE format('LOCK TABLE access.%I IN SHARE MODE', name);
  EXECUTE format('SELECT count(*) FROM access.%I', name) INTO n;
  EXECUTE format('SELECT a.xid, a.id FROM access.%I a ORDER BY a.xid DESC, a.id DESC LIMIT 1', name)
    INTO tail_xid, tail_id;
  IF n <> copied OR tail_xid IS DISTINCT FROM last_xid OR tail_id IS DISTINCT FROM last_id THEN
    RAISE EXCEPTION 'partition % changed since its copy', name USING ERRCODE = 'serialization_failure';
  END IF;
  INSERT INTO access_ops.audit_tier_moves
    (partition, tenant_id, month, rows, root, object_key, object_sha256, last_xid, last_id)
  VALUES (name, leaf.tenant, leaf.month, n, root, object_key, object_sha256, last_xid, last_id);
  EXECUTE format('ALTER TABLE access.%I DETACH PARTITION access.%I', leaf.parent, name);
  EXECUTE format('ALTER TABLE access.%I SET SCHEMA access_audit_cold', name);
  EXECUTE format('REVOKE ALL ON access_audit_cold.%I FROM PUBLIC, access_app, access_checkpointer', name);
  EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_audit_cold.%I '
                 'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', name);
END
$$;

REVOKE ALL ON FUNCTION access.secure_audit_leaf(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.open_audit_tenant(date, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.audit_leaf(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.audit_partitions_due() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.audit_partition_rows(text, xid8, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.move_audit_partition(text, bigint, bytea, text, bytea, xid8, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.open_audit_tenant(date, uuid) TO access_archive;
GRANT EXECUTE ON FUNCTION access.audit_partitions_due() TO access_archive;
GRANT EXECUTE ON FUNCTION access.audit_partition_rows(text, xid8, bigint, integer) TO access_archive;
GRANT EXECUTE ON FUNCTION access.move_audit_partition(text, bigint, bytea, text, bytea, xid8, bigint) TO access_archive;
GRANT SELECT ON access_ops.audit_tier_moves TO access_archive;
GRANT USAGE ON SCHEMA access_ops TO access_archive;

RESET ROLE;
