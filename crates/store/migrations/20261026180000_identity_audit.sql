-- OP-10, OP-13b, OP-17, OP-37, OP-38, OPI-6, OP-134: identity plane audit log and its checkpoints
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_audit (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  at timestamptz NOT NULL DEFAULT now(),
  id bigint GENERATED ALWAYS AS IDENTITY,
  xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
  event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,63}$'),
  actor text NOT NULL CHECK (actor ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  target text NOT NULL CHECK (target ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  correlation text NOT NULL CHECK (correlation ~ '^[A-Za-z0-9_:.-]{1,128}$'),
  PRIMARY KEY (tenant_id, at, id)
) PARTITION BY RANGE (at);
CREATE INDEX identity_audit_watermark ON access.identity_audit (xid, id);

CREATE FUNCTION access.secure_audit_partition(t regclass) RETURNS void
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
  EXECUTE format('CREATE POLICY checkpointer_reads ON %s AS RESTRICTIVE TO access_checkpointer '
                 'USING (true) WITH CHECK (false)', t);
  EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON %s '
                 'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON %s '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
END
$$;

SELECT access.secure_audit_partition('access.identity_audit');
CREATE TABLE access.identity_audit_default PARTITION OF access.identity_audit DEFAULT;
ALTER TABLE access.identity_audit_default ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_audit_default FORCE ROW LEVEL SECURITY;
CREATE POLICY rows ON access.identity_audit_default AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_audit_default AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_audit_default
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- OP-13b: one partition per month, opened ahead by the archive role's job
CREATE FUNCTION access.open_audit_month(month date) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  start date := date_trunc('month', month)::date;
  name text := format('identity_audit_%s', to_char(start, 'YYYYMM'));
BEGIN
  IF to_regclass(format('access.%I', name)) IS NOT NULL THEN
    RETURN name;
  END IF;
  EXECUTE format('CREATE TABLE access.%I PARTITION OF access.identity_audit FOR VALUES FROM (%L) TO (%L)',
                 name, start, (start + interval '1 month')::date);
  EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', name);
  EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', name);
  EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', name);
  EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                 'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', name);
  EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', name);
  RETURN name;
END
$$;

CREATE TABLE access_ops.audit_checkpoint (
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  frontier bytea[] NOT NULL,
  xid xid8 NOT NULL,
  id bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (size)
);
ALTER TABLE access_ops.audit_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.audit_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.audit_checkpoint FROM PUBLIC;
CREATE POLICY rows ON access_ops.audit_checkpoint AS PERMISSIVE USING (true);
CREATE POLICY checkpointer_only ON access_ops.audit_checkpoint AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.audit_checkpoint
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.audit_checkpoint
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.secure_audit_partition(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.open_audit_month(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.open_audit_month(date) TO access_archive;
GRANT INSERT, SELECT ON access.identity_audit TO access_app;
GRANT SELECT ON access.identity_audit TO access_checkpointer;
GRANT SELECT, INSERT ON access_ops.audit_checkpoint TO access_checkpointer;

RESET ROLE;
