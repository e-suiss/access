-- OP-20, OP-131: identity plane outbox delivered by xid8 watermark
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.tenant_scope() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog
  AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE TABLE access.identity_outbox (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  id bigint GENERATED ALWAYS AS IDENTITY,
  xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
  kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
  payload bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, id)
);
CREATE INDEX identity_outbox_watermark ON access.identity_outbox (xid, id);

ALTER TABLE access.identity_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_outbox FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_outbox FROM PUBLIC;
CREATE POLICY rows ON access.identity_outbox AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_outbox AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY reader_reads ON access.identity_outbox AS RESTRICTIVE TO access_outbox_reader
  USING (true) WITH CHECK (false);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.identity_outbox
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access_ops.outbox_cursor (
  consumer text NOT NULL CHECK (consumer ~ '^[a-z][a-z0-9_-]{0,63}$'),
  xid xid8 NOT NULL,
  id bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer)
);
ALTER TABLE access_ops.outbox_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.outbox_cursor FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.outbox_cursor FROM PUBLIC;
CREATE POLICY rows ON access_ops.outbox_cursor AS PERMISSIVE USING (true);
CREATE POLICY reader_only ON access_ops.outbox_cursor AS RESTRICTIVE
  USING (current_user <> '' AND pg_has_role(current_user, 'access_outbox_reader', 'MEMBER'));

REVOKE ALL ON FUNCTION access.tenant_scope() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.tenant_scope() TO access_app;
GRANT INSERT, SELECT ON access.identity_outbox TO access_app;
GRANT SELECT ON access.identity_outbox TO access_outbox_reader;
GRANT SELECT, INSERT, UPDATE ON access_ops.outbox_cursor TO access_outbox_reader;

RESET ROLE;
