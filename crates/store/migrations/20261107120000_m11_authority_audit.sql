-- OP-39, OP-44, U53, PI-4, §17.6.11: the authority plane's operational audit stream. A protocol
-- rejection makes no record, and an audit read is not an Exercise unless it is an export; both
-- are written here, one row per event, never sampled. The stream is its own chain: the
-- checkpointer integrates it into a tree apart from the identity audit log's.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.authority_audit (
  at timestamptz NOT NULL DEFAULT now(),
  id bigint GENERATED ALWAYS AS IDENTITY,
  xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
  occurred_at bigint NOT NULL CHECK (occurred_at >= 0),
  tenant_id uuid,
  domain_id bytea CHECK (domain_id IS NULL OR octet_length(domain_id) = 32),
  event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,63}$'),
  actor text NOT NULL CHECK (actor ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  target text NOT NULL CHECK (target ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  reason text NOT NULL CHECK (reason ~ '^[a-z0-9_.:-]{0,64}$'),
  correlation text NOT NULL CHECK (correlation ~ '^[A-Za-z0-9_:.-]{1,128}$'),
  PRIMARY KEY (at, id)
) PARTITION BY RANGE (at);
CREATE INDEX authority_audit_watermark ON access_ops.authority_audit (xid, id);

CREATE TABLE access_ops.authority_audit_default PARTITION OF access_ops.authority_audit DEFAULT;

ALTER TABLE access_ops.authority_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.authority_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE access_ops.authority_audit_default ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.authority_audit_default FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.authority_audit FROM PUBLIC;
REVOKE ALL ON access_ops.authority_audit_default FROM PUBLIC;
CREATE POLICY rows ON access_ops.authority_audit AS PERMISSIVE USING (true);
CREATE POLICY rows ON access_ops.authority_audit_default AS PERMISSIVE USING (true);
CREATE POLICY app_appends ON access_ops.authority_audit AS RESTRICTIVE TO access_app
  USING (false) WITH CHECK (true);
CREATE POLICY checkpointer_reads ON access_ops.authority_audit AS RESTRICTIVE TO access_checkpointer
  USING (true) WITH CHECK (false);
CREATE POLICY app_appends ON access_ops.authority_audit_default AS RESTRICTIVE TO access_app
  USING (false) WITH CHECK (true);
CREATE POLICY checkpointer_reads ON access_ops.authority_audit_default AS RESTRICTIVE
  TO access_checkpointer USING (true) WITH CHECK (false);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.authority_audit
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.authority_audit
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.authority_audit_default
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access_ops.authority_audit_checkpoint (
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  frontier bytea[] NOT NULL,
  xid xid8 NOT NULL,
  id bigint NOT NULL,
  note text NOT NULL CHECK (octet_length(note) <= 262144),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (size)
);
ALTER TABLE access_ops.authority_audit_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.authority_audit_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.authority_audit_checkpoint FROM PUBLIC;
CREATE POLICY rows ON access_ops.authority_audit_checkpoint AS PERMISSIVE USING (true);
CREATE POLICY checkpointer_only ON access_ops.authority_audit_checkpoint AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_checkpointer', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.authority_audit_checkpoint
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.authority_audit_checkpoint
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT INSERT ON access_ops.authority_audit TO access_app;
GRANT SELECT ON access_ops.authority_audit TO access_checkpointer;
GRANT SELECT, INSERT ON access_ops.authority_audit_checkpoint TO access_checkpointer;

RESET ROLE;
