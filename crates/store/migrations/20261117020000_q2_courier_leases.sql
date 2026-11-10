-- OP-156 m.3 (c), E42, OP-31, OP-73: one courier per outbox consumer. A node sends only while it
-- holds the consumer's live lease; the epoch grows on every change of holder and fences the
-- cursor, so a node that lost the lease cannot move it. Rows are updated, never removed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.courier_leases (
  consumer text PRIMARY KEY CHECK (consumer ~ '^[a-z][a-z0-9_-]{0,63}$'),
  holder text NOT NULL CHECK (octet_length(holder) BETWEEN 1 AND 128),
  epoch bigint NOT NULL CHECK (epoch > 0),
  acquired_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  released_at timestamptz
);

ALTER TABLE access_ops.courier_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.courier_leases FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.courier_leases FROM PUBLIC;
CREATE POLICY rows ON access_ops.courier_leases AS PERMISSIVE USING (true);
CREATE POLICY reader_only ON access_ops.courier_leases AS RESTRICTIVE
  USING (current_user <> '' AND pg_has_role(current_user, 'access_outbox_reader', 'MEMBER'));
CREATE TRIGGER no_delete BEFORE DELETE ON access_ops.courier_leases
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.courier_leases
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE ON access_ops.courier_leases TO access_outbox_reader;

-- OP-156 m.3 (c), OP-73: a resent Relay message is a new outbox row under a new CloudEvents id;
-- this row links it to the message it repeats and names who asked. Append-only.
CREATE TABLE access.relay_resends (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  event_id uuid NOT NULL,
  original_event_id uuid NOT NULL,
  actor text NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 128),
  correlation text NOT NULL CHECK (octet_length(correlation) BETWEEN 1 AND 128),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, event_id),
  FOREIGN KEY (tenant_id, realm_id, original_event_id)
    REFERENCES access.relay_undelivered (tenant_id, realm_id, event_id)
);
CREATE INDEX relay_resends_original ON access.relay_resends (tenant_id, realm_id, original_event_id);

ALTER TABLE access.relay_resends ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.relay_resends FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.relay_resends FROM PUBLIC;
CREATE POLICY rows ON access.relay_resends AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.relay_resends AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.relay_resends
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.relay_resends
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.relay_resends TO access_app;

RESET ROLE;
