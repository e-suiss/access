-- E42 m.5, OP-131, OP-146 m.4 (b), OP-73: Relay messages the courier could not deliver.
-- The outbox row stays (append-only); this row only records why the cursor passed it, so
-- nothing is lost and an operator can redrive it. No personal data: ids, kind and a reason code.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.relay_undelivered (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  event_id uuid NOT NULL,
  outbox_xid xid8 NOT NULL,
  outbox_id bigint NOT NULL,
  kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
  reason text NOT NULL CHECK (reason IN ('malformed', 'no_subject', 'shredded', 'expired', 'rejected')),
  relay_status integer CHECK (relay_status BETWEEN 100 AND 599),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, event_id)
);

ALTER TABLE access.relay_undelivered ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.relay_undelivered FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.relay_undelivered FROM PUBLIC;
CREATE POLICY rows ON access.relay_undelivered AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.relay_undelivered AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.relay_undelivered
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.relay_undelivered
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.relay_undelivered TO access_app;

RESET ROLE;
