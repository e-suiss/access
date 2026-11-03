-- OIDC Back-Channel Logout 1.0, §10.4.6, OP-146 m.11 (d), OP-73: logout notices the back-channel
-- courier could not deliver. The outbox row stays (append-only); this row only records why the
-- courier passed a grant, so nothing is lost and an operator can see it. No personal data: ids,
-- a reason code and the client's HTTP status.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.backchannel_undelivered (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  outbox_xid xid8 NOT NULL,
  outbox_id bigint NOT NULL,
  reason text NOT NULL CHECK (reason IN ('rejected', 'refused', 'unreachable', 'missing')),
  client_status integer CHECK (client_status BETWEEN 100 AND 599),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, grant_id)
);

ALTER TABLE access.backchannel_undelivered ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.backchannel_undelivered FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.backchannel_undelivered FROM PUBLIC;
CREATE POLICY rows ON access.backchannel_undelivered AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.backchannel_undelivered AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.backchannel_undelivered
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.backchannel_undelivered
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.backchannel_undelivered TO access_app;

RESET ROLE;
