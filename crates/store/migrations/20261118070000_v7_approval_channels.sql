-- OP-157 m.3 (m), §13.7.3, SEC26, TN-100, §8.17.11.4, A-3, C30: the realm's approval channels
-- (notification and batch, each opened by a CT2 meta-action and closed by a CT1 one) and the
-- invitations sent for a pushed approval request. One invitation per approver and intent; the
-- invitation window throttles a requester against an approver. Rows are never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_approval_channels (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  channel text NOT NULL CHECK (channel IN ('inline', 'batch')),
  version bigint NOT NULL CHECK (version > 0),
  enabled boolean NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, channel, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

CREATE TABLE access.approval_invites (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  invite_id uuid NOT NULL DEFAULT uuidv7(),
  request_id uuid NOT NULL,
  requester bytea NOT NULL CHECK (octet_length(requester) = 16),
  approver uuid NOT NULL,
  intent bytea NOT NULL CHECK (octet_length(intent) = 32),
  tier smallint NOT NULL CHECK (tier BETWEEN 0 AND 3),
  created_ms bigint NOT NULL CHECK (created_ms >= 0),
  answered_ms bigint CHECK (answered_ms IS NULL OR answered_ms >= 0),
  outcome text CHECK (outcome IN ('approved', 'denied')),
  PRIMARY KEY (tenant_id, realm_id, invite_id),
  UNIQUE (tenant_id, realm_id, approver, intent),
  FOREIGN KEY (tenant_id, realm_id, request_id)
    REFERENCES access.approval_requests (tenant_id, realm_id, request_id),
  FOREIGN KEY (tenant_id, realm_id, approver)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX approval_invites_window
  ON access.approval_invites (tenant_id, realm_id, requester, approver, created_ms DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_approval_channels', 'approval_invites'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app
      USING (tenant_id = (SELECT access.tenant_scope()))
      WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
    EXECUTE format('CREATE POLICY realm_scope ON access.%I AS RESTRICTIVE TO access_app
      USING (realm_id = (SELECT access.realm_scope()))
      WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I
      FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I
      FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END $$;

GRANT SELECT, INSERT ON access.idp_approval_channels TO access_app;
GRANT SELECT, INSERT, UPDATE (answered_ms, outcome) ON access.approval_invites TO access_app;

RESET ROLE;
