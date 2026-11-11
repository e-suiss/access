-- OP-157 m.3 (w), m.6 (f), IDP-39 (3): one row per idp.review.schedule or schedule_close. A
-- campaign is a view over the reviewer's team's Grants, never a queue, and writes no authority;
-- the row only names its period and scope. A closed name is never reused; nothing is deleted
-- (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.review_schedules (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'closed')),
  period_days integer NOT NULL CHECK (period_days BETWEEN 7 AND 366),
  scope text NOT NULL CHECK (scope IN ('manager_team')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.review_schedules
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.review.schedule',
                                                 'idp.review.schedule_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.review_schedules
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.review_schedules
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.review_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.review_schedules FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.review_schedules FROM PUBLIC;
CREATE POLICY rows ON access.review_schedules AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.review_schedules AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.review_schedules TO access_app;

RESET ROLE;
