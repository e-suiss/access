-- OP-156 m.3 (c), Ek B 5294: the security notice courier's cursor in each domain's authority
-- outbox, `(pos, idx)` of the last event it turned into a notice. Updated, never removed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.relay_notice_cursor (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos >= 0),
  idx integer NOT NULL CHECK (idx >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id)
);

ALTER TABLE access.relay_notice_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.relay_notice_cursor FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.relay_notice_cursor FROM PUBLIC;
CREATE POLICY rows ON access.relay_notice_cursor AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.relay_notice_cursor AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_delete BEFORE DELETE ON access.relay_notice_cursor
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.relay_notice_cursor
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE ON access.relay_notice_cursor TO access_app;

RESET ROLE;
