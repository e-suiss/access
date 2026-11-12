-- OP-159 m.3 (e), m.9 (h), m.4 (l): the CT3 time-lock of an algorithm joining a domain's
-- allowlist. A request is kept when it is first made; the allowlist changes only when the
-- request is made again after the time-lock and before the request lapses. Rows are never
-- changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.algorithm_admissions (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  algorithm integer NOT NULL,
  requested_at bigint NOT NULL CHECK (requested_at >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, algorithm, requested_at),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

ALTER TABLE access.algorithm_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.algorithm_admissions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.algorithm_admissions FROM PUBLIC;
CREATE POLICY rows ON access.algorithm_admissions AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.algorithm_admissions AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.algorithm_admissions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.algorithm_admissions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.algorithm_admissions TO access_sequencer;
GRANT SELECT ON access.algorithm_admissions TO access_app;

RESET ROLE;
