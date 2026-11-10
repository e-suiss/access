-- OP-156 m.4 (Q20, appended), AG-39, AG-43, Ek B 4390: what discovery connectors reported, one
-- row per admitted `discovered_app` Claim whose disclosed body matched its value, appended only
-- (OP-73). The `discovery` search reads it; nothing decides on it.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.discovered_apps (
  domain_id bytea NOT NULL,
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  issuer_id bytea NOT NULL CHECK (octet_length(issuer_id) = 16),
  subject_id bytea NOT NULL CHECK (octet_length(subject_id) = 16),
  connector text NOT NULL CHECK (connector IN ('google-workspace', 'microsoft-graph')),
  app text NOT NULL CHECK (octet_length(app) BETWEEN 1 AND 512),
  name text CHECK (name IS NULL OR octet_length(name) BETWEEN 1 AND 512),
  scopes text[] NOT NULL CHECK (cardinality(scopes) <= 256),
  pos bigint NOT NULL CHECK (pos > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, claim_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX discovered_apps_app ON access.discovered_apps (domain_id, connector, app);

ALTER TABLE access.discovered_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.discovered_apps FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.discovered_apps FROM PUBLIC;
CREATE POLICY rows ON access.discovered_apps AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.discovered_apps AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.discovered_apps
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.discovered_apps
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.discovered_apps TO access_sequencer;
GRANT SELECT ON access.discovered_apps TO access_app;

RESET ROLE;
