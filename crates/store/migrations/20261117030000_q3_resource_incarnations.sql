-- OP-156 m.3 (k), INV-32, §7.9.10.4, E14: the resource lifecycle facts a domain product declared
-- with `resource_lifecycle` Claims, one row per admitted Claim and appended only (OP-73). The
-- highest incarnation seen for a resource is the bound Claim Ingest checks a new create or
-- reincarnate against; the same incarnation is never created twice.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.resource_incarnations (
  domain_id bytea NOT NULL,
  namespace text NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 128),
  path text[] NOT NULL CHECK (cardinality(path) BETWEEN 1 AND 32),
  incarnation bigint NOT NULL CHECK (incarnation >= 0),
  event text NOT NULL CHECK (event IN ('create', 'delete', 'reincarnate')),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  issuer_id bytea NOT NULL CHECK (octet_length(issuer_id) = 16),
  pos bigint NOT NULL CHECK (pos > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, claim_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX resource_incarnations_resource
  ON access.resource_incarnations (domain_id, namespace, path, incarnation DESC);
CREATE UNIQUE INDEX resource_incarnations_once
  ON access.resource_incarnations (domain_id, namespace, path, incarnation)
  WHERE event IN ('create', 'reincarnate');

ALTER TABLE access.resource_incarnations ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.resource_incarnations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.resource_incarnations FROM PUBLIC;
CREATE POLICY rows ON access.resource_incarnations AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.resource_incarnations AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.resource_incarnations
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.resource_incarnations
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.resource_incarnations TO access_sequencer;
GRANT SELECT ON access.resource_incarnations TO access_app;

RESET ROLE;
