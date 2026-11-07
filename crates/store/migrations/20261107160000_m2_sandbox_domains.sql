-- OP-151 m.2 M2, m.3 (m), X21, H8, D7, INV-29, X31, OP-73: the sandbox domains the platform-admin
-- surface opens, each the governing domain of its own realm with the sandbox template's fixed
-- budget. The router role reads which side of the sandbox line a domain is on, nothing more.
SET LOCAL ROLE access_migrator;

-- OP-151 m.3 (m): a sandbox is a separate AuthorityDomain; the row is written once and never changed
CREATE TABLE access.sandbox_domains (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  exercises_per_day bigint NOT NULL CHECK (exercises_per_day > 0),
  projections_per_day bigint NOT NULL CHECK (projections_per_day > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id),
  FOREIGN KEY (tenant_id, realm_id, domain_id)
    REFERENCES access.realms (tenant_id, realm_id, governing_domain_id)
);
CREATE INDEX sandbox_domains_tenant ON access.sandbox_domains (tenant_id, realm_id);

ALTER TABLE access.sandbox_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.sandbox_domains FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.sandbox_domains FROM PUBLIC;
CREATE POLICY rows ON access.sandbox_domains AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.sandbox_domains AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-151 m.3 (m): which side of the sandbox line a domain is on, read across tenants
CREATE POLICY router_reads ON access.sandbox_domains AS RESTRICTIVE TO access_router
  USING (true) WITH CHECK (false);
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.sandbox_domains
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.sandbox_domains
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE ON access.sandbox_domains
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.sandbox_domains TO access_app;
GRANT SELECT (domain_id, exercises_per_day, projections_per_day) ON access.sandbox_domains TO access_router;

RESET ROLE;
