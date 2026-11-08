-- TN-90, §12.3.8, Ek B 3611: what an upstream identity provider asserted about a person's domain
-- in a sign-in it vouched for (Google's `hd`; Microsoft's `tid` is kept as the tenant it names,
-- which is not a DNS name). The latest assertion of each person, provider and domain is kept;
-- nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.upstream_domain_assertions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 512),
  domain text NOT NULL CHECK (domain ~ '^[a-z0-9.-]{1,253}$'),
  tenant_hint text CHECK (tenant_hint IS NULL OR length(tenant_hint) <= 64),
  asserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, subject_id, issuer, domain),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

ALTER TABLE access.upstream_domain_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.upstream_domain_assertions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.upstream_domain_assertions FROM PUBLIC;
CREATE POLICY rows ON access.upstream_domain_assertions AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.upstream_domain_assertions AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.upstream_domain_assertions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.upstream_domain_assertions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.upstream_domain_assertions TO access_app;
GRANT UPDATE (tenant_hint, asserted_at) ON access.upstream_domain_assertions TO access_app;

RESET ROLE;
