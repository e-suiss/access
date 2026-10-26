-- TN-1, TN-6, TN-16, TN-19, TN-20, MD-5, OP-12, OP-40, OP-73, OP-132: tenants, realms, hostnames
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.realm_scope() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog
  AS $$ SELECT nullif(current_setting('app.realm_id', true), '')::uuid $$;

CREATE TABLE access.tenants (
  tenant_id uuid NOT NULL DEFAULT uuidv7(),
  placement_id text NOT NULL DEFAULT 'pool-default' CHECK (placement_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  status text NOT NULL DEFAULT 'provisioning'
    CHECK (status IN ('provisioning', 'active', 'suspended', 'deleted')),
  audit_hot_days integer NOT NULL DEFAULT 30 CHECK (audit_hot_days BETWEEN 30 AND 90),
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (tenant_id)
);

ALTER TABLE access.authority_domain
  ADD CONSTRAINT authority_domain_tenant UNIQUE (tenant_id, domain_id);

CREATE TABLE access.realms (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL DEFAULT uuidv7(),
  governing_domain_id bytea NOT NULL,
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
  placement_id text NOT NULL CHECK (placement_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
  audit_hot_days integer CHECK (audit_hot_days BETWEEN 30 AND 90),
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id),
  FOREIGN KEY (tenant_id, governing_domain_id) REFERENCES access.authority_domain (tenant_id, domain_id)
);
-- TN-16, TN-20: one of the four global identifiers; deleted realms keep theirs (INV-32)
CREATE UNIQUE INDEX realms_slug ON access.realms (slug);

CREATE TABLE access.realm_hostnames (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  hostname text NOT NULL CHECK (hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  kind text NOT NULL CHECK (kind IN ('subdomain', 'custom')),
  verified_at timestamptz,
  reverify_at timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
  deleted_at timestamptz,
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, hostname),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
-- TN-20: hostnames are global; the check above keeps them lower case
CREATE UNIQUE INDEX realm_hostnames_live ON access.realm_hostnames (hostname) WHERE status = 'active';

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenants', 'realms', 'realm_hostnames'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
  END LOOP;
END
$$;
CREATE POLICY realm_scope ON access.realm_hostnames AS RESTRICTIVE TO access_app
  USING (realm_id = (SELECT access.realm_scope()))
  WITH CHECK (realm_id = (SELECT access.realm_scope()));
-- OP-132 m.3: Host resolution reads the live mapping across tenants and nothing else
CREATE POLICY router_reads ON access.realm_hostnames AS RESTRICTIVE TO access_router
  USING (status = 'active') WITH CHECK (false);
CREATE POLICY router_reads ON access.realms AS RESTRICTIVE TO access_router
  USING (status = 'active') WITH CHECK (false);

REVOKE ALL ON FUNCTION access.realm_scope() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.realm_scope() TO access_app;
GRANT SELECT, INSERT, UPDATE ON access.tenants, access.realms, access.realm_hostnames TO access_app;
GRANT SELECT (tenant_id, realm_id, hostname, status) ON access.realm_hostnames TO access_router;
GRANT SELECT (tenant_id, realm_id, slug, status) ON access.realms TO access_router;

RESET ROLE;
