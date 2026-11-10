-- OP-156 m.3 (p), IDP-32: the realm's Linux client hosts. A host is registered, retired, and its
-- offline and break-glass rules set only under a committed idp.linux.* ALLOW; each change is a
-- new version of the host's row. A host names its server group (the resource of the ssh.login
-- Grants whose principals sign in to it) and the x5t#S256 of its client certificate. The NSS
-- ids a realm hands its Linux users and groups are allocated once and never reused. Nothing is
-- deleted (OP-73).
SET LOCAL ROLE access_migrator;

-- one row per idp.linux.host_register, host_retire, offline_policy or break_glass_policy
CREATE TABLE access.linux_hosts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  host_group text NOT NULL CHECK (host_group ~ '^[a-z][a-z0-9-]{0,62}$'),
  certificate text NOT NULL CHECK (certificate ~ '^[A-Za-z0-9_-]{43}$'),
  nss_ttl_s bigint NOT NULL CHECK (nss_ttl_s BETWEEN 0 AND 43200),
  console_ttl_s bigint NOT NULL CHECK (console_ttl_s BETWEEN 0 AND 28800),
  sudo_ct smallint NOT NULL CHECK (sudo_ct IN (2, 3)),
  shell text NOT NULL CHECK (shell ~ '^/[A-Za-z0-9/._-]{0,254}$'),
  break_glass boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE INDEX linux_hosts_certificate ON access.linux_hosts (tenant_id, realm_id, certificate);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.linux_hosts
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.linux.host_register', 'idp.linux.host_retire',
                                                 'idp.linux.offline_policy',
                                                 'idp.linux.break_glass_policy');

-- one row per Linux user or group name the realm served; its id is never handed out again
CREATE TABLE access.linux_ids (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('user', 'group')),
  name text NOT NULL CHECK (name ~ '^[a-z_][a-z0-9_-]{0,62}$'),
  id bigint NOT NULL CHECK (id BETWEEN 200000 AND 2147483647),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, kind, name),
  UNIQUE (tenant_id, realm_id, id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['linux_hosts', 'linux_ids'] LOOP
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I
                      FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I
                      FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format(
      'CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app
         USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
         WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))',
      t);
    EXECUTE format('GRANT SELECT, INSERT ON access.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
