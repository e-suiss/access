-- OP-158 m.3 (o), (p), CMP-26, OP-30, TI-17, HL-40: the values of the Placement Directory. A
-- routing lookup reads the latest placement of one subject across tenants and nothing else; the
-- cell's own profile (name, region, residency class, durability, the tenant it is dedicated to)
-- is the configuration it started with, one version per change; a realm's residency is the
-- committed idp.realm.residency. Nothing is changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

-- TI-17: routing only; never a decision input
CREATE FUNCTION access.placement_cell(kind text, subj bytea)
  RETURNS TABLE (cell text, dedicated boolean, version bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT p.cell, p.dedicated, p.version FROM access.placement p
   WHERE p.subject_kind = kind AND p.subject = subj
   ORDER BY p.version DESC LIMIT 1
$$;
REVOKE ALL ON FUNCTION access.placement_cell(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.placement_cell(text, bytea) TO access_app, access_router;

-- OP-158 m.3 (o): the tenant of a domain this cell holds, for a placement or a rehome target; the
-- domain scope is set for the one read and restored on return
CREATE FUNCTION access.domain_tenant(d bytea) RETURNS uuid
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  t uuid;
  prev text := current_setting('app.domain_id', true);
BEGIN
  PERFORM set_config('app.domain_id', encode(d, 'hex'), true);
  SELECT a.tenant_id INTO t FROM access.authority_domain a WHERE a.domain_id = d;
  PERFORM set_config('app.domain_id', coalesce(prev, ''), true);
  RETURN t;
END
$$;
REVOKE ALL ON FUNCTION access.domain_tenant(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.domain_tenant(bytea) TO access_app;

-- OP-158 m.3 (o), (p): this cell as its configuration declares it
CREATE TABLE access_ops.cell_profile (
  version bigint NOT NULL CHECK (version > 0),
  cell text NOT NULL CHECK (cell ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  region text CHECK (region ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  class text NOT NULL CHECK (class IN ('regional', 'multi-region-sync')),
  durability text NOT NULL CHECK (durability IN ('replicated', 'single-node')),
  dedicated_to uuid,
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (version)
);
ALTER TABLE access_ops.cell_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.cell_profile FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.cell_profile FROM PUBLIC;
CREATE POLICY rows ON access_ops.cell_profile AS PERMISSIVE USING (true);
CREATE POLICY readers ON access_ops.cell_profile AS RESTRICTIVE FOR SELECT
  USING (pg_has_role(current_user, 'access_app', 'MEMBER')
         OR pg_has_role(current_user, 'access_router', 'MEMBER')
         OR pg_has_role(current_user, 'access_migrator', 'MEMBER'));
CREATE POLICY writers ON access_ops.cell_profile AS RESTRICTIVE FOR INSERT
  WITH CHECK (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.cell_profile
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.cell_profile
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access_ops.cell_profile TO access_app;
GRANT SELECT ON access_ops.cell_profile TO access_router;
GRANT USAGE ON SCHEMA access_ops TO access_router;

-- OP-12, OP-48: a dedicated cell holds its one tenant and no other
CREATE FUNCTION access.tenant_dedicated() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  only_tenant uuid;
BEGIN
  SELECT p.dedicated_to INTO only_tenant FROM access_ops.cell_profile p ORDER BY p.version DESC LIMIT 1;
  IF only_tenant IS NOT NULL AND NEW.tenant_id <> only_tenant THEN
    RAISE EXCEPTION 'this cell is dedicated to tenant %', only_tenant
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.tenant_dedicated() FROM PUBLIC;
CREATE TRIGGER tenant_dedicated BEFORE INSERT ON access.tenants
  FOR EACH ROW EXECUTE FUNCTION access.tenant_dedicated();

-- OP-158 m.3 (o), CMP-26, OP-30: a realm's declared residency, one version per committed
-- idp.realm.residency
CREATE TABLE access.realm_residency (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  region text NOT NULL CHECK (region ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  class text NOT NULL CHECK (class IN ('regional', 'multi-region-sync')),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
ALTER TABLE access.realm_residency ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_residency FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_residency FROM PUBLIC;
CREATE POLICY rows ON access.realm_residency AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_residency AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER idp_bound BEFORE INSERT ON access.realm_residency
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.residency');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_residency
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.realm_residency
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.realm_residency TO access_app;

RESET ROLE;
