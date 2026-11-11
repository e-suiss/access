-- OP-29, HL-31, OP-158 m.3 (r): a realm's idp.realm.dr_profile, one version per committed change;
-- the latest is in force and a NULL rpo_s is a closed profile. A realm without a declared profile
-- is never served from a promoted async copy. Rows are never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_dr_profiles (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  rpo_s bigint CHECK (rpo_s > 0),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
ALTER TABLE access.realm_dr_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_dr_profiles FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_dr_profiles FROM PUBLIC;
CREATE POLICY rows ON access.realm_dr_profiles AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_dr_profiles AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_dr_profiles
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.realm_dr_profiles
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.realm_dr_profiles TO access_app;

-- OP-29: after an async DR promote, the realms of the cell that declared a profile, for the
-- cell-wide epoch raise; read across tenants by the DR command only.
CREATE FUNCTION access.dr_profiled_realms() RETURNS TABLE (tenant_id uuid, realm_id uuid, rpo_s bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT DISTINCT ON (p.tenant_id, p.realm_id) p.tenant_id, p.realm_id, p.rpo_s
    FROM access.realm_dr_profiles p
   ORDER BY p.tenant_id, p.realm_id, p.version DESC
$$;
REVOKE ALL ON FUNCTION access.dr_profiled_realms() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.dr_profiled_realms() TO access_app;

-- OP-29, OP-158 m.3 (n), (r): each async DR promote of the cell, never changed. After one, no
-- authority domain is led until it has continued under a fence proof with its last head covered
-- (§17.4.1 item 2); an async copy is never promoted into a domain's lineage (FA-13).
CREATE TABLE access_ops.dr_promotions (
  generation bigint NOT NULL CHECK (generation > 0),
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  realms integer NOT NULL CHECK (realms >= 0),
  PRIMARY KEY (generation)
);
ALTER TABLE access_ops.dr_promotions ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.dr_promotions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.dr_promotions FROM PUBLIC;
CREATE POLICY rows ON access_ops.dr_promotions AS PERMISSIVE USING (true);
CREATE POLICY readers ON access_ops.dr_promotions AS RESTRICTIVE FOR SELECT
  USING (pg_has_role(current_user, 'access_app', 'MEMBER')
         OR pg_has_role(current_user, 'access_sequencer', 'MEMBER'));
CREATE POLICY writers ON access_ops.dr_promotions AS RESTRICTIVE FOR INSERT
  WITH CHECK (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.dr_promotions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.dr_promotions
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access_ops.dr_promotions TO access_app;
GRANT USAGE ON SCHEMA access_ops TO access_sequencer;
GRANT SELECT ON access_ops.dr_promotions TO access_sequencer;

RESET ROLE;
