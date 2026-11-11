-- OP-35, OP-158 m.3 (a), (v): a realm's idp.realm.rate_limit (`rate_limit_rps`), one version per
-- committed change; the latest is in force, the product default until the first. Rows are never
-- changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_rate_limits (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  rps integer NOT NULL CHECK (rps BETWEEN 1 AND 1000000),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
ALTER TABLE access.realm_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_rate_limits FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_rate_limits FROM PUBLIC;
CREATE POLICY rows ON access.realm_rate_limits AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_rate_limits AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_rate_limits
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.realm_rate_limits
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.realm_rate_limits TO access_app;

-- TN-24, OP-35: one identity request of a realm, drawn from its tenant's request quota and the
-- realm's `rate_limit_rps` (p_default_rps until a rate limit is set); the burst is p_burst_s
-- seconds of the rate and p_now is in microseconds. Returns the refusing counter ('tenant' or
-- 'realm'; null when admitted) and the highest share of a burst in use, percent.
CREATE FUNCTION access.realm_quota(
  p_tenant uuid, p_realm uuid, p_now bigint, p_default_rps integer, p_tenant_rps integer,
  p_burst_s integer, OUT refused text, OUT used integer
)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  rps integer;
  taken integer[];
BEGIN
  IF p_default_rps NOT BETWEEN 1 AND 1000000 OR p_tenant_rps NOT BETWEEN 1 AND 1000000
     OR p_burst_s < 1 THEN
    RAISE EXCEPTION 'realm_quota: malformed limit' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT l.rps INTO rps FROM access.realm_rate_limits l
   WHERE l.tenant_id = p_tenant AND l.realm_id = p_realm ORDER BY l.version DESC LIMIT 1;
  rps := coalesce(rps, p_default_rps);
  taken := access.quota_take(p_tenant, 'request', ARRAY['tenant', 'realm'],
                               ARRAY[uuid_send(p_tenant), uuid_send(p_realm)], p_now,
                               ARRAY[(1000000 / p_tenant_rps)::bigint,
                                     (1000000 / rps)::bigint],
                               ARRAY[(p_tenant_rps * p_burst_s)::bigint, (rps * p_burst_s)::bigint]);
  refused := CASE taken[1] WHEN 0 THEN NULL WHEN 1 THEN 'tenant' ELSE 'realm' END;
  used := taken[2];
END
$$;

REVOKE ALL ON FUNCTION access.realm_quota(uuid, uuid, bigint, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.realm_quota(uuid, uuid, bigint, integer, integer, integer) TO access_app;

RESET ROLE;
