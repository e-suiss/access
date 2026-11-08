-- SEC9, §13.7.7, OP-150 m.11 (c), (j): the issuer cutoff a realm key drop records is consumed at
-- Claim ingest: a carrier signed by a dropped realm key and dated after its cutoff is held. The
-- authority plane reads only that one number, by the realm's issuer and the key id, across
-- tenants; nothing else of the realm is readable this way.
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.realm_key_cutoff(p_issuer text, p_kid bytea) RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
  SELECT min(c.cutoff_at_ms)
    FROM access.realms r
    JOIN access.idp_realm_key_changes c
      ON c.tenant_id = r.tenant_id AND c.realm_id = r.realm_id
   WHERE r.issuer = p_issuer AND c.kid = p_kid AND c.action = 'idp.realm.key_drop'
$$;
REVOKE ALL ON FUNCTION access.realm_key_cutoff(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.realm_key_cutoff(text, bytea) TO access_app;

RESET ROLE;
