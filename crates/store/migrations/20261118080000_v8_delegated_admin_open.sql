-- TN-114, §12.5.2, OP-157 m.3 (t): whether a domain's realm has opened delegated administration
-- is the last decided idp.realm.delegated_admin or delegated_admin_close bound in its config log;
-- nothing else of the log is readable this way, and no row means closed.
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.realm_delegated_admin_open(p_domain bytea) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
  SELECT coalesce(
    (SELECT l.action = 'idp.realm.delegated_admin'
       FROM access.idp_config_log l
      WHERE l.domain_id = p_domain
        AND l.action IN ('idp.realm.delegated_admin', 'idp.realm.delegated_admin_close')
      ORDER BY l.decision_pos DESC
      LIMIT 1),
    false)
$$;
REVOKE ALL ON FUNCTION access.realm_delegated_admin_open(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.realm_delegated_admin_open(bytea) TO access_app;

RESET ROLE;
