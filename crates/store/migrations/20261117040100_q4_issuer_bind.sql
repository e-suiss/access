-- OP-156 m.3 (i), TN-16, TN-17: idp.domain.issuer_bind may move the realm's issuer to its custom
-- domain bound as issuer in the same transaction, and may pin the realm's RP ID; the slug and any
-- other issuer change stay refused.
SET LOCAL ROLE access_migrator;

CREATE OR REPLACE FUNCTION access.realm_names_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.slug IS DISTINCT FROM OLD.slug THEN
    RAISE EXCEPTION 'realm %: slug and issuer are immutable', OLD.realm_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.issuer IS NOT NULL AND NEW.issuer IS DISTINCT FROM OLD.issuer
     AND NOT EXISTS (
       SELECT 1 FROM access.realm_domains d
         JOIN access.idp_config_log l
           ON l.tenant_id = d.tenant_id AND l.realm_id = d.realm_id
          AND l.domain_id = d.domain_id AND l.decision_pos = d.bind_pos
        WHERE d.tenant_id = OLD.tenant_id AND d.realm_id = OLD.realm_id
          AND d.bound_as = 'issuer' AND NEW.issuer = 'https://' || d.hostname
          AND l.action = 'idp.domain.issuer_bind' AND l.bound_xact = pg_current_xact_id()) THEN
    RAISE EXCEPTION 'realm %: slug and issuer are immutable', OLD.realm_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER idp_bound_change ON access.idp_realm_settings;
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.jose_alg', 'idp.realm.argon2',
                                                 'idp.realm.rp_id', 'idp.client.cimd_policy',
                                                 'idp.domain.issuer_bind');

RESET ROLE;
