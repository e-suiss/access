-- OP-158 m.18 (e), E14: an unused rehome end expires 24 h after it was recorded; an expired end
-- completes no rehome (fail-closed).
SET LOCAL ROLE access_migrator;

CREATE OR REPLACE FUNCTION access.realm_rehome_ends() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.rehome_ends e
                  WHERE e.tenant_id = NEW.tenant_id AND e.realm_id = NEW.realm_id
                    AND e.domain_id = NEW.from_domain AND e.decision_pos = NEW.from_pos
                    AND e.side = 'from' AND e.from_domain = NEW.from_domain
                    AND e.to_domain = NEW.to_domain
                    AND e.created_at > now() - interval '24 hours')
     OR NOT EXISTS (SELECT 1 FROM access.rehome_ends e
                     WHERE e.tenant_id = NEW.tenant_id AND e.realm_id = NEW.realm_id
                       AND e.domain_id = NEW.to_domain AND e.decision_pos = NEW.to_pos
                       AND e.side = 'to' AND e.from_domain = NEW.from_domain
                       AND e.to_domain = NEW.to_domain
                       AND e.created_at > now() - interval '24 hours') THEN
    RAISE EXCEPTION 'realm_rehomes: a rehome needs both of its ends, each recorded within 24 h'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.realm_rehome_ends() FROM PUBLIC;

RESET ROLE;
