-- OP-158 m.3 (o), §5.16, §12.1.1 2a, E14, MD-5a, EI-25: a realm rehome is two-ended. Each end is a
-- committed ALLOW of idp.realm.rehome, one in the realm's governing domain and one in the domain it
-- moves to; the realm's governing domain changes only in the transaction that records a rehome
-- naming both unused ends. A configuration decision binds only in the realm's current governing
-- domain; the domains that governed it before keep their bound decisions. Nothing is changed or
-- removed but the realm's governing domain (OP-73).
SET LOCAL ROLE access_migrator;

-- MD-5a: every domain that ever governed a realm; the configuration log names one of them
CREATE TABLE access.realm_governors (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, domain_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id) REFERENCES access.authority_domain (tenant_id, domain_id)
);
INSERT INTO access.realm_governors (tenant_id, realm_id, domain_id)
  SELECT tenant_id, realm_id, governing_domain_id FROM access.realms;
ALTER TABLE access.realm_governors ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_governors FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_governors FROM PUBLIC;
CREATE POLICY rows ON access.realm_governors AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_governors AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_governors
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.realm_governors
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.realm_governors TO access_app;

-- OP-158 m.3 (o): the domains that govern or governed one tenant's realms in this cell, for a silo
-- move
CREATE FUNCTION access.tenant_domains(t uuid) RETURNS SETOF bytea
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT d FROM (
    SELECT r.governing_domain_id AS d, r.created_at AS at FROM access.realms r WHERE r.tenant_id = t
    UNION
    SELECT g.domain_id, g.created_at FROM access.realm_governors g WHERE g.tenant_id = t
  ) x GROUP BY d ORDER BY min(at), d
$$;
REVOKE ALL ON FUNCTION access.tenant_domains(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.tenant_domains(uuid) TO access_app;

CREATE FUNCTION access.realm_governed() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  INSERT INTO access.realm_governors (tenant_id, realm_id, domain_id)
    VALUES (NEW.tenant_id, NEW.realm_id, NEW.governing_domain_id)
    ON CONFLICT DO NOTHING;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.realm_governed() FROM PUBLIC;
CREATE TRIGGER realm_governed AFTER INSERT ON access.realms
  FOR EACH ROW EXECUTE FUNCTION access.realm_governed();

ALTER TABLE access.idp_config_log
  DROP CONSTRAINT idp_config_log_tenant_id_realm_id_domain_id_fkey;
ALTER TABLE access.idp_config_log
  ADD CONSTRAINT idp_config_log_governor FOREIGN KEY (tenant_id, realm_id, domain_id)
    REFERENCES access.realm_governors (tenant_id, realm_id, domain_id) NOT VALID;
ALTER TABLE access.idp_config_log VALIDATE CONSTRAINT idp_config_log_governor;

-- EI-25, MD-5a: a decision binds only in the realm's governing domain at the time it binds
CREATE FUNCTION access.idp_log_governing() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.realms r
                  WHERE r.tenant_id = NEW.tenant_id AND r.realm_id = NEW.realm_id
                    AND r.governing_domain_id = NEW.domain_id FOR SHARE) THEN
    RAISE EXCEPTION 'idp_config_log: % is not the realm''s governing domain', encode(NEW.domain_id, 'hex')
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.idp_log_governing() FROM PUBLIC;
CREATE TRIGGER idp_log_governing BEFORE INSERT ON access.idp_config_log
  FOR EACH ROW EXECUTE FUNCTION access.idp_log_governing();

-- E14: one end of a rehome, a committed ALLOW of idp.realm.rehome in the domain it names
CREATE TABLE access.rehome_ends (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  side text NOT NULL CHECK (side IN ('from', 'to')),
  from_domain bytea NOT NULL CHECK (octet_length(from_domain) = 32),
  to_domain bytea NOT NULL CHECK (octet_length(to_domain) = 32),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos > 0),
  nonce bytea NOT NULL,
  intent_digest bytea NOT NULL CHECK (octet_length(intent_digest) = 32),
  outcome text NOT NULL DEFAULT 'allow' CHECK (outcome = 'allow'),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (from_domain <> to_domain),
  CHECK ((side = 'from' AND domain_id = from_domain) OR (side = 'to' AND domain_id = to_domain)),
  PRIMARY KEY (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, to_domain) REFERENCES access.authority_domain (tenant_id, domain_id),
  FOREIGN KEY (domain_id, nonce, decision_pos, intent_digest, outcome)
    REFERENCES access.authority_nonce (domain_id, nonce, decision_pos, intent_digest, outcome)
);
ALTER TABLE access.rehome_ends ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.rehome_ends FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.rehome_ends FROM PUBLIC;
CREATE POLICY rows ON access.rehome_ends AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.rehome_ends AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.rehome_ends
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.rehome_ends
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.rehome_ends TO access_app;

-- E14: the from end is decided in the realm's governing domain at the time it is recorded
CREATE FUNCTION access.rehome_end_governing() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.realms r
                  WHERE r.tenant_id = NEW.tenant_id AND r.realm_id = NEW.realm_id
                    AND r.governing_domain_id = NEW.from_domain FOR SHARE) THEN
    RAISE EXCEPTION 'rehome_ends: % does not govern the realm', encode(NEW.from_domain, 'hex')
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.rehome_end_governing() FROM PUBLIC;
CREATE TRIGGER rehome_end_governing BEFORE INSERT ON access.rehome_ends
  FOR EACH ROW EXECUTE FUNCTION access.rehome_end_governing();

-- E14: a completed rehome; each end completes at most one
CREATE TABLE access.realm_rehomes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  from_domain bytea NOT NULL,
  to_domain bytea NOT NULL,
  from_pos bigint NOT NULL,
  to_pos bigint NOT NULL,
  xact xid8 NOT NULL DEFAULT pg_current_xact_id(),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, version),
  UNIQUE (tenant_id, from_domain, from_pos),
  UNIQUE (tenant_id, to_domain, to_pos),
  FOREIGN KEY (tenant_id, from_domain, from_pos)
    REFERENCES access.rehome_ends (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, to_domain, to_pos)
    REFERENCES access.rehome_ends (tenant_id, domain_id, decision_pos)
);
ALTER TABLE access.realm_rehomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_rehomes FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_rehomes FROM PUBLIC;
CREATE POLICY rows ON access.realm_rehomes AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_rehomes AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.realm_rehomes
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.realm_rehomes
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.realm_rehomes TO access_app;

-- E14: both ends are of this realm and this move: the from end in the old domain, the to end in
-- the new one
CREATE FUNCTION access.realm_rehome_ends() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.rehome_ends e
                  WHERE e.tenant_id = NEW.tenant_id AND e.realm_id = NEW.realm_id
                    AND e.domain_id = NEW.from_domain AND e.decision_pos = NEW.from_pos
                    AND e.side = 'from' AND e.from_domain = NEW.from_domain
                    AND e.to_domain = NEW.to_domain)
     OR NOT EXISTS (SELECT 1 FROM access.rehome_ends e
                     WHERE e.tenant_id = NEW.tenant_id AND e.realm_id = NEW.realm_id
                       AND e.domain_id = NEW.to_domain AND e.decision_pos = NEW.to_pos
                       AND e.side = 'to' AND e.from_domain = NEW.from_domain
                       AND e.to_domain = NEW.to_domain) THEN
    RAISE EXCEPTION 'realm_rehomes: a rehome needs both of its ends'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.realm_rehome_ends() FROM PUBLIC;
CREATE TRIGGER realm_rehome_ends BEFORE INSERT ON access.realm_rehomes
  FOR EACH ROW EXECUTE FUNCTION access.realm_rehome_ends();

-- MD-5a, E14: the governing domain changes only with a rehome recorded in the same transaction
CREATE FUNCTION access.realm_governance_moved() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.governing_domain_id IS DISTINCT FROM OLD.governing_domain_id
     AND NOT EXISTS (SELECT 1 FROM access.realm_rehomes h
                      WHERE h.tenant_id = OLD.tenant_id AND h.realm_id = OLD.realm_id
                        AND h.from_domain = OLD.governing_domain_id
                        AND h.to_domain = NEW.governing_domain_id
                        AND h.xact = pg_current_xact_id()) THEN
    RAISE EXCEPTION 'realm %: the governing domain changes only by a two-ended rehome', OLD.realm_id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.realm_governance_moved() FROM PUBLIC;
CREATE TRIGGER realm_governance_moved BEFORE UPDATE ON access.realms
  FOR EACH ROW EXECUTE FUNCTION access.realm_governance_moved();

RESET ROLE;
