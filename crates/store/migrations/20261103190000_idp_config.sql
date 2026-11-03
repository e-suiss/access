-- MD-14, E34, EI-25, TN-110, OP-146 I10: identity plane configuration is written only against a
-- committed ALLOW of an idp.* action in the realm's governing domain. The binding is declarative:
-- foreign keys to the decision's nonce row (outcome allow, same intent digest) and to the realm's
-- governing domain; referential checks see across row-level security, nothing else does.
SET LOCAL ROLE access_migrator;

-- OP-141 m.9: a decision's nonce row, addressable with its intent and outcome
CREATE UNIQUE INDEX authority_nonce_decision
  ON access.authority_nonce (domain_id, nonce, decision_pos, intent_digest, outcome);
-- MD-5a: a realm with its one governing domain
CREATE UNIQUE INDEX realms_governing ON access.realms (tenant_id, realm_id, governing_domain_id);

CREATE TABLE access.idp_config_log (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos > 0),
  nonce bytea NOT NULL,
  intent_digest bytea NOT NULL CHECK (octet_length(intent_digest) = 32),
  outcome text NOT NULL DEFAULT 'allow' CHECK (outcome = 'allow'),
  change_digest bytea NOT NULL CHECK (octet_length(change_digest) = 32),
  action text NOT NULL CHECK (action ~ '^idp\.[a-z_]+\.[a-z0-9_]+$'),
  bound_xact xid8 NOT NULL,
  bound_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, realm_id, domain_id)
    REFERENCES access.realms (tenant_id, realm_id, governing_domain_id),
  FOREIGN KEY (domain_id, nonce, decision_pos, intent_digest, outcome)
    REFERENCES access.authority_nonce (domain_id, nonce, decision_pos, intent_digest, outcome)
);

CREATE FUNCTION access.idp_log_xact() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  NEW.bound_xact := pg_current_xact_id();
  RETURN NEW;
END
$$;
CREATE TRIGGER idp_log_xact BEFORE INSERT ON access.idp_config_log
  FOR EACH ROW EXECUTE FUNCTION access.idp_log_xact();

-- EI-25: a configuration row names a decision bound in its own transaction to one of the
-- actions the trigger lists; an unbound or reused decision is refused
CREATE FUNCTION access.idp_bound() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.decision_pos IS NULL THEN
    IF TG_OP = 'INSERT' AND TG_NARGS = 0 THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION '%: a change needs a committed idp.* ALLOW', TG_TABLE_NAME
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.domain_id = OLD.domain_id AND NEW.decision_pos = OLD.decision_pos THEN
    RAISE EXCEPTION '%: a change needs its own committed idp.* ALLOW', TG_TABLE_NAME
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM access.idp_config_log l
                  WHERE l.tenant_id = NEW.tenant_id AND l.realm_id = NEW.realm_id
                    AND l.domain_id = NEW.domain_id AND l.decision_pos = NEW.decision_pos
                    AND l.bound_xact = pg_current_xact_id() AND l.action = ANY (TG_ARGV)) THEN
    RAISE EXCEPTION '%: not bound to a committed ALLOW of %', TG_TABLE_NAME, TG_ARGV
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

-- TN-15, TN-20, IDP-7, OP-137: clients; the opaque client_id is global and never reused
CREATE TABLE access.idp_clients (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  client_id text NOT NULL CHECK (client_id ~ '^cli_[0-9a-hjkmnp-tv-z]{26}$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
  auth_method text NOT NULL CHECK (auth_method IN ('none', 'private_key_jwt', 'client_secret_basic')),
  jwks_uri text CHECK (length(jwks_uri) <= 2048 AND jwks_uri ~ '^https://'),
  redirect_uris text[] NOT NULL CHECK (cardinality(redirect_uris) <= 32),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  retired_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  CHECK ((auth_method = 'private_key_jwt') = (jwks_uri IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE UNIQUE INDEX idp_clients_client_id ON access.idp_clients (client_id);

CREATE FUNCTION access.idp_client_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.client_id IS DISTINCT FROM OLD.client_id OR NEW.client_uuid IS DISTINCT FROM OLD.client_uuid
     OR OLD.status = 'retired' THEN
    RAISE EXCEPTION 'client %: the id is fixed and a retired client stays retired', OLD.client_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

-- OP-146 m.4 (f), m.8 (e), IDP-5, §11.3: realm settings; the Genesis defaults need no decision
CREATE TABLE access.idp_realm_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  jose_alg text NOT NULL DEFAULT 'ES256' CHECK (jose_alg IN ('ES256', 'Ed25519')),
  argon2_m_kib integer NOT NULL DEFAULT 7168 CHECK (argon2_m_kib >= 7168),
  argon2_t integer NOT NULL DEFAULT 5 CHECK (argon2_t >= 5),
  argon2_p integer NOT NULL DEFAULT 1 CHECK (argon2_p >= 1),
  rp_id text CHECK (rp_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  cimd_enabled boolean NOT NULL DEFAULT false,
  cimd_domains text[] NOT NULL DEFAULT '{}' CHECK (cardinality(cimd_domains) <= 64),
  domain_id bytea,
  decision_pos bigint,
  CHECK ((domain_id IS NULL) = (decision_pos IS NULL)),
  CHECK (decision_pos IS NOT NULL OR (jose_alg = 'ES256' AND argon2_m_kib = 7168 AND argon2_t = 5
         AND argon2_p = 1 AND rp_id IS NULL AND NOT cimd_enabled AND cimd_domains = '{}')),
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- OP-33: Argon2 parameters only rise
CREATE FUNCTION access.idp_argon2_raise() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.argon2_m_kib < OLD.argon2_m_kib OR NEW.argon2_t < OLD.argon2_t OR NEW.argon2_p < OLD.argon2_p THEN
    RAISE EXCEPTION 'realm %: Argon2 parameters may only be raised', OLD.realm_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

-- TN-117, must-never #18, §9.9.4: token claims set from profile attributes; reserved protocol
-- claims cannot be defined
CREATE TABLE access.idp_claim_mappers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  claim text NOT NULL CHECK (claim ~ '^[a-z][a-z0-9_]{0,63}$' AND claim <> ALL (ARRAY[
    'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'act', 'may_act', 'cnf', 'scope', 'client_id',
    'nonce', 'auth_time', 'acr', 'amr', 'azp', 'sid', 'at_hash', 'c_hash', 'authorization_details'])),
  source text CHECK (source ~ '^[a-z][a-z0-9_]{0,63}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
  removed_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  CHECK ((status = 'removed') = (removed_at IS NOT NULL)),
  CHECK ((status = 'active') = (source IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, claim),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_clients
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.register');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_clients
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.update', 'idp.client.retire');
CREATE TRIGGER idp_client_fixed BEFORE UPDATE ON access.idp_clients
  FOR EACH ROW EXECUTE FUNCTION access.idp_client_fixed();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound();
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.jose_alg', 'idp.realm.argon2',
                                                 'idp.realm.rp_id', 'idp.client.cimd_policy');
CREATE TRIGGER idp_argon2_raise BEFORE UPDATE ON access.idp_realm_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_argon2_raise();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_claim_mappers
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.mapper.set');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_claim_mappers
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.mapper.set');

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_config_log', 'idp_clients', 'idp_realm_settings', 'idp_claim_mappers'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
    EXECUTE format('CREATE POLICY realm_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
END
$$;

-- OP-17, OP-73: the binding log is append-only
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_config_log
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.idp_config_log
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.idp_log_xact() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_bound() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_client_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_argon2_raise() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_config_log TO access_app;
GRANT SELECT, INSERT, UPDATE ON access.idp_clients, access.idp_realm_settings, access.idp_claim_mappers
  TO access_app;

RESET ROLE;
