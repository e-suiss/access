-- OP-156 m.3 (i), §10.2.4, TN-16, TN-20: a realm's custom domains, their ACME orders and the
-- certificates the TLS listener serves for them. A registration is written only under a
-- committed idp.domain.register ALLOW; retiring it needs idp.domain.retire and binding it as the
-- realm's issuer or RP ID idp.domain.issuer_bind, which never comes undone. The verification
-- check moves a registration between pending, verified, lapsed and expired without a decision.
-- Only one realm holds a host verified at a time; DNS decides which (§12.3.8). Nothing is
-- deleted (OP-73): a certificate key is crypto-shredded when its certificate is superseded or
-- withdrawn.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_domains (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_uuid uuid NOT NULL,
  hostname text NOT NULL CHECK (length(hostname) <= 253
    AND hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  challenge text NOT NULL CHECK (challenge ~ '^[A-Za-z0-9_-]{43}$'),
  cname_target text NOT NULL CHECK (length(cname_target) <= 253),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'verified', 'lapsed', 'expired', 'retired')),
  finding text CHECK (length(finding) <= 64),
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  checked_at timestamptz,
  verified_at timestamptz,
  reverify_by timestamptz,
  bound_as text CHECK (bound_as IN ('issuer', 'rp_id')),
  bound_at timestamptz,
  acme_failures integer NOT NULL DEFAULT 0 CHECK (acme_failures >= 0),
  acme_next_at timestamptz,
  acme_error text CHECK (length(acme_error) <= 64),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  retire_pos bigint,
  retired_at timestamptz,
  bind_pos bigint,
  CHECK ((status = 'retired') = (retire_pos IS NOT NULL)),
  CHECK ((retire_pos IS NULL) = (retired_at IS NULL)),
  CHECK ((bound_as IS NULL) = (bind_pos IS NULL)),
  CHECK ((bound_as IS NULL) = (bound_at IS NULL)),
  CHECK (status <> 'verified' OR reverify_by IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, domain_uuid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, domain_id, retire_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, domain_id, bind_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
-- TN-20: one realm serves a host
CREATE UNIQUE INDEX realm_domains_verified ON access.realm_domains (hostname)
  WHERE status = 'verified';
CREATE UNIQUE INDEX realm_domains_live ON access.realm_domains (tenant_id, realm_id, hostname)
  WHERE status IN ('pending', 'verified', 'lapsed');
CREATE UNIQUE INDEX realm_domains_one_issuer ON access.realm_domains (tenant_id, realm_id)
  WHERE bound_as = 'issuer';

CREATE FUNCTION access.realm_domain_bound() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
DECLARE
  pos bigint;
  act text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    pos := NEW.decision_pos;
    act := 'idp.domain.register';
    IF NEW.status <> 'pending' OR NEW.bound_as IS NOT NULL OR NEW.retire_pos IS NOT NULL THEN
      RAISE EXCEPTION 'realm_domains: a registration starts pending'
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSE
    IF NEW.hostname IS DISTINCT FROM OLD.hostname OR NEW.challenge IS DISTINCT FROM OLD.challenge
       OR NEW.cname_target IS DISTINCT FROM OLD.cname_target OR NEW.domain_id IS DISTINCT FROM OLD.domain_id
       OR NEW.decision_pos IS DISTINCT FROM OLD.decision_pos
       OR NEW.registered_at IS DISTINCT FROM OLD.registered_at
       OR OLD.status IN ('retired', 'expired')
       OR (OLD.bound_as IS NOT NULL AND (NEW.bound_as IS DISTINCT FROM OLD.bound_as
           OR NEW.bind_pos IS DISTINCT FROM OLD.bind_pos)) THEN
      RAISE EXCEPTION 'realm_domains: the registration is fixed, a binding never comes undone, and a retired or expired one stays so'
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.retire_pos IS NOT NULL AND OLD.retire_pos IS NULL THEN
      pos := NEW.retire_pos;
      act := 'idp.domain.retire';
    ELSIF NEW.bind_pos IS NOT NULL AND OLD.bind_pos IS NULL THEN
      pos := NEW.bind_pos;
      act := 'idp.domain.issuer_bind';
    ELSE
      RETURN NEW;
    END IF;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM access.idp_config_log l
                  WHERE l.tenant_id = NEW.tenant_id AND l.realm_id = NEW.realm_id
                    AND l.domain_id = NEW.domain_id AND l.decision_pos = pos
                    AND l.bound_xact = pg_current_xact_id() AND l.action = act) THEN
    RAISE EXCEPTION 'realm_domains: not bound to a committed ALLOW of %', act
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER realm_domain_bound BEFORE INSERT OR UPDATE ON access.realm_domains
  FOR EACH ROW EXECUTE FUNCTION access.realm_domain_bound();

CREATE TABLE access.acme_orders (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  order_uuid uuid NOT NULL,
  domain_uuid uuid NOT NULL,
  hostname text NOT NULL,
  status text NOT NULL DEFAULT 'challenging' CHECK (status IN ('challenging', 'valid', 'failed')),
  alpn_digest bytea CHECK (octet_length(alpn_digest) = 32),
  error text CHECK (length(error) <= 64),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  CHECK ((status = 'challenging') = (ended_at IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, order_uuid),
  FOREIGN KEY (tenant_id, realm_id, domain_uuid)
    REFERENCES access.realm_domains (tenant_id, realm_id, domain_uuid)
);
CREATE UNIQUE INDEX acme_orders_one_open ON access.acme_orders (hostname)
  WHERE status = 'challenging';

CREATE TABLE access.domain_certificates (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  cert_uuid uuid NOT NULL,
  domain_uuid uuid NOT NULL,
  hostname text NOT NULL,
  chain_pem text NOT NULL CHECK (length(chain_pem) <= 65536),
  kek_id text,
  wrapped_dek bytea,
  key_nonce bytea CHECK (octet_length(key_nonce) = 12),
  key_sealed bytea,
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  renew_after timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded', 'withdrawn')),
  ended_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (not_before < not_after AND renew_after <= not_after),
  CHECK ((status = 'active') = (ended_at IS NULL)),
  CHECK ((kek_id IS NULL) = (key_sealed IS NULL) AND (wrapped_dek IS NULL) = (key_sealed IS NULL)
         AND (key_nonce IS NULL) = (key_sealed IS NULL)),
  CHECK (status <> 'active' OR key_sealed IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, cert_uuid),
  FOREIGN KEY (tenant_id, realm_id, domain_uuid)
    REFERENCES access.realm_domains (tenant_id, realm_id, domain_uuid)
);
CREATE UNIQUE INDEX domain_certificates_active ON access.domain_certificates (tenant_id, realm_id, domain_uuid)
  WHERE status = 'active';

CREATE FUNCTION access.domain_certificate_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.chain_pem IS DISTINCT FROM OLD.chain_pem OR NEW.hostname IS DISTINCT FROM OLD.hostname
     OR NEW.domain_uuid IS DISTINCT FROM OLD.domain_uuid OR NEW.not_after IS DISTINCT FROM OLD.not_after
     OR OLD.status <> 'active' AND (NEW.status IS DISTINCT FROM OLD.status OR NEW.key_sealed IS NOT NULL)
     OR (NEW.key_sealed IS NOT NULL AND NEW.key_sealed IS DISTINCT FROM OLD.key_sealed) THEN
    RAISE EXCEPTION 'domain_certificates: a certificate is fixed; it only ends and its key is only shredded'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER domain_certificate_fixed BEFORE UPDATE ON access.domain_certificates
  FOR EACH ROW EXECUTE FUNCTION access.domain_certificate_fixed();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['realm_domains', 'acme_orders', 'domain_certificates'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

-- OP-132 m.3, §17.9.6: Host resolution reads the verified custom domains across tenants, and the
-- TLS listeners the open TLS-ALPN-01 challenges; nothing else
CREATE POLICY router_reads ON access.realm_domains AS RESTRICTIVE TO access_router
  USING (status = 'verified') WITH CHECK (false);
CREATE POLICY router_reads ON access.acme_orders AS RESTRICTIVE TO access_router
  USING (status = 'challenging') WITH CHECK (false);

GRANT SELECT, INSERT, UPDATE ON access.realm_domains, access.acme_orders, access.domain_certificates
  TO access_app;
GRANT SELECT (tenant_id, realm_id, hostname, status, reverify_by, bound_as)
  ON access.realm_domains TO access_router;
GRANT SELECT (hostname, status, alpn_digest) ON access.acme_orders TO access_router;

RESET ROLE;
