-- OP-151 m.1 (b), m.3 (o); TN-46, TN-47, TN-108, IDP-39, §4.4, CI-2, MD-8, EI-25, OP-47, OP-73.
-- (a) The realm's protection mode, `idp.realm.protection_mode`: per protection monitor or
--     enforce, the SL2 stage and the denied ASNs; written only against a committed ALLOW bound in
--     its own transaction. A realm without a row runs the defaults (monitor, shadow).
-- (b) Canary accounts, `idp.account.canary` (§4.4): a matched canary credential never obtains a
--     session.
-- (c) What SL2 keeps of a subject's last sign-in: when, the address as a keyed pseudonym and its
--     /24 or /48 prefix, the coarse place and the last level. Never the address itself.
-- (d) The human review queue (TN-46, GDPR art. 22): one item per SL2 step-up request, actual or
--     shadowed, and per high level; a person marks it. Risk never locks an account.
-- Rows hold ids, digests, closed codes and coarse places; nothing is deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.realm_protection (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  bot text NOT NULL CHECK (bot IN ('monitor', 'enforce')),
  suspicious_ip text NOT NULL CHECK (suspicious_ip IN ('monitor', 'enforce')),
  breached_password text NOT NULL CHECK (breached_password IN ('monitor', 'enforce')),
  sl2 text NOT NULL CHECK (sl2 IN ('shadow', 'stepup', 'stepup_caep')),
  denied_asns bigint[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(denied_asns) <= 1024 AND 0 < ALL (denied_asns)
           AND 4294967295 >= ALL (denied_asns)),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TABLE access.risk_canary (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TRIGGER idp_bound BEFORE INSERT ON access.realm_protection
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.protection_mode');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.realm_protection
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.protection_mode');
CREATE TRIGGER idp_bound BEFORE INSERT ON access.risk_canary
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.account.canary');
CREATE TRIGGER append_only_row BEFORE UPDATE ON access.risk_canary
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.risk_subject (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  last_at_ms bigint NOT NULL CHECK (last_at_ms > 0),
  ip_pseudonym bytea CHECK (ip_pseudonym IS NULL OR octet_length(ip_pseudonym) = 32),
  ip_prefix text CHECK (ip_prefix IS NULL OR ip_prefix ~ '^[0-9a-f.:]{2,40}/(24|48)$'),
  country text CHECK (country IS NULL OR country ~ '^[A-Z]{2}$'),
  asn bigint CHECK (asn IS NULL OR asn BETWEEN 1 AND 4294967295),
  lat_cdeg integer CHECK (lat_cdeg IS NULL OR lat_cdeg BETWEEN -9000 AND 9000),
  lon_cdeg integer CHECK (lon_cdeg IS NULL OR lon_cdeg BETWEEN -18000 AND 18000),
  level text CHECK (level IS NULL OR level IN ('low', 'medium', 'high')),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((lat_cdeg IS NULL) = (lon_cdeg IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

CREATE TABLE access.risk_review (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  review_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  level text NOT NULL CHECK (level IN ('unavailable', 'low', 'medium', 'high')),
  signals text[] NOT NULL CHECK (cardinality(signals) <= 16),
  mode text NOT NULL CHECK (mode IN ('shadow', 'stepup', 'stepup_caep')),
  reason text NOT NULL CHECK (reason IN ('step_up', 'shadow_step_up', 'high', 'canary_hit')),
  state text NOT NULL DEFAULT 'open'
    CHECK (state IN ('open', 'confirmed', 'false_positive', 'dismissed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  decided_by text CHECK (decided_by IS NULL OR decided_by ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  CHECK ((state = 'open') = (decided_at IS NULL)),
  CHECK ((decided_at IS NULL) = (decided_by IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, review_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX risk_review_open ON access.risk_review (tenant_id, realm_id, created_at)
  WHERE state = 'open';
CREATE INDEX risk_review_day ON access.risk_review (tenant_id, realm_id, created_at);

-- TN-46: a decided review is a record; only an open one is decided, once
CREATE FUNCTION access.risk_review_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF OLD.state <> 'open' THEN
    RAISE EXCEPTION 'risk_review: a decided review never changes' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tenant_id, NEW.realm_id, NEW.review_id, NEW.subject_id, NEW.level, NEW.signals, NEW.mode,
      NEW.reason, NEW.created_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.realm_id, OLD.review_id, OLD.subject_id, OLD.level, OLD.signals, OLD.mode,
      OLD.reason, OLD.created_at) THEN
    RAISE EXCEPTION 'risk_review: only the decision changes' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.risk_review_rules() FROM PUBLIC;
CREATE TRIGGER risk_review_rules BEFORE UPDATE ON access.risk_review
  FOR EACH ROW EXECUTE FUNCTION access.risk_review_rules();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['realm_protection', 'risk_canary', 'risk_subject', 'risk_review'] LOOP
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
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE ON access.realm_protection TO access_app;
GRANT SELECT, INSERT ON access.risk_canary TO access_app;
GRANT SELECT, INSERT, UPDATE ON access.risk_subject TO access_app;
GRANT SELECT, INSERT ON access.risk_review TO access_app;
GRANT UPDATE (state, decided_at, decided_by) ON access.risk_review TO access_app;

RESET ROLE;
