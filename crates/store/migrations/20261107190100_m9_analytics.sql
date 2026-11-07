-- OP-151 m.3 (n); IDP-36, TI-18, OP-47, OP-73.
-- Tenant analytics as DERIVED daily summaries per realm: counters only, no identifier and no
-- pseudonym, recomputed from the sign-in flows, credentials, audit log and review queue by the
-- daily job. Never a decision input. The realm breakdown lives here, never in metric labels.
-- A failed-login surge leaves an alert row. Rows are overwritten by recomputation, never deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.analytics_daily (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  day integer NOT NULL CHECK (day >= 0),
  flows_started bigint NOT NULL CHECK (flows_started >= 0),
  identifier_entered bigint NOT NULL CHECK (identifier_entered >= 0),
  first_factor_passed bigint NOT NULL CHECK (first_factor_passed >= 0),
  second_factor_passed bigint NOT NULL CHECK (second_factor_passed >= 0),
  sessions_created bigint NOT NULL CHECK (sessions_created >= 0),
  method_password bigint NOT NULL CHECK (method_password >= 0),
  method_passkey bigint NOT NULL CHECK (method_passkey >= 0),
  method_email_code bigint NOT NULL CHECK (method_email_code >= 0),
  method_magic_link bigint NOT NULL CHECK (method_magic_link >= 0),
  accounts_active bigint NOT NULL CHECK (accounts_active >= 0),
  accounts_with_passkey bigint NOT NULL CHECK (accounts_with_passkey >= 0),
  accounts_with_mfa bigint NOT NULL CHECK (accounts_with_mfa >= 0),
  mfa_setup_started bigint NOT NULL CHECK (mfa_setup_started >= 0),
  mfa_setup_completed bigint NOT NULL CHECK (mfa_setup_completed >= 0),
  failed_logins bigint NOT NULL CHECK (failed_logins >= 0),
  risk_step_ups bigint NOT NULL CHECK (risk_step_ups >= 0),
  risk_reviews bigint NOT NULL CHECK (risk_reviews >= 0),
  risk_false_positives bigint NOT NULL CHECK (risk_false_positives >= 0),
  computed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, day),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

CREATE TABLE access.analytics_alert (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  day integer NOT NULL CHECK (day >= 0),
  kind text NOT NULL CHECK (kind IN ('failed_login_surge')),
  observed bigint NOT NULL CHECK (observed >= 0),
  baseline bigint NOT NULL CHECK (baseline >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, realm_id, day, kind),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['analytics_daily', 'analytics_alert'] LOOP
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

GRANT SELECT, INSERT, UPDATE ON access.analytics_daily TO access_app;
GRANT SELECT, INSERT ON access.analytics_alert TO access_app;

RESET ROLE;
