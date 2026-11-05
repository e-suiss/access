-- TN-106, TN-118, §13.2, §9.9.6, P55, MD-14: a realm's branding and its decided JOSE key
-- changes are idp.* configuration, written only against a committed ALLOW bound in the same
-- transaction (EI-25); claim mappers name neither authority claims nor sources outside the
-- subject's standard profile.
SET LOCAL ROLE access_migrator;

-- TN-106: branding is data the hosted page draws, never a template; one row per realm
CREATE TABLE access.idp_realm_branding (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  branding bytea NOT NULL CHECK (octet_length(branding) <= 4096),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- TN-118, §13.2, §13.7.7: decided policy changes, rotations and drops of the realm's JOSE keys;
-- a drop carries the issuer cutoff it declares. Append-only.
CREATE TABLE access.idp_realm_key_changes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  action text NOT NULL
    CHECK (action IN ('idp.realm.key_policy', 'idp.realm.key_rotate', 'idp.realm.key_drop')),
  kid bytea CHECK (octet_length(kid) = 32),
  policy bytea CHECK (octet_length(policy) <= 1024),
  compromised_at_ms bigint CHECK (compromised_at_ms >= 0),
  declared_at_ms bigint NOT NULL CHECK (declared_at_ms >= 0),
  cutoff_at_ms bigint CHECK (cutoff_at_ms >= 0),
  CHECK ((action = 'idp.realm.key_policy') = (policy IS NOT NULL)),
  CHECK ((action = 'idp.realm.key_policy') = (kid IS NULL)),
  CHECK ((action = 'idp.realm.key_drop') = (cutoff_at_ms IS NOT NULL)),
  CHECK (compromised_at_ms IS NULL OR action = 'idp.realm.key_drop'),
  PRIMARY KEY (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_branding
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.branding');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_branding
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.branding');
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_key_changes
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.key_policy', 'idp.realm.key_rotate',
                                                 'idp.realm.key_drop');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_realm_key_changes
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.idp_realm_key_changes
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.idp_realm_branding
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.idp_realm_branding
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_realm_branding', 'idp_realm_key_changes'] LOOP
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

GRANT SELECT, INSERT, UPDATE ON access.idp_realm_branding TO access_app;
GRANT SELECT, INSERT ON access.idp_realm_key_changes TO access_app;

-- §9.9.6, P55, S-1, INV-33: a mapper defines no authority claim and takes its value only from
-- the subject's standard profile
ALTER TABLE access.idp_claim_mappers DROP CONSTRAINT idp_claim_mappers_claim_check;
ALTER TABLE access.idp_claim_mappers ADD CONSTRAINT idp_claim_mappers_claim_check
  CHECK (claim ~ '^[a-z][a-z0-9_]{0,63}$' AND claim <> ALL (ARRAY[
    'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'act', 'may_act', 'cnf', 'scope', 'client_id',
    'nonce', 'auth_time', 'acr', 'amr', 'azp', 'sid', 'at_hash', 'c_hash', 'authorization_details',
    'roles', 'role', 'groups', 'entitlements', 'permissions', 'access_contract', 'family', 'rev',
    'status', 'events']));
ALTER TABLE access.idp_claim_mappers DROP CONSTRAINT idp_claim_mappers_source_check;
ALTER TABLE access.idp_claim_mappers ADD CONSTRAINT idp_claim_mappers_source_check
  CHECK (source = ANY (ARRAY[
    'name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username',
    'profile', 'picture', 'website', 'email', 'email_verified', 'gender', 'birthdate', 'zoneinfo',
    'locale', 'phone_number', 'phone_number_verified', 'updated_at']));

RESET ROLE;
