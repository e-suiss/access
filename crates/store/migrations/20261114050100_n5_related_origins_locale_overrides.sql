-- TN-18, IDP-5, OP-153 m.3 (s), (u), XI-25, X35: lane N5. A realm's Related Origins list and its
-- message overrides are idp.* configuration, written only against a committed ALLOW bound in the
-- same transaction (EI-25): idp.realm.related_origins names only origins under the realm's
-- verified domains, at most five registrable labels; idp.realm.locale_overrides never names a
-- protected message. One row per realm, replaced by the next decision, never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_realm_related_origins (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  origins text[] NOT NULL CHECK (cardinality(origins) <= 16),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TABLE access.idp_realm_locale_overrides (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  overrides bytea NOT NULL CHECK (octet_length(overrides) <= 65536),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_related_origins
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.related_origins');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_related_origins
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.related_origins');
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_locale_overrides
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.locale_overrides');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_locale_overrides
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.locale_overrides');

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_realm_related_origins', 'idp_realm_locale_overrides'] LOOP
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON access.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
