-- OP-151 m.10 (e), m.11 (h), MD-14, EI-25: what a realm's extension points may reach and
-- receive is realm configuration, written only against a committed ALLOW of
-- idp.realm.extension_policy, next to the realm's other policies. Nothing stored is the default:
-- no private target, no disclosure.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_realm_policies
  ADD COLUMN extension_policy bytea CHECK (octet_length(extension_policy) <= 1024);

DROP TRIGGER idp_bound ON access.idp_realm_policies;
DROP TRIGGER idp_bound_change ON access.idp_realm_policies;
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.signin_policy',
                                                 'idp.realm.session_policy',
                                                 'idp.realm.extension_policy');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.signin_policy',
                                                 'idp.realm.session_policy',
                                                 'idp.realm.extension_policy');

RESET ROLE;
