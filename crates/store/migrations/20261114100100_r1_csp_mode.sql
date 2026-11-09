-- OP-153 m.22 (g), m.25 (b), EI-25: the hosted page's CSP mode lives in the branding record and
-- changes by its own actions, `idp.realm.csp_mode` (tightening, CT1) and
-- `idp.realm.csp_mode_loosen` (CT2); the row accepts a committed ALLOW of either beside
-- `idp.realm.branding`
SET LOCAL ROLE access_migrator;

DROP TRIGGER idp_bound ON access.idp_realm_branding;
DROP TRIGGER idp_bound_change ON access.idp_realm_branding;
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_branding
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.branding', 'idp.realm.csp_mode',
                                                 'idp.realm.csp_mode_loosen');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_branding
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.branding', 'idp.realm.csp_mode',
                                                 'idp.realm.csp_mode_loosen');

RESET ROLE;
