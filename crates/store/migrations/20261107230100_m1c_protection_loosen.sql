-- OP-151 m.14 (f), EI-25: a protection mode change that loosens anything is its own action,
-- `idp.realm.protection_mode_loosen` (CT2), beside the tightening `idp.realm.protection_mode`
-- (CT1); the row accepts a committed ALLOW of either
SET LOCAL ROLE access_migrator;

DROP TRIGGER idp_bound ON access.realm_protection;
DROP TRIGGER idp_bound_change ON access.realm_protection;
CREATE TRIGGER idp_bound BEFORE INSERT ON access.realm_protection
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.protection_mode',
                                                 'idp.realm.protection_mode_loosen');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.realm_protection
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.protection_mode',
                                                 'idp.realm.protection_mode_loosen');

RESET ROLE;
