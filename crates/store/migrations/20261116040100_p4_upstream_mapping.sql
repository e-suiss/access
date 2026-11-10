-- L6 (ii), TN-117, OP-148 m.4 (b), OP-155 m.3 (h): a group whose members an upstream issues is
-- the upstream's mapping, written only under a committed idp.upstream.mapping ALLOW (reserved,
-- CT3); an administrator-issued group stays idp.group.create.
SET LOCAL ROLE access_migrator;

DROP TRIGGER idp_bound ON access.idp_groups;
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_groups
  FOR EACH ROW WHEN (NEW.membership_issuer = 'admin')
  EXECUTE FUNCTION access.idp_bound('idp.group.create');
CREATE TRIGGER idp_bound_upstream BEFORE INSERT ON access.idp_groups
  FOR EACH ROW WHEN (NEW.membership_issuer <> 'admin')
  EXECUTE FUNCTION access.idp_bound('idp.upstream.mapping');

RESET ROLE;
