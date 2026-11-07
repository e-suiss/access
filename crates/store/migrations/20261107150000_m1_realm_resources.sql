-- TN-110, TN-117, TN-129, TN-132, §12.3.1, OP-150 m.11 (j), OP-151 m.2 M1, OP-73: the realm
-- resources the management API adds. Every row names a committed ALLOW of its idp.* action
-- bound in the same transaction (EI-25); nothing is deleted, a retired row stays.
SET LOCAL ROLE access_migrator;

-- TN-117: a group has exactly one membership issuer, fixed at creation
CREATE TABLE access.idp_groups (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
  membership_issuer text NOT NULL
    CHECK (membership_issuer ~ '^(admin|upstream:[a-z][a-z0-9_-]{0,63})$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  retired_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, name),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE FUNCTION access.idp_group_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.name IS DISTINCT FROM OLD.name OR NEW.membership_issuer IS DISTINCT FROM OLD.membership_issuer
     OR OLD.status = 'retired' THEN
    RAISE EXCEPTION 'group %: the name and membership issuer are fixed and a retired group stays retired',
      OLD.name USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

-- TN-117: members of an administration-issued group, by internal subject id
CREATE TABLE access.idp_group_members (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  group_name text NOT NULL,
  subject_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
  removed_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  CHECK ((status = 'removed') = (removed_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, group_name, subject_id),
  FOREIGN KEY (tenant_id, realm_id, group_name)
    REFERENCES access.idp_groups (tenant_id, realm_id, name),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- TN-117: only the administration issues members through idp.group.members_*
CREATE FUNCTION access.idp_member_admin_issued() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.idp_groups g
                  WHERE g.tenant_id = NEW.tenant_id AND g.realm_id = NEW.realm_id
                    AND g.name = NEW.group_name AND g.membership_issuer = 'admin'
                    AND (g.status = 'active' OR NEW.status = 'removed')) THEN
    RAISE EXCEPTION 'group %: members are issued elsewhere or the group is retired', NEW.group_name
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

-- OP-150 m.11 (j): an upstream provider's storage contract; its secret only by reference
CREATE TABLE access.idp_upstreams (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$'),
  issuer text NOT NULL CHECK (length(issuer) <= 2048 AND issuer ~ '^https://'),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
  client_secret_ref text CHECK (client_secret_ref ~ '^secret://[A-Za-z0-9/._-]{1,246}$'),
  jwks_uri text NOT NULL CHECK (length(jwks_uri) <= 2048 AND jwks_uri ~ '^https://'),
  ssf_configuration_uri text CHECK (length(ssf_configuration_uri) <= 2048
                                    AND ssf_configuration_uri ~ '^https://'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  retired_at timestamptz,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, name),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

CREATE FUNCTION access.idp_upstream_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.name IS DISTINCT FROM OLD.name OR OLD.status = 'retired' THEN
    RAISE EXCEPTION 'upstream %: the name is fixed and a retired provider stays retired', OLD.name
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

-- TN-129, TN-132: the realm's sign-in requirements and console session policy, deterministic
-- CBOR; no row means the defaults
CREATE TABLE access.idp_realm_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  signin_policy bytea CHECK (octet_length(signin_policy) <= 32768),
  session_policy bytea CHECK (octet_length(session_policy) <= 1024),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- §12.3.1, TN-49: decided suspensions and reactivations; append-only. The subject's status
-- changes in the same transaction.
CREATE TABLE access.idp_account_changes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('idp.account.suspend', 'idp.account.reactivate')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  PRIMARY KEY (tenant_id, domain_id, decision_pos),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);

-- CR-38, OP-151 m.2 M1: a rotated secret stays valid until its overlap ends
ALTER TABLE access.idp_clients
  ADD COLUMN previous_secret_hash bytea CHECK (octet_length(previous_secret_hash) = 32),
  ADD COLUMN previous_secret_until timestamptz,
  ADD CONSTRAINT idp_clients_previous_secret
    CHECK ((previous_secret_hash IS NULL) = (previous_secret_until IS NULL));
DROP TRIGGER idp_bound_change ON access.idp_clients;
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_clients
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.update', 'idp.client.retire',
                                                 'idp.client.secret_rotate');

CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_groups
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.group.create');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_groups
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.group.update', 'idp.group.retire');
CREATE TRIGGER idp_group_fixed BEFORE UPDATE ON access.idp_groups
  FOR EACH ROW EXECUTE FUNCTION access.idp_group_fixed();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_group_members
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.group.members_add');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_group_members
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.group.members_add',
                                                 'idp.group.members_remove', 'idp.group.retire');
CREATE TRIGGER idp_member_admin_issued BEFORE INSERT OR UPDATE ON access.idp_group_members
  FOR EACH ROW EXECUTE FUNCTION access.idp_member_admin_issued();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_upstreams
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.upstream.register');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_upstreams
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.upstream.update', 'idp.upstream.retire');
CREATE TRIGGER idp_upstream_fixed BEFORE UPDATE ON access.idp_upstreams
  FOR EACH ROW EXECUTE FUNCTION access.idp_upstream_fixed();
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_realm_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.signin_policy',
                                                 'idp.realm.session_policy');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.idp_realm_policies
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.signin_policy',
                                                 'idp.realm.session_policy');
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_account_changes
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.account.suspend', 'idp.account.reactivate');

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_groups', 'idp_group_members', 'idp_upstreams',
                           'idp_realm_policies', 'idp_account_changes'] LOOP
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
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

CREATE TRIGGER append_only_row BEFORE UPDATE ON access.idp_account_changes
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.idp_group_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_member_admin_issued() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.idp_upstream_fixed() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON access.idp_groups, access.idp_group_members, access.idp_upstreams,
  access.idp_realm_policies TO access_app;
GRANT SELECT, INSERT ON access.idp_account_changes TO access_app;

RESET ROLE;
