-- OP-156 m.3 (o), IDP-32: the realm's SSH user certificate authority. The CA is turned on, off,
-- rotated or replaced only under a committed idp.ssh.* ALLOW; access-server brings the identity
-- signer's ssh-ca keys in line with the newest change and records every key's phase, so that
-- ca.pub names the keys servers trust and the KRL names every key that no longer signs. Server
-- groups are the resources of ssh.login Grants. A certificate is a projection.issue projection:
-- its record names the Exercise and the intent it was allowed for, and a revocation (its basis
-- ended, its CA key replaced or turned off) is a row of its own. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

-- one row per idp.ssh.ca_enable, ca_disable, ca_rotate or ca_emergency; the newest rules
CREATE TABLE access.ssh_ca_changes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  change text NOT NULL CHECK (change IN ('enable', 'disable', 'rotate', 'emergency')),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.ssh_ca_changes
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.ssh.ca_enable', 'idp.ssh.ca_disable',
                                                 'idp.ssh.ca_rotate', 'idp.ssh.ca_emergency');

-- one row per phase a CA key enters, following the change it carries out; the newest row of a
-- key is its phase. 'revoked' keys are in the KRL; 'removed' keys signed nothing still valid.
CREATE TABLE access.ssh_ca_keys (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  version bigint NOT NULL CHECK (version >= 1),
  phase text NOT NULL CHECK (phase IN ('published', 'active', 'retiring', 'removed', 'revoked')),
  since_ms bigint NOT NULL CHECK (since_ms >= 0),
  change_version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, public_key, version),
  FOREIGN KEY (tenant_id, realm_id, change_version)
    REFERENCES access.ssh_ca_changes (tenant_id, realm_id, version)
);
CREATE INDEX ssh_ca_keys_change ON access.ssh_ca_keys (tenant_id, realm_id, change_version);

-- one row per idp.ssh.host_group_register or host_group_retire; a retired name is never reused
CREATE TABLE access.ssh_host_groups (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'retired')),
  description text NOT NULL CHECK (char_length(description) <= 256),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.ssh_host_groups
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.ssh.host_group_register',
                                                 'idp.ssh.host_group_retire');

-- one row per issued certificate; the serial is the u64 drawn from the RNG, stored bit for bit
CREATE TABLE access.ssh_certificates (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  ca_key bytea NOT NULL CHECK (octet_length(ca_key) = 32),
  serial bigint NOT NULL CHECK (serial <> 0),
  key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  exercise bytea NOT NULL CHECK (octet_length(exercise) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos >= 0),
  intent bytea NOT NULL CHECK (octet_length(intent) BETWEEN 1 AND 65536),
  holder text NOT NULL CHECK (holder IN ('person', 'agent')),
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  host_group text NOT NULL CHECK (host_group ~ '^[a-z][a-z0-9-]{0,62}$'),
  principals text[] NOT NULL CHECK (cardinality(principals) BETWEEN 1 AND 256),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  valid_after bigint NOT NULL CHECK (valid_after >= 0),
  valid_before bigint NOT NULL,
  issued_ms bigint NOT NULL CHECK (issued_ms > 0),
  CHECK (valid_before > valid_after),
  PRIMARY KEY (tenant_id, realm_id, ca_key, serial),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE UNIQUE INDEX ssh_certificates_exercise ON access.ssh_certificates (tenant_id, realm_id, exercise);
CREATE INDEX ssh_certificates_valid ON access.ssh_certificates (tenant_id, realm_id, valid_before);

-- one row per revoked certificate; the KRL lists every one still within its validity
CREATE TABLE access.ssh_revocations (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  ca_key bytea NOT NULL,
  serial bigint NOT NULL,
  reason text NOT NULL CHECK (reason IN ('basis-ended', 'ca-replaced', 'ca-off')),
  revoked_ms bigint NOT NULL CHECK (revoked_ms > 0),
  PRIMARY KEY (tenant_id, realm_id, ca_key, serial),
  FOREIGN KEY (tenant_id, realm_id, ca_key, serial)
    REFERENCES access.ssh_certificates (tenant_id, realm_id, ca_key, serial)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ssh_ca_changes', 'ssh_ca_keys', 'ssh_host_groups', 'ssh_certificates',
                           'ssh_revocations'] LOOP
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I
                      FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I
                      FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format(
      'CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app
         USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
         WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))',
      t);
    EXECUTE format('GRANT SELECT, INSERT ON access.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
