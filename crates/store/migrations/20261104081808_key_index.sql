-- OP-149 m.5, CMP-9, INV-33: the derived history of Instance keys by RFC 7638 thumbprint. The
-- deriver writes it from the domain log next to the Grant index; it answers key lookups at a
-- ledger position and is never a commit input.
-- OP-149 m.4: the tenant snapshot reads every tenant's status through the router role.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_derived.key_index (
  domain_id bytea NOT NULL,
  kid bytea NOT NULL CHECK (octet_length(kid) = 32),
  instance_id bytea NOT NULL CHECK (octet_length(instance_id) = 16),
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  public_key bytea NOT NULL,
  since_pos bigint NOT NULL CHECK (since_pos >= 0),
  since_at bigint NOT NULL CHECK (since_at >= 0),
  ended_pos bigint CHECK (ended_pos >= since_pos),
  ended_at bigint CHECK (ended_at >= 0),
  successor_id bytea CHECK (successor_id IS NULL OR octet_length(successor_id) = 16),
  pos bigint NOT NULL CHECK (pos >= 0),
  CHECK ((ended_pos IS NULL) = (ended_at IS NULL)),
  PRIMARY KEY (domain_id, kid)
);

ALTER TABLE access_derived.key_index ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_derived.key_index FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_derived.key_index FROM PUBLIC;
CREATE POLICY rows ON access_derived.key_index AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access_derived.key_index AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
GRANT SELECT, INSERT, UPDATE ON access_derived.key_index TO access_deriver;
GRANT SELECT ON access_derived.key_index TO access_app;

CREATE POLICY router_reads ON access.tenants AS RESTRICTIVE TO access_router
  USING (true) WITH CHECK (false);
GRANT SELECT (tenant_id, status) ON access.tenants TO access_router;

RESET ROLE;
