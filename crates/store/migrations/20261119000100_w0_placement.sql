-- OP-158 m.3 (o), CMP-26, OP-30, TI-17: the Placement Directory. Each row is one version of where a
-- tenant, one of its realms or one of its domains is served: its cell and whether the cell is
-- dedicated. It routes requests and is never a decision input; a cell that does not lead a domain
-- refuses it. A move is a new version; nothing is changed or deleted (OP-73). Rows are scoped to
-- their tenant. Lane W9 writes it.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.placement (
  tenant_id uuid NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('tenant', 'realm', 'domain')),
  subject bytea NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 64),
  version bigint NOT NULL CHECK (version >= 1),
  cell text NOT NULL CHECK (cell ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  dedicated boolean NOT NULL DEFAULT false,
  since bigint NOT NULL CHECK (since >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, subject_kind, subject, version),
  FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.placement
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.placement
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.placement ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.placement FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.placement FROM PUBLIC;
CREATE POLICY rows ON access.placement AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.placement AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
GRANT SELECT, INSERT ON access.placement TO access_app;

RESET ROLE;
