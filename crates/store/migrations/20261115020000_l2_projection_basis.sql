-- INV-5, OP-154 m.3 (m), §9.9 table: the basis an authority token family was decided on. A
-- token's state is the state of its lineage: once a Grant or Anchor above the basis ends, the
-- family's tokens introspect inactive and no refresh of it is decided again. The row is written
-- when the family opens and never changes (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.projection_basis (
  domain_id bytea NOT NULL,
  family_id bytea NOT NULL CHECK (octet_length(family_id) = 16),
  basis bytea NOT NULL CHECK (octet_length(basis) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, family_id),
  FOREIGN KEY (domain_id, family_id) REFERENCES access.projection_family (domain_id, family_id)
);

ALTER TABLE access.projection_basis ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.projection_basis FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.projection_basis FROM PUBLIC;
CREATE POLICY rows ON access.projection_basis AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.projection_basis AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.projection_basis
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.projection_basis
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.projection_basis TO access_sequencer;
GRANT SELECT ON access.projection_basis TO access_app;

RESET ROLE;
