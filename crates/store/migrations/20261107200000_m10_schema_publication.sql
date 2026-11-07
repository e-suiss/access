-- §8.17.10.2, §9.13, E10, X21, OP-151 m.2 (M10): Schema Publication Packages as their publisher
-- published them, by fingerprint. A published version is immutable: one row per (publisher,
-- namespace, catalog version), never updated or deleted (OP-73). A row is a statement only; it
-- changes no domain until the domain accepts its exact fingerprint with an `acceptance.amend`
-- Exercise. A package is kept once per domain it is offered to and read only within that
-- domain's scope, so neither a fingerprint nor a version becomes a cross-tenant channel (TN-20).
-- Rows hold ids, digests and the package bytes, no personal data.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.schema_publication (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
  publisher bytea NOT NULL CHECK (octet_length(publisher) = 16),
  namespace text NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 255),
  catalog_version bigint NOT NULL CHECK (catalog_version >= 0),
  package bytea NOT NULL CHECK (octet_length(package) BETWEEN 1 AND 1048576),
  published_ms bigint NOT NULL CHECK (published_ms >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, fingerprint),
  UNIQUE (domain_id, publisher, namespace, catalog_version)
);
CREATE INDEX schema_publication_namespace
  ON access.schema_publication (domain_id, namespace, catalog_version DESC);

ALTER TABLE access.schema_publication ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.schema_publication FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.schema_publication FROM PUBLIC;
CREATE POLICY rows ON access.schema_publication AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.schema_publication AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.schema_publication
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.schema_publication
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_update BEFORE UPDATE ON access.schema_publication
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.schema_publication TO access_app;

RESET ROLE;
