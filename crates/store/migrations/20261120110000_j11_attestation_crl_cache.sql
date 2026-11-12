-- OP-159 m.3 (ll), §10.2.4: the CRLs a server fetched for the distribution points of WebAuthn
-- attestation chains under a realm's direct policy, one row per URL and CRL content, so every
-- process and a restart reuse a current CRL instead of the URL. A row is the raw CRL; a reader
-- checks its signature, nextUpdate and serials again during path validation. The cache belongs
-- to the cell, not to a tenant: its rows sit under the nil tenant id. Nothing is replaced or
-- deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.attestation_crl_cache (
  tenant_id uuid NOT NULL CHECK (tenant_id = '00000000-0000-0000-0000-000000000000'),
  source bytea NOT NULL CHECK (octet_length(source) = 32),
  url text NOT NULL CHECK (char_length(url) BETWEEN 9 AND 512),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  next_update_s bigint NOT NULL CHECK (next_update_s >= 0),
  crl bytea NOT NULL CHECK (octet_length(crl) BETWEEN 1 AND 1048576),
  fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, source, digest)
);
CREATE INDEX attestation_crl_cache_newest
  ON access.attestation_crl_cache (tenant_id, source, fetched_at DESC);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.attestation_crl_cache
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.attestation_crl_cache
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.attestation_crl_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.attestation_crl_cache FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.attestation_crl_cache FROM PUBLIC;
CREATE POLICY rows ON access.attestation_crl_cache AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.attestation_crl_cache AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
GRANT SELECT, INSERT ON access.attestation_crl_cache TO access_app;

RESET ROLE;
