-- OP-148, OP-146 m.4 (d), OP-158 m.3 (y): the FIDO metadata blobs a server fetched from its
-- configured URL, one row per serial, so every process and a restart start from the last
-- verified blob instead of the URL. A row is the raw JWT; a reader verifies it again against
-- its own root and trusted time. The blob belongs to the cell, not to a tenant: its rows sit
-- under the nil tenant id, so the tenant scope rules hold for them as for every other table. A
-- serial is never replaced, and nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.mds_cache (
  tenant_id uuid NOT NULL CHECK (tenant_id = '00000000-0000-0000-0000-000000000000'),
  source bytea NOT NULL CHECK (octet_length(source) = 32),
  serial bigint NOT NULL CHECK (serial >= 0),
  next_update_s bigint NOT NULL CHECK (next_update_s >= 0),
  blob bytea NOT NULL CHECK (octet_length(blob) BETWEEN 1 AND 33554432),
  fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, source, serial)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.mds_cache
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.mds_cache
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.mds_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.mds_cache FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.mds_cache FROM PUBLIC;
CREATE POLICY rows ON access.mds_cache AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.mds_cache AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
GRANT SELECT, INSERT ON access.mds_cache TO access_app;

RESET ROLE;
