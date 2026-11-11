-- OP-157 m.3 (v), m.4 (j), (l), §8.17.9.6, E6, TN-75: each offboarding an administrator
-- committed, one row per departure. The preview itself is a read; what is kept is the choice
-- made for every channel (direct Grants, Instances, rule-shaped holdings, the self-anchor,
-- re-entry), the departure Exercise it ended with and who committed it. A Party reads as
-- offboarded only once a row names its departure. Rows are append-only and never deleted
-- (OP-73); a later offboarding of the same Party is a new version.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.offboarding_previews (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  version bigint NOT NULL CHECK (version >= 1),
  subject_id uuid,
  choices text NOT NULL CHECK (octet_length(choices) BETWEEN 2 AND 65536),
  reentry text NOT NULL CHECK (reentry IN ('allowed', 'blocked')),
  departure bytea NOT NULL CHECK (octet_length(departure) = 32),
  departure_pos bigint NOT NULL CHECK (departure_pos > 0),
  actor bytea NOT NULL CHECK (octet_length(actor) = 32),
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, party, version),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX offboarding_previews_subject ON access.offboarding_previews
  (tenant_id, realm_id, subject_id) WHERE subject_id IS NOT NULL;

CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.offboarding_previews
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.offboarding_previews
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.offboarding_previews ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.offboarding_previews FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.offboarding_previews FROM PUBLIC;
CREATE POLICY rows ON access.offboarding_previews AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.offboarding_previews AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.offboarding_previews TO access_app;

RESET ROLE;
