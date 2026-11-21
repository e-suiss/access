-- TN-177: the organization a person chose to continue with for an app that asked for the
-- `organization` scope. A choice counts only for the sign-in it followed; a later choice for the
-- same app replaces it by being newer. It names context, never authority. Nothing is changed or
-- deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_organization_choices (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  choice_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  organization_party bytea NOT NULL CHECK (octet_length(organization_party) = 16),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  PRIMARY KEY (tenant_id, environment_id, choice_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id)
);
CREATE INDEX identity_organization_choices_latest
  ON access.identity_organization_choices (tenant_id, environment_id, subject_id, client_uuid, created_ms DESC);

ALTER TABLE access.identity_organization_choices ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_organization_choices FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_organization_choices FROM PUBLIC;
CREATE POLICY rows ON access.identity_organization_choices AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_organization_choices AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-132 m.5
CREATE POLICY environment_scope ON access.identity_organization_choices AS RESTRICTIVE TO access_app
  USING (environment_id = (SELECT access.environment_scope()))
  WITH CHECK (environment_id = (SELECT access.environment_scope()));
CREATE TRIGGER append_only_mutation BEFORE UPDATE OR DELETE ON access.identity_organization_choices
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_organization_choices
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.identity_organization_choices TO access_app;

RESET ROLE;
