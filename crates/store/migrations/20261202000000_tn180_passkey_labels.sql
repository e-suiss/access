-- TN-180: the name a person gave a passkey when adding it, for the account page's list. A newer
-- name for the same credential replaces it by being newer. Nothing is changed or deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_passkey_labels (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  label_id uuid NOT NULL DEFAULT uuidv7(),
  credential_id uuid NOT NULL,
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  PRIMARY KEY (tenant_id, environment_id, label_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id)
);
CREATE INDEX identity_passkey_labels_latest
  ON access.identity_passkey_labels (tenant_id, environment_id, credential_id, created_ms DESC);

ALTER TABLE access.identity_passkey_labels ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_passkey_labels FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_passkey_labels FROM PUBLIC;
CREATE POLICY rows ON access.identity_passkey_labels AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_passkey_labels AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-132 m.5
CREATE POLICY environment_scope ON access.identity_passkey_labels AS RESTRICTIVE TO access_app
  USING (environment_id = (SELECT access.environment_scope()))
  WITH CHECK (environment_id = (SELECT access.environment_scope()));
CREATE TRIGGER append_only_mutation BEFORE UPDATE OR DELETE ON access.identity_passkey_labels
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_passkey_labels
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.identity_passkey_labels TO access_app;

RESET ROLE;
