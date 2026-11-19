-- TN-159: a sign-in with a provider identity linked to no account, whose vouched address is
-- another account's, waits here while the person signs in to that account in the same browser.
-- It names the provider identity by its keyed digest, lives ten minutes, is used once and never
-- removed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_pending_links (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  pending_id uuid NOT NULL DEFAULT uuidv7(),
  device_hash bytea NOT NULL CHECK (octet_length(device_hash) = 32),
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{0,63}$'),
  -- pii:none
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  subject_id uuid NOT NULL,
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  used_ms bigint,
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 600000),
  PRIMARY KEY (tenant_id, environment_id, pending_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id),
  FOREIGN KEY (tenant_id, environment_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, environment_id, subject_id)
);
CREATE INDEX identity_pending_links_device
  ON access.identity_pending_links (tenant_id, environment_id, device_hash, pending_id);

-- TN-159: a pending link is used once; what it names never changes
CREATE FUNCTION access.identity_pending_link_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'pending links are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.used_ms IS NOT NULL OR NEW.used_ms IS NULL
     OR (NEW.tenant_id, NEW.environment_id, NEW.pending_id, NEW.device_hash, NEW.provider,
         NEW.identity_key, NEW.subject_id, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.environment_id, OLD.pending_id, OLD.device_hash,
                          OLD.provider, OLD.identity_key, OLD.subject_id, OLD.created_ms,
                          OLD.expires_ms) THEN
    RAISE EXCEPTION 'pending link transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_pending_link_transition BEFORE UPDATE OR DELETE
  ON access.identity_pending_links
  FOR EACH ROW EXECUTE FUNCTION access.identity_pending_link_transition();

ALTER TABLE access.identity_pending_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_pending_links FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_pending_links FROM PUBLIC;
CREATE POLICY rows ON access.identity_pending_links AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_pending_links AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-132 m.5
CREATE POLICY environment_scope ON access.identity_pending_links AS RESTRICTIVE TO access_app
  USING (environment_id = (SELECT access.environment_scope()))
  WITH CHECK (environment_id = (SELECT access.environment_scope()));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_pending_links
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.identity_pending_link_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_pending_links TO access_app;
GRANT UPDATE (used_ms) ON access.identity_pending_links TO access_app;

RESET ROLE;
