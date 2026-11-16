-- OP-159 m.47 (f), TN-89 (1)-(9), (11), TN-109, TN-140, OP-73: tenant administrator invitations.
--
-- An `idp.tenant.admin_invite` writes one row in the management environment: the link token and
-- the magic code are kept as SHA-256 only, the invitee as the environment's blind index and the
-- address's domain (TN-89 (1), (4), (8)). Acceptance proves the address with the code, makes the
-- invitee's account and adds it as an administrator, never as an owner; an invitee from another
-- domain than the inviter's waits out TN-109's cooling. A newer invitation to the same address
-- supersedes a pending one. An invitation is verified, accepted or superseded once and never
-- removed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.tenant_admin_invitations (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  invitation_id uuid NOT NULL DEFAULT uuidv7(),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  -- pii:none
  invitee_index bytea NOT NULL CHECK (octet_length(invitee_index) = 32),
  invitee_domain text NOT NULL CHECK (invitee_domain ~ '^[a-z0-9.-]{1,253}$'),
  inviter_subject uuid NOT NULL,
  cross_domain boolean NOT NULL,
  created_exercise bytea NOT NULL CHECK (octet_length(created_exercise) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  accepted_at timestamptz,
  accepted_subject uuid,
  superseded_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
  CHECK ((accepted_at IS NULL) = (accepted_subject IS NULL)),
  CHECK (accepted_at IS NULL OR verified_at IS NOT NULL),
  CHECK (accepted_at IS NULL OR superseded_at IS NULL),
  PRIMARY KEY (tenant_id, environment_id, invitation_id),
  UNIQUE (tenant_id, environment_id, token_hash),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id)
);
CREATE INDEX tenant_admin_invitations_created
  ON access.tenant_admin_invitations (tenant_id, environment_id, created_at);
CREATE INDEX tenant_admin_invitations_invitee
  ON access.tenant_admin_invitations (tenant_id, environment_id, invitee_index);

-- TN-89 (7), (9): a step happens once, in order; what an invitation names never changes
CREATE FUNCTION access.tenant_admin_invitation_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'invitations are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.accepted_at IS NOT NULL OR OLD.superseded_at IS NOT NULL
     OR NEW.invitation_id <> OLD.invitation_id OR NEW.token_hash <> OLD.token_hash
     OR NEW.code_hash <> OLD.code_hash OR NEW.invitee_index <> OLD.invitee_index
     OR NEW.invitee_domain <> OLD.invitee_domain OR NEW.inviter_subject <> OLD.inviter_subject
     OR NEW.cross_domain <> OLD.cross_domain OR NEW.created_exercise <> OLD.created_exercise
     OR NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at
     OR (OLD.verified_at IS NOT NULL AND NEW.verified_at IS DISTINCT FROM OLD.verified_at) THEN
    RAISE EXCEPTION 'invitation transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER tenant_admin_invitation_transition BEFORE UPDATE OR DELETE
  ON access.tenant_admin_invitations
  FOR EACH ROW EXECUTE FUNCTION access.tenant_admin_invitation_transition();

ALTER TABLE access.tenant_admin_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.tenant_admin_invitations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.tenant_admin_invitations FROM PUBLIC;
CREATE POLICY rows ON access.tenant_admin_invitations AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.tenant_admin_invitations AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
-- OP-132 m.5
CREATE POLICY environment_scope ON access.tenant_admin_invitations AS RESTRICTIVE TO access_app
  USING (environment_id = (SELECT access.environment_scope()))
  WITH CHECK (environment_id = (SELECT access.environment_scope()));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.tenant_admin_invitations
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.tenant_admin_invitation_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.tenant_admin_invitations TO access_app;
GRANT UPDATE (verified_at, accepted_at, accepted_subject, superseded_at)
  ON access.tenant_admin_invitations TO access_app;

RESET ROLE;
