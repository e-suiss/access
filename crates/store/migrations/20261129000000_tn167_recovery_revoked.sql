-- TN-167: an account recovery revokes the authenticator app it never proved; the mark lets the
-- recovered account set up a new one at sign-in once the grace period is over.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_credentials
  ADD COLUMN revoked_by text CHECK (revoked_by IS NULL OR revoked_by = 'recovery'),
  ADD CONSTRAINT identity_credentials_revoked_by_revoked CHECK (revoked_by IS NULL OR status = 'revoked') NOT VALID;

CREATE OR REPLACE FUNCTION access.credential_transition()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_credentials: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'identity_credentials: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status = 'revoked' AND (NEW.status <> 'revoked' OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
                                 OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by) THEN
    RAISE EXCEPTION 'identity_credentials: a revoked credential stays revoked' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$function$;

GRANT UPDATE (revoked_by) ON access.identity_credentials TO access_app;

RESET ROLE;
