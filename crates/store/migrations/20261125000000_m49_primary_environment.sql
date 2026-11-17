-- OP-159 m.49 (a), (d), (f), TN-143, TN-144, OP-73:
--
-- environments.kind: `standard` or `primary`; the tenant's management environment becomes its
--   primary environment, an end-user environment that also holds the tenant's administrators.
-- tenant_foundings.primary_environment_id: the founding's environment, renamed with the kind.
-- tenant_admin_invitations.scope, tenant_admins.scope: the environments an administrator is
--   invited to administer; NULL is the whole tenant. Fixed once written.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.environments DISABLE TRIGGER environment_kind_fixed;
ALTER TABLE access.environments DROP CONSTRAINT environments_kind_check;
UPDATE access.environments SET kind = 'primary' WHERE kind = 'management';
ALTER TABLE access.environments
  ADD CONSTRAINT environments_kind_check CHECK (kind IN ('standard', 'primary')) NOT VALID;
ALTER TABLE access.environments ENABLE TRIGGER environment_kind_fixed;

ALTER TABLE access.tenant_foundings RENAME COLUMN management_environment_id TO primary_environment_id;

CREATE OR REPLACE FUNCTION access.tenant_founding_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'foundings are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.completed_at IS NOT NULL
     OR NEW.tenant_id <> OLD.tenant_id OR NEW.slug <> OLD.slug
     OR NEW.primary_environment_id <> OLD.primary_environment_id
     OR NEW.founder_index <> OLD.founder_index
     OR NEW.created_exercise <> OLD.created_exercise OR NEW.created_at <> OLD.created_at
     OR NEW.reinvites < OLD.reinvites
     OR (OLD.verified_at IS NOT NULL AND NEW.verified_at IS DISTINCT FROM OLD.verified_at
         AND NEW.reinvites = OLD.reinvites) THEN
    RAISE EXCEPTION 'founding transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  IF (NEW.token_hash <> OLD.token_hash OR NEW.code_hash <> OLD.code_hash
      OR NEW.expires_at <> OLD.expires_at OR NEW.issued_at <> OLD.issued_at)
     AND (NEW.reinvites <> OLD.reinvites + 1 OR NEW.verified_at IS NOT NULL) THEN
    RAISE EXCEPTION 'founding secrets change only by a reinvitation' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION access.slug_space() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('access.slug:' || NEW.slug, 0));
  IF TG_TABLE_NAME = 'tenant_foundings' THEN
    IF EXISTS (SELECT 1 FROM access.environments e WHERE e.slug = NEW.slug) THEN
      RAISE EXCEPTION 'slug taken' USING ERRCODE = 'unique_violation';
    END IF;
  ELSIF EXISTS (SELECT 1 FROM access.tenant_foundings f
                 WHERE f.slug = NEW.slug
                   AND NOT (f.tenant_id = NEW.tenant_id AND f.primary_environment_id = NEW.environment_id
                            AND NEW.kind = 'primary')) THEN
    RAISE EXCEPTION 'slug taken' USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NEW;
END
$$;

DROP FUNCTION access.founding_by_token(bytea);
CREATE FUNCTION access.founding_by_token(p_token_hash bytea)
  RETURNS TABLE (tenant_id uuid, primary_slug text, primary_environment_id uuid, expires_at timestamptz,
                 verified boolean, completed boolean)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
  SELECT f.tenant_id, f.slug, f.primary_environment_id, f.expires_at,
         f.verified_at IS NOT NULL, f.completed_at IS NOT NULL
    FROM access.tenant_foundings f
   WHERE f.token_hash = p_token_hash
$$;
REVOKE ALL ON FUNCTION access.founding_by_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.founding_by_token(bytea) TO access_app, access_router;

ALTER TABLE access.tenant_admin_invitations
  ADD COLUMN scope uuid[] CHECK (scope IS NULL OR cardinality(scope) BETWEEN 1 AND 64);
ALTER TABLE access.tenant_admins
  ADD COLUMN scope uuid[] CHECK (scope IS NULL OR cardinality(scope) BETWEEN 1 AND 64);

CREATE FUNCTION access.admin_scope_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.scope IS DISTINCT FROM OLD.scope THEN
    RAISE EXCEPTION 'administrator scope is fixed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.admin_scope_fixed() FROM PUBLIC;
CREATE TRIGGER admin_scope_fixed BEFORE UPDATE ON access.tenant_admin_invitations
  FOR EACH ROW EXECUTE FUNCTION access.admin_scope_fixed();
CREATE TRIGGER admin_scope_fixed BEFORE UPDATE ON access.tenant_admins
  FOR EACH ROW EXECUTE FUNCTION access.admin_scope_fixed();

RESET ROLE;
